import argparse
import json
import re
import sqlite3

from dotenv import load_dotenv
load_dotenv()

from pathlib import Path

import numpy as np

from hosted_embeddings import create_embedding_client, load_embedding_config


CACHE_DB_FILENAME = "query_cache.sqlite"


def _is_blank(value) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        return value.strip() == ""
    return False


def _tokenize_for_fts(query: str) -> str:
    tokens = re.findall(r"[A-Za-z0-9_]{2,}", query)
    tokens = [t.lower() for t in tokens]
    if not tokens:
        return query
    # High-recall lexical query
    return " OR ".join(tokens[:20])


def _normalize(vec: np.ndarray) -> np.ndarray:
    norm = np.linalg.norm(vec)
    if norm == 0:
        return vec
    return vec / norm


def _normalize_query(query: str) -> str:
    return " ".join(str(query).lower().split())


def _cache_db_path() -> Path:
    return Path(__file__).resolve().parent / CACHE_DB_FILENAME


def _cache_connect(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def _cache_init(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS query_embedding_cache (
            query_norm TEXT NOT NULL,
            provider TEXT NOT NULL,
            model TEXT NOT NULL,
            embedding_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY (query_norm, provider, model)
        )
        """
    )


def _cache_get(
    conn: sqlite3.Connection,
    *,
    query_norm: str,
    provider: str,
    model: str,
) -> list[float] | None:
    row = conn.execute(
        """
        SELECT embedding_json
        FROM query_embedding_cache
        WHERE query_norm=? AND provider=? AND model=?
        """,
        (query_norm, provider, model),
    ).fetchone()
    if not row:
        return None
    try:
        return json.loads(row[0])
    except json.JSONDecodeError:
        return None


def _cache_put(
    conn: sqlite3.Connection,
    *,
    query_norm: str,
    provider: str,
    model: str,
    embedding: list[float],
) -> None:
    conn.execute(
        """
        INSERT OR REPLACE INTO query_embedding_cache
        (query_norm, provider, model, embedding_json, created_at)
        VALUES(?, ?, ?, ?, datetime('now'))
        """,
        (query_norm, provider, model, json.dumps(embedding)),
    )
    conn.commit()


def query_index(
    *,
    index_dir: Path,
    query: str,
    vector_k: int,
    bm25_k: int,
    lexical_weight: float,
    top_techniques: int,
    top_chunks_per_technique: int,
    provider: str | None,
    model: str | None,
    lexical_only: bool,
    output_json: bool,
) -> None:
    meta_path = index_dir / "index_meta.json"
    db_path = index_dir / "offense_index.sqlite"

    if not meta_path.exists():
        raise RuntimeError(f"Missing index metadata: {meta_path}")
    if not db_path.exists():
        raise RuntimeError(f"Missing index database: {db_path}")

    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    emb_meta = meta.get("embeddings")
    sims = None
    vector_doc_ids: list[int] = []

    if not lexical_only:
        if not emb_meta:
            raise RuntimeError("Index has no embeddings; rebuild without --skip-embeddings or use --lexical-only")

        emb_path = index_dir / emb_meta.get("file", "embeddings.npy")
        if not emb_path.exists():
            raise RuntimeError(f"Missing embeddings file: {emb_path}")

        # Embedding client (defaults to index settings unless overridden)
        provider = provider or emb_meta.get("provider")
        model = model or emb_meta.get("model")
        cfg = load_embedding_config(provider=provider, model=model)
        client = create_embedding_client(cfg)

        cache_conn = _cache_connect(_cache_db_path())
        _cache_init(cache_conn)
        query_norm = _normalize_query(query)
        cache_model = cfg.model or cfg.azure_deployment or "unknown"

        try:
            cached = _cache_get(
                cache_conn,
                query_norm=query_norm,
                provider=cfg.provider,
                model=cache_model,
            )
            if cached is None:
                q_emb = client.embed_texts([query])[0]
                _cache_put(
                    cache_conn,
                    query_norm=query_norm,
                    provider=cfg.provider,
                    model=cache_model,
                    embedding=q_emb,
                )
            else:
                q_emb = cached
        finally:
            cache_conn.close()

        q_vec = _normalize(np.asarray(q_emb, dtype=np.float32))

        emb = np.load(str(emb_path), mmap_mode="r")
        if emb.ndim != 2:
            raise RuntimeError("embeddings.npy has unexpected shape")

        if emb.shape[1] != q_vec.shape[0]:
            raise RuntimeError(f"Dim mismatch: index={emb.shape[1]}, query={q_vec.shape[0]}")

        # Vector hits: full scan dot-product (fast enough at this scale)
        sims = emb @ q_vec
        k = min(vector_k, sims.shape[0])
        if k <= 0:
            raise RuntimeError("vector_k must be > 0")

        top_idx = np.argpartition(-sims, kth=k - 1)[:k]
        top_idx = top_idx[np.argsort(-sims[top_idx])]
        vector_doc_ids = (top_idx + 1).tolist()  # doc_id == rowid

    # Lexical hits (SQLite FTS5 bm25)
    conn = sqlite3.connect(str(db_path))
    fts_query = _tokenize_for_fts(query)

    lexical_doc_ids: list[int] = []
    lexical_rank_score_by_id: dict[int, float] = {}

    try:
        rows = conn.execute(
            """
            SELECT rowid, bm25(chunks_fts) AS score
            FROM chunks_fts
            WHERE chunks_fts MATCH ?
            ORDER BY score
            LIMIT ?
            """,
            (fts_query, bm25_k),
        ).fetchall()

        for rank, (rowid, _score) in enumerate(rows):
            doc_id = int(rowid)
            lexical_doc_ids.append(doc_id)
            lexical_rank_score_by_id[doc_id] = 1.0 / (1.0 + float(rank))

    except sqlite3.OperationalError:
        # If query parse fails, fall back to raw query
        rows = conn.execute(
            """
            SELECT rowid, bm25(chunks_fts) AS score
            FROM chunks_fts
            WHERE chunks_fts MATCH ?
            ORDER BY score
            LIMIT ?
            """,
            (query, bm25_k),
        ).fetchall()
        for rank, (rowid, _score) in enumerate(rows):
            doc_id = int(rowid)
            lexical_doc_ids.append(doc_id)
            lexical_rank_score_by_id[doc_id] = 1.0 / (1.0 + float(rank))

    # Union candidates
    candidates = set(vector_doc_ids) | set(lexical_doc_ids)
    cand_list = sorted(candidates)

    if not cand_list:
        print("No matches.")
        return

    # Fetch metadata
    placeholders = ",".join(["?"] * len(cand_list))
    rows = conn.execute(
        f"SELECT id, mitre_id, name, chunk_type, chunk_id, text, metadata_json FROM chunks WHERE id IN ({placeholders})",
        cand_list,
    ).fetchall()

    # Aggregate by technique
    by_tech: dict[str, dict] = {}

    for (doc_id, mitre_id, name, chunk_type, chunk_id, text, metadata_json) in rows:
        mitre_id = mitre_id or "Unknown"
        tech = by_tech.setdefault(
            mitre_id,
            {
                "mitre_id": mitre_id,
                "name": name,
                "vector_max": 0.0,
                "lexical_best": 0.0,
                "chunks": [],
            },
        )

        vector_sim = None
        if sims is not None:
            vector_sim = float(sims[int(doc_id) - 1]) if int(doc_id) - 1 < sims.shape[0] else None
        lex_score = lexical_rank_score_by_id.get(int(doc_id))

        if vector_sim is not None:
            tech["vector_max"] = max(float(tech["vector_max"]), vector_sim)
        if lex_score is not None:
            tech["lexical_best"] = max(float(tech["lexical_best"]), float(lex_score))

        # Keep a few chunk exemplars for explainability
        tech["chunks"].append(
            {
                "doc_id": int(doc_id),
                "chunk_id": chunk_id,
                "chunk_type": chunk_type,
                "vector_sim": vector_sim,
                "lexical_rank_score": lex_score,
                "text": (text or "")[:300],
            }
        )

    # Compute final hybrid score and sort
    results = []
    for tech in by_tech.values():
        if lexical_only:
            hybrid = float(tech["lexical_best"])
        else:
            hybrid = float(tech["vector_max"]) + float(lexical_weight) * float(tech["lexical_best"])
        tech["hybrid_score"] = hybrid
        # Sort chunks by vector_sim
        tech["chunks"].sort(
            key=lambda c: (c["vector_sim"] is not None, c["vector_sim"] or -1.0),
            reverse=True,
        )
        tech["chunks"] = tech["chunks"][: max(1, int(top_chunks_per_technique))]
        results.append(tech)

    results.sort(key=lambda r: r["hybrid_score"], reverse=True)
    results = results[: max(1, int(top_techniques))]

    if output_json:
        print(json.dumps({"query": query, "results": results}, ensure_ascii=False, indent=2))
        return

    for i, r in enumerate(results, start=1):
        if lexical_only:
            print(
                f"{i}. {r['mitre_id']} - {r.get('name') or 'Unknown'} | lexical={r['hybrid_score']:.4f}"
            )
        else:
            print(
                f"{i}. {r['mitre_id']} - {r.get('name') or 'Unknown'} | hybrid={r['hybrid_score']:.4f} "
                f"(vec_max={r['vector_max']:.4f}, lex_best={r['lexical_best']:.4f})"
            )
        for ch in r["chunks"]:
            ct = ch.get("chunk_type") or "chunk"
            vs = ch.get("vector_sim")
            vs_s = f"{vs:.4f}" if isinstance(vs, float) else "n/a"
            print(f"   - {ct} | vec={vs_s} | {ch.get('text','').replace('\n',' ')[:250]}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Hybrid query over offense-only MITRE chunk index")
    parser.add_argument("query", help="Natural language query")
    parser.add_argument("--index-dir", default="offense_index", help="Index directory created by build_offense_index.py")
    parser.add_argument("--vector-k", type=int, default=25, help="Top K vector chunks")
    parser.add_argument("--bm25-k", type=int, default=25, help="Top K lexical chunks")
    parser.add_argument("--lexical-weight", type=float, default=0.05, help="Weight for lexical rank score")
    parser.add_argument("--top-techniques", type=int, default=10, help="How many techniques to return")
    parser.add_argument("--top-chunks", type=int, default=2, help="How many chunks to show per technique")
    parser.add_argument("--provider", default=None, help="Override embedding provider")
    parser.add_argument("--model", default=None, help="Override embedding model/deployment")
    parser.add_argument("--lexical-only", action="store_true", help="Skip embeddings and use only FTS lexical")
    parser.add_argument("--json", action="store_true", help="Output JSON")

    args = parser.parse_args()

    query_index(
        index_dir=Path(args.index_dir),
        query=str(args.query),
        vector_k=int(args.vector_k),
        bm25_k=int(args.bm25_k),
        lexical_weight=float(args.lexical_weight),
        top_techniques=int(args.top_techniques),
        top_chunks_per_technique=int(args.top_chunks),
        provider=args.provider,
        model=args.model,
        lexical_only=bool(args.lexical_only),
        output_json=bool(args.json),
    )


if __name__ == "__main__":
    main()
