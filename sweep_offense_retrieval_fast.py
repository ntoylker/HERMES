import argparse
import itertools
import json
import os
import re
import sqlite3
from pathlib import Path
import numpy as np

from hosted_embeddings import create_embedding_client, load_embedding_config


def _load_dotenv(workspace: Path) -> None:
    env_path = workspace / ".env"
    if not env_path.exists():
        return

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        os.environ.setdefault(key, value)


def _normalize(vec: np.ndarray) -> np.ndarray:
    norm = np.linalg.norm(vec)
    if norm == 0:
        return vec
    return vec / norm


def _normalize_query(query: str) -> str:
    return " ".join(str(query).lower().split())


def _tokenize_for_fts(query: str) -> str:
    tokens = re.findall(r"[A-Za-z0-9_]{2,}", query)
    tokens = [token.lower() for token in tokens]
    if not tokens:
        return query
    return " OR ".join(tokens[:20])


def _recall_at_k(pred: list[str], gold: set[str], k: int) -> float:
    for item in pred[:k]:
        if item in gold:
            return 1.0
    return 0.0


def _reciprocal_rank(pred: list[str], gold: set[str]) -> float:
    for i, item in enumerate(pred, start=1):
        if item in gold:
            return 1.0 / float(i)
    return 0.0


def _load_cases(path: Path) -> list[dict]:
    cases: list[dict] = []
    for line_num, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            case = json.loads(line)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"Invalid JSON on line {line_num} in {path}") from exc
        query = case.get("query")
        if not query:
            raise RuntimeError(f"Missing query on line {line_num} in {path}")
        expected = case.get("expected") or []
        if isinstance(expected, str):
            expected = [expected]
        cases.append({"query": str(query), "expected": set(expected)})
    return cases


def _load_chunks(conn: sqlite3.Connection) -> dict[int, dict]:
    rows = conn.execute(
        "SELECT id, mitre_id, name, chunk_type FROM chunks ORDER BY id"
    ).fetchall()
    chunks: dict[int, dict] = {}
    for doc_id, mitre_id, name, chunk_type in rows:
        chunks[int(doc_id)] = {
            "doc_id": int(doc_id),
            "mitre_id": mitre_id or "Unknown",
            "name": name or "Unknown",
            "chunk_type": chunk_type,
        }
    return chunks


def _top_lexical_ids(
    conn: sqlite3.Connection,
    query: str,
    bm25_k: int,
) -> tuple[list[int], dict[int, float]]:
    lexical_doc_ids: list[int] = []
    lexical_rank_score_by_id: dict[int, float] = {}
    fts_query = _tokenize_for_fts(query)

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
    except sqlite3.OperationalError:
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

    return lexical_doc_ids, lexical_rank_score_by_id


def _aggregate_predictions(
    *,
    chunks: dict[int, dict],
    vector_ids: list[int],
    lexical_ids: list[int],
    lexical_rank_score_by_id: dict[int, float],
    sims: np.ndarray | None,
    vector_k: int,
    bm25_k: int,
    lexical_weight: float,
    top_techniques: int,
    lexical_only: bool,
) -> list[str]:
    vector_selected = set(vector_ids[:vector_k])
    lexical_selected = set(lexical_ids[:bm25_k])
    candidate_ids = sorted(vector_selected | lexical_selected)

    by_tech: dict[str, dict] = {}

    for doc_id in candidate_ids:
        chunk = chunks.get(int(doc_id))
        if not chunk:
            continue

        mitre_id = chunk["mitre_id"]
        tech = by_tech.setdefault(
            mitre_id,
            {
                "mitre_id": mitre_id,
                "vector_max": 0.0,
                "lexical_best": 0.0,
            },
        )

        vector_sim = None
        if not lexical_only and sims is not None and int(doc_id) in vector_selected:
            vector_sim = float(sims[int(doc_id) - 1])
        lex_score = lexical_rank_score_by_id.get(int(doc_id)) if int(doc_id) in lexical_selected else None

        if vector_sim is not None:
            tech["vector_max"] = max(float(tech["vector_max"]), vector_sim)
        if lex_score is not None:
            tech["lexical_best"] = max(float(tech["lexical_best"]), float(lex_score))

    ranked = []
    for tech in by_tech.values():
        if lexical_only:
            score = float(tech["lexical_best"])
        else:
            score = float(tech["vector_max"]) + float(lexical_weight) * float(tech["lexical_best"])
        ranked.append((score, str(tech["mitre_id"])))

    ranked.sort(key=lambda item: item[0], reverse=True)
    return [mitre_id for _score, mitre_id in ranked[: max(1, int(top_techniques))]]


def main() -> None:
    parser = argparse.ArgumentParser(description="Fast parameter sweep for offense retrieval")
    parser.add_argument("--cases", default="data/eval/eval_cases.jsonl", help="JSONL eval cases file")
    parser.add_argument("--index-dir", default="artifacts/offense_index", help="Index directory")
    parser.add_argument("--vector-ks", default="25", help="Comma-separated vector_k values")
    parser.add_argument("--bm25-ks", default="25", help="Comma-separated bm25_k values")
    parser.add_argument("--lexical-weights", default="0.05", help="Comma-separated lexical weights")
    parser.add_argument("--top-techniques", type=int, default=20, help="How many techniques to rank")
    parser.add_argument("--k", type=int, default=10, help="Recall@K")
    parser.add_argument("--provider", default=None, help="Override embedding provider")
    parser.add_argument("--model", default=None, help="Override embedding model")
    parser.add_argument("--top-results", type=int, default=10, help="How many configs to print")
    parser.add_argument("--lexical-only", action="store_true", help="Evaluate lexical-only mode")
    args = parser.parse_args()

    workspace = Path(__file__).resolve().parent
    _load_dotenv(workspace)

    index_dir = Path(args.index_dir)
    meta_path = index_dir / "index_meta.json"
    db_path = index_dir / "offense_index.sqlite"
    emb_path = index_dir / "embeddings.npy"

    if not meta_path.exists():
        raise RuntimeError(f"Missing index metadata: {meta_path}")
    if not db_path.exists():
        raise RuntimeError(f"Missing index database: {db_path}")

    cases = _load_cases(Path(args.cases))
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    emb_meta = meta.get("embeddings") or {}

    conn = sqlite3.connect(str(db_path))
    chunks = _load_chunks(conn)

    vector_ks = [int(v.strip()) for v in args.vector_ks.split(",") if v.strip()]
    bm25_ks = [int(v.strip()) for v in args.bm25_ks.split(",") if v.strip()]
    lexical_weights = [float(v.strip()) for v in args.lexical_weights.split(",") if v.strip()]

    if not vector_ks or not bm25_ks or not lexical_weights:
        raise RuntimeError("vector-ks, bm25-ks, and lexical-weights must not be empty")

    max_vector_k = max(vector_ks)
    max_bm25_k = max(bm25_ks)
    emb = None
    client = None

    if not args.lexical_only:
        provider = args.provider or emb_meta.get("provider")
        model = args.model or emb_meta.get("model")
        cfg = load_embedding_config(provider=provider, model=model)
        client = create_embedding_client(cfg)
        emb = np.load(str(emb_path), mmap_mode="r")
        if emb.ndim != 2:
            raise RuntimeError("embeddings.npy has unexpected shape")

    query_cache: dict[str, np.ndarray] = {}
    lexical_cache: dict[str, tuple[list[int], dict[int, float]]] = {}
    precomputed = []

    total_cases = len(cases)
    total_configs = len(vector_ks) * len(bm25_ks) * len(lexical_weights)

    print(f"PRECOMPUTE_START cases={total_cases}", flush=True)

    for case_idx, case in enumerate(cases, start=1):
        query = case["query"]
        q_norm = _normalize_query(query)

        if q_norm in lexical_cache:
            lexical_ids, lexical_score_by_id = lexical_cache[q_norm]
        else:
            lexical_ids, lexical_score_by_id = _top_lexical_ids(conn, query, max_bm25_k)
            lexical_cache[q_norm] = (lexical_ids, lexical_score_by_id)

        if args.lexical_only:
            vector_ids: list[int] = []
            sims = None
        else:
            assert client is not None
            assert emb is not None
            if q_norm in query_cache:
                q_vec = query_cache[q_norm]
            else:
                q_emb = client.embed_texts([query])[0]
                q_vec = _normalize(np.asarray(q_emb, dtype=np.float32))
                query_cache[q_norm] = q_vec

            if emb.shape[1] != q_vec.shape[0]:
                raise RuntimeError(f"Dim mismatch: index={emb.shape[1]}, query={q_vec.shape[0]}")

            sims = emb @ q_vec
            k = min(max_vector_k, sims.shape[0])
            if k <= 0:
                raise RuntimeError("vector_k must be > 0")
            top_idx = np.argpartition(-sims, kth=k - 1)[:k]
            top_idx = top_idx[np.argsort(-sims[top_idx])]
            vector_ids = (top_idx + 1).tolist()

        precomputed.append(
            {
                "expected": case["expected"],
                "lexical_ids": lexical_ids,
                "lexical_score_by_id": lexical_score_by_id,
                "vector_ids": vector_ids,
                "sims": sims,
            }
        )

        print(
            f"PRECOMPUTE_PROGRESS {case_idx}/{total_cases} query={query[:80]!r}",
            flush=True,
        )

    print(f"PRECOMPUTE_DONE cases={total_cases}", flush=True)

    results = []
    for config_idx, (vector_k, bm25_k, lexical_weight) in enumerate(
        itertools.product(vector_ks, bm25_ks, lexical_weights),
        start=1,
    ):
        recalls = []
        rrs = []
        for item in precomputed:
            pred = _aggregate_predictions(
                chunks=chunks,
                vector_ids=item["vector_ids"],
                lexical_ids=item["lexical_ids"],
                lexical_rank_score_by_id=item["lexical_score_by_id"],
                sims=item["sims"],
                vector_k=vector_k,
                bm25_k=bm25_k,
                lexical_weight=lexical_weight,
                top_techniques=args.top_techniques,
                lexical_only=bool(args.lexical_only),
            )
            recalls.append(_recall_at_k(pred, item["expected"], args.k))
            rrs.append(_reciprocal_rank(pred, item["expected"]))

        results.append(
            {
                "vector_k": vector_k,
                "bm25_k": bm25_k,
                "lexical_weight": lexical_weight,
                "lexical_only": bool(args.lexical_only),
                "recall_at_10": sum(recalls) / float(len(recalls)),
                "mrr": sum(rrs) / float(len(rrs)),
            }
        )

        latest = results[-1]
        print(
            "CONFIG_PROGRESS "
            f"{config_idx}/{total_configs} "
            f"vector_k={vector_k} bm25_k={bm25_k} lexical_weight={lexical_weight} "
            f"recall@10={latest['recall_at_10']:.4f} mrr={latest['mrr']:.4f}",
            flush=True,
        )

    results.sort(key=lambda r: (r["recall_at_10"], r["mrr"], -r["vector_k"] - r["bm25_k"], -r["lexical_weight"]), reverse=True)

    print("SWEEP_SUMMARY")
    print(f"cases={len(cases)}")
    print(f"configs={len(results)}")
    print()
    print("TOP_RESULTS")
    for item in results[: max(1, int(args.top_results))]:
        print(json.dumps(item, ensure_ascii=False))


if __name__ == "__main__":
    main()