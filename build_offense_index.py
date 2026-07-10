import argparse
import json
import sqlite3

from dotenv import load_dotenv
load_dotenv()

from datetime import datetime, timezone
from pathlib import Path

import numpy as np
from tqdm import tqdm

from hosted_embeddings import create_embedding_client, load_embedding_config


def _is_blank(value) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        return value.strip() == ""
    return False


def _count_jsonl(path: Path) -> int:
    n = 0
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                n += 1
    return n


def _truncate_for_embedding(text: str, max_chars: int = 12000) -> str:
    if text is None:
        return ""
    text = str(text)
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 200] + "\n[TRUNCATED]"


def _lexical_text(metadata: dict, text: str) -> str:
    parts: list[str] = []

    if not _is_blank(text):
        parts.append(str(text))

    for key in [
        "mitre_id",
        "name",
        "parent_mitre_id",
        "parent_name",
        "chunk_type",
        "source_name",
        "source_attack_id",
        "source_type",
    ]:
        v = metadata.get(key)
        if not _is_blank(v):
            parts.append(str(v))

    for key in ["tactics", "platforms", "domains", "source_aliases"]:
        v = metadata.get(key)
        if isinstance(v, list) and v:
            parts.append(" ".join(str(x) for x in v if not _is_blank(x)))

    return "\n".join(parts)


def _connect_sqlite(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA temp_store=MEMORY")
    conn.execute("PRAGMA cache_size=-200000")  # ~200MB cache if possible
    return conn


def _init_db(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS chunks (
            id INTEGER PRIMARY KEY,
            chunk_id TEXT,
            mitre_id TEXT,
            name TEXT,
            chunk_type TEXT,
            text TEXT,
            metadata_json TEXT,
            embedded INTEGER NOT NULL DEFAULT 0
        )
        """
    )

    conn.execute(
        """
        CREATE VIRTUAL TABLE IF NOT EXISTS chunks_fts
        USING fts5(lexical_text)
        """
    )

    conn.execute("CREATE INDEX IF NOT EXISTS idx_chunks_mitre_id ON chunks(mitre_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_chunks_chunk_id ON chunks(chunk_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_chunks_embedded ON chunks(embedded)")


def _load_jsonl_records(path: Path):
    with path.open("r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as e:
                raise RuntimeError(f"Invalid JSONL at line {line_num}: {e}")


def _normalize_rows(matrix: np.ndarray) -> np.ndarray:
    norms = np.linalg.norm(matrix, axis=1, keepdims=True)
    norms = np.where(norms == 0, 1.0, norms)
    return matrix / norms


def build_index(
    *,
    corpus_path: Path,
    outdir: Path,
    provider: str | None,
    model: str | None,
    skip_embeddings: bool,
    overwrite: bool,
    batch_size: int,
    limit: int | None,
) -> None:
    outdir.mkdir(parents=True, exist_ok=True)

    db_path = outdir / "offense_index.sqlite"
    emb_path = outdir / "embeddings.npy"
    meta_path = outdir / "index_meta.json"

    db_existed = db_path.exists()

    if overwrite:
        if db_path.exists():
            db_path.unlink()
        if emb_path.exists():
            emb_path.unlink()
        if meta_path.exists():
            meta_path.unlink()

    conn = _connect_sqlite(db_path)
    _init_db(conn)

    # If DB already contains chunks and we are not overwriting, skip re-import.
    if db_existed and not overwrite:
        existing = conn.execute("SELECT COUNT(1) FROM chunks").fetchone()[0]
        if existing and int(existing) > 0:
            total = int(existing)
            if limit is not None:
                print("Note: --limit is ignored when reusing an existing index.")
            print(f"Found existing SQLite index with {total} chunks; skipping corpus import.")
        else:
            total = _count_jsonl(corpus_path)
            if limit is not None:
                total = min(total, limit)
            print(f"Indexing {total} chunks into {outdir}...")
    else:
        total = _count_jsonl(corpus_path)
        if limit is not None:
            total = min(total, limit)
        print(f"Indexing {total} chunks into {outdir}...")

    # Phase 1: load chunks + FTS (only if DB doesn't already contain data)
    existing_now = conn.execute("SELECT COUNT(1) FROM chunks").fetchone()[0]
    if not existing_now or int(existing_now) == 0:
        cur = conn.cursor()
        cur.execute("BEGIN")
        inserted = 0

        pbar = tqdm(total=total, desc="SQLite+FTS", unit="chunk")
        for record in _load_jsonl_records(corpus_path):
            if limit is not None and inserted >= limit:
                break

            metadata = record.get("metadata") or {}
            text = record.get("text") or ""
            if not isinstance(metadata, dict):
                metadata = {}

            chunk_id = metadata.get("chunk_id") or f"row{inserted + 1}"
            mitre_id = metadata.get("mitre_id")
            name = metadata.get("name")
            chunk_type = metadata.get("chunk_type")
            metadata_json = json.dumps(metadata, ensure_ascii=False)
            lexical = _lexical_text(metadata, text)

            row_id = inserted + 1
            cur.execute(
                """
                INSERT INTO chunks(id, chunk_id, mitre_id, name, chunk_type, text, metadata_json, embedded)
                VALUES(?, ?, ?, ?, ?, ?, ?, 0)
                """,
                (row_id, chunk_id, mitre_id, name, chunk_type, text, metadata_json),
            )
            cur.execute(
                "INSERT INTO chunks_fts(rowid, lexical_text) VALUES(?, ?)",
                (row_id, lexical),
            )

            inserted += 1
            pbar.update(1)

            if inserted % 2000 == 0:
                conn.commit()
                cur.execute("BEGIN")

        conn.commit()
        pbar.close()

        if inserted != total:
            total = inserted
    else:
        total = int(existing_now)

    # Phase 2: embeddings
    if skip_embeddings:
        meta = {
            "created_at": datetime.now(timezone.utc).isoformat(),
            "corpus": str(corpus_path),
            "count": total,
            "embeddings": None,
        }
        meta_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print("Done (skipped embeddings).")
        return

    cfg = load_embedding_config(provider=provider, model=model)
    client = create_embedding_client(cfg)

    # Resume support
    dims: int | None = None
    emb_mem = None
    if emb_path.exists():
        emb_mem = np.load(str(emb_path), mmap_mode="r+")
        if emb_mem.ndim != 2:
            raise RuntimeError("Existing embeddings.npy has unexpected shape")
        dims = int(emb_mem.shape[1])

    # Determine which rows still need embeddings
    cur = conn.cursor()
    pending = cur.execute("SELECT COUNT(1) FROM chunks WHERE embedded=0").fetchone()[0]
    print(f"Embedding provider={cfg.provider}, pending={pending} chunks")

    # We'll embed in id order for stable row mapping
    while True:
        rows = cur.execute(
            "SELECT id, text FROM chunks WHERE embedded=0 ORDER BY id LIMIT ?",
            (batch_size,),
        ).fetchall()
        if not rows:
            break

        ids = [r[0] for r in rows]
        texts = [_truncate_for_embedding(r[1]) for r in rows]

        embeddings = client.embed_texts(texts)
        batch_arr = np.asarray(embeddings, dtype=np.float32)
        if batch_arr.ndim != 2:
            raise RuntimeError("Embedding client returned unexpected shape")

        if dims is None:
            dims = int(batch_arr.shape[1])
            emb_mem = np.lib.format.open_memmap(
                str(emb_path),
                mode="w+",
                dtype=np.float32,
                shape=(total, dims),
            )

        if int(batch_arr.shape[1]) != int(dims):
            raise RuntimeError(f"Embedding dim mismatch: got {batch_arr.shape[1]}, expected {dims}")

        batch_arr = _normalize_rows(batch_arr)

        # Write
        assert emb_mem is not None
        for i, row_id in enumerate(ids):
            emb_mem[row_id - 1] = batch_arr[i]

        # Mark embedded
        cur.executemany("UPDATE chunks SET embedded=1 WHERE id=?", [(i,) for i in ids])
        conn.commit()

    if emb_mem is not None:
        emb_mem.flush()

    # Persist meta
    meta = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "corpus": str(corpus_path),
        "count": total,
        "embeddings": {
            "provider": cfg.provider,
            "model": cfg.model or cfg.azure_deployment,
            "dims": dims,
            "file": str(emb_path.name),
            "normalized": True,
        },
    }
    meta_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    print(f"Done. SQLite={db_path.name}, embeddings={emb_path.name}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Build hybrid (FTS5+embeddings) index for offense-only MITRE chunks")
    parser.add_argument(
        "--corpus",
        default="data/processed/rag_offense_mitre_chunks.jsonl",
        help="Input JSONL corpus (from build_offense_corpus.py)",
    )
    parser.add_argument(
        "--outdir",
        default="artifacts/offense_index",
        help="Output directory for SQLite + embeddings",
    )

    parser.add_argument("--provider", default=None, help="Embedding provider: openai | azure_openai | google_ai_studio")
    parser.add_argument("--model", default=None, help="Embedding model (OpenAI) or deployment (Azure)")

    parser.add_argument("--skip-embeddings", action="store_true", help="Only build SQLite/FTS index")
    parser.add_argument("--overwrite", action="store_true", help="Overwrite any existing index files")
    parser.add_argument("--batch-size", type=int, default=96, help="Embedding batch size")
    parser.add_argument("--limit", type=int, default=None, help="Limit number of chunks (debug)")

    args = parser.parse_args()

    build_index(
        corpus_path=Path(args.corpus),
        outdir=Path(args.outdir),
        provider=args.provider,
        model=args.model,
        skip_embeddings=bool(args.skip_embeddings),
        overwrite=bool(args.overwrite),
        batch_size=int(args.batch_size),
        limit=args.limit,
    )


if __name__ == "__main__":
    main()
