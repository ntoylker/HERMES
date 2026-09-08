import argparse
import json
import subprocess
import sys
from pathlib import Path

from dotenv import load_dotenv
load_dotenv()

import numpy as np

from hosted_embeddings import create_embedding_client, load_embedding_config


def _load_cases(path: Path) -> list[dict]:
    cases: list[dict] = []
    if not path.exists():
        raise RuntimeError(f"Missing eval cases file: {path}")
    for line_num, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            case = json.loads(line)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"Invalid JSON on line {line_num} in {path}") from exc
        if not case.get("query"):
            raise RuntimeError(f"Missing query on line {line_num} in {path}")
        expected = case.get("expected") or []
        if isinstance(expected, str):
            expected = [expected]
        case["expected"] = list(expected)
        cases.append(case)
    return cases


def _run_generation(
    *,
    query: str,
    index_dir: Path,
    human_output_dir: Path,
    machine_output_dir: Path,
    top_techniques: int,
    vector_k: int,
    bm25_k: int,
    lexical_weight: float,
    gen_model: str | None,
) -> dict:
    cmd = [
        sys.executable,
        "generate_offense_rag.py",
        query,
        "--index-dir", str(index_dir),
        "--human-output-dir", str(human_output_dir),
        "--machine-output-dir", str(machine_output_dir),
        "--top-techniques", str(top_techniques),
        "--vector-k", str(vector_k),
        "--bm25-k", str(bm25_k),
        "--lexical-weight", str(lexical_weight),
    ]
    if gen_model:
        cmd += ["--gen-model", gen_model]

    output = subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT)
    # generate_offense_rag.py prints exactly one path line per run; take the last line defensively.
    output_path = Path(output.strip().splitlines()[-1])
    return json.loads(output_path.read_text(encoding="utf-8"))


def _cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
    denom = float(np.linalg.norm(a) * np.linalg.norm(b))
    if denom == 0.0:
        return 0.0
    return float(np.dot(a, b) / denom)


def _faithfulness(payload: dict) -> float | None:
    # RAGAS-style faithfulness, scored deterministically from the citation validator's kept/dropped counts.
    dropped = len((payload.get("citation_validation") or {}).get("dropped") or [])
    kept = len(payload.get("top_techniques") or []) + len(payload.get("alternatives") or [])
    total = kept + dropped
    return (kept / float(total)) if total else None


def _end_to_end_recall(payload: dict, expected: set[str]) -> float:
    # Recall of the final, validated answer - complements eval_offense_retrieval.py's raw-retrieval recall@K.
    got = {t.get("mitre_id") for t in (payload.get("top_techniques") or [])}
    got |= {t.get("mitre_id") for t in (payload.get("alternatives") or [])}
    return 1.0 if got & expected else 0.0


def _answer_text(payload: dict) -> str:
    summary = str(payload.get("summary") or "").strip()
    if summary:
        return summary
    rationales = [str(t.get("rationale") or "") for t in (payload.get("top_techniques") or [])]
    return " ".join(r for r in rationales if r).strip()


def _mean(values: list[float]) -> float:
    return sum(values) / float(len(values)) if values else 0.0


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Evaluate Stage 1 generation quality: faithfulness, answer relevancy, end-to-end recall"
    )
    parser.add_argument("--cases", default="data/eval/eval_cases.jsonl", help="JSONL eval cases file")
    parser.add_argument("--index-dir", default="artifacts/offense_index", help="Index directory")
    parser.add_argument(
        "--human-output-dir",
        default="data/eval/human_outs",
        help="Where generated Stage 1 .json files are written",
    )
    parser.add_argument(
        "--machine-output-dir",
        default="data/eval/machine_outs",
        help="Where generated Stage 1 .jsonl files are written",
    )
    parser.add_argument("--top-techniques", type=int, default=8, help="How many techniques to retrieve")
    parser.add_argument("--vector-k", type=int, default=25, help="Top K vector chunks")
    parser.add_argument("--bm25-k", type=int, default=25, help="Top K lexical chunks")
    parser.add_argument("--lexical-weight", type=float, default=0.05, help="Weight for lexical rank score")
    parser.add_argument("--gen-model", default=None, help="Gemini generation model override")
    parser.add_argument("--provider", default=None, help="Override embedding provider (used for answer relevancy)")
    parser.add_argument("--model", default=None, help="Override embedding model (used for answer relevancy)")
    parser.add_argument("--limit", type=int, default=None, help="Limit number of cases")
    parser.add_argument("--show-failures", type=int, default=5, help="How many failing cases to show")

    args = parser.parse_args()

    cases = _load_cases(Path(args.cases))
    if args.limit is not None:
        cases = cases[: int(args.limit)]
    if not cases:
        raise RuntimeError("No eval cases found")

    human_output_dir = Path(args.human_output_dir)
    machine_output_dir = Path(args.machine_output_dir)
    human_output_dir.mkdir(parents=True, exist_ok=True)
    machine_output_dir.mkdir(parents=True, exist_ok=True)

    embed_cfg = load_embedding_config(provider=args.provider, model=args.model)
    embed_client = create_embedding_client(embed_cfg)

    faithfulness_scores: list[float] = []
    relevancy_scores: list[float] = []
    recalls: list[float] = []
    failures: list[dict] = []

    for case in cases:
        query = str(case["query"])
        expected = set(case.get("expected") or [])

        try:
            payload = _run_generation(
                query=query,
                index_dir=Path(args.index_dir),
                human_output_dir=human_output_dir,
                machine_output_dir=machine_output_dir,
                top_techniques=int(args.top_techniques),
                vector_k=int(args.vector_k),
                bm25_k=int(args.bm25_k),
                lexical_weight=float(args.lexical_weight),
                gen_model=args.gen_model,
            )
        except subprocess.CalledProcessError as exc:
            recalls.append(0.0)
            failures.append({"query": query, "expected": sorted(expected), "error": exc.output.strip()[:500]})
            continue

        if "citation_validation" not in payload:
            # Upstream miss (no retrieval hits / empty model text / invalid JSON) - counts as a recall failure.
            recalls.append(0.0)
            failures.append(
                {
                    "query": query,
                    "expected": sorted(expected),
                    "error": payload.get("summary") or "no validated Stage 1 output",
                }
            )
            continue

        faithfulness = _faithfulness(payload)
        if faithfulness is not None:
            faithfulness_scores.append(faithfulness)

        answer_text = _answer_text(payload)
        if answer_text:
            embs = embed_client.embed_texts([query, answer_text])
            relevancy = _cosine_similarity(
                np.asarray(embs[0], dtype=np.float32), np.asarray(embs[1], dtype=np.float32)
            )
            relevancy_scores.append(relevancy)

        recall = _end_to_end_recall(payload, expected)
        recalls.append(recall)

        if recall == 0.0 or (faithfulness is not None and faithfulness < 1.0):
            failures.append(
                {
                    "query": query,
                    "expected": sorted(expected),
                    "final_techniques": sorted(t.get("mitre_id") for t in (payload.get("top_techniques") or [])),
                    "faithfulness": faithfulness,
                    "dropped": (payload.get("citation_validation") or {}).get("dropped") or [],
                }
            )

    print(f"cases={len(cases)}")
    print(f"faithfulness_mean={_mean(faithfulness_scores):.4f} (n={len(faithfulness_scores)})")
    print(f"answer_relevancy_mean={_mean(relevancy_scores):.4f} (n={len(relevancy_scores)})")
    print(f"end_to_end_recall_mean={_mean(recalls):.4f} (n={len(recalls)})")

    if failures:
        print("\nfailures:")
        for f in failures[: int(args.show_failures)]:
            print(f"- query: {f['query']}")
            print(f"  expected: {f.get('expected')}")
            if "error" in f:
                print(f"  error: {f['error']}")
            else:
                print(f"  final_techniques: {f.get('final_techniques')}")
                print(f"  faithfulness: {f.get('faithfulness')}")
                if f.get("dropped"):
                    print(f"  dropped: {f['dropped']}")


if __name__ == "__main__":
    main()
