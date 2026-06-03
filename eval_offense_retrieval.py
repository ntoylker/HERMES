import argparse
import json
import subprocess
import sys
from pathlib import Path


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


def _run_retrieval(
    *,
    query: str,
    index_dir: Path,
    top_techniques: int,
    vector_k: int,
    bm25_k: int,
    lexical_weight: float,
    lexical_only: bool,
) -> list[str]:
    cmd = [
        sys.executable,
        "query_offense_index.py",
        query,
        "--index-dir",
        str(index_dir),
        "--top-techniques",
        str(top_techniques),
        "--top-chunks",
        "1",
        "--vector-k",
        str(vector_k),
        "--bm25-k",
        str(bm25_k),
        "--lexical-weight",
        str(lexical_weight),
        "--json",
    ]
    if lexical_only:
        cmd.append("--lexical-only")

    try:
        output = subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"Retrieval failed: {exc.output.strip()}") from exc

    data = json.loads(output)
    results = data.get("results") or []
    return [r.get("mitre_id") or "Unknown" for r in results]


def _recall_at_k(pred: list[str], gold: set[str], k: int) -> float:
    for p in pred[:k]:
        if p in gold:
            return 1.0
    return 0.0


def _reciprocal_rank(pred: list[str], gold: set[str]) -> float:
    for i, p in enumerate(pred, start=1):
        if p in gold:
            return 1.0 / float(i)
    return 0.0


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate hybrid retrieval for offense index")
    parser.add_argument("--cases", default="eval_cases.jsonl", help="JSONL eval cases file")
    parser.add_argument("--index-dir", default="offense_index", help="Index directory")
    parser.add_argument("--k", type=int, default=10, help="Recall@K")
    parser.add_argument("--top-techniques", type=int, default=20, help="How many techniques to retrieve")
    parser.add_argument("--vector-k", type=int, default=200, help="Top K vector chunks")
    parser.add_argument("--bm25-k", type=int, default=200, help="Top K lexical chunks")
    parser.add_argument("--lexical-weight", type=float, default=0.15, help="Weight for lexical rank score")
    parser.add_argument("--lexical-only", action="store_true", help="Use only lexical retrieval")
    parser.add_argument("--limit", type=int, default=None, help="Limit number of cases")
    parser.add_argument("--show-failures", type=int, default=5, help="How many failures to show")

    args = parser.parse_args()

    cases = _load_cases(Path(args.cases))
    if args.limit is not None:
        cases = cases[: int(args.limit)]

    if not cases:
        raise RuntimeError("No eval cases found")

    recalls = []
    rrs = []
    failures = []

    for case in cases:
        query = str(case["query"])
        expected = set(case.get("expected") or [])
        pred = _run_retrieval(
            query=query,
            index_dir=Path(args.index_dir),
            top_techniques=int(args.top_techniques),
            vector_k=int(args.vector_k),
            bm25_k=int(args.bm25_k),
            lexical_weight=float(args.lexical_weight),
            lexical_only=bool(args.lexical_only),
        )

        rec = _recall_at_k(pred, expected, int(args.k))
        rr = _reciprocal_rank(pred, expected)
        recalls.append(rec)
        rrs.append(rr)

        if rec == 0.0:
            failures.append(
                {
                    "query": query,
                    "expected": sorted(expected),
                    "got": pred[: min(10, len(pred))],
                }
            )

    recall_k = sum(recalls) / float(len(recalls))
    mrr = sum(rrs) / float(len(rrs))

    print(f"cases={len(cases)}")
    print(f"recall@{int(args.k)}={recall_k:.4f}")
    print(f"mrr={mrr:.4f}")

    if failures:
        print("\nfailures:")
        for f in failures[: int(args.show_failures)]:
            print(f"- query: {f['query']}")
            print(f"  expected: {f['expected']}")
            print(f"  got: {f['got']}")


if __name__ == "__main__":
    main()
    