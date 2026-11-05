"""Linux-filtered variant of Stage 0 corpus building: wraps build_offense_corpus.py's
chunking logic with a platform filter so the output is a Linux-focused offense corpus,
written to its own path alongside (not replacing) the unfiltered full corpus.
"""

import argparse

from build_offense_corpus import build_offense_corpus


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build a Linux-filtered, offense-only, chunked MITRE ATT&CK JSONL for RAG."
    )
    parser.add_argument(
        "--input",
        default="data/raw/enterprise-attack/enterprise-attack.json",
        help="Path to the MITRE ATT&CK Enterprise STIX bundle (enterprise-attack.json)",
    )
    parser.add_argument(
        "--output",
        default="data/processed/rag_offense_mitre_linux_chunks.jsonl",
        help="Output JSONL path (separate from the unfiltered full corpus)",
    )
    parser.add_argument(
        "--platform",
        default="Linux",
        help="x_mitre_platforms value to filter on (inclusive membership test)",
    )

    args = parser.parse_args()
    build_offense_corpus(args.input, args.output, platform=args.platform)


if __name__ == "__main__":
    main()
