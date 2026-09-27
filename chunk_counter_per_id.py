"""Temporary script: counts chunks per MITRE technique ID in the offense corpus."""
import json

INPUT_PATH = "data/processed/rag_offense_mitre_chunks.jsonl"
OUTPUT_PATH = "data/processed/count-chunks-per-id.json"

counts: dict[str, int] = {}

with open(INPUT_PATH, "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        record = json.loads(line)
        mitre_id = record.get("metadata", {}).get("mitre_id", "Unknown")
        counts[mitre_id] = counts.get(mitre_id, 0) + 1

with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
    json.dump(counts, f, ensure_ascii=False, indent=2)

print(f"Wrote chunk counts for {len(counts)} technique IDs to {OUTPUT_PATH}")
