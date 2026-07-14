import argparse
import json
import re
from datetime import datetime, timezone

from mitreattack.stix20 import MitreAttackData



def _is_blank(value) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        return value.strip() == ""
    return False


def _attack_external_id(stix_obj, source_name: str = "mitre-attack") -> str | None:
    ext_refs = stix_obj.get("external_references", []) if stix_obj else []
    for ref in ext_refs:
        if ref.get("source_name") == source_name and ref.get("external_id"):
            return ref["external_id"]
    return None


def _dedupe_preserve_order(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if _is_blank(item) or item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def _first_paragraph(text: str) -> str:
    if _is_blank(text):
        return ""
    parts = re.split(r"\n\s*\n", text.strip(), maxsplit=1)
    return parts[0].strip()


def _safe_get_type(stix_obj) -> str | None:
    if not stix_obj:
        return None
    # Many stix objects expose a .type attribute
    t = getattr(stix_obj, "type", None)
    if t:
        return t
    return stix_obj.get("type")


def build_offense_corpus(input_path: str, output_path: str) -> None:
    print(f"Loading {input_path} (this might take a minute)...")
    mitre_data = MitreAttackData(input_path)

    techniques = mitre_data.get_techniques(remove_revoked_deprecated=True)

    generated_at = datetime.now(timezone.utc).isoformat()

    count_chunks = 0
    count_proc = 0

    with open(output_path, "w", encoding="utf-8") as f:
        for technique in techniques:
            mitre_id = _attack_external_id(technique) or "Unknown"
            name = technique.get("name") or "Unknown"
            description = technique.get("description") or ""

            if _is_blank(description):
                continue

            platforms = technique.get("x_mitre_platforms") or []
            domains = technique.get("x_mitre_domains") or []

            tactics = mitre_data.get_tactics_by_technique(technique.id)
            tactic_names = [t.name for t in tactics] if tactics else []

            is_sub = bool(technique.get("x_mitre_is_subtechnique"))
            parent_attack_id: str | None = None
            parent_name: str | None = None
            if is_sub:
                parent_data = mitre_data.get_parent_technique_of_subtechnique(technique.id)
                parent_obj = None
                if parent_data and isinstance(parent_data, list):
                    parent_obj = parent_data[0].get("object")
                if parent_obj:
                    parent_attack_id = _attack_external_id(parent_obj)
                    parent_name = parent_obj.get("name")

            base_metadata = {
                "mitre_id": mitre_id,
                "name": name,
                "stix_id": technique.id,
                "tactics": tactic_names,
                "platforms": platforms,
                "domains": domains,
                "is_subtechnique": is_sub,
                "parent_mitre_id": parent_attack_id,
                "parent_name": parent_name,
                "generated_at": generated_at,
            }

            # Chunk: short overview (first paragraph)
            overview = _first_paragraph(description)
            if not _is_blank(overview):
                chunk = {
                    "metadata": {
                        **base_metadata,
                        "chunk_type": "technique_overview",
                        "chunk_id": f"{mitre_id}|overview",
                    },
                    "text": f"Technique {mitre_id}: {name}. {overview}",
                }
                f.write(json.dumps(chunk, ensure_ascii=False) + "\n")
                count_chunks += 1

            # Chunk: full technique description
            chunk = {
                "metadata": {
                    **base_metadata,
                    "chunk_type": "technique_description",
                    "chunk_id": f"{mitre_id}|description",
                },
                "text": f"Technique {mitre_id}: {name}. Description: {description}",
            }
            f.write(json.dumps(chunk, ensure_ascii=False) + "\n")
            count_chunks += 1

            # Chunk(s): procedure examples / observed usage (uses relationships)
            try:
                procedures = mitre_data.get_procedure_examples_by_technique(technique.id)
            except Exception:
                procedures = []

            for rel in procedures or []:
                rel_id = rel.get("id") if isinstance(rel, dict) else getattr(rel, "id", None)
                source_ref = rel.get("source_ref") if isinstance(rel, dict) else getattr(rel, "source_ref", None)
                rel_desc = rel.get("description") if isinstance(rel, dict) else getattr(rel, "description", None)

                if _is_blank(source_ref):
                    continue

                # Resolve the source object (group, malware, tool, campaign)
                source_obj = None
                try:
                    source_obj = mitre_data.get_object_by_stix_id(source_ref)
                except Exception:
                    source_obj = None

                source_name = None
                source_attack_id = None
                source_type = None
                source_aliases: list[str] = []
                if source_obj:
                    source_name = source_obj.get("name")
                    source_attack_id = _attack_external_id(source_obj)
                    source_type = _safe_get_type(source_obj)
                    # groups often use `aliases`, software uses `x_mitre_aliases`
                    source_aliases = source_obj.get("aliases") or source_obj.get("x_mitre_aliases") or []

                source_name = source_name or source_ref
                source_type = source_type or "unknown"

                # Even when MITRE doesn't provide a description, keep a compact stub
                if _is_blank(rel_desc):
                    rel_text = f"Observed usage: {source_name} used Technique {mitre_id}: {name}."
                    chunk_type = "procedure_example_stub"
                else:
                    rel_text = (
                        f"Procedure example: {source_name} used Technique {mitre_id}: {name}. "
                        f"{str(rel_desc).strip()}"
                    )
                    chunk_type = "procedure_example"

                chunk = {
                    "metadata": {
                        **base_metadata,
                        "chunk_type": chunk_type,
                        "chunk_id": f"{mitre_id}|proc|{rel_id or source_ref}",
                        "source_stix_id": source_ref,
                        "source_type": source_type,
                        "source_name": source_name,
                        "source_attack_id": source_attack_id,
                        "source_aliases": _dedupe_preserve_order([str(a) for a in source_aliases if not _is_blank(a)]),
                        "relationship_stix_id": rel_id,
                    },
                    "text": rel_text,
                }
                f.write(json.dumps(chunk, ensure_ascii=False) + "\n")
                count_chunks += 1
                count_proc += 1

    print(f"Wrote {count_chunks} chunks to {output_path} ({count_proc} procedure-example chunks).")


def main() -> None:
    parser = argparse.ArgumentParser(description="Build offense-only, chunked MITRE ATT&CK JSONL for RAG.")
    parser.add_argument(
        "--input",
        default="data/raw/enterprise-attack/enterprise-attack.json",
        help="Path to the MITRE ATT&CK Enterprise STIX bundle (enterprise-attack.json)",
    )
    parser.add_argument(
        "--output",
        default="data/processed/rag_offense_mitre_chunks.jsonl",
        help="Output JSONL path",
    )

    args = parser.parse_args()
    build_offense_corpus(args.input, args.output)


if __name__ == "__main__":
    main()
