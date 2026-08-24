---
name: concise-python-docs
description: Add minimal inline documentation to Python files for software engineers
---

# Concise Python Documentation

When documenting Python code for this project:

## Module Docstrings
- Add a brief module docstring at the top describing the file's role in the pipeline
- Mention which stage (Stage 1, Stage 2, or utility) it belongs to
- Keep it to 1-3 lines maximum

## Inline Comments
- Comment only non-obvious logic, JSON schemas, validation loops, and API calls
- NO verbose explanations — assume the reader is a software engineer
- Focus on WHAT and WHY, not HOW (the code shows the how)
- Explain business logic and domain-specific ATT&CK/STIX concepts

## What NOT to Document
- Self-explanatory variable assignments
- Standard Python patterns (list comprehensions, context managers, etc.)
- Obvious control flow
- Type hints already explain parameter purposes

## Example Style

```python
"""Stage 2 planner: convert Stage 1 ATT&CK links into validated coding-task plans.

The LLM proposes task structure; this module supplies local evidence and patterns,
then deterministically validates, orders, and persists the canonical plan.
"""

def _validate_and_normalize(draft: dict, context: dict):
    # Accept evidence references only from the context supplied to the model.
    valid_chunk_ids = {e["chunk_id"] for e in context["evidence"]}
    
    # Depth-first traversal returns dependencies before the tasks that require them.
    order, has_cycle = _topo_order(local_ids, edges)
```

Keep documentation precise, minimal, and focused on helping engineers understand the pipeline's flow.
