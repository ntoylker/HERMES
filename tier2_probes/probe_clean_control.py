"""Negative control for the Tier 2 rule layer: ordinary computation and file I/O, no credential-looking paths,
no network, no child processes. The rule layer must report zero signals for this file."""
import hashlib, json
digest = hashlib.sha256(b"hello hermes").hexdigest()
with open("result.json", "w") as f:
    json.dump({"digest": digest, "squares": [n * n for n in range(10)]}, f)
print(json.load(open("result.json"))["digest"][:12], open(__file__).read().count("\n"))
