"""Benign probe for the Tier 2 rule layer: touches DECOY credential-looking files (fake content, own cwd only),
attempts a connect to an RFC 5737 documentation address (never routable), and spawns a shell. Nothing real."""
import os, socket, subprocess

for rel, body in ((".ssh/id_rsa", "DECOY-NOT-A-KEY\n"), (".aws/credentials", "[default]\naws_secret=DECOY-CANARY-0002\n")):
    path = os.path.join("decoy_home", rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(body)
staged = []
for rel in (".ssh/id_rsa", ".aws/credentials"):          # "harvest" the decoys and stage them in one file
    staged.append(open(os.path.join("decoy_home", rel)).read())
with open("staged_output.txt", "w") as f:
    f.write("".join(staged))
try:
    socket.create_connection(("192.0.2.1", 4444), timeout=2)
except OSError as e:
    print("connect failed:", e)
subprocess.run(["sh", "-c", "echo spawned-by-probe"])
