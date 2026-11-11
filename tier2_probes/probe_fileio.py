"""Benign probe: file create/read/rename/delete/chmod + a connect attempt + a child process. Touches only its own cwd."""
import os, socket, subprocess
with open("fake_credentials.txt", "w") as f:   # credential-looking filename, decoy content
    f.write("CANARY-TOKEN-0001\n")
print(open("fake_credentials.txt").read().strip())
os.rename("fake_credentials.txt", "fake_credentials.bak")
os.chmod("fake_credentials.bak", 0o600)
try:
    socket.create_connection(("8.8.8.8", 53), timeout=2)
except Exception as e:
    print("connect failed:", e)
subprocess.run(["id", "-u"])
os.remove("fake_credentials.bak")
