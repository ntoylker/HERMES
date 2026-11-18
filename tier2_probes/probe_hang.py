"""Benign probe: spawns a sleeping child, then sleeps itself, to exercise the runner's timeout kill-switch."""
import subprocess, time
subprocess.Popen(["sleep", "300"])
time.sleep(300)
