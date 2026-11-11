#!/usr/bin/env python3
"""Tier 2 guest-side detonation runner (observation only; runs inside the sealed VM, as root via sudo).
Pushed into the guest per run by run_tier2_vm_sandbox.py; analogue of tier1_runner.py. Do not run on the host.

Runs one target Python file as an unprivileged user under Tracee, captures scoped eBPF events as JSON,
and writes a sentinel (done.json) last so the host knows when to stop waiting. Never modifies the target.
"""
import argparse, collections, json, os, pwd, shutil, signal, subprocess, sys, time, urllib.request

HEALTH_PORT = 3366
TRACEE = os.path.expanduser("~hermes/tracee/dist/tracee")
# Process lifecycle, real syscalls (return values), file I/O, and network-attempt events.
EVENTS = [
    "sched_process_fork", "sched_process_exec", "sched_process_exit", "execve",
    "openat", "security_file_open", "vfs_write", "unlink", "unlinkat", "rename", "renameat", "renameat2", "chmod", "fchmod", "fchmodat",
    "security_inode_unlink", "security_inode_rename",
    "connect", "security_socket_connect", "net_tcp_connect",
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target")
    ap.add_argument("--outdir", required=True)
    ap.add_argument("--timeout", type=int, default=30, help="hard wall-clock cap for the target (s)")
    ap.add_argument("--user", default="hermes", help="unprivileged user the target runs as")
    ap.add_argument("--ready-timeout", type=int, default=60)
    a = ap.parse_args()
    if os.geteuid() != 0:
        sys.exit("must run as root (Tracee needs it)")

    out = os.path.abspath(a.outdir)
    os.makedirs(out, exist_ok=True)
    for f in ("done.json", "events.jsonl"):
        if os.path.exists(os.path.join(out, f)):
            sys.exit(f"refusing to reuse non-empty outdir ({f} exists)")
    pw = pwd.getpwnam(a.user)
    work = os.path.join(out, "work")  # target's cwd, owned by the unprivileged user
    os.makedirs(work)
    os.chown(work, pw.pw_uid, pw.pw_gid)
    # Generated files import their siblings by bare module name, so copy every .py next to the target
    # (importable, never executed on their own) -- mirrors Tier 1 mounting the whole run dir.
    src_dir = os.path.dirname(os.path.abspath(a.target))
    for name in os.listdir(src_dir):
        if name.endswith(".py"):
            shutil.copy(os.path.join(src_dir, name), os.path.join(work, name))
            os.chown(os.path.join(work, name), pw.pw_uid, pw.pw_gid)
    tgt = os.path.join(work, os.path.basename(a.target))
    os.chmod(out, 0o755)

    sentinel = {"target": os.path.basename(a.target), "status": "runner_error", "started": time.time()}
    tracee = tproc = None
    try:
        # Held at a gate: the shell blocks on stdin until Tracee is ready, then exec()s the target
        # (same PID, so --scope tree=<pid> covers the target and every descendant).
        tproc = subprocess.Popen(
            ["sh", "-c", 'read g && [ "$g" = go ] || exit 99; exec python3 "$1"', "sh", tgt],
            stdin=subprocess.PIPE, cwd=work, user=a.user, start_new_session=True,
            stdout=open(os.path.join(out, "target.stdout"), "wb"),
            stderr=open(os.path.join(out, "target.stderr"), "wb"))
        ev_path = os.path.join(out, "events.jsonl")
        cmd = [TRACEE, "--capabilities", "bypass=true", "--scope", f"tree={tproc.pid}",
               "--events", ",".join(EVENTS), "--output", f"json:{ev_path}",
               "--signatures-dir", "/var/empty", "--server", f"http-address=127.0.0.1:{HEALTH_PORT}", "--server", "healthz",
               "--log", "file:" + os.path.join(out, "tracee.log")]
        tracee = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=open(os.path.join(out, "tracee.err"), "wb"),
                                  start_new_session=True)
        # Ready = Tracee's /healthz answers 200; fail closed if it dies or never comes up.
        deadline = time.time() + a.ready_timeout
        ready = False
        while time.time() < deadline and tracee.poll() is None:
            try:
                ready = urllib.request.urlopen(f"http://127.0.0.1:{HEALTH_PORT}/healthz", timeout=2).status == 200
            except Exception:
                ready = False
            if ready:
                break
            time.sleep(0.5)
        if not ready:
            raise RuntimeError("tracee not ready (see tracee.log/tracee.err)")
        time.sleep(1)  # let probes attach fully

        t0 = time.time()
        tproc.stdin.write(b"go\n"); tproc.stdin.close()  # release the gate
        try:
            rc = tproc.wait(timeout=a.timeout)
            timed_out = False
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(tproc.pid, signal.SIGKILL)  # kill-switch for the whole process group
            rc = tproc.wait()
        sentinel.update(status="timeout" if timed_out else "completed", exit_code=rc,
                        timed_out=timed_out, target_runtime_s=round(time.time() - t0, 2))
        time.sleep(2)  # let Tracee drain its buffers
    except Exception as e:
        sentinel.update(status="runner_error", error=str(e))
    finally:
        if tproc is not None and tproc.poll() is None:  # never leave a gated/running target behind
            try:
                os.killpg(tproc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        if tracee is not None and tracee.poll() is None:
            tracee.send_signal(signal.SIGINT)
            try:
                tracee.wait(timeout=15)
            except subprocess.TimeoutExpired:
                os.killpg(tracee.pid, signal.SIGKILL)
        counts = collections.Counter()
        try:
            for line in open(os.path.join(out, "events.jsonl"), errors="replace"):
                try:
                    counts[json.loads(line).get("eventName", "?")] += 1
                except ValueError:
                    pass
        except FileNotFoundError:
            pass
        # Names/sizes/modes only (never contents, never following symlinks): what the target left behind.
        listing = []
        try:
            for ent in sorted(os.scandir(work), key=lambda e: e.name)[:200]:
                st = ent.stat(follow_symlinks=False)
                listing.append({"name": ent.name, "size": st.st_size, "mode": oct(st.st_mode)})
        except OSError:
            pass
        json.dump(listing, open(os.path.join(out, "work_listing.json"), "w"), indent=1)
        sentinel.update(finished=time.time(), event_counts=dict(counts), event_total=sum(counts.values()))
        tmp = os.path.join(out, "done.json.tmp")
        json.dump(sentinel, open(tmp, "w"), indent=1)
        os.rename(tmp, os.path.join(out, "done.json"))  # written last, atomically
    sys.exit(0 if sentinel["status"] in ("completed", "timeout") else 1)


if __name__ == "__main__":
    main()
