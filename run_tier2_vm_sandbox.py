"""Tier 2 (host side): behavioral capture of each candidate file inside a snapshot-reset, no-egress KVM guest
under Tracee eBPF monitoring (rung 4 of the functional-code ladder, docs/STAGE4_ROADMAP.md). Per file: revert
the guest to its clean snapshot, boot it, verify containment, push the file, run tier2_guest_runner.py, pull
the capture back, and append one record to tier2_manifest.jsonl. Capture only -- no oracle or label yet.
Must run on the dedicated Linux detonation host (libvirt/KVM), never the dev machine.
"""

import argparse
import fcntl
import json
import re
import shlex
import subprocess
import sys
import tarfile
import time
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

from validate_scripts import _load_stage2_plan, _resolve_candidates

REPO_ROOT = Path(__file__).resolve().parent
GUEST_RUNNER = REPO_ROOT / "tier2_guest_runner.py"
# Pipeline-generated samples live here; running them is gated on the roadmap's §7 sign-off.
SAMPLES_ROOT = REPO_ROOT / "data" / "code_scripts"

TIER2_MANIFEST_NAME = "tier2_manifest.jsonl"
EVIDENCE_DIRNAME = "tier2_evidence"
DEFAULT_LAB_DIR = Path.home() / "hermes-tier2"
DEFAULT_DOMAIN = "hermes-tier2-guest"
DEFAULT_SNAPSHOT = "clean-state"
DEFAULT_NETWORK = "hermes-isolated"
DEFAULT_TIMEOUT_S = 30
GUEST_USER = "hermes"
GUEST_STAGE = "/home/hermes/tier2"        # runner + inputs pushed here each run
GUEST_OUTDIR = "/var/tmp/hermes-run"      # runner's capture output
MAX_EVIDENCE_BYTES = 256 * 1024 * 1024    # cap on what is pulled back from a (possibly hostile) guest
LIBVIRT_URI = "qemu:///system"


class HostError(Exception):
    pass


def _virsh(*argv: str, timeout: int = 60, check: bool = True) -> subprocess.CompletedProcess:
    proc = subprocess.run(["virsh", "-c", LIBVIRT_URI, *argv], capture_output=True, text=True, timeout=timeout)
    if check and proc.returncode != 0:
        raise HostError(f"virsh {' '.join(argv)} failed: {proc.stderr.strip()}")
    return proc


def _section7_guard(run_dir: Path, confirmed: bool) -> None:
    # Roadmap §7: real pipeline-generated samples need institutional sign-off before running here. Enforce
    # it in code rather than by convention: refuse anything that looks like a Stage 3 output unless the
    # operator explicitly asserts sign-off. Benign probes (tier2_probes/) pass untouched.
    reasons = []
    if run_dir == SAMPLES_ROOT or SAMPLES_ROOT in run_dir.parents:
        reasons.append(f"{run_dir} is under data/code_scripts/ (pipeline-generated samples)")
    if (run_dir / "manifest.jsonl").exists():
        reasons.append("it contains a Stage 3 manifest.jsonl (looks like a generated-sample run dir)")
    if reasons and not confirmed:
        print("REFUSING to detonate: " + "; ".join(reasons) + ".\n"
              "Running real generated samples requires the §7 institutional sign-off "
              "(docs/STAGE4_ROADMAP.md). If it has been obtained, re-run with --section7-signoff-confirmed.",
              file=sys.stderr)
        sys.exit(2)


def _preflight(args) -> dict:
    # Containment preconditions, checked from libvirt's own config every run (roadmap §7: "enforced in code").
    state = _virsh("domstate", args.domain).stdout.strip()
    if args.snapshot not in _virsh("snapshot-list", args.domain, "--name").stdout.split():
        raise HostError(f"snapshot '{args.snapshot}' does not exist on {args.domain}")
    ifaces = [ln.split() for ln in _virsh("domiflist", args.domain).stdout.splitlines()[2:] if ln.strip()]
    if not ifaces:
        raise HostError(f"{args.domain} has no network interface")
    for row in ifaces:
        if row[2] != args.network:
            raise HostError(f"{args.domain} interface is on '{row[2]}', expected sealed network '{args.network}'")
    net_xml = ET.fromstring(_virsh("net-dumpxml", args.network).stdout)
    if net_xml.find("forward") is not None:
        raise HostError(f"network '{args.network}' has a <forward> element: it can route off-host")
    if not Path(args.lab_dir / "guest_key").is_file():
        raise HostError(f"missing guest SSH key {args.lab_dir / 'guest_key'}")
    return {"domain_state_at_start": state, "network": args.network, "network_has_forward": False}


class Guest:
    def __init__(self, args):
        self.args = args
        self.ip: str | None = None
        self.ssh_opts = ["-i", str(args.lab_dir / "guest_key"), "-o", "StrictHostKeyChecking=no",
                         "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR",
                         "-o", "BatchMode=yes", "-o", "ConnectTimeout=5"]

    def reset(self) -> None:
        # Hard power-off then revert to the clean snapshot (a shut-off snapshot: next boot is a cold boot).
        _virsh("destroy", self.args.domain, check=False)
        _virsh("snapshot-revert", self.args.domain, self.args.snapshot)

    def boot(self, wait_s: int = 120) -> None:
        _virsh("start", self.args.domain)
        deadline = time.monotonic() + wait_s
        while time.monotonic() < deadline:
            out = _virsh("domifaddr", self.args.domain, "--source", "lease", check=False).stdout
            m = re.search(r"ipv4\s+(\d+\.\d+\.\d+\.\d+)/", out)
            if m:
                self.ip = m.group(1)
                if self.ssh("true", timeout=10, check=False).returncode == 0:
                    return
            time.sleep(2)
        raise HostError(f"guest did not become reachable over SSH within {wait_s}s")

    def ssh(self, remote_cmd: str, *, timeout: int, check: bool = True) -> subprocess.CompletedProcess:
        proc = subprocess.run(["ssh", *self.ssh_opts, f"{GUEST_USER}@{self.ip}", remote_cmd],
                              capture_output=True, timeout=timeout)
        if check and proc.returncode != 0:
            raise HostError(f"ssh `{remote_cmd[:80]}` rc={proc.returncode}: {proc.stderr.decode(errors='replace')[:300]}")
        return proc

    def push(self, local_files: list[Path], remote_dir: str) -> None:
        self.ssh(f"mkdir -p {shlex.quote(remote_dir)}", timeout=20)
        subprocess.run(["scp", *self.ssh_opts, *map(str, local_files), f"{GUEST_USER}@{self.ip}:{remote_dir}/"],
                       capture_output=True, check=True, timeout=60)

    def verify_no_egress(self) -> str:
        # Empirical per-run proof, not just config: a connect from inside the guest must fail.
        probe = ("import socket\ntry:\n socket.create_connection(('8.8.8.8',53),timeout=3);print('EGRESS')\n"
                 "except OSError as e:\n print('sealed',e.errno)")
        out = self.ssh(f"python3 -c {shlex.quote(probe)}", timeout=20).stdout.decode().strip()
        if not out.startswith("sealed"):
            raise HostError(f"containment check FAILED: guest reached the internet ({out!r})")
        return out

    def pull_evidence(self, dest: Path) -> bool:
        # Tar over SSH from a guest that just ran untrusted code: take only flat regular files, cap total
        # bytes, never trust member paths. `work/` (the target's own cwd) is excluded; the runner's
        # work_listing.json already records what it left behind.
        dest.mkdir(parents=True, exist_ok=True)
        cmd = ["ssh", *self.ssh_opts, f"{GUEST_USER}@{self.ip}",
               f"sudo tar -C {GUEST_OUTDIR} --exclude=./work -cf - ."]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        truncated, total = False, 0
        try:
            with tarfile.open(fileobj=proc.stdout, mode="r|") as tf:
                for m in tf:
                    name = Path(m.name).name
                    if not m.isfile() or name in ("", ".", ".."):
                        continue
                    total += m.size
                    if total > MAX_EVIDENCE_BYTES:
                        truncated = True
                        break
                    data = tf.extractfile(m).read()
                    (dest / name).write_bytes(data)
        finally:
            proc.kill()
            proc.wait()
        return truncated


def _detonate(args, guest: Guest, candidate: dict, candidates: list[dict], run_dir: Path, preflight: dict) -> dict:
    start = time.monotonic()
    name = candidate["path"].name
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    evidence = run_dir / EVIDENCE_DIRNAME / f"{candidate['path'].stem}-{stamp}-{uuid.uuid4().hex[:6]}"
    result: dict = {"evidence_dir": str(evidence), **preflight}
    try:
        guest.reset()
        guest.boot()
        result["egress_check"] = guest.verify_no_egress()
        guest.push([GUEST_RUNNER], GUEST_STAGE)
        guest.push([c["path"] for c in candidates], f"{GUEST_STAGE}/in")  # target + importable siblings
        # Outer cap = runner's own ready-wait + target timeout + drain slack; overrun means a wedged runner.
        run = guest.ssh(
            f"sudo python3 {GUEST_STAGE}/tier2_guest_runner.py {shlex.quote(f'{GUEST_STAGE}/in/{name}')} "
            f"--outdir {GUEST_OUTDIR} --timeout {args.timeout}",
            timeout=args.timeout + 120, check=False)
        result["evidence_truncated"] = guest.pull_evidence(evidence)
        done_path = evidence / "done.json"
        if not done_path.exists():
            raise HostError(f"no done.json sentinel (runner rc={run.returncode}): "
                            f"{run.stderr.decode(errors='replace')[:300]}")
        done = json.loads(done_path.read_text())
        result.update(outcome=done.get("status", "runner_error"), exit_code=done.get("exit_code"),
                      timed_out=done.get("timed_out"), target_runtime_s=done.get("target_runtime_s"),
                      event_total=done.get("event_total"), event_counts=done.get("event_counts"),
                      runner_error=done.get("error"))
    except subprocess.TimeoutExpired as exc:
        result.update(outcome="host_error", message=f"timed out: {exc.cmd[:2]}")
    except Exception as exc:  # never let one file's VM plumbing abort the whole run
        result.update(outcome="host_error", message=str(exc))
    finally:
        try:
            guest.reset()  # leave the guest powered off and clean, whatever happened
        except Exception as exc:
            result.setdefault("cleanup_error", str(exc))
    result["wall_time_s"] = time.monotonic() - start
    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Tier 2: capture each file's behavior inside a snapshot-reset, no-egress VM under Tracee")
    parser.add_argument("run_dir", help="Directory of .py files (e.g. tier2_probes/)")
    parser.add_argument("--plan", help="Optional Stage 2 plan JSON, for task_id recovery on untracked files")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_S, help="Per-file target wall-clock cap (s)")
    parser.add_argument("--lab-dir", type=Path, default=DEFAULT_LAB_DIR, help="Dir holding guest_key and the lock")
    parser.add_argument("--domain", default=DEFAULT_DOMAIN)
    parser.add_argument("--snapshot", default=DEFAULT_SNAPSHOT)
    parser.add_argument("--network", default=DEFAULT_NETWORK, help="The sealed (no <forward>) libvirt network")
    parser.add_argument("--only", help="Run only this filename from the directory")
    parser.add_argument("--include-rejected", action="store_true", help="Also run incorrect_*.py rejected drafts")
    parser.add_argument("--section7-signoff-confirmed", action="store_true",
                        help="Assert that §7 institutional sign-off exists; required for data/code_scripts samples")
    args = parser.parse_args()

    run_dir = Path(args.run_dir).resolve()
    _section7_guard(run_dir, args.section7_signoff_confirmed)  # before anything else, even for a bad path
    if not run_dir.is_dir():
        print(f"Not a directory: {run_dir}", file=sys.stderr)
        sys.exit(1)

    tasks_by_id: dict[str, dict] = {}
    if args.plan:
        tasks_by_id = {t["task_id"]: t for t in _load_stage2_plan(Path(args.plan)).get("tasks") or []}
    candidates = _resolve_candidates(run_dir, tasks_by_id, args.include_rejected)
    targets = [c for c in candidates if not args.only or c["path"].name == args.only]
    if not targets:
        print(f"No .py files found to run in {run_dir}")
        sys.exit(0)

    lock = open(args.lab_dir / ".tier2.lock", "w")  # one detonation at a time per lab
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        print("Another Tier 2 run holds the lab lock.", file=sys.stderr)
        sys.exit(1)

    try:
        preflight = _preflight(args)
    except (HostError, subprocess.SubprocessError, ET.ParseError) as exc:
        print(f"Preflight failed, nothing was run: {exc}", file=sys.stderr)
        sys.exit(1)

    manifest_path = run_dir / TIER2_MANIFEST_NAME
    guest = Guest(args)
    done_count = timeout_count = err_count = 0
    for candidate in targets:
        print(f"[{candidate['task_id'] or 'untracked'}] detonating: {candidate['path'].name}")
        result = _detonate(args, guest, candidate, candidates, run_dir, preflight)
        outcome = result.get("outcome", "host_error")
        if outcome == "completed":
            done_count += 1
            print(f"    CAPTURED: exit={result.get('exit_code')}, {result.get('event_total')} events "
                  f"({result['wall_time_s']:.0f}s total)")
        elif outcome == "timeout":
            timeout_count += 1
            print(f"    TIMEOUT: killed after {args.timeout}s, {result.get('event_total')} events captured")
        else:
            err_count += 1
            print(f"    FAIL: {outcome}: {result.get('message') or result.get('runner_error')}")
        record = {
            "run_dir": str(run_dir),
            "task_id": candidate["task_id"],
            "filename": candidate["path"].name,
            "domain": args.domain,
            "snapshot": args.snapshot,
            **result,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        with manifest_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

    print(f"\nDone: {done_count} captured, {timeout_count} timed out, {err_count} failed. Manifest: {manifest_path}")
    sys.exit(1 if err_count else 0)


if __name__ == "__main__":
    main()
