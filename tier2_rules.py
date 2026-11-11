"""Tier 2 rule layer: deterministic observed-behavior signals over a Tracee capture (docs/STAGE4_ROADMAP.md §5.2).
Emits signals with evidence refs and ATT&CK hints -- observations only, never a verdict or capability label.
Pure Python over events.jsonl; no LLM, no execution, safe to run on any host.
"""

import argparse
import errno
import ipaddress
import json
import os
import re
import sys
from pathlib import Path

REPORT_NAME = "behavior_report.json"
MAX_EVIDENCE = 5  # evidence refs kept per finding (the full stream stays in events.jsonl)

# Credential-looking paths. First match wins. `strength` is how specific the *path* is to credential
# material -- a property of the pattern, not of the sample; any verdict is the profile layer's job.
SENSITIVE_PATHS = [
    ("system_shadow", "T1003.008", "strong", re.compile(r"^/etc/(shadow|gshadow)-?$")),
    ("private_key", "T1552.004", "strong", re.compile(r"(^|/)\.ssh/(id_[A-Za-z0-9_]+|identity)$")),
    ("credential_store_file", "T1552.001", "strong", re.compile(
        r"(^|/)(\.aws/credentials|\.netrc|\.git-credentials|\.pgpass|\.docker/config\.json|\.kube/config)$")),
    ("system_user_db", "T1087.001", "weak", re.compile(r"^/etc/passwd-?$")),
    ("credential_named_file", "T1552.001", "medium", re.compile(
        r"(?i)(^|/)[^/]*(credential|secret|passw(or)?d|api[_-]?key|token)[^/]*$")),
]
# System paths whose names merely look credential-ish (PAM, TLS trust stores, package db, stdlib).
SYSTEM_PREFIXES = ("/usr/", "/lib/", "/lib64/", "/proc/", "/sys/", "/etc/pam.d/", "/etc/ssl/",
                   "/etc/security/", "/var/lib/dpkg/", "/var/lib/pam/", "/etc/ld.so")

SHELLS = {"sh", "bash", "dash", "zsh", "ash", "ksh", "csh", "tcsh", "fish"}
INTERPRETERS = ("python", "perl", "ruby", "node", "php", "lua")

O_ACCMODE, O_CREAT, O_TRUNC, O_APPEND = 0o3, 0o100, 0o1000, 0o2000


def _args(event: dict) -> dict:
    return {a.get("name"): a.get("value") for a in event.get("args") or []}


def load_events(path: Path) -> list[dict]:
    # Normalized, line-numbered events so evidence refs are stable (events.jsonl:<line>).
    events = []
    with open(path, errors="replace") as f:
        for lineno, line in enumerate(f, 1):
            try:
                raw = json.loads(line)
            except ValueError:
                continue
            events.append({"line": lineno, "name": raw.get("eventName"), "ts": raw.get("timestamp"),
                           "pid": raw.get("processId"), "ppid": raw.get("parentProcessId"),
                           "comm": raw.get("processName"), "uid": raw.get("userId"),
                           "ret": raw.get("returnValue"), "args": _args(raw)})
    return events


def _errno_name(ret: int) -> str:
    return errno.errorcode.get(-ret, str(ret)) if isinstance(ret, int) and ret < 0 else "OK"


def _ref(ev: dict, **detail) -> dict:
    return {"ref": f"events.jsonl:{ev['line']}", "event": ev["name"], "pid": ev["pid"], "comm": ev["comm"], **detail}


def _finding(rule_id, description, hints, strength, evidence, count, **extra) -> dict:
    return {"rule_id": rule_id, "description": description, "attack_hints": hints, "strength": strength,
            "count": count, "evidence": evidence[:MAX_EVIDENCE], **extra}


def _classify_path(path: str):
    if not isinstance(path, str) or path.startswith(SYSTEM_PREFIXES):
        return None
    for label, tid, strength, rx in SENSITIVE_PATHS:
        if rx.search(path):
            return label, tid, strength
    return None


def rule_sensitive_file_access(events: list[dict], root_pid: int) -> list[dict]:
    # Successful opens come from the LSM hook (absolute, resolved path); failed attempts (EACCES/ENOENT)
    # only surface in the raw openat syscall, which carries the errno. Successes in openat are skipped
    # so one open isn't reported twice (once relative, once resolved).
    grouped: dict[tuple, dict] = {}
    for ev in events:
        if ev["name"] == "security_file_open":
            path, outcome, ret = ev["args"].get("pathname"), "opened", 0
        elif ev["name"] == "openat" and isinstance(ev["ret"], int) and ev["ret"] < 0:
            path, outcome, ret = ev["args"].get("pathname"), f"failed:{_errno_name(ev['ret'])}", ev["ret"]
        else:
            continue
        hit = _classify_path(path)
        if not hit:
            continue
        label, tid, strength = hit
        flags = ev["args"].get("flags")
        write = isinstance(flags, int) and ((flags & O_ACCMODE) in (1, 2) or bool(flags & (O_CREAT | O_TRUNC | O_APPEND)))
        key = (label, path, outcome, "write" if write else "read")
        g = grouped.setdefault(key, {"tid": tid, "strength": strength, "evidence": [], "count": 0})
        g["count"] += 1
        g["evidence"].append(_ref(ev, path=path, outcome=outcome, access="write" if write else "read"))
    findings = []
    for (label, path, outcome, access), g in sorted(grouped.items(), key=lambda kv: kv[1]["evidence"][0]["ref"]):
        findings.append(_finding(f"file.sensitive_access.{label}",
                                 f"{access} {outcome} on credential-looking path {path}",
                                 [g["tid"]], g["strength"], g["evidence"], g["count"],
                                 path=path, outcome=outcome, access=access))
    return findings


RFC1918 = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def _ip_scope(ip) -> str:
    # `ipaddress.is_private` also covers documentation/link-local/etc.; keep RFC1918 (where a lab peer would
    # live) distinct from other reserved ranges so later profile rules can tell them apart.
    if ip.is_loopback:
        return "loopback"
    if ip.is_global:
        return "public"
    return "private" if any(ip in net for net in RFC1918 if ip.version == net.version) else "reserved"


def rule_network_connect_attempts(events: list[dict], root_pid: int) -> list[dict]:
    # The raw `connect` syscall carries the real errno; security_socket_connect / net_tcp_connect report 0
    # for any observed attempt (LSM/kprobe), so they must NOT be read as success. AF_UNIX/NETLINK ignored.
    grouped: dict[tuple, dict] = {}
    for ev in events:
        if ev["name"] != "connect":
            continue
        addr = ev["args"].get("addr")
        if not isinstance(addr, dict) or addr.get("sa_family") not in ("AF_INET", "AF_INET6"):
            continue
        ip = addr.get("sin_addr") or addr.get("sin6_addr")
        port = addr.get("sin_port") or addr.get("sin6_port")
        ret = ev["ret"]
        if ret == 0:
            outcome = "connected"
        elif ret == -errno.EINPROGRESS:
            outcome = "in_progress"  # non-blocking connect: outcome not visible from this event alone
        else:
            outcome = f"failed:{_errno_name(ret)}"
        try:
            ip_obj = ipaddress.ip_address(ip)
            scope = _ip_scope(ip_obj)
        except ValueError:
            scope = "unknown"
        key = (ip, str(port), outcome)
        g = grouped.setdefault(key, {"evidence": [], "count": 0, "scope": scope})
        g["count"] += 1
        g["evidence"].append(_ref(ev, dst=ip, port=port, outcome=outcome, ret=ret))
    return [
        _finding("network.connect_attempt", f"connect to {ip}:{port} -> {outcome} ({g['scope']})",
                 [], "n/a", g["evidence"], g["count"], dst=ip, port=port, outcome=outcome, dst_scope=g["scope"])
        for (ip, port, outcome), g in sorted(grouped.items(), key=lambda kv: kv[1]["evidence"][0]["ref"])
    ]


def rule_child_processes(events: list[dict], root_pid: int) -> list[dict]:
    # The target's own initial exec shares root_pid; anything else that execs is a descendant it spawned.
    findings = []
    for ev in events:
        if ev["name"] != "sched_process_exec" or ev["pid"] == root_pid:
            continue
        path = ev["args"].get("pathname") or ev["args"].get("cmdpath") or ""
        base = os.path.basename(path)
        argv = ev["args"].get("argv") or []
        detail = {"path": path, "argv": argv, "ppid": ev["ppid"]}
        findings.append(_finding("process.child_exec", f"spawned {path} {argv}", [], "n/a",
                                 [_ref(ev, **detail)], 1, path=path, argv=argv))
        if base in SHELLS:
            findings.append(_finding("process.shell_spawn", f"spawned shell {path} {argv}", ["T1059.004"], "medium",
                                     [_ref(ev, **detail)], 1, path=path, argv=argv))
        elif base.startswith(INTERPRETERS):
            findings.append(_finding("process.interpreter_spawn", f"spawned interpreter {path} {argv}",
                                     ["T1059.006"] if base.startswith("python") else [], "medium",
                                     [_ref(ev, **detail)], 1, path=path, argv=argv))
    return findings


RULES = [rule_sensitive_file_access, rule_network_connect_attempts, rule_child_processes]


def analyze_events(events: list[dict], target: str | None = None) -> dict:
    root_pid = events[0]["pid"] if events else None  # first event of a tree-scoped capture = the target root
    findings = []
    for rule in RULES:
        findings.extend(rule(events, root_pid))
    return {
        "schema": 1, "target": target, "root_pid": root_pid, "event_total": len(events),
        "signals": sorted({f["rule_id"] for f in findings}),
        "findings": findings,
        "note": "Observed signals in a sealed lab; not a capability label and not evidence of field efficacy.",
    }


def analyze_evidence(evidence_dir: Path) -> dict:
    # Evidence dir = one orchestrator capture (events.jsonl + done.json). Writes behavior_report.json beside it.
    evidence_dir = Path(evidence_dir)
    target = None
    try:
        target = json.loads((evidence_dir / "done.json").read_text()).get("target")
    except (OSError, ValueError):
        pass
    report = analyze_events(load_events(evidence_dir / "events.jsonl"), target)
    (evidence_dir / REPORT_NAME).write_text(json.dumps(report, indent=1, ensure_ascii=False))
    return report


def main() -> None:
    ap = argparse.ArgumentParser(description="Tier 2: run the rule layer over a captured evidence directory")
    ap.add_argument("evidence_dir")
    args = ap.parse_args()
    if not (Path(args.evidence_dir) / "events.jsonl").is_file():
        print(f"No events.jsonl in {args.evidence_dir}", file=sys.stderr)
        sys.exit(1)
    report = analyze_evidence(Path(args.evidence_dir))
    print(f"{report['target']}: {report['event_total']} events, signals: {', '.join(report['signals']) or 'none'}")
    for f in report["findings"]:
        print(f"  [{f['rule_id']}] {f['description']}  x{f['count']}  hints={f['attack_hints']}")


if __name__ == "__main__":
    main()
