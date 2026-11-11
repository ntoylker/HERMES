"""Unit tests for tier2_rules.py on synthetic Tracee events (no VM, no execution). Run: python -m unittest test_tier2_rules"""

import errno
import unittest

import tier2_rules as R

ROOT = 100


def ev(name, pid=ROOT, ret=0, comm="python3", ppid=1, **args):
    return {"line": 0, "name": name, "ts": 0, "pid": pid, "ppid": ppid, "comm": comm, "uid": 1000, "ret": ret,
            "args": args}


def fopen(path, flags=0):
    return ev("security_file_open", pathname=path, flags=flags)


def sock(ip, port, ret, family="AF_INET"):
    key = "sin_addr" if family == "AF_INET" else "sin6_addr"
    return ev("connect", ret=ret, addr={"sa_family": family, key: ip, "sin_port": str(port)})


def signals(events):
    return R.analyze_events(events)["signals"]


class SensitiveFileAccess(unittest.TestCase):
    def test_shadow_read_is_strong_with_hint(self):
        r = R.analyze_events([fopen("/etc/shadow")])
        f = r["findings"][0]
        self.assertEqual(f["rule_id"], "file.sensitive_access.system_shadow")
        self.assertEqual((f["strength"], f["attack_hints"]), ("strong", ["T1003.008"]))

    def test_denied_open_is_reported_with_errno(self):
        r = R.analyze_events([ev("openat", ret=-errno.EACCES, pathname="/etc/shadow", flags=0)])
        self.assertEqual(r["findings"][0]["outcome"], "failed:EACCES")

    def test_successful_openat_not_double_counted(self):
        r = R.analyze_events([ev("openat", ret=3, pathname="creds.txt", flags=0), fopen("/w/credentials.txt")])
        self.assertEqual(sum(f["count"] for f in r["findings"]), 1)

    def test_private_key_and_pub_distinction(self):
        self.assertIn("file.sensitive_access.private_key", signals([fopen("/home/u/.ssh/id_ed25519")]))
        self.assertEqual(signals([fopen("/home/u/.ssh/id_ed25519.pub")]), [])

    def test_credential_store_files(self):
        self.assertIn("file.sensitive_access.credential_store_file", signals([fopen("/home/u/.aws/credentials")]))

    def test_write_vs_read_access(self):
        w = R.analyze_events([fopen("/w/fake_credentials.txt", flags=0o101)])["findings"][0]  # O_WRONLY|O_CREAT
        r = R.analyze_events([fopen("/w/fake_credentials.txt", flags=0)])["findings"][0]
        self.assertEqual((w["access"], r["access"]), ("write", "read"))

    def test_passwd_is_weak_not_credential_named(self):
        f = R.analyze_events([fopen("/etc/passwd")])["findings"][0]
        self.assertEqual((f["rule_id"], f["strength"]), ("file.sensitive_access.system_user_db", "weak"))

    def test_system_paths_with_credentialish_names_are_ignored(self):
        for p in ("/etc/pam.d/common-password", "/usr/lib/python3.12/getpass.py", "/etc/ssl/certs/ca-token.pem",
                  "/proc/self/status", "/usr/share/dict/words"):
            self.assertEqual(signals([fopen(p)]), [], p)

    def test_ordinary_python_startup_files_do_not_fire(self):
        paths = ["/etc/ld.so.cache", "/usr/bin/python3.12", "/usr/lib/python3.12/os.py", "/etc/localtime",
                 "/var/tmp/hermes-run/work/main.py", "/dev/null"]
        self.assertEqual(signals([fopen(p) for p in paths]), [])


class NetworkConnect(unittest.TestCase):
    def test_failed_connect_uses_real_errno_not_lsm_zero(self):
        # LSM/kprobe events report 0 for any observed attempt; only the syscall's -101 is the truth.
        events = [ev("security_socket_connect", ret=0), ev("net_tcp_connect", ret=0),
                  sock("192.0.2.1", 4444, -errno.ENETUNREACH)]
        r = R.analyze_events(events)
        self.assertEqual([f["outcome"] for f in r["findings"]], ["failed:ENETUNREACH"])

    def test_connected_and_in_progress_distinguished(self):
        r = R.analyze_events([sock("10.0.0.5", 80, 0), sock("10.0.0.6", 80, -errno.EINPROGRESS)])
        self.assertEqual([f["outcome"] for f in r["findings"]], ["connected", "in_progress"])

    def test_scope_classification(self):
        r = R.analyze_events([sock("127.0.0.1", 1, 0), sock("192.168.100.1", 1, 0), sock("8.8.8.8", 53, 0),
                              sock("192.0.2.1", 4444, 0), sock("169.254.1.1", 1, 0)])
        self.assertEqual([f["dst_scope"] for f in r["findings"]],
                         ["loopback", "private", "public", "reserved", "reserved"])

    def test_ipv6_and_dedup(self):
        r = R.analyze_events([sock("::1", 9, -errno.ECONNREFUSED, "AF_INET6")] + [sock("1.2.3.4", 5, -111)] * 3)
        self.assertEqual(sorted(f["count"] for f in r["findings"]), [1, 3])

    def test_unix_and_netlink_sockets_ignored(self):
        e = ev("connect", ret=0, addr={"sa_family": "AF_UNIX", "sun_path": "/run/x"})
        self.assertEqual(signals([e]), [])

    def test_no_hints_from_transport_alone(self):
        self.assertEqual(R.analyze_events([sock("8.8.8.8", 53, 0)])["findings"][0]["attack_hints"], [])


class ChildProcesses(unittest.TestCase):
    def exec_(self, path, argv, pid=200):
        return ev("sched_process_exec", pid=pid, comm=path.rsplit("/", 1)[-1], ppid=ROOT, pathname=path, argv=argv)

    def test_targets_own_exec_is_not_a_child(self):
        self.assertEqual(signals([ev("sched_process_exec", pathname="/usr/bin/python3.12", argv=["python3", "t.py"])]), [])

    def test_shell_spawn(self):
        r = R.analyze_events([ev("sched_process_exec", pathname="/usr/bin/python3.12"),
                              self.exec_("/usr/bin/dash", ["sh", "-c", "echo hi"])])
        self.assertEqual(r["signals"], ["process.child_exec", "process.shell_spawn"])
        self.assertEqual([f for f in r["findings"] if f["rule_id"] == "process.shell_spawn"][0]["attack_hints"],
                         ["T1059.004"])

    def test_python_child_is_interpreter_not_shell(self):
        s = signals([ev("sched_process_exec", pathname="/usr/bin/python3.12"),
                     self.exec_("/usr/bin/python3.12", ["python3", "-c", "1"])])
        self.assertIn("process.interpreter_spawn", s)
        self.assertNotIn("process.shell_spawn", s)

    def test_plain_utility_is_child_exec_only(self):
        self.assertEqual(signals([ev("sched_process_exec", pathname="/usr/bin/python3.12"),
                                  self.exec_("/usr/bin/id", ["id", "-u"])]), ["process.child_exec"])


class Report(unittest.TestCase):
    def test_empty_capture_is_clean_and_deterministic(self):
        r = R.analyze_events([])
        self.assertEqual((r["signals"], r["findings"], r["event_total"]), ([], [], 0))

    def test_report_carries_boundary_note_and_no_verdict(self):
        r = R.analyze_events([fopen("/etc/shadow")])
        self.assertIn("not a capability label", r["note"])
        self.assertNotIn("verdict", r)

    def test_evidence_capped(self):
        r = R.analyze_events([sock("1.2.3.4", 5, -111)] * 50)
        self.assertEqual(len(r["findings"][0]["evidence"]), R.MAX_EVIDENCE)
        self.assertEqual(r["findings"][0]["count"], 50)


if __name__ == "__main__":
    unittest.main()
