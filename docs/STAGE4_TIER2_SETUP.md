# Stage 4 / Tier 2 — VM + Tracee Setup Reference

This is the operational reference for the Tier 2 behavioral-detonation environment: what machine it's
on, exactly how the VM and network are built, how Tracee (the eBPF capture tool) is installed and why a
bug in it had to be patched, and — most importantly for whoever picks this back up — **what is still not
wired together**, so configuring the actual per-category rule sets doesn't have to start by
re-discovering all of this.

[STAGE4_ROADMAP.md](STAGE4_ROADMAP.md) stays the design/status document (the functional-code ladder, the
validation-profile registry concept, the safety gating). This doc is the "how it's actually built, right
now, on this specific machine" companion to that §10 progress log.

**Read this if**: you're about to configure per-`task_type` signature sets (§3 of the roadmap), debug
why Tracee did or didn't fire, rebuild the VM from scratch, or just need to remember what any of this is
after a long gap.

---

## 0. The one thing to know before anything else

**Two layers exist here, and they are not the same thing.** The VM itself — the libvirt domain, its
no-egress network, and the Tracee install inside it — lives entirely outside the git repo, in
`~/hermes-tier2/` on this laptop. It is not version-controlled, not backed up by git, and not portable to
another machine without redoing most of §1–§7 below. If this laptop's home directory is ever lost, that
part is gone and has to be rebuilt from this doc.

**As of 2026-11-18, the automation that drives that VM *does* live in the repo.**
`run_tier2_vm_sandbox.py` (host-side orchestrator), `tier2_guest_runner.py` (pushed into the guest per
run), `tier2_rules.py` (a tested, deterministic signal layer), and `tier2_probes/` (benign test fixtures)
were merged into `main` from `feat/tier2-vm-orchestrator` — a branch actually **authored 2026-11-11, the
same day** as the hand-driven session logged in `STAGE4_ROADMAP.md` §10, developed in parallel with it, but
not reconciled into `main` until today. See §8a for exactly what each file does, how it relates to the
hand-run testing described elsewhere in this doc, and what evidence does (and doesn't) exist that it's
actually been exercised against the real VM.

The repo also contains:
- [STAGE4_ROADMAP.md](STAGE4_ROADMAP.md) (this doc's sibling, design-level)
- [`data/code_scripts_PAST/level2_cred_disc_lat_mov_QWEN_1/TIER2_TEST_REPORT.md`](../data/code_scripts_PAST/level2_cred_disc_lat_mov_QWEN_1/TIER2_TEST_REPORT.md)
  — the write-up of the one real generated sample tested here so far (see §8 below for how that test
  relates to — and does *not* go through — either the hand-run Tracee pipeline or the new orchestrator)

## 1. The host

This laptop (the same machine the HERMES repo lives on) is the Tier 2 host. Worth being explicit about
this because an earlier version of the roadmap's §10 entry described it as "a dedicated secondary Linux
laptop... not the development machine" — that was the original intent, but nested virtualization on the
actual Windows development machine proved fragile, so this Linux laptop ended up serving both roles. It's
a deliberate choice, not an oversight — don't move this work to the Windows machine.

**Virtualization stack**: KVM/QEMU/libvirt (built into Linux, not VirtualBox or VMware — see rationale in
the conversation history/memory if this ever needs re-justifying to someone: KVM gives scriptable,
file-defined networking, which is what makes the no-egress guarantee below auditable as plain text rather
than a GUI checkbox).

Useful host-side commands, used throughout this doc:
```bash
virsh list --all                              # VM state
virsh snapshot-list hermes-tier2-guest        # see §3
virsh snapshot-revert hermes-tier2-guest <name> && virsh start hermes-tier2-guest
virsh domifaddr hermes-tier2-guest            # poll this after start for the guest's DHCP IP (varies per boot)
virsh shutdown hermes-tier2-guest             # always do this when done, don't leave it running idle
virsh net-dumpxml hermes-isolated             # confirm the network definition hasn't drifted
```

## 2. The guest VM

- **Name**: `hermes-tier2-guest`. Ubuntu 24.04, provisioned via `virt-install` + cloud-init
  (`~/hermes-tier2/user-data.yaml`, `meta-data.yaml`, `seed.iso`).
- **User**: `hermes`, passwordless `sudo` (`NOPASSWD:ALL`), SSH-key-only login.
- **SSH access**: dedicated key pair `~/hermes-tier2/guest_key` / `guest_key.pub` (chmod 600 the private
  half before use) — a host-control key, not anyone's personal key. The guest's IP changes per boot
  (DHCP), so poll `virsh domifaddr` after starting rather than hardcoding one. Typical connect:
  ```bash
  ssh -i ~/hermes-tier2/guest_key -o IdentitiesOnly=yes -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null hermes@<guest-ip>
  ```
- **Network**: `hermes-isolated` (bridge `virbr-hermes`, `192.168.100.0/24`, DHCP `.10`–`.100`, gateway/
  host side `192.168.100.1`). Defined with **no `<forward>` element at all** — this is the actual
  no-egress guarantee, and it's been empirically re-verified multiple times (most recently 2026-11-18,
  during the Tracee fix work below): a connect attempt to `8.8.8.8:53` from inside the guest returns
  `[Errno 101] Network is unreachable`. The XML file at `~/hermes-tier2/isolated-network.xml` is the
  source of truth; `virsh net-dumpxml hermes-isolated` should always match it byte-for-byte (modulo
  libvirt's own bookkeeping attributes like `<uuid>`/`<mac>`/`connections=`).

## 3. Snapshots

Internal qcow2 snapshots, each a full independent disk state. As of 2026-11-18:

| Snapshot | What it is |
|---|---|
| `clean-state` | **The current baseline — use this for normal work.** Holds the Tracee-fixed install (§6). Revert to this before any new test. |
| `clean-state-orig-broken-tracee` | The original 2026-11-11 baseline, before the Tracee signature fix. Rollback target if the fix ever needs backing out: `virsh snapshot-revert hermes-tier2-guest clean-state-orig-broken-tracee`. |
| `clean-state-tracee-fixed` | Identical contents to the current `clean-state`; a redundant duplicate from the fix process. Safe to delete (`virsh snapshot-delete hermes-tier2-guest clean-state-tracee-fixed`) whenever convenient. |
| `pre-tracee-rebuild` | The VM's live disk exactly as it was right before the 2026-11-18 Tracee work started (had been used/booted a few times since 2026-11-11, so it's not byte-identical to `clean-state-orig-broken-tracee`, just close). Mostly historical. |

**Snapshot/rollback is confirmed working**, repeatedly — the roadmap's §10 originally flagged this as
"not yet exercised"; that's now stale. It's been used for: the 2026-11-16 real-sample SSH test (§8), and
the 2026-11-18 Tracee rebuild/verification work (§6).

**Workflow for any new work**: always `virsh snapshot-revert hermes-tier2-guest clean-state` before
starting, and `virsh shutdown hermes-tier2-guest` when done. If you make guest-side changes you want to
keep as the new baseline, snapshot explicitly (`virsh snapshot-create-as hermes-tier2-guest <name>`)
*before* you start, so you can always get back to a known-good state if something goes wrong — and take
a fresh "before" snapshot specifically before ever touching the active `clean-state` baseline itself.

## 4. `~/hermes-tier2/` directory layout

(This is the external, non-repo lab directory. For the repo-side orchestrator that now drives it —
`run_tier2_vm_sandbox.py` and friends, at the repo root — see §8a.)

```
~/hermes-tier2/
├── isolated-network.xml          libvirt network definition (the no-egress proof, see §2)
├── user-data.yaml, meta-data.yaml, seed.iso    cloud-init config, used once at VM creation
├── guest_key, guest_key.pub      host-control SSH keypair (not a personal key)
├── images/                       VM disk image(s)
├── guest/
│   ├── hermes_guest_runner.py    the host-written, guest-side detonation runner (§7) — UNCHANGED by the
│   │                             2026-11-18 Tracee fix; still only requests raw syscall events, no
│   │                             signatures yet (see the TODO in §9)
│   ├── probe_hang.py             benign probe: spawns a child + sleeps, to exercise the timeout kill-switch
│   └── probe_fileio.py           benign probe: file create/rename/chmod/delete + a failed connect attempt
│                                 + a child process spawn
├── sample_runs/
│   ├── run2/, run3/              Tracee capture output from the two 2026-11-11 benign-probe runs
│                                 (events.jsonl + done.json each) — predate the signature fix, so these
│                                 have zero signature events even for probes that might trigger one
├── build/                        (new, 2026-11-18) the Tracee signature-fix build — see §6
│   ├── tracee-v0.24.1-builtin-signatures.patch
│   ├── build_tracee_builtin_sigs.sh      one-command reproducible rebuild
│   ├── build-tracee.log
│   ├── artifacts/tracee, tracee.sha256   the binary actually installed in the guest
│   ├── tracee-src/                       v0.24.1 checkout + patch applied, branch `hermes/builtin-signatures`
│   ├── toolchain/                        unpacked Go 1.24.9 + clang/llvm 19 sysroot (no system install)
│   └── official-release/                 the unmodified official v0.24.1 tarball, kept for comparison
│       (this whole directory is ~2.4GB; safe to delete once no further rebuild is needed — the patch +
│        script + artifacts/tracee are what actually matter long-term)
├── tracee-acceptance/
│   ├── ptraceme_probe.py         minimal benign trigger for the `anti_debugging` signature
│   └── run_acceptance.sh         starts Tracee with only that signature selected, runs the probe, checks
│                                 the resulting JSON event — the test used to verify the fix (§6)
└── TRACEE_SIGNATURE_FIX_REPORT.md   full write-up of the 2026-11-18 fix: diagnosis, patch rationale,
                                     exact build steps, verbatim test output
```

Inside the guest, under `/home/hermes/tracee/`:
```
~hermes/tracee/
├── dist/                  the ACTIVE install — currently the rebuilt, fixed `tracee` binary + docs/ only
│                          (no signatures/ dir, no .so — see §6, "built-in" route)
└── dist.orig-broken/      the ORIGINAL 2026-11-11 install, fully preserved: tracee, tracee-static,
                           tracee-ebpf, tracee-ebpf-static, tracee-rules, signatures/builtin.so, and the
                           original stderr logs. Kept for comparison/rollback; never deleted.
```

## 5. Tracee — what it is and why it was chosen

eBPF-based security monitoring tool (Aqua Security). Chosen over Cuckoo/CAPE specifically because CAPE's
community ATT&CK-mapped signature library is overwhelmingly Windows-malware-oriented — a poor fit once
the project pivoted Linux-only (see CLAUDE.md, Project section). Tracee ships its own Linux-native,
MITRE ATT&CK-tagged detection signatures, which was the deciding factor over plain `strace`/auditd.

**Version installed: v0.24.1** (confirmed still the latest upstream release as of 2026-11-18 — check
<https://github.com/aquasecurity/tracee/releases> before assuming this is still current if it's been a
while).

### Known gotchas, already worked around — don't re-discover these

- **`libvirt-qemu` needs explicit `setfacl` grants** on every host directory leading to the VM's disk
  image. The home directory's default mode blocks it; `virt-install` warns but doesn't fix it.
- **BTF/capabilities bug** ([aquasecurity/tracee#5330](https://github.com/aquasecurity/tracee/issues/5330)):
  on this guest's kernel, Tracee's capability auto-selection omits `CAP_SYS_ADMIN`, which the kernel
  requires for `BPF_BTF_GET_FD_BY_ID`. Symptom: `createNewInnerMap: could not find BTF id N: operation
  not permitted`. **Workaround: always pass `--capabilities bypass=true`** (the `=true` matters — the
  bare flag alone is not sufficient). Already baked into `hermes_guest_runner.py` and
  `tracee-acceptance/run_acceptance.sh`.
- **File I/O is not in Tracee's default event set.** The original §10 roadmap entry flagged this as an
  unconfirmed open question — it's now resolved and confirmed: `hermes_guest_runner.py`'s `EVENTS` list
  already explicitly requests `openat`, `security_file_open`, `vfs_write`, `unlink`/`unlinkat`,
  `rename`/`renameat`/`renameat2`, `chmod`/`fchmod`/`fchmodat`, etc. Any new runner or policy needs the
  same explicit opt-in for categories like `credential_access`/`collection`/`discovery`/`persistence`.
- **`security_socket_connect`/`net_tcp_connect`'s `returnValue: 0` is not the real `connect(2)` errno.**
  It reflects an LSM permission-check / attempt-observation, confirmed by the no-egress test still
  showing `returnValue: 0` even though the application-level connect genuinely fails. Don't read this
  field as literal success/failure in a future oracle — the real `connect` syscall event isn't in the
  default set either and would need explicit capture if that distinction matters.
- **Man-page metadata can be wrong; trust the emitted JSON / source over the man page.** Confirmed during
  the 2026-11-18 verification: `anti_debugging`'s man page says category "Defense Evasion: Execution
  Guardrails", severity 3 — but the actual signature source and the real emitted event say
  **"Debugger Evasion", T1622, severity 1**. Separately, man pages list event sets like
  `signatures, defense_evasion`, but at runtime every signature actually registers under
  `signatures, default` — filtering by a tactic-named set (as the man pages imply you could) will not
  work; filter by signature name instead.

## 6. The 2026-11-18 signature-plugin fix

### The bug

Tracee ships ~30 ATT&CK-tagged Go signatures (`stdio_over_socket`, `anti_debugging`,
`ptrace_code_injection`, `k8s_cert_theft`, etc. — full list in §7) as a separate plugin,
`signatures/builtin.so`, loaded dynamically at runtime via `--signatures-dir`. On the stock v0.24.1
release, loading that plugin failed with:
```
plugin.Open(...): plugin was built with a different version of package net
```
and as a direct result, every one of those 30 detections was completely inert — `tracee list`'s
"Signature Events" table came back with zero rows.

### Root cause (confirmed, not guessed)

**Not a Go toolchain version mismatch** — both the `tracee` binary and `builtin.so` were built with the
same Go version (go1.24.9). The actual cause, found via `go version -m` on the official release files, is
a **build-tag mismatch baked into Tracee's own release pipeline**: the official `tracee-x86_64.v0.24.1`
tarball's dynamic `tracee` binary was built *without* the `netgo` tag, while `builtin.so` (built in an
earlier, `STATIC=1` pass of the same release `Makefile` target, whose output then gets reused for the
dynamic pass without rebuilding) *was* built with `netgo`. Different `net` package implementation →
Go's plugin loader refuses to load it. **This is a packaging bug in the official v0.24.1 release itself**,
not anything specific to how it was installed here — the guest's files' sha256 hashes matched the
official tarball exactly.

### The fix: compiled-in signatures, not a repaired plugin

Tracee's own docs describe two ways signatures can run: load as a Go plugin (fragile, what was broken),
or compile directly into the main binary (what Tracee's own docs call "the preferred way" — nothing
loads dynamically at runtime, so this entire bug class becomes structurally impossible).

A small patch — `~/hermes-tier2/build/tracee-v0.24.1-builtin-signatures.patch`
(868 lines, almost entirely a `package main` → `package golang` rename across the
~30 signature files so they become importable, plus a small, reviewed change to
`pkg/signatures/signature/signature.go`'s `Find()` to start from the compiled-in list) — makes this the
default. The rebuilt `tracee` binary needs no `--signatures-dir` and no `.so` file at all. A thin
`signatures/golang/plugin/` shim is kept so `make signatures` can still produce a legacy `builtin.so` for
anyone who wants one, but nothing in this project's own tooling uses it.

**Reproducing or re-doing this build**: `~/hermes-tier2/build/build_tracee_builtin_sigs.sh [workdir]` is a
one-command, from-scratch rebuild — pins Go 1.24.9 (matching `go.mod`'s `toolchain` directive) and the
exact Ubuntu 24.04 clang/llvm 19 + libelf/zlib/zstd package versions Tracee's own official Docker builder
uses, downloads everything with sha256 verification, clones `v0.24.1` at a verified commit hash, applies
the patch, and builds with `STATIC=0 BTFHUB=0` (matching the official shared-build flags). No `sudo`,
no Docker, nothing installed system-wide — it was written this way because the build environment
available at the time had neither root nor Docker access. Full narrative, exact commands, and verbatim
test output: `~/hermes-tier2/TRACEE_SIGNATURE_FIX_REPORT.md` (not a repo-relative link — it lives outside
the repo, see §0).

### Verification (independently re-confirmed, not just taken on report)

- `tracee version` → `v0.24.1-hermes-builtin-sigs`.
- `tracee list` → 30 signature rows, 0 error lines (re-run and re-counted independently).
- A minimal, deliberately benign probe (`ptraceme_probe.py`, one `ptrace(PTRACE_TRACEME)` call on itself)
  triggered a real `anti_debugging` detection — `TRC-102`, MITRE **T1622**, category `defense-evasion` —
  re-run independently with the same result both times.
- The existing *external* `hermes_guest_runner.py` (`~/hermes-tier2/guest/`, not the repo's
  `tier2_guest_runner.py` — see §8a, which wasn't tested here since it wasn't yet known to be merged),
  run unmodified against `probe_fileio.py`, produced the exact same 216-event, same-per-event-count
  result as the pre-fix 2026-11-11 run (`sample_runs/run2`) — i.e. **no regression** to the raw-event
  capture path. The two runners are near-identical in how they invoke Tracee, so this result should carry
  over, but hasn't been independently re-checked against the repo's copy.
- Network egress re-confirmed still blocked after the rebuild (`[Errno 101] Network is unreachable`).
- `isolated-network.xml` and `hermes_guest_runner.py` both confirmed byte-identical to their pre-fix
  state — the fix touched only Tracee itself.
- Original broken install fully preserved at `~hermes/tracee/dist.orig-broken/` (hash-verified against
  the values the fix report claims).

### What this does *not* do yet

Built-in signatures are always *registered* now, but a signature only actually *runs* when its event
name is explicitly selected via `--events` (or a policy file). **`hermes_guest_runner.py`'s `EVENTS` list
was deliberately left unmodified** — it still only requests raw syscall/lifecycle events, no signature
names. Real pipeline runs through the existing runner will produce **zero** signature detections until
someone adds the relevant signature names to that list. This is intentional — picking which signatures
matter for which `task_type` is exactly the work the roadmap's §3 validation-profile registry describes,
and deliberately wasn't guessed at here. (As of 2026-11-18, the same gap exists in the repo's own
`tier2_guest_runner.py` — see §8a — which is the one that actually matters going forward.) See §9 for the
concrete next step.

## 7. The full signature catalog (confirmed live, 2026-11-18)

All 30 signature names currently available via `--events <name>`, read directly off a live `tracee list`
run (not copied from a report):

```
stdio_over_socket          k8s_api_connection          aslr_inspection
proc_mem_code_injection    docker_abuse                scheduled_task_mod
ld_preload                 cgroup_notify_on_release    default_loader_mod
sudoers_modification       sched_debug_recon           system_request_key_mod
cgroup_release_agent       rcd_modification            core_pattern_modification
proc_kcore_read            proc_mem_access             hidden_file_created
anti_debugging             ptrace_code_injection        process_vm_write_inject
disk_mount                 dynamic_code_loading         fileless_execution
illegitimate_shell         kernel_module_loading       k8s_cert_theft
proc_fops_hooking          syscall_hooking             dropped_executable
```

MITRE mapping confirmed directly (from man pages / live emitted event JSON) for three of these so far —
useful as a starting template for the §3 registry:

| Signature | Signature ID | MITRE ATT&CK | Category |
|---|---|---|---|
| `anti_debugging` | TRC-102 | T1622 (Debugger Evasion) | defense-evasion |
| `ptrace_code_injection` | TRC-103 | T1055.008 | defense-evasion |
| `k8s_cert_theft` | TRC-1018 | T1528 (Steal Application Access Token) | credential-access |

For the other 27: each has a man page at `~hermes/tracee/dist/docs/man/<event-name>.1` inside the guest
(note: a handful use a longer canonical filename than their event name — e.g. `k8s_cert_theft`'s man page
is `kubernetes_certificate_theft_attempt.1` — if a direct lookup 404s, grep the `docs/man/` directory for
the event name instead), or `tracee man <name>` once logged in. **Verify each signature's actual trigger
condition against its Go source under `signatures/golang/` (in `~/hermes-tier2/build/tracee-src/`) before
relying on a man page's metadata block** — §6's fix process already found one man page (`anti_debugging`)
with wrong metadata relative to the real code.

Most of these are generic Linux host-security signatures (container/k8s abuse, rootkit-style hooking,
anti-forensics) rather than tightly matched to this project's specific `task_type` free-text categories —
don't assume a 1:1 mapping exists yet; building that mapping is the actual work of §9 below.

## 8. How this relates to the one real-sample test done so far

On 2026-11-16, the pipeline's first real generated sample was executed in `hermes-tier2-guest` under the
§7 institutional sign-off (confirmed obtained that day) — see
[`TIER2_TEST_REPORT.md`](../data/code_scripts_PAST/level2_cred_disc_lat_mov_QWEN_1/TIER2_TEST_REPORT.md)
for the full account (SSH-key discovery + lateral movement, plus a second round of adversarial
failure-mode testing).

**Important: that test did not go through Tracee or `hermes_guest_runner.py` at all.** It was a simpler,
direct method — the generated functions were imported and called straight over the host-control SSH
session, with output read from the terminal. It proved the *generated code's behavior* (did discovery/
lateral-movement actually work), but produced no eBPF capture and exercised no signature.

So, as of this writing: the VM substrate has hosted one real generated sample (with sign-off); the
Tracee/eBPF capture pipeline described in this doc has only ever observed hand-written benign probes,
never a real generated sample, signature-fixed or not. Closing that gap is still open work — and, per
§8a, that now means running it through `run_tier2_vm_sandbox.py` (the real orchestrator), not hand-SSHing
with `hermes_guest_runner.py` as this one test did.

## 8a. The repo-side orchestrator (merged into `main` 2026-11-18)

Everything in this section lives in the git repo at the repo root, not in `~/hermes-tier2/`. It was
authored 2026-11-11 on a branch (`feat/tier2-vm-orchestrator`) that developed in parallel with the
hand-run session logged in `STAGE4_ROADMAP.md` §10, and only reconciled into `main` a week later. Read
every file directly before relying on this summary — this section is a map, not a replacement for the
source.

**`run_tier2_vm_sandbox.py`** — a real host-side orchestrator, not a stub. Points at the exact same lab
as the rest of this doc (`DEFAULT_LAB_DIR = ~/hermes-tier2`, `DEFAULT_DOMAIN = hermes-tier2-guest`,
`DEFAULT_SNAPSHOT = clean-state`, `DEFAULT_NETWORK = hermes-isolated` — all the same defaults used
throughout §1–§7). Per candidate file: `virsh snapshot-revert` + `virsh start`, re-verifies no-egress
**empirically, every single run** (not just once — it actually attempts a connection from inside the
freshly-booted guest and fails closed if that ever succeeds), pushes the target file plus every sibling
`.py` next to it, SSHes in to run `tier2_guest_runner.py`, pulls the resulting evidence back over a capped
tar stream (treats the guest as hostile: flat files only, size-capped, never trusts member paths), runs
`tier2_rules.py` over it, and appends one record to `tier2_evidence/<run>/` + `tier2_manifest.jsonl`. The
guest is reset to clean again in a `finally` block regardless of outcome. A `.tier2.lock` (`fcntl.flock`,
non-blocking) enforces one detonation at a time per lab — the same `~/hermes-tier2/.tier2.lock` already
referenced in §3, which already existed before this merge.

**The §7 institutional sign-off is now enforced in code, not just by convention.**
`_section7_guard()` refuses to run anything under `data/code_scripts/` or anything whose directory
contains a `manifest.jsonl` (i.e., anything that looks like real Stage 3 output) unless the operator
passes `--section7-signoff-confirmed` explicitly. Benign probes (`tier2_probes/`) pass through untouched.
This is a genuine upgrade over what the rest of this doc describes — until now, that gate was honored by
habit (always reverting to a clean snapshot, always checking sign-off status before running anything
real), not by anything that would actually stop a careless invocation.

**`tier2_guest_runner.py`** (repo root) is a close relative of the *external*
`~/hermes-tier2/guest/hermes_guest_runner.py` referenced throughout §2–§6 — same gate-behind-Tracee-startup
design, same `TRACEE` path, same `EVENTS` list (so it has the exact same gap: no signature names
requested, same as the TODO in §9), same `--capabilities bypass=true` workaround. Two differences: it
copies *every* sibling `.py` file into the guest work directory (not just the target), matching how
generated files actually import each other by bare module name; and it writes `work_listing.json` —
names/sizes/modes of whatever the target left behind (never contents, never following symlinks). Going
forward, **this is the runner that matters** — it's what `run_tier2_vm_sandbox.py` actually pushes and
invokes. The external hand-written copy remains useful only for manual, ad hoc SSH testing (which is what
produced every result in §6 above).

**`tier2_rules.py`** is a real, tested deterministic signal layer — directly implementing part of
roadmap §5.2 ("judge deterministically... a rule engine over the structured report, not an LLM"). Three
rule families, each with evidence refs (`events.jsonl:<line>`) and ATT&CK hints:
- *Sensitive file access* — regex-classified credential-looking paths (private SSH keys, AWS/.netrc/
  .docker/.kube credential files, `/etc/shadow`, generically-named "secret"/"password"/"token" files),
  each mapped to a real technique ID (T1003.008, T1552.004, T1552.001, T1087.001) and a strength
  (`weak`/`medium`/`strong`). Correctly excludes system paths that merely *look* credential-ish (PAM
  config, TLS trust stores, `/proc`, Python's own `getpass.py`) — confirmed by its own test suite.
- *Network connect attempts* — uses the raw `connect` syscall's real errno, explicitly **not**
  `security_socket_connect`/`net_tcp_connect`'s always-0 `returnValue` (the exact LSM-attempt-vs-success
  nuance already documented in §5 above) — and classifies destination scope (loopback/private/public/
  reserved) via RFC1918.
- *Child processes* — distinguishes the target's own first exec (not a "child") from genuine descendants,
  and further distinguishes a shell spawn (T1059.004) from an interpreter spawn (T1059.006) from a plain
  utility.

**It deliberately stops at signals, never a verdict** — confirmed both by its module docstring
("observations only, never a verdict or capability label") and by its own test suite, which explicitly
asserts `"verdict"` is *not* a key in its output. This is real progress toward §5.2, but it is **not**
§3's per-category validation-profile registry (all three rule families run uniformly over every capture,
regardless of `task_type` — there is no category-keying here at all) and **not** §6's dataset label
(`confirmed`/`partial`/`not_observed`/`inconclusive`). Both remain exactly as unbuilt as described in §9
below; what's changed is that there's now a tested foundation to build them on top of, instead of nothing.

**`test_tier2_rules.py`** — 22 unit tests over synthetic Tracee events (no VM, no execution needed to run
them). Independently re-run during this review; all 22 pass. Worth knowing this test suite exists and is
fast — it's the right place to add a case before trusting any change to `tier2_rules.py`.

**`tier2_probes/`** — four benign fixtures, two of which are exactly the "known-good and known-broken"
validation pair roadmap §9 ("Oracle fairness") says every oracle needs before it's trusted:
- `probe_clean_control.py` — the **known-good** half: ordinary computation and file I/O, explicitly
  designed to produce zero signals.
- `probe_decoy_behaviors.py` — the **known-bad** half: deliberately trips all three rule families at
  once — decoy `.ssh/id_rsa` and `.aws/credentials` files (fake content, own cwd only, a
  `DECOY-CANARY-0002` marker), a connect attempt to `192.0.2.1` (an RFC 5737 TEST-NET-1 address —
  reserved, genuinely non-routable, a safe and deliberate choice), and a shell spawn.
- `probe_fileio.py` / `probe_hang.py` — the same two probes already described in §2 of this section's
  external counterpart (`~/hermes-tier2/guest/`), now also version-controlled here.

**What's *not* confirmed: whether this has ever actually run against the real VM.** Both commits are
dated 2026-11-11 (18:59 and 19:17). `~/hermes-tier2/.tier2.lock`'s modification time (19:10, between the
two commits) is circumstantial evidence the lock was acquired around then — but no `tier2_manifest.jsonl`
or `tier2_evidence/` directory survives anywhere on this machine today to confirm a completed detonation.
Treat "has this been exercised for real" as genuinely unconfirmed rather than assuming either answer.

## 9. TODO — pick this up here

In rough order, each building on the last. Updated 2026-11-18 to account for §8a — some of this is now
real engineering work on top of an existing foundation, not a blank page.

1. **Wire signature names into `tier2_guest_runner.py`'s `EVENTS` list** (the repo copy that matters going
   forward — see §8a; the external `hermes_guest_runner.py` has the identical gap but is no longer what
   real runs use). Trivial mechanically (append names from §7's catalog), but the actual decision — which
   signatures are relevant to which `task_type` — is real design work, not a guess. Candidates worth
   starting from, based on what's documented so far: `anti_debugging`/`ptrace_code_injection`/
   `process_vm_write_inject` for anything `defense_evasion`- or injection-flavored; `k8s_cert_theft` only
   if a task ever touches Kubernetes (unlikely given the project's current Linux/Python/non-container
   scope — may not be relevant at all); none of the 30 are an obvious fit for plain SSH-based lateral
   movement (the one real sample tested so far) — that gap alone suggests Tracee's bundled set
   under-covers this project's actual task categories, and `tier2_rules.py`'s raw-event rules (§8a) may
   matter more day-to-day than the bundled 30.
2. **Make `tier2_rules.py` category-aware, and build the validation-profile registry around it** (roadmap
   §3). Not starting from nothing anymore: §8a's three rule families are a real, tested, generic
   foundation — but they run uniformly regardless of `task_type` today. The registry work is deciding
   *which* of these rules (plus which Tracee signatures, once wired in) apply to which category, and
   authoring the category-specific ones `tier2_rules.py` doesn't cover yet (persistence, discovery,
   `c2_transport` beyond a bare connect attempt).
3. **Turn signals into a verdict** (roadmap §5.2's remaining half, and §6's dataset label). `tier2_rules.py`
   deliberately produces signals only — its own tests assert there is no `"verdict"` field. Deciding how a
   set of signals (plus, once wired up, which Tracee signature fired) maps to
   `confirmed`/`partial`/`not_observed`/`inconclusive` is still open, and is exactly the kind of judgment
   call the roadmap says must stay rule-based, never an LLM's.
4. **Actually run `run_tier2_vm_sandbox.py` against something, starting with its own probes.** Per §8a,
   there's no surviving evidence this orchestrator has ever completed a real detonation — not even against
   the benign `tier2_probes/` it ships with. That's the cheapest possible next step and should happen
   before trusting it with anything real. Only after that: run a real generated sample through it
   end-to-end (with `--section7-signoff-confirmed`), closing the gap noted in §8 — ideally the same or a
   similar sample to the 2026-11-16 SSH test, so the two results can be compared.
5. Keep an eye on Tracee upstream: `main` (unreleased, as of commit `2f9dc40c20b1`, 2026-09-29) has already
   moved these same 30 signatures into a new, compiled-in-by-default `detectors/` system, which should make
   this project's patch unnecessary once a release ships it. Check
   <https://github.com/aquasecurity/tracee/releases> before doing further work here in case that's already
   happened — if so, re-evaluate whether to migrate instead of maintaining the patch.
6. `~/hermes-tier2/build/` (~2.4GB) can be deleted once no further rebuild is anticipated; keep the patch
   file, build script, and `TRACEE_SIGNATURE_FIX_REPORT.md` regardless — they're small and are what make
   this reproducible.
