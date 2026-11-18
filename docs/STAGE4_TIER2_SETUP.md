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

**None of this infrastructure lives in the git repo.** It's all in `~/hermes-tier2/` on this laptop,
outside `/home/ntoylker/Desktop/HERMES/mvp/`. It is not version-controlled, not backed up by git, and not
portable to another machine without redoing most of the steps below. If this laptop's home directory is
ever lost, this environment is gone and has to be rebuilt from this doc.

The repo itself only contains two things related to Tier 2:
- [STAGE4_ROADMAP.md](STAGE4_ROADMAP.md) (this doc's sibling, design-level)
- [`data/code_scripts_PAST/level2_cred_disc_lat_mov_QWEN_1/TIER2_TEST_REPORT.md`](../data/code_scripts_PAST/level2_cred_disc_lat_mov_QWEN_1/TIER2_TEST_REPORT.md)
  — the write-up of the one real generated sample tested here so far (see §8 below for how that test
  relates to — and does *not* go through — the Tracee pipeline described in this doc)

There is no `run_tier2_vm_sandbox.py`-equivalent anywhere, unlike Tier 1's
`run_tier1_sandbox.py`/`tier1_runner.py`/`Dockerfile.tier1`, which *are* in the repo. Everything here is
run by hand, over SSH.

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
- The existing `hermes_guest_runner.py`, run unmodified against `probe_fileio.py`, produced the exact
  same 216-event, same-per-event-count result as the pre-fix 2026-11-11 run (`sample_runs/run2`) — i.e.
  **no regression** to the raw-event capture path.
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
and deliberately wasn't guessed at here. See §9 for the concrete next step.

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
never a real generated sample, signature-fixed or not. Closing that gap — running a real sample *through*
`hermes_guest_runner.py` with relevant signatures enabled — is still open work.

## 9. TODO — pick this up here

In rough order, each building on the last:

1. **Wire signature names into `hermes_guest_runner.py`'s `EVENTS` list.** Trivial mechanically (append
   names from §7's catalog), but the actual decision — which signatures are relevant to which `task_type`
   — is real design work, not a guess. Candidates worth starting from, based on what's documented so far:
   `anti_debugging`/`ptrace_code_injection`/`process_vm_write_inject` for anything `defense_evasion`- or
   injection-flavored; `k8s_cert_theft` only if a task ever touches Kubernetes (unlikely given the
   project's current Linux/Python/non-container scope — may not be relevant at all); none of the 30 are an
   obvious fit for plain SSH-based lateral movement (the one real sample tested so far) — that gap alone
   suggests Tracee's bundled set under-covers this project's actual task categories, and custom signatures
   (or raw-event rules, per roadmap §5.2) may matter more than the bundled 30.
2. **Build the validation-profile registry itself** (roadmap §3) — still entirely unbuilt. This is where
   the "which signature(s)/events for which `task_type`" decision actually belongs, not scattered ad hoc
   into the runner.
3. **Design the actual oracle logic** (roadmap §5.2) — today, a human reads `events.jsonl` by hand. A
   deterministic rule engine over the captured JSON (signature events once wired up, plus the raw-event
   patterns already captured) is still to be built.
4. **Run a real generated sample through the Tracee pipeline end to end**, closing the gap noted in §8 —
   ideally the same or a similar sample to the 2026-11-16 SSH test, so the two results can be compared.
5. Keep an eye on Tracee upstream: `main` (unreleased, as of commit `2f9dc40c20b1`, 2026-09-29) has already
   moved these same 30 signatures into a new, compiled-in-by-default `detectors/` system, which should make
   this project's patch unnecessary once a release ships it. Check
   <https://github.com/aquasecurity/tracee/releases> before doing further work here in case that's already
   happened — if so, re-evaluate whether to migrate instead of maintaining the patch.
6. `~/hermes-tier2/build/` (~2.4GB) can be deleted once no further rebuild is anticipated; keep the patch
   file, build script, and `TRACEE_SIGNATURE_FIX_REPORT.md` regardless — they're small and are what make
   this reproducible.
