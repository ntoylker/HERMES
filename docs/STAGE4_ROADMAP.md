# Stage 4 Roadmap — Behavioral Validation, Containment, and Labeling

Status: **mostly design still.** Today's Stage 4 is Stage 4a (static validation) plus Tier 1 (the
import-only execution gate); the validation-profile registry and any oracle described below do not exist
yet. One piece has moved past prototype: §10 logs a hand-driven VM + eBPF (Tracee) capture environment.
Its full setup, build/patch history, and operational detail now live in a dedicated companion doc —
[STAGE4_TIER2_SETUP.md](STAGE4_TIER2_SETUP.md) — rather than here; this doc stays design/status-level.
The §7 institutional sign-off has been obtained (2026-11-16), and one real generated sample has since been
executed in the Tier 2 VM under it — but via a simpler direct-SSH method, not through the eBPF/Tracee
capture pipeline itself, which to date has only ever observed hand-written benign probes (see
STAGE4_TIER2_SETUP.md §8 for the exact boundary between the two). This roadmap describes how the project
intends to climb from
"the code loads" to "the code *demonstrably performs the declared behavior, under observation, inside a
sealed lab*" — and, crucially, where that climb must stop.

This is a **measurement and containment** document. Its subject is the *validator*: how to observe whether
generated code does what its plan claims, how to contain that observation safely, and how to label the
result honestly. It is explicitly **not** about improving, optimizing, or operationalizing generated code.

## 1. The research claim this enables (and its hard boundary)

The thesis studies whether an LLM pipeline, given structured adversary knowledge, can produce code that
*works* — so that the research community can be warned about that capability. The scientifically and
ethically defensible form of that claim is:

> *"The generated code demonstrably exhibits the ATT&CK technique its plan declared, when exercised under
> observation in a sealed, instrumented environment."*

It is **not**, and must never be stated as:

> ~~"The generated code works as a weapon against a real target."~~

No sealed environment can establish field efficacy — efficacy is a property of a *specific target and its
defenses*, not of the code — and attempting to establish it would require real targets, which this project
forbids (see CLAUDE.md, thesis-safety). The deliverable is therefore a **graded capability label** derived
from *observed behavior in containment*, carrying its own confidence and fidelity, never a boolean
"weaponized" verdict. Stating this boundary explicitly is both a safety requirement and what keeps the
dataset credible: a reader must be able to see exactly what a "dangerous" label does and does not assert.

This reframing is how the project escapes the "green-flag trap": instead of a verdict that passes code it
never exercised (today's Tier 1 import gate — see
[STAGE4_A_STATIC_VALIDATION.md](STAGE4_A_STATIC_VALIDATION.md) "Tier 1 — current limitations"), the label is
earned only by *observed* technique behavior.

## 2. The functional-code ladder

Each rung is run only on what passed the cheaper rung below it.

| Rung | Question | Built by | Status |
|---|---|---|---|
| 1 | Does it parse / compile? | Stage 3 `ast.parse` + Stage 4a `compile()` | ✅ |
| 2 | Do imports resolve and the symbol contract hold (statically)? | Stage 4a | ✅ |
| 3 | Does module-level code load/run cleanly in isolation? | Tier 1 (import gate) | ✅ |
| 3.5 | Does self-contained, deterministic logic behave correctly? | *self-test oracle* | ⬜ planned |
| 4 | Does it **exhibit the declared technique behavior**, under observation, sealed? | *behavioral detonation + per-category oracle* | ⬜ planned (environment + capture prototyped, see §10) |

Rung 4 is the heart of this roadmap. Note rung 3.5 as a cheap, honest intermediate: a lot of generated code
is deterministic and self-contained (encoders, serializers, a transport's framing/length-prefix round-trip,
obfuscation/crypto helpers). Those can be *functionally* verified by calling their entry points with fixed
inputs in a container — no network, no victim — and the resulting green is real, not a false-green.

## 3. Category-driven validation (the intended architecture)

The core design decision: **validation is per adversary category, not generic.** Different ATT&CK tactics
produce different observable effects and need different environments to exhibit them; one uniform runner
cannot fairly judge them. The plan is a **validation-profile registry** keyed to the Stage 2 `task_type`
label. Stage 2 no longer enforces a fixed task_type vocabulary (the `stage2_constraints.json` file that
used to constrain it was removed — `task_type` is now free text the model assigns per task), so this
registry's category set will need to be defined and owned by Stage 4 itself rather than inherited from a
Stage 2 schema. Each category's validation profile is authored and reviewed once; from then on, when a
run's category is known (chosen early in the flow), Stage 4 provisions that category's environment
automatically.

Each profile is three things — all framed as *observation inside containment*:

1. **Environment profile** — guest OS; network mode (fully isolated / sealed fake-service network /
   lab-controlled paired peer); seeded decoy fixtures; privilege level; snapshot requirement.
2. **Stimulus** — how the code is *exercised* for observation (invoke the declared entry point, run as
   `__main__`, attach a lab peer, present a decoy store). This is measurement mechanics, nothing more.
3. **Success oracle** — the *observable* that confirms the declared technique fired, evaluated
   deterministically over the behavioral report (see §5). Prefer **canary/decoy** oracles: plant a unique
   marker, and "the marker surfaced where it should not" is an unambiguous, reproducible signal.

*(2026-11-18: `tier2_rules.py` — merged into `main` from `feat/tier2-vm-orchestrator`, see §10 — is a real,
tested step toward point 3, but it is explicitly generic, not category-keyed: the same three rule families
(sensitive-file-access, network-connect-attempt, child-process/shell-spawn) run uniformly over every
capture regardless of `task_type`. The registry itself — deciding which of those rules, plus which
category-specific ones, apply per category — is still unbuilt. See `docs/STAGE4_TIER2_SETUP.md` §8a.)*

Observation-level sketches (what to *watch for*, not how to perform anything):

| Category (`task_type`) | Environment | Success oracle (observed signal) |
|---|---|---|
| `c2_transport` / reverse shell | sealed net with a lab-controlled peer **or** a fake-service responder | connection attempt to the *lab* endpoint in the capture **and** a child interpreter/shell process in the process tree **and** a message round-trip within the sealed net |
| `credential_access` | guest seeded with a **decoy** secret store (unique canary token) | the code reads the seeded store **and** the canary token appears in its output/staging location |
| `persistence` | snapshotting guest | an autostart artifact is created **and** it re-executes after a snapshot relaunch |
| `discovery` | guest seeded with decoy facts | the planted facts appear in what the code collected |
| `execution` | instrumented guest | a child process / interpreter is actually spawned |
| `defense_evasion` | baseline-dependent | largely observational (did it *attempt* the declared obfuscation); true efficacy needs a specific defense baseline and is out of scope → graded low-confidence |

**Non-goals of the registry (state these in code comments too):** it does not modify, repair, optimize, or
increase the effectiveness of any generated code; it does not target anything real; it only observes a
sealed detonation and records what was seen. It is a measuring instrument, not a build step.

## 4. Environment & isolation tiers

Two independent axes, often conflated — keep them separate:

- **Isolation strength (safety):** plain Docker shares the host kernel and is *not* a sufficient boundary
  for code intended to be malicious. Rung 4 detonation needs a stronger boundary: a user-space-kernel
  sandbox (e.g. gVisor) or a microVM (e.g. Firecracker) for Linux workloads, or a full virtual machine for
  the strongest isolation and for snapshot/rollback.
- **Fidelity (can the behavior even run):** the dataset spans OSes. Windows-targeted techniques can only be
  truthfully observed on a **Windows guest** — which rules out Linux-only sandboxes and the current Linux
  base image. Cross-OS fidelity therefore implies full VMs with snapshots (which is exactly what Cuckoo/CAPE
  orchestrate).

Consequence: **tier the environment per sample.** Deterministic, self-contained, Linux-only logic → cheap
container/gVisor (rung 3.5). Anything touching the OS, network, persistence, or a non-Linux target → a
snapshotting VM (rung 4). The per-category profile (§3) selects the tier.

Isolation alone is necessary but **not sufficient**. Sealed detonation also requires:

- **No egress.** The detonation network must not reach any real host. To let network-dependent code *attempt*
  its behavior so it can be observed, use a **self-contained fake-service network** (e.g. INetSim/FakeNet
  simulating DNS/HTTP/etc.) or a **lab-controlled paired peer** — never a real endpoint. This is what lets
  the project observe "it tried to connect and hand off a session" without any real peer existing.
- **Snapshot + rollback**, so each detonation starts clean and leaves nothing.
- **A disposable/air-gapped host** dedicated to detonation, with a kill-switch and hard time/resource caps.
  *(What's actually been built, per §10 and STAGE4_TIER2_SETUP.md §1: a disposable, network-isolated guest
  VM — snapshot/revert-able, no `<forward>` route out, empirically verified — running on this project's
  ordinary, networked development laptop, not a separate air-gapped machine. The original intent was a
  dedicated secondary host; nested virtualization on the intended separate Windows machine proved fragile,
  so this laptop ended up serving both roles. The guest's isolation is real and verified; the host itself
  was never air-gapped and isn't dedicated to detonation alone.)*

## 5. Evidence capture and interpretation

**5.1. Capture.** Detonate under instrumentation that records the process tree, API/syscall activity,
file/registry changes, and a network capture. Two routes: an off-the-shelf behavioral sandbox
(Cuckoo/**CAPE**), which already emits a structured JSON report with **ATT&CK-tagged** signatures — a
natural fit because it speaks the same language as Stage 1 — or a DIY instrumented VM (Sysmon/`strace`/
auditd + pcap + filesystem diff) if CAPE's operational overhead isn't worth it early on. *(§10 records
which route was actually taken — neither of these two, as sketched; see STAGE4_TIER2_SETUP.md.)*

**5.2. Judge deterministically.** The capability label is a **rule engine over the structured report**, not
an LLM. Each category's success oracle (§3) is expressed as explicit conditions over observed signals.
Deterministic judging is reproducible and auditable — essential for a defensible dataset. *(2026-11-18:
`tier2_rules.py` is exactly this — a tested, deterministic rule engine with evidence refs and ATT&CK hints,
no LLM involved — but it stops at signals, not a verdict; its own test suite asserts no `"verdict"` key
exists in its output. See `docs/STAGE4_TIER2_SETUP.md` §8a.)*

**5.3. The headline metric: the ATT&CK round-trip.** Stage 1 grounded the task in a technique; §5.2 observes
which technique behaviors actually fired. *Claimed technique vs. observed technique* is the project's
core measurement, and it closes the loop the rest of the pipeline set up.

**5.4. LLM as assistant, never judge.** An LLM may summarize/triage a verbose report, *draft* candidate
oracle rules for human review, or attach a natural-language rationale to an already-deterministic label. It
must not assign the label itself: an LLM judging LLM output is non-reproducible and circular, and would
itself need validating. Keep the verdict rule-based; keep the LLM in an explain/assist role with a human in
the loop.

*(Numbered 5.1–5.4 rather than a plain 1–4 list specifically so the "§5.1"/"§5.2" cross-references already
used elsewhere in this doc — §10's capture-tooling entry, and §5.3 above referencing §5.2 — point at
something real instead of an undeclared convention. The mapping (5.1 Capture, 5.2 Judge deterministically,
5.3 the round-trip metric, 5.4 LLM-as-assistant) matches how those existing references were already being
used before this renumbering; nothing about which point means what has changed.)*

## 6. The dataset label

Replace any boolean "dangerous/weaponized" field with a structured, graded record, e.g.:

```
capability_label:
  task_type:        <category>
  claimed_technique: <ATT&CK id from Stage 1>
  observed_technique: <id(s) actually exhibited, or none>
  verdict:          confirmed | partial | not_observed | inconclusive
  fidelity:         <environment tier: self-test | linux-vm | windows-vm | ...>
  confidence:       <high | medium | low, from oracle strength>
  evidence_ref:     <path to the behavioral report + which signals matched>
  boundary:         "demonstrated in sealed lab; NOT field efficacy"
```

Every label carries the boundary line, so no downstream reader can mistake "confirmed in containment" for
"works in the wild."

## 7. Safety, ethics, and authorization (gating, not optional)

Rung 4 means deliberately detonating code intended to be malicious. Before any of §3–§6 is built or run:

- **Institutional sign-off.** Written approval from the supervising professor / institution for detonating
  generated offensive code, with scope and handling rules agreed in advance. *(Status: satisfied — stated
  directly by the thesis author: "the university has already provided me with legitimate license to
  conduct such research with the necessary tools and uses." Separately, the specific written sign-off for
  rung-4 detonation of generated offensive code was confirmed obtained on 2026-11-16 — see the 2026-11-18
  update in §10 and STAGE4_TIER2_SETUP.md.)*
- **Containment preconditions, enforced in code.** No egress; fake-service network or lab peer only;
  VM-level isolation with snapshots for anything beyond self-test; disposable/air-gapped detonation host;
  kill-switch; strict time/resource caps. *(2026-11-18: the sign-off gate above is now literally "enforced
  in code" for the first time — `run_tier2_vm_sandbox.py`'s `_section7_guard()` refuses to run anything
  under `data/code_scripts/` without an explicit `--section7-signoff-confirmed` flag. The no-egress check
  is also now re-verified empirically on every single run, not just checked once. See
  `docs/STAGE4_TIER2_SETUP.md` §8a. Fake-service networking, the per-category profiles, and the verdict
  label are still not code-enforced anywhere.)*
- **Keep samples in-lab.** Never submit generated samples to third-party or cloud sandboxes — that is
  uncontrolled distribution. Run analysis on infrastructure you control.
- **Data handling.** Generated code and reports are sensitive research artifacts: access-controlled storage,
  clear retention, and the existing `.gitignore` discipline (nothing under `data/` is committed).
- **Responsible disclosure.** The point is to *warn* the community. Publish findings and aggregate risk
  signals; do not publish runnable harmful artifacts. Follow coordinated-disclosure norms for anything that
  implicates a specific real product or service.
- **Content safety still isn't machine-checked.** Per CLAUDE.md, nothing yet scans task *content* for
  forbidden capabilities. A behavioral tier raises the stakes of that gap; a content-policy gate (what the
  pipeline is permitted to attempt to validate) should be designed alongside rung 4, not after it.

## 8. Phased build plan

1. **Rung 3.5 first.** Add a self-test oracle for deterministic, self-contained logic in a container/gVisor,
   no network. Cheap, honest functional signal; no detonation-safety burden yet.
2. **Author the validation-profile registry** (§3) with **two** categories you can judge cleanly end-to-end —
   suggested: `c2_transport` (sealed peer/fake-service) and `credential_access` (canary decoy). The registry
   schema and these two profiles are the primary research artifact.
3. **Stand up one contained detonation environment** (§4) with no-egress + fake-service + snapshots, gated by
   the §7 sign-off. Validate containment with a benign probe before any real sample. *(Status as of
   2026-11-18 — per §10's progress log and STAGE4_TIER2_SETUP.md: no-egress networking and snapshot/
   rollback are both built and empirically verified; the §7 sign-off is obtained (2026-11-16); one real
   generated sample has run in this environment under that sign-off, via a direct-SSH method (see
   `TIER2_TEST_REPORT.md`), not through the eBPF capture pipeline described in §10/§5. A real host-side
   orchestrator and rule layer also now exist (`run_tier2_vm_sandbox.py`/`tier2_rules.py`, merged into
   `main` today from a branch authored 2026-11-11 — see STAGE4_TIER2_SETUP.md §8a), but there is no
   surviving evidence either has ever completed a run against the actual VM, benign or otherwise.
   **Fake-service networking is still entirely unbuilt** — nothing in this environment currently lets
   network-dependent code attempt a connection to anything but a silently-unreachable address; this remains
   the one genuinely open item from this phase.)*
4. **Add capture + deterministic oracle + the ATT&CK round-trip metric** (§5). Label per §6.
5. **Generalize** to more categories once the two-category loop is trustworthy and the containment is proven.

## 9. Open questions / risks

- **Oracle fairness.** A weak oracle under-credits working code; an over-eager one false-greens. Each
  oracle needs its own small validation set (known-good and known-broken samples) before it labels anything.
  *(2026-11-18: `tier2_probes/probe_clean_control.py` (known-good, zero signals expected) and
  `probe_decoy_behaviors.py` (known-bad, deliberately trips every rule `tier2_rules.py` currently has) are
  exactly this pair for that rule layer — already built, already used by its 22-case unit test suite. The
  same discipline still needs applying to whatever category-specific rules get added next. See
  `docs/STAGE4_TIER2_SETUP.md` §8a.)*
- **Environment detection.** Sandbox-aware code may suppress behavior under observation → a false
  `not_observed`. Record environment fidelity on every label and treat `not_observed` as weak evidence, not
  proof of harmlessness.
- **Category coverage.** The fixed category set bounds what the pipeline can be asked to generate *and*
  validate; keep the two in sync (a category with no validation profile should not be generable, or should
  be labeled `inconclusive` by construction).
- **Operational cost.** Full-VM detonation is slow and heavy; the tiering in §4 is what keeps it tractable.

## 10. Progress log

**November 2026 — Tier 2 environment prototyped on a dedicated second host (infra only; no real sample run,
no §7 sign-off yet).**

Scope of this entry: building and proving the *environment and capture mechanism* rung 4 needs, exercised
against a benign probe, per §8 phase 3's instruction to "validate containment with a benign probe before
any real sample." It does **not** cover the validation-profile registry (§3), any oracle (§3/§5.2), or the
capability label (§6) — those remain entirely unbuilt. *(⚠ Stale as of 2026-11-16/18 on the rest of this
sentence — the §7 sign-off has since been obtained, and one real generated sample has run under it, though
via a simpler method than the capture pipeline described here. See the dated update at the end of this
section.)*

- **Host and isolation tier (§4).** Stood up on a dedicated secondary Linux laptop (Ubuntu 24.04,
  KVM-capable, kernel 6.8+ with BTF) acting as the disposable detonation host per §7 — not the development
  machine. KVM/QEMU/libvirt, with a single Ubuntu 24.04 guest VM (`virt-install` + cloud-init) as the
  detonation target. This is the "full virtual machine" tier §4 calls for; the gVisor/Firecracker
  container-tier alternative for rung 3.5 is untouched by this work. *(Correction: in practice this ended
  up being the same laptop the HERMES repo and development work live on — nested virtualization on the
  originally-intended separate Windows dev machine proved fragile. Deliberate, not an oversight; see
  STAGE4_TIER2_SETUP.md §1.)*
- **No-egress networking (§4), empirically verified, not just configured.** Replaced the guest's default
  NAT network with a libvirt network defined with no `<forward>` element at all (the host can still reach
  the guest for control; the guest has no route anywhere else). Verified with a before/after: the same
  benign probe script attempting `socket.create_connection(("8.8.8.8", 53))` printed `connected` on the NAT
  network and `[Errno 101] Network is unreachable` after the swap — the isolation is real, not just a
  renamed network.
- **Snapshot/rollback (§4): not yet exercised.** The guest has been shut down, reconfigured, and restarted,
  but `virsh snapshot-create-as` / `snapshot-revert` has not actually been used yet. Internal qcow2
  snapshots are the planned mechanism; still open work. *(⚠ Stale as of 2026-11-18 — now exercised
  repeatedly, both for the 2026-11-16 real-sample test and the signature fix below. See
  STAGE4_TIER2_SETUP.md §3.)*
- **Capture tooling (§5), a concrete decision diverging from this doc's original sketch.** §5.1 names
  Cuckoo/CAPE or a DIY `strace`/auditd-based VM as the two routes. CAPE was evaluated and deliberately
  **not** chosen: its community ATT&CK-mapped signature set is overwhelmingly Windows-malware-oriented,
  a weak fit now that the project has pivoted Linux-only (see Project section, CLAUDE.md). The DIY route
  was built instead, using **Tracee** (eBPF-based, Aqua Security) rather than the `strace`/auditd
  combination originally sketched — Tracee ships its own MITRE ATT&CK-mapped signature set (AVD), which
  was the deciding factor over plain syscall tracing.
  - **Working:** raw eBPF event capture, run as root inside the guest (`--capabilities bypass=true` — see
    gotcha below). Verified against a benign probe to produce correctly-attributed `sched_process_exec`
    events (exact PID, argv, parent PID) and network-attempt events (`security_socket_connect`,
    `net_tcp_connect`, with destination IP/port) that correctly chain a multi-level process tree
    (`timeout` → `python3` → `whoami`).
  - **Not working: the prebuilt ATT&CK signature plugin.** Tracee's shipped `signatures/builtin.so` fails
    to load (`plugin was built with a different version of package net` — a Go plugin ABI mismatch,
    present even within the same official v0.24.1 release tarball). Until resolved, technique-matching
    against Tracee's own signature set is unavailable; only raw events are captured. A rule engine over raw
    events (§5.2) is not blocked by this, but gets no assist from Tracee's own signatures yet.
    *(⚠ Stale as of 2026-11-18 — fixed. Root cause turned out to be a build-tag mismatch in Tracee's own
    release pipeline, not a toolchain mismatch; all 30 bundled signatures are now compiled directly into
    the binary and verified firing correctly. Full diagnosis, patch, and verification:
    STAGE4_TIER2_SETUP.md §6. Not yet wired into `hermes_guest_runner.py`'s own event selection — see
    STAGE4_TIER2_SETUP.md §9.)*
  - **Known gap: file I/O is not in Tracee's default event set.** `credential_access`/`collection`/
    `discovery`/`persistence` profiles (§3) will need explicit event selection (e.g. `-e openat,write`) —
    unconfirmed as of this entry. *(⚠ Resolved — `hermes_guest_runner.py`'s `EVENTS` list already requests
    `openat`, `security_file_open`, `vfs_write`, rename/chmod/unlink variants, etc. See
    STAGE4_TIER2_SETUP.md §5.)*
  - **Known nuance for oracle-writing (§5.2, §9 oracle fairness):** `security_socket_connect`/
    `net_tcp_connect`'s `returnValue: 0` reflects an LSM permission check / attempt-observation, not the
    real `connect(2)` errno — confirmed by the no-egress test above showing `returnValue: 0` on both sealed
    and open runs despite the application-level outcome differing. Matches this doc's own oracle framing
    (§3: "connection attempt... in the capture", not confirmed success) but must not be read as a literal
    success/failure field if a future oracle checks it directly; the real `connect` syscall event is not in
    the default set either and would need explicit capture.
- **Gotchas worth recording for whoever continues this:**
  - `libvirt-qemu` (the user QEMU processes run as under `qemu:///system`) needs explicit `setfacl` search
    grants on every host directory leading to a VM's disk image — the home directory's default mode blocks
    it, and `virt-install` warns about this but doesn't fix it.
  - Tracee v0.24.1 on kernel ≥6.8-ish with `perf_event_paranoid < 2` hits a real upstream bug
    ([aquasecurity/tracee#5330](https://github.com/aquasecurity/tracee/issues/5330)): its capability
    auto-selection omits `CAP_SYS_ADMIN`, which the kernel requires for `BPF_BTF_GET_FD_BY_ID` regardless of
    `CAP_BPF`. Fixed upstream after this version; the workaround is `--capabilities bypass=true` (note the
    `=true` — the bare flag is not sufficient).

**Still entirely unbuilt (as of the November 2026 entry above):** the validation-profile registry (§3),
any category's actual oracle, the guest-side detonation runner and host-side orchestrator (the real
automation — this prototyping was done by hand over SSH), capture + rule engine + the ATT&CK round-trip
metric (§5), the dataset label (§6), and §7's institutional sign-off. *(⚠ Stale, differently than it looks
— see the 2026-11-18 update below: the orchestrator/runner/rule-engine pieces of this sentence existed in
code the whole time, just on an unmerged branch authored the same day as this entry; they weren't
"unbuilt," they were unreconciled with `main`.)*

---

**2026-11-18 update.** Three things changed since the entry above; full operational detail for all of them
now lives in the dedicated companion doc, [STAGE4_TIER2_SETUP.md](STAGE4_TIER2_SETUP.md), rather than here:

- **§7 sign-off obtained (2026-11-16).** A real generated sample
  (`data/code_scripts_PAST/level2_cred_disc_lat_mov_QWEN_1/`) was executed in the Tier 2 VM under it —
  see [`TIER2_TEST_REPORT.md`](../data/code_scripts_PAST/level2_cred_disc_lat_mov_QWEN_1/TIER2_TEST_REPORT.md).
  **This did not go through Tracee or the eBPF capture pipeline** — it used a simpler direct-SSH method.
  The capture pipeline itself has still only ever observed benign probes; closing that gap is open work
  (STAGE4_TIER2_SETUP.md §8–9).
- **A guest-side detonation runner now exists** (`~/hermes-tier2/guest/hermes_guest_runner.py`, outside the
  repo) — gates a target script behind Tracee startup, captures scoped eBPF events as JSON, enforces a
  wall-clock kill-switch. *(Superseded by the next bullet as the one that matters going forward — see it
  before concluding anything from this one in isolation.)*
- **Tracee's bundled ATT&CK signature plugin is fixed.** The "Not working" finding above is resolved: all
  30 signatures are now compiled directly into the `tracee` binary and verified firing correctly (full
  diagnosis and verification in STAGE4_TIER2_SETUP.md §6–7). Not yet wired into the guest runner's own
  event selection, and never yet exercised against a real sample — both are the next concrete steps
  (STAGE4_TIER2_SETUP.md §9), directly feeding into building the validation-profile registry (§3) above.
- **`feat/tier2-vm-orchestrator` merged into `main`.** That branch — authored 2026-11-11, the same day as
  the entry above, developed in parallel with it rather than after it — adds a real host-side orchestrator
  (`run_tier2_vm_sandbox.py`), a guest-side runner (`tier2_guest_runner.py`), a tested deterministic signal
  layer (`tier2_rules.py`, 22 passing unit tests, implementing part of §5.2), and benign test probes
  including a known-good/known-bad validation pair (§9's "Oracle fairness" need). It enforces the §7
  sign-off gate in code for the first time. Full detail: STAGE4_TIER2_SETUP.md §8a — including the honest
  caveat that there's no surviving evidence this orchestrator has ever completed a run against the real
  VM, even against its own benign probes.
