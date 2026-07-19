# Fleet reboot orchestrator — design approach

> Status: **design proposal.** The central escalation-ticket boundary is
> included, but deployment-specific pipelines, node automation, scheduling and
> boot governance are intentionally outside this repository. This design plugs
> into `security_escalation_command_template` (see the README
> "Security-coverage escalation" section).

## Purpose

Livepatches cover the common case: a security fix is delivered to the fleet with
no reboot. The reboot path is the **exception** — when a required security fix
cannot be livepatched or classified, the fleet must instead converge onto the
fixed kernel by draining and rebooting. This orchestrator coordinates that
convergence across an HTCondor cluster, safely and under human approval.

It fires rarely, so it is optimised for **correctness, auditability and
interruptibility**, not speed.

## Where it sits

```
central builder                         GitLab                     HTCondor fleet
---------------                         ------                     -------------
reconcile
  └─ SECURITY-COVERAGE-GAP
       └─ hook: trigger pipeline ─────► pipeline (plan)
          (base, target, CVEs)           └─ compute node set (condor_status)
                                         └─ render + publish rollout plan
                                         ── APPROVAL GATE (human) ──
                                         approved maintenance window
                                           └─ runner + Ansible ───────► drain → reboot →
                                                                        verify → resume
                                         └─ (last) update+reboot the builder itself
```

The central builder only **signals**. It never reboots or drains anything
itself. Everything downstream is a separate, approve-gated system.

## Design principles

1. **Central host signals only.** The escalation hook does one fast thing —
   trigger a GitLab pipeline (or enqueue a ticket) — and returns.
2. **Definite human approval.** Nothing drains or reboots without an explicit
   approval by an authorised person.
3. **Converge to a single target, don't chase per-base.** The rollout drives
   *every* affected node to one target kernel `Y`, which also repairs a mixed
   fleet (see below).
4. **Integrate with node tooling.** The proposed orchestrator assumes an
   external, field-tested drain→reboot→verify→resume implementation. That
   node-side tooling is deliberately outside this central-only repository; the
   orchestrator sequences it rather than reinventing it.
5. **Idempotent and resumable.** Re-running is safe: `drain-reboot` no-ops when
   the target already runs, and the plan stage recomputes the shrinking set of
   nodes not yet on `Y`.
6. **Treat the ticket as data.** The orchestrator re-derives/confirms the
   security state; the ticket is an input to verify, not a command to obey.

## GitLab as the orchestrator platform

GitLab supplies every primitive this needs:

| Need | GitLab mechanism |
|---|---|
| Trigger from the central hook | Pipeline **trigger token** (`POST .../trigger/pipeline`) with `base`, `target`, `cves` as variables — a single fast `curl` from the hook. |
| Human approval gate | A **manual job** (`when: manual`) on a **protected environment**, restricted to authorised roles. (Multi-approver **deployment approval rules** need Premium; a protected manual job is the Free-tier equivalent.) |
| Admission window | A **pipeline schedule** (cron) that picks up *approved-and-pending* convergences and runs the rollout only within a site-defined maintenance window. |
| Execution against the fleet | A **GitLab Runner** on a control node running **Ansible**. |
| Audit trail | Pipelines, job logs, approvals and environment deployments are all recorded. |
| Secrets | Masked/protected CI variables, or (preferred) a runner on a control node holding scoped SSH credentials to the fleet. |

### Stages

1. **Trigger** — the hook calls the trigger API with the gap context. Fast,
   fire-and-forget. Implemented by `livepatch_repo/escalation_ticket.py`; the
   wire format is the [ticket contract](escalation-ticket-contract.md).
   (Alternatively the hook writes a ticket to a repo and a scheduled pipeline
   consumes it; the trigger API is simpler and immediate.)
2. **Plan** — compute the affected node set from HTCondor, render a rollout plan
   (nodes, current kernels, target `Y`, CVEs and their severities, chosen
   profile), and publish it as a job artifact / issue. **No changes made.**
3. **Approve** — a protected manual job. The approver reviews the plan during
   working hours and selects a **rollout profile** (below). This is the gate.
4. **Roll out** — run by the scheduled pipeline inside the admission window;
   drives the per-node sequence with bounded concurrency.
5. **Converge the builder** — once the fleet is healthy on `Y`, update and reboot
   the builder last, re-establishing the livepatch base.

## Rollout mechanics

### Per-node sequence (generic Ansible play, reusing node tooling)

`drain (peaceful) → wait until idle → ensure target kernel installed + set as
default → reboot → verify uname -r == Y and node healthy → resume`.

"Resume" (`condor_drain -cancel`) is the "start accepting jobs" trigger, gated on
the version + health check. "Check all up" is a fleet-level health gate before
the run is declared complete and before the builder is converged.

### HTCondor specifics

- **Peaceful drain.** `condor_drain -peaceful` stops accepting jobs and waits for
  running work to finish without eviction. A node-side implementation should
  expose an explicitly validated drain-mode policy and default to peaceful.
- **Bounded by the existing deadline.** Peaceful can wait a long time on a running
  job, so the wait is bounded by the existing `DRAIN_TIMEOUT_SECONDS`: on expiry
  the node is left **drained and held, NOT rebooted**, and alerts — a human then
  decides. Set that timeout generously for peaceful. Rather than auto-escalating a
  stuck peaceful drain, the **approver chooses the mode up front** from the
  ticket's CVE severity (peaceful for routine, `quick`/`graceful` for a Critical
  "drain the lot").
- **Targeting and verification via ClassAds.** Have nodes advertise their running
  kernel as a startd ClassAd (`STARTD_ATTRS`, e.g. `KernelNVRA`). The orchestrator
  then selects with `condor_status -constraint` and confirms `== Y` after reboot.
- **Resume** with `condor_drain -cancel` after verification.

### Staggering — rolling max-in-flight, not fixed batches

Under peaceful drain, nodes finish at very different times, so **fixed batches
stall on the slowest node**. Prefer a **max-in-flight** model: keep `N` nodes
draining concurrently and admit the next as each completes.

- Ansible's default `linear` strategy with `serial: N` is fixed-batch (stalls on
  slowest). For true max-in-flight use `strategy: free` with `throttle: N`
  (and `async`/`poll` for the long drain), or drive the admission loop from the
  CI job. A modest `serial:` is an acceptable pragmatic start if the free-strategy
  play proves fiddly.
- **Rollout profiles**, chosen by the approver from the ticket severity:
  - `staggered` (default): small `N`, peaceful drain.
  - `accelerated`: larger `N`.
  - `all-at-once`: `N = all`, optionally `graceful` drain — the "if critical,
    drain the lot" case.

### Admission window

Only **start** new drains during a site-defined maintenance window with suitable
operator cover. In-flight drains may continue outside the window, but no new
node is admitted. The human approval is a one-off action; the schedule then
paces admission according to local policy.

## The convergence / mixed-fleet problem

A fleet can drift across several kernel releases when nodes update and reboot
independently.

This is the crux for a livepatch fleet, because a central livepatch RPM is bound
to **one exact base kernel**. A mixed fleet fragments coverage — one built
livepatch cannot load on nodes running a different base — and the single-base
central model assumes the fleet mirrors the builder's kernel.

### In the rollout: target the complement of `Y`

Do **not** select "nodes on the builder's base `X`". Select **every node not
already on the target `Y`** (`condor_status -constraint 'KernelNVRA != "Y"'`).
The convergence then pulls every outlying base onto a single `Y`. This makes the
reboot fallback double as mixed-fleet repair.

### Prevent it recurring: centrally govern the *booted* base

The mixed fleet is a symptom of nodes autonomously choosing *and booting*
kernels. For a livepatch fleet the booted base must stay uniform, so:

- **Decouple "installed" from "booted".** Let `dnf-automatic` install kernel
  updates (so packages/debuginfo are present), but pin the **default boot** kernel
  (for example with grubby) so nodes do not advance their running base on their
  own.
- **Pin the sanctioned base** fleet-wide (e.g. `dnf versionlock` on `kernel*`, or
  a boot-default pin), so closely spaced releases do not scatter the fleet.
- **Let the central pipeline be the only thing that advances the booted base.**
  The fleet stays uniform and livepatchable; the convergence rollout is the sole,
  coordinated mechanism that moves everyone to a new base — and only when a fix
  cannot be livepatched.

This turns "converging on the same kernel" from an accident into a governed,
auditable transition.

## Idempotency, failure handling, kill switch

- **Idempotent:** `drain-reboot` no-ops on an already-correct node; re-triggering
  recomputes the shrinking non-`Y` set. Coalesce repeated escalations for the same
  target.
- **Halt on failure:** a node that fails to reach `Y` or comes up unhealthy is
  left **drained and held**, alerts, and **stops further admission** pending a
  human. Never resume a node that failed verification.
- **Global kill switch:** a fleet-wide enable flag (mirror the node-side
  `AUTO_REBOOT_ENABLED`) that halts all admission immediately.

## Security / trust boundary

- The trigger token and ticket path are a **privileged boundary** — a stray or
  forged ticket must not be able to reboot the fleet. Authenticate the trigger and
  restrict who/what can invoke it.
- Keep fleet SSH/reboot authority on the **control-node runner** with scoped
  credentials, not on the central builder. The builder never gains push authority
  over nodes.
- The approval gate is the human check on all of the above.

## Implementation boundary

Included here:

- [x] **Escalation-ticket hand-off.**
  `python3 -m livepatch_repo.escalation_ticket --report {report}` builds a
  versioned ticket and can trigger a pipeline when `GITLAB_*` is configured;
  otherwise it is a safe alert-only no-op. See the
  [ticket contract](escalation-ticket-contract.md).

Deployment-specific work:

- [ ] **GitLab project/pipeline.** `plan` → protected manual `approve` →
  scheduled `rollout`; trigger token, CI variables, environment for audit.
  First safe step: scaffold `plan`+`approve` and send a real ticket in dry-run
  (no node action).
- [ ] **Ansible play.** Per-node drain/reboot/verify/resume plus the rolling
  max-in-flight admission driver; profiles for staggered/accelerated/all-at-once.
- [ ] **Node kernel ClassAd.** Advertise `KernelNVRA` via HTCondor
  `STARTD_ATTRS` for targeting and post-reboot verification.
- [ ] **Boot governance.** Decouple installed-vs-booted (grubby default pin
  and/or `versionlock`) so the fleet stays uniform between coordinated
  convergences.
- [ ] **Converge the builder last** as the tail of a rollout.

## Open decisions

- GitLab tier (manual-job approval vs Premium deployment-approval rules).
- Max-in-flight `N` defaults per profile, and the `DRAIN_DEADLINE` value.
- Boot-governance mechanism: grubby default-pin vs `versionlock` vs both.
- Whether the builder converges automatically at the tail, or as a separate
  approved step.
