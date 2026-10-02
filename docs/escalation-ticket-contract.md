# Escalation ticket contract (central → GitLab / webhook / email)

The versioned handoff between the central builder's escalation hooks and
whatever downstream system acts on them: the fleet reboot orchestrator, an
on-call webhook, or a plain email alert. Implemented by
`livepatch_repo/escalation_ticket.py`; the orchestrator design is in
[`escalation-orchestrator.md`](escalation-orchestrator.md).

The central builder performs no client action. It only emits a ticket and,
when configured, delivers it over one or more channels. Everything after
that is the receiving system's responsibility -- for the fleet-reboot ticket
kind specifically, that means the approve-gated orchestrator.

## Two hooks, one tool

`escalation_ticket.py` is the reference target for **two** independent config
hooks, distinguished by the ticket `kind` it derives from the report:

```ini
[policy]
# Fires immediately on a security-coverage gap, or once build-failure review
# (below) is unconfigured/exhausted. Ticket kind: fleet-reboot-request.
security_escalation_command_template = python3 -m livepatch_repo.escalation_ticket --report {report}

# Optional. Fires first, before a build failure reaches the line above, so an
# operator-scoped review (e.g. an agent working under human guidance) gets a
# chance to fix it. Ticket kind: build-failure-review-request. Must return
# promptly -- it is a trigger, not the review itself, exactly like the row
# above. Reconcile holds off re-escalating the same failure for
# build_failure_review_grace_seconds (default 86400) while retrying the build
# on each tick; if the review's fix lands, the next build just succeeds and
# nothing further is sent. Left empty (the default), build failures escalate
# immediately, same as before this hook existed.
build_failure_review_command_template = python3 -m livepatch_repo.escalation_ticket --report {report}
build_failure_review_timeout_seconds = 300
build_failure_review_grace_seconds = 86400
```

`{report}` is the path to the JSON record reconciliation writes before
invoking the hook (`<state-dir>/escalation.json` or
`<state-dir>/build-failure-review.json`).

## Delivery channels

Each channel is independent and optional; configure any combination. None of
this is stored in the config template -- it comes from the environment (e.g.
the reconcile unit's `EnvironmentFile`), so secrets stay out of ordinary
settings:

| Variable | Meaning |
|---|---|
| `GITLAB_URL` / `GITLAB_PROJECT_ID` / `GITLAB_TRIGGER_TOKEN` / `GITLAB_REF` | Trigger a GitLab pipeline (the fleet-reboot orchestrator's transport). `GITLAB_REF` defaults to `main`. |
| `ALERT_WEBHOOK_URL` / `ALERT_WEBHOOK_HEADER` | POST the ticket as JSON to a generic webhook. `ALERT_WEBHOOK_HEADER` is one optional `"Name: value"` header (e.g. an API key). |
| `ALERT_EMAIL_TO` / `ALERT_EMAIL_FROM` / `ALERT_SMTP_HOST` / `ALERT_SMTP_PORT` | Send a plain-text alert email. `ALERT_SMTP_PORT` defaults to 25. |

**With none set, the tool is a safe no-op:** it prints the ticket and sends
nothing, so an unconfigured deployment stays alert-only and the reconcile does
not fail. Each configured channel is attempted independently; a channel that
fails to send returns a non-zero exit and its own `_error` detail, so the
escalation records it and retries that channel on the next run without
blocking the others.

## Ticket schema (v1)

```json
{
  "schema_version": 1,
  "kind": "fleet-reboot-request",
  "ticket_id": "8f14e45fceea167a",
  "base": "5.14.0-687.22.1.el9_8.x86_64",
  "target": "5.14.0-687.25.1.el9_8.x86_64",
  "cves": ["CVE-2026-40001", "CVE-2026-40002"],
  "reason": "security data has no severity for: CVE-2026-40001",
  "diagnostics": {},
  "source": {
    "system": "central-livepatch-repo",
    "report_kind": "security-coverage-gap",
    "raised_at": "2026-07-19T16:00:00Z",
    "failure_stage": "classification",
    "failure_kind": "unresolved-security-data"
  }
}
```

- **`kind`** — `fleet-reboot-request` for a security-coverage gap or an
  exhausted build-failure review; `build-failure-review-request` when the
  report's own `kind` is `build-failure-review` (a fresh, not-yet-exhausted
  build failure being handed to review first).
- **`ticket_id`** — `sha256(base \0 target \0 sorted(cves))[:16]`. Stable and
  order-independent: the same gap always yields the same id, so the orchestrator
  can **deduplicate** repeated triggers. The central alert record additionally
  includes failure stage and kind in its notification signature, so a later
  build-stage failure can still alert after an earlier metadata-stage warning;
  both fold into the same approval ticket when base, target and CVEs match.
- **`base` / `target`** — the exposed base kernel and the convergence target the
  fleet should reach. The orchestrator drives *every node not already on
  `target`* onto it (see the mixed-fleet section of the orchestrator doc).
- **`cves`** — sorted and normalised. For classification/build gaps these are
  the required fixes the missing livepatch would have carried. The list is
  empty for a newly available kernel whose updateinfo is not yet sufficient to
  determine whether any CVE exists; `source.failure_kind` and `diagnostics`
  carry the pending/timeout condition instead.
- **`reason`** — human-readable cause (the escalation message).
- **`diagnostics`** — additive structured evidence. For a metadata gap this
  includes `first_seen`, age, timeout, available target notices and missing CVE
  releases. For a build-stage gap it includes the job/backend, unsupported ELF
  objects and sections when recognised, selected patches associated with newly
  uncovered CVEs, the last published same-base coverage, and retained evidence
  paths.
- **`source`** — provenance for audit; not authoritative.

## GitLab trigger mapping

`POST {GITLAB_URL}/api/v4/projects/{GITLAB_PROJECT_ID}/trigger/pipeline`, form
body `token=…&ref=…&variables[NAME]=…`. The ticket is projected to pipeline
variables the plan/approval jobs consume:

| Variable | Value |
|---|---|
| `LP_TICKET_SCHEMA` | schema version |
| `LP_TICKET_ID` | stable ticket id (use for dedup / idempotency) |
| `LP_BASE` | base kernel NVRA |
| `LP_TARGET` | convergence target NVRA |
| `LP_CVES` | comma-separated sorted CVEs |
| `LP_REASON` | reason string |
| `LP_TICKET_JSON` | the full ticket JSON (authoritative payload) |

## Rules for the orchestrator

- **Treat the ticket as data, not a command.** Re-derive/confirm the security
  state and the affected node set from HTCondor before acting; the ticket is an
  input to verify.
- **Idempotency on `ticket_id`.** Repeated triggers for the same gap must not
  start a second rollout; fold them into the existing one.
- **The trigger boundary is privileged.** Restrict who can call the trigger
  token; keep it a masked/protected CI variable. A stray ticket must never be
  able to move the fleet without the human approval gate.

## Versioning

`schema_version` is bumped only on an incompatible change. Additive fields keep
the same version; consumers must ignore unknown fields. The current version is
`1`.
