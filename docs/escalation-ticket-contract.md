# Escalation ticket contract (central → GitLab)

The versioned handoff between the central builder's security-coverage escalation
and the fleet reboot orchestrator. Implemented by
`livepatch_repo/escalation_ticket.py`; the orchestrator design is in
[`escalation-orchestrator.md`](escalation-orchestrator.md).

The central builder performs no client action. It only emits a ticket and,
when configured, triggers a GitLab pipeline. Everything after that is the
approve-gated orchestrator's responsibility.

## Wiring

Point the escalation hook at the ticket tool:

```ini
[policy]
security_escalation_command_template = python3 -m livepatch_repo.escalation_ticket --report {report}
```

`{report}` is the path to `<state-dir>/escalation.json`, which reconciliation
writes before invoking the hook. GitLab configuration comes from the
environment (e.g. the reconcile unit's `EnvironmentFile`), never the config
template, so the trigger token is not stored beside ordinary settings:

| Variable | Meaning |
|---|---|
| `GITLAB_URL` | Base URL, e.g. `https://gitlab.example.com`. |
| `GITLAB_PROJECT_ID` | Numeric project id of the orchestrator repo. |
| `GITLAB_TRIGGER_TOKEN` | Pipeline trigger token (a **secret**). |
| `GITLAB_REF` | Branch/tag to run (default `main`). |

**With none set, the tool is a safe no-op:** it prints the ticket and sends
nothing, so an unconfigured deployment stays alert-only and the reconcile does
not fail. A configured send that fails returns non-zero, so the escalation
records a `command_error` and retries on the next run.

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
  "source": {
    "system": "central-livepatch-repo",
    "report_kind": "security-coverage-gap",
    "raised_at": "2026-07-19T16:00:00Z"
  }
}
```

- **`ticket_id`** — `sha256(base \0 target \0 sorted(cves))[:16]`. Stable and
  order-independent: the same gap always yields the same id, so the orchestrator
  can **deduplicate** repeated triggers (matching the escalation record's own
  dedup signature). A changed CVE set yields a new id.
- **`base` / `target`** — the exposed base kernel and the convergence target the
  fleet should reach. The orchestrator drives *every node not already on
  `target`* onto it (see the mixed-fleet section of the orchestrator doc).
- **`cves`** — sorted, normalised; the required security fixes the missing
  livepatch would have carried.
- **`reason`** — human-readable cause (the escalation message).
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
