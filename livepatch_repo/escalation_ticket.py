"""Turn a security-coverage escalation into a fleet-reboot ticket and, when
configured, trigger a GitLab pipeline for the reboot orchestrator.

This is the reference target for `security_escalation_command_template`:

    security_escalation_command_template =
        python3 -m livepatch_repo.escalation_ticket --report {report}

The central builder still performs no client action. This only *hands off* a
versioned ticket. GitLab configuration comes from the environment
(``GITLAB_URL``, ``GITLAB_PROJECT_ID``, ``GITLAB_TRIGGER_TOKEN``,
``GITLAB_REF``); with none set it is a safe no-op that emits the ticket and does
not send anything, so an unconfigured deployment stays alert-only. See
``docs/escalation-ticket-contract.md`` for the wire contract.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Callable
from urllib.parse import urlencode
from urllib.request import Request, urlopen


TICKET_SCHEMA_VERSION = 1


def ticket_id(base: str | None, target: str | None, cves: list[str]) -> str:
    """Stable identifier for a gap: same base/target/CVEs → same id.

    Matches the escalation record's dedup signature, so the orchestrator can
    coalesce repeated triggers for one gap.
    """
    signature = "\0".join(
        [base or "", target or "", ",".join(sorted(cves))]
    )
    return hashlib.sha256(signature.encode()).hexdigest()[:16]


def build_ticket(report: dict) -> dict:
    """Build a versioned fleet-reboot ticket from an escalation record."""
    if not isinstance(report, dict):
        raise ValueError("escalation report must be an object")
    cves = report.get("cves") or []
    if not isinstance(cves, list):
        raise ValueError("escalation report cves must be a list")
    base = report.get("base")
    target = report.get("target")
    normalised_cves = sorted(str(cve) for cve in cves)
    return {
        "schema_version": TICKET_SCHEMA_VERSION,
        "kind": "fleet-reboot-request",
        "ticket_id": ticket_id(base, target, normalised_cves),
        "base": base,
        "target": target,
        "cves": normalised_cves,
        "reason": str(report.get("reason", "")),
        "source": {
            "system": "central-livepatch-repo",
            "report_kind": report.get("kind"),
            "raised_at": report.get("raised_at"),
        },
    }


def pipeline_variables(ticket: dict) -> dict:
    """Map a ticket to GitLab pipeline trigger variables."""
    return {
        "LP_TICKET_SCHEMA": str(ticket["schema_version"]),
        "LP_TICKET_ID": ticket["ticket_id"],
        "LP_BASE": ticket["base"] or "",
        "LP_TARGET": ticket["target"] or "",
        "LP_CVES": ",".join(ticket["cves"]),
        "LP_REASON": ticket["reason"],
        "LP_TICKET_JSON": json.dumps(ticket, sort_keys=True),
    }


def trigger_request(
    gitlab_url: str,
    project_id: str,
    token: str,
    ref: str,
    variables: dict,
) -> Request:
    """Build the GitLab pipeline-trigger POST request (does not send it)."""
    url = (
        f"{gitlab_url.rstrip('/')}/api/v4/projects/{project_id}/trigger/pipeline"
    )
    form = {"token": token, "ref": ref}
    for name, value in variables.items():
        form[f"variables[{name}]"] = value
    return Request(
        url,
        data=urlencode(form).encode(),
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )


def main(
    argv: list[str] | None = None,
    *,
    sender: Callable[[Request], str] | None = None,
) -> int:
    parser = argparse.ArgumentParser(
        description="Emit a fleet-reboot ticket and optionally trigger GitLab."
    )
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--gitlab-url", default=os.environ.get("GITLAB_URL", ""))
    parser.add_argument(
        "--project-id", default=os.environ.get("GITLAB_PROJECT_ID", "")
    )
    parser.add_argument("--ref", default=os.environ.get("GITLAB_REF", "main"))
    parser.add_argument(
        "--trigger-token", default=os.environ.get("GITLAB_TRIGGER_TOKEN", "")
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="build and print the ticket but never send it",
    )
    args = parser.parse_args(argv)

    try:
        report = json.loads(args.report.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        print(f"escalation-ticket: cannot read report: {error}", file=sys.stderr)
        return 1

    try:
        ticket = build_ticket(report)
    except ValueError as error:
        print(f"escalation-ticket: invalid report: {error}", file=sys.stderr)
        return 1

    configured = bool(args.gitlab_url and args.project_id and args.trigger_token)
    if args.dry_run or not configured:
        # Safe default: emit the ticket, send nothing. Unconfigured deployments
        # stay alert-only without failing the reconcile.
        print(json.dumps({"ticket": ticket, "sent": False}, sort_keys=True))
        if not configured and not args.dry_run:
            print(
                "escalation-ticket: GitLab trigger not configured "
                "(GITLAB_URL/GITLAB_PROJECT_ID/GITLAB_TRIGGER_TOKEN); "
                "ticket not sent",
                file=sys.stderr,
            )
        return 0

    request = trigger_request(
        args.gitlab_url,
        args.project_id,
        args.trigger_token,
        args.ref,
        pipeline_variables(ticket),
    )
    try:
        if sender is not None:
            body = sender(request)
        else:
            with urlopen(request, timeout=30) as response:
                body = response.read().decode("utf-8", errors="replace")
    except Exception as error:  # network, HTTP error, etc.
        print(
            f"escalation-ticket: GitLab trigger failed: {error}",
            file=sys.stderr,
        )
        return 1
    print(json.dumps({"ticket": ticket, "sent": True}, sort_keys=True))
    if body.strip():
        print(body, file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
