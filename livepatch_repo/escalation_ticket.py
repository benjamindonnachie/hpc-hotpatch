"""Turn an escalation record into a ticket and, when configured, deliver it
over one or more independently-configurable channels: a GitLab pipeline
trigger (for the reboot orchestrator), a generic webhook, and/or email.

This is the reference target for both `security_escalation_command_template`
and `build_failure_review_command_template`:

    security_escalation_command_template =
        python3 -m livepatch_repo.escalation_ticket --report {report}
    build_failure_review_command_template =
        python3 -m livepatch_repo.escalation_ticket --report {report}

The ticket `kind` is derived from the escalation record: a security-coverage
gap or a build failure that has exhausted review both become a
`fleet-reboot-request`; a fresh build-failure-review record becomes a
`build-failure-review-request`. The central builder still performs no client
action itself -- this only *hands off* a versioned ticket to whichever
channels are configured. Each channel is independently optional and comes
from the environment:

    GITLAB_URL, GITLAB_PROJECT_ID, GITLAB_TRIGGER_TOKEN, GITLAB_REF
    ALERT_WEBHOOK_URL, ALERT_WEBHOOK_HEADER (optional "Name: value")
    ALERT_EMAIL_TO, ALERT_EMAIL_FROM, ALERT_SMTP_HOST, ALERT_SMTP_PORT

With none set, this is a safe no-op that emits the ticket and sends nothing,
so an unconfigured deployment stays alert-only. See
``docs/escalation-ticket-contract.md`` for the wire contract.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import smtplib
import sys
from email.message import EmailMessage
from pathlib import Path
from typing import Callable
from urllib.parse import urlencode
from urllib.request import Request, urlopen


TICKET_SCHEMA_VERSION = 1

_REVIEW_REPORT_KIND = "build-failure-review"


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
    ticket_kind = (
        "build-failure-review-request"
        if report.get("kind") == _REVIEW_REPORT_KIND
        else "fleet-reboot-request"
    )
    return {
        "schema_version": TICKET_SCHEMA_VERSION,
        "kind": ticket_kind,
        "ticket_id": ticket_id(base, target, normalised_cves),
        "base": base,
        "target": target,
        "cves": normalised_cves,
        "reason": str(report.get("reason", "")),
        "diagnostics": report.get("diagnostics") or {},
        "source": {
            "system": "central-livepatch-repo",
            "report_kind": report.get("kind"),
            "raised_at": report.get("raised_at"),
            "failure_stage": report.get("failure_stage"),
            "failure_kind": report.get("failure_kind"),
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


def webhook_request(url: str, ticket: dict, header: str = "") -> Request:
    """Build the generic webhook POST request (does not send it)."""
    headers = {"Content-Type": "application/json"}
    if header:
        name, _, value = header.partition(":")
        if name.strip() and value.strip():
            headers[name.strip()] = value.strip()
    return Request(
        url,
        data=json.dumps(ticket, sort_keys=True).encode("utf-8"),
        method="POST",
        headers=headers,
    )


def build_email(ticket: dict, *, to: str, sender: str) -> EmailMessage:
    """Build the alert email (does not send it)."""
    message = EmailMessage()
    message["Subject"] = (
        f"[livepatch] {ticket['kind']}: {ticket['base']} -> {ticket['target']}"
    )
    message["From"] = sender
    message["To"] = to
    message.set_content(
        f"{ticket['reason']}\n\n"
        f"kind: {ticket['kind']}\n"
        f"ticket_id: {ticket['ticket_id']}\n"
        f"base: {ticket['base']}\n"
        f"target: {ticket['target']}\n"
        f"cves: {', '.join(ticket['cves']) or '-'}\n\n"
        f"{json.dumps(ticket, sort_keys=True, indent=2)}\n"
    )
    return message


def main(
    argv: list[str] | None = None,
    *,
    sender: Callable[[Request], str] | None = None,
    smtp_client: Callable[[], "smtplib.SMTP"] | None = None,
) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Emit a ticket and optionally deliver it over GitLab/webhook/email."
        )
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
        "--webhook-url", default=os.environ.get("ALERT_WEBHOOK_URL", "")
    )
    parser.add_argument(
        "--webhook-header", default=os.environ.get("ALERT_WEBHOOK_HEADER", "")
    )
    parser.add_argument("--email-to", default=os.environ.get("ALERT_EMAIL_TO", ""))
    parser.add_argument(
        "--email-from",
        default=os.environ.get("ALERT_EMAIL_FROM", "livepatch-repo@localhost"),
    )
    parser.add_argument(
        "--smtp-host", default=os.environ.get("ALERT_SMTP_HOST", "")
    )
    parser.add_argument(
        "--smtp-port", type=int, default=int(os.environ.get("ALERT_SMTP_PORT", "25"))
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

    channels: list[tuple[str, bool]] = []
    failed = False
    sent = False

    gitlab_configured = bool(
        args.gitlab_url and args.project_id and args.trigger_token
    )
    if gitlab_configured and not args.dry_run:
        request = trigger_request(
            args.gitlab_url,
            args.project_id,
            args.trigger_token,
            args.ref,
            pipeline_variables(ticket),
        )
        try:
            if sender is not None:
                sender(request)
            else:
                with urlopen(request, timeout=30) as response:
                    response.read()
            channels.append(("gitlab", True))
            sent = True
        except Exception as error:  # network, HTTP error, etc.
            print(f"escalation-ticket: GitLab trigger failed: {error}", file=sys.stderr)
            channels.append(("gitlab", False))
            failed = True

    if args.webhook_url and not args.dry_run:
        request = webhook_request(args.webhook_url, ticket, args.webhook_header)
        try:
            if sender is not None:
                sender(request)
            else:
                with urlopen(request, timeout=30) as response:
                    response.read()
            channels.append(("webhook", True))
            sent = True
        except Exception as error:
            print(f"escalation-ticket: webhook delivery failed: {error}", file=sys.stderr)
            channels.append(("webhook", False))
            failed = True

    if args.email_to and args.smtp_host and not args.dry_run:
        message = build_email(ticket, to=args.email_to, sender=args.email_from)
        try:
            if smtp_client is not None:
                client = smtp_client()
                client.send_message(message)
            else:
                with smtplib.SMTP(args.smtp_host, args.smtp_port, timeout=30) as client:
                    client.send_message(message)
            channels.append(("email", True))
            sent = True
        except Exception as error:
            print(f"escalation-ticket: email delivery failed: {error}", file=sys.stderr)
            channels.append(("email", False))
            failed = True

    print(
        json.dumps(
            {"ticket": ticket, "sent": sent, "channels": dict(channels)},
            sort_keys=True,
        )
    )
    if not channels and not args.dry_run:
        # Safe default: emit the ticket, send nothing. Unconfigured
        # deployments stay alert-only without failing the reconcile.
        print(
            "escalation-ticket: no delivery channel configured "
            "(GitLab/ALERT_WEBHOOK_URL/ALERT_EMAIL_TO+ALERT_SMTP_HOST); "
            "ticket not sent",
            file=sys.stderr,
        )
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
