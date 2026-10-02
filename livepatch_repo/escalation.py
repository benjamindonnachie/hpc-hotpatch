from __future__ import annotations

import json
import shlex
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Mapping

from .state import write_json_atomic

if TYPE_CHECKING:
    from .config import Config
    from .models import KernelRelease


class SecurityCoverageError(ValueError):
    """A required in-interval security fix cannot be confidently classified or
    covered, so no livepatch can be produced for this base.

    This is an operational escalation, not a crash. Fleet nodes on the base may
    be exposed and no livepatch is coming, so the operator — or, once wired,
    automation — must decide whether to update, drain and reboot into the fixed
    kernel instead. It subclasses ``ValueError`` so existing generic error
    handling still catches it, while callers that care can distinguish it.
    """

    def __init__(
        self,
        message: str,
        *,
        base: "KernelRelease | None" = None,
        target: "KernelRelease | None" = None,
        cves: tuple[str, ...] = (),
        failure_stage: str = "classification",
        failure_kind: str = "unresolved-security-data",
        diagnostics: Mapping[str, object] | None = None,
    ) -> None:
        super().__init__(message)
        self.base = base
        self.target = target
        self.cves = tuple(cves)
        self.failure_stage = failure_stage
        self.failure_kind = failure_kind
        self.diagnostics = dict(diagnostics or {})


def _iso(moment: datetime) -> str:
    return moment.isoformat().replace("+00:00", "Z")


def escalate_security_gap(
    *,
    config: "Config",
    state_dir: Path,
    error: SecurityCoverageError,
    now: datetime | None = None,
) -> dict:
    """Record and signal a security-coverage gap.

    The always-on behaviour is alert-only: a prominent ``SECURITY-COVERAGE-GAP``
    line is emitted and a durable record is written to
    ``<state-dir>/escalation.json``. The central host never reboots anything
    itself. If an operator has configured an escalation command, it is invoked
    once per distinct gap (deduplicated on base/target/CVEs) so their own
    automation can schedule a kernel update, drain and reboot.
    """
    moment = now or datetime.now(timezone.utc)
    base = error.base.nvra if error.base is not None else None
    target = error.target.nvra if error.target is not None else None
    cves = sorted(error.cves)
    reason = str(error)
    signature = [
        base,
        target,
        cves,
        error.failure_stage,
        error.failure_kind,
    ]

    path = state_dir / "escalation.json"
    previous: object = None
    if path.is_file():
        try:
            previous = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            previous = None
    already_notified = (
        isinstance(previous, dict)
        and previous.get("signature") == signature
        and previous.get("notified_at") is not None
    )

    record: dict = {
        "schema_version": 1,
        "kind": "security-coverage-gap",
        "raised_at": _iso(moment),
        "base": base,
        "target": target,
        "cves": cves,
        "reason": reason,
        "failure_stage": error.failure_stage,
        "failure_kind": error.failure_kind,
        "diagnostics": error.diagnostics,
        "signature": signature,
        "action": (
            "command"
            if config.security_escalation_command_template
            else "alert-only"
        ),
        "notified_at": (
            previous.get("notified_at")
            if already_notified and isinstance(previous, dict)
            else None
        ),
    }

    print(
        "SECURITY-COVERAGE-GAP "
        f"base={base} target={target} "
        f"cves={','.join(cves) or '-'} "
        f"stage={error.failure_stage} kind={error.failure_kind} "
        f"action={record['action']} reason={reason!r}",
        flush=True,
    )
    write_json_atomic(path, record)

    if not config.security_escalation_command_template or already_notified:
        return record

    values = {
        "base": base or "",
        "target": target or "",
        "cves": ",".join(cves),
        "reason": reason,
        "report": str(path),
    }
    command = [
        token.format_map(values)
        for token in shlex.split(config.security_escalation_command_template)
    ]
    try:
        subprocess.run(
            command,
            check=True,
            timeout=config.security_escalation_timeout_seconds,
        )
    except (OSError, subprocess.SubprocessError) as command_error:
        record["command_error"] = str(command_error)
        write_json_atomic(path, record)
        print(
            "livepatch-repo: WARNING: security escalation command failed: "
            f"{command_error}",
            flush=True,
        )
        return record
    record["notified_at"] = _iso(moment)
    write_json_atomic(path, record)
    return record


def request_build_failure_review(
    *,
    config: "Config",
    state_dir: Path,
    error: SecurityCoverageError,
    now: datetime | None = None,
) -> dict:
    """Give an operator-configured review step first refusal on a build
    failure, before it escalates to a fleet-reboot request.

    Alert-only/escalate-immediately by default (no command configured), same
    as `escalate_security_gap`. When `build_failure_review_command_template`
    is set, the first occurrence of a distinct build failure (deduplicated on
    base/target/cves/failure_kind, same as the escalation record) hands off
    to that command -- expected to be a quick, idempotent trigger (e.g.
    enqueue a job), not the review itself, exactly like the escalation
    hand-off. The actual review is expected to be scoped and approved by an
    operator ahead of time; this only dispatches it.

    Reconcile then holds off escalating while later ticks reproduce the SAME
    failure, up to `build_failure_review_grace_seconds`. Every reconcile
    tick's build re-attempt is itself the retry: if the review's fix lands,
    the next build naturally succeeds and there is nothing left to escalate.
    Once the grace window elapses with the same failure still occurring,
    escalation proceeds as if no review were configured at all.

    Returns a dict with ``under_review`` (True while the caller should hold
    off calling `escalate_security_gap` for this failure) and ``expired``.
    """
    moment = now or datetime.now(timezone.utc)
    base = error.base.nvra if error.base is not None else None
    target = error.target.nvra if error.target is not None else None
    cves = sorted(error.cves)
    signature = [base, target, cves, error.failure_stage, error.failure_kind]

    path = state_dir / "build-failure-review.json"
    previous: object = None
    if path.is_file():
        try:
            previous = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            previous = None
    same_failure = isinstance(previous, dict) and previous.get("signature") == signature
    first_seen = None
    if same_failure and isinstance(previous, dict):
        try:
            first_seen = datetime.fromisoformat(
                str(previous.get("first_seen", "")).replace("Z", "+00:00")
            )
        except ValueError:
            first_seen = None
    if first_seen is None or first_seen > moment:
        first_seen = moment
    age_seconds = max(0, int((moment - first_seen).total_seconds()))
    expired = age_seconds >= config.build_failure_review_grace_seconds

    if not config.build_failure_review_command_template:
        return {"under_review": False, "expired": True}

    already_requested = (
        same_failure
        and isinstance(previous, dict)
        and previous.get("requested_at") is not None
    )
    record: dict = {
        "schema_version": 1,
        "kind": "build-failure-review",
        "signature": signature,
        "base": base,
        "target": target,
        "cves": cves,
        "reason": str(error),
        "failure_stage": error.failure_stage,
        "failure_kind": error.failure_kind,
        "diagnostics": error.diagnostics,
        "first_seen": _iso(first_seen),
        "last_seen": _iso(moment),
        "age_seconds": age_seconds,
        "grace_seconds": config.build_failure_review_grace_seconds,
        "expired": expired,
        "requested_at": (
            previous.get("requested_at")
            if already_requested and isinstance(previous, dict)
            else None
        ),
    }

    if expired:
        write_json_atomic(path, record)
        print(
            "BUILD-FAILURE-REVIEW grace window elapsed "
            f"base={base} target={target} age={age_seconds}s -- escalating",
            flush=True,
        )
        return {"under_review": False, "expired": True}

    if already_requested:
        write_json_atomic(path, record)
        return {"under_review": True, "expired": False}

    print(
        "BUILD-FAILURE-REVIEW requesting review "
        f"base={base} target={target} "
        f"cves={','.join(cves) or '-'} kind={error.failure_kind}",
        flush=True,
    )
    values = {
        "base": base or "",
        "target": target or "",
        "cves": ",".join(cves),
        "reason": str(error),
        "report": str(path),
    }
    command = [
        token.format_map(values)
        for token in shlex.split(config.build_failure_review_command_template)
    ]
    try:
        subprocess.run(
            command,
            check=True,
            timeout=config.build_failure_review_timeout_seconds,
        )
    except (OSError, subprocess.SubprocessError) as command_error:
        record["command_error"] = str(command_error)
        write_json_atomic(path, record)
        print(
            "livepatch-repo: WARNING: build failure review command failed: "
            f"{command_error}",
            flush=True,
        )
        # Could not even dispatch the review -- do not silently hold the
        # failure behind a review that never started.
        return {"under_review": False, "expired": False}
    record["requested_at"] = _iso(moment)
    write_json_atomic(path, record)
    return {"under_review": True, "expired": False}
