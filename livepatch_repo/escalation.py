from __future__ import annotations

import json
import shlex
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

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
    ) -> None:
        super().__init__(message)
        self.base = base
        self.target = target
        self.cves = tuple(cves)


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
    signature = [base, target, cves]

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
        f"unresolved-cves={','.join(cves) or '-'} "
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
