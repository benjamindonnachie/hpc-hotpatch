from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import shlex
import subprocess
from typing import Any

from .config import Config
from .models import (
    CVE_SEVERITIES,
    AdvisoryFix,
    BuildJob,
    CvePolicyDecision,
    KernelRelease,
)
from .sources import RepositorySnapshot


@dataclass(frozen=True)
class BuildPlan:
    generated_at: str
    base: KernelRelease
    target: KernelRelease | None
    jobs: tuple[BuildJob, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": 2,
            "generated_at": self.generated_at,
            "base": self.base.to_dict(),
            "target": self.target.to_dict() if self.target is not None else None,
            "jobs": [job.to_dict() for job in self.jobs],
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "BuildPlan":
        jobs = value.get("jobs")
        if not isinstance(jobs, list):
            raise ValueError("plan jobs must be a list")
        target = value.get("target")
        base = value.get("base")
        if not isinstance(base, dict):
            raise ValueError("plan base must be an object")
        return cls(
            generated_at=str(value["generated_at"]),
            base=KernelRelease.from_dict(base),
            target=(KernelRelease.from_dict(target) if isinstance(target, dict) else None),
            jobs=tuple(BuildJob.from_dict(job) for job in jobs),
        )

    @classmethod
    def read(cls, path: Path) -> "BuildPlan":
        with path.open(encoding="utf-8") as handle:
            value = json.load(handle)
        if not isinstance(value, dict):
            raise ValueError("plan root must be an object")
        return cls.from_dict(value)

    def job(self, job_id: str) -> BuildJob:
        matches = [job for job in self.jobs if job.job_id == job_id]
        if len(matches) != 1:
            raise ValueError(f"plan contains no unique job {job_id!r}")
        return matches[0]


def _backend_for(kernel: KernelRelease) -> str:
    if kernel.distro_major == 9:
        return "kpatch-build"
    if kernel.distro_major >= 10:
        return "klp-build"
    raise ValueError(f"unsupported EL major: {kernel.distro_major}")


def _interval_policy_decisions(
    base: KernelRelease,
    target: KernelRelease,
    advisories: tuple[AdvisoryFix, ...],
    eligible_cve_severities: tuple[str, ...],
) -> tuple[CvePolicyDecision, ...]:
    severity_rank = {
        severity: len(CVE_SEVERITIES) - index
        for index, severity in enumerate(CVE_SEVERITIES)
    }
    fixes: dict[str, str] = {}
    for advisory in advisories:
        if (
            advisory.kernel.same_family(base)
            and base < advisory.kernel
            and (advisory.kernel < target or advisory.kernel == target)
        ):
            previous = fixes.get(advisory.cve)
            if previous is None or severity_rank[advisory.severity] > severity_rank[
                previous
            ]:
                fixes[advisory.cve] = advisory.severity
    eligible = set(eligible_cve_severities)
    return tuple(
        CvePolicyDecision(
            cve,
            severity,
            "required" if severity in eligible else "below-policy",
        )
        for cve, severity in sorted(fixes.items())
    )


def _interval_ticket_evidence(
    base: KernelRelease,
    target: KernelRelease,
    advisories: tuple[AdvisoryFix, ...],
    required_cves: frozenset[str],
) -> tuple[tuple[str, tuple[str, ...]], ...]:
    evidence: dict[str, set[str]] = {}
    for advisory in advisories:
        if (
            advisory.kernel.same_family(base)
            and base < advisory.kernel
            and (advisory.kernel < target or advisory.kernel == target)
            and advisory.cve in required_cves
            and advisory.ticket_ids
        ):
            evidence.setdefault(advisory.cve, set()).update(advisory.ticket_ids)
    return tuple(
        (cve, tuple(sorted(ticket_ids)))
        for cve, ticket_ids in sorted(evidence.items())
    )


def _metadata_complete(
    base: KernelRelease,
    target: KernelRelease,
    snapshot: RepositorySnapshot,
) -> bool:
    target_notices = tuple(
        notice
        for notice in snapshot.notices
        if notice.kernel == target
    )
    if not target_notices:
        return False
    security_kernels = {
        notice.kernel
        for notice in snapshot.notices
        if notice.kind == "security"
        and notice.kernel.same_family(base)
        and base < notice.kernel
        and (notice.kernel < target or notice.kernel == target)
    }
    cve_kernels = {
        advisory.kernel
        for advisory in snapshot.advisories
        if advisory.kernel.same_family(base)
    }
    return security_kernels <= cve_kernels


def create_plan(
    snapshot: RepositorySnapshot,
    *,
    architecture: str,
    distro_stream: str,
    base: KernelRelease,
    target_kernel: KernelRelease | None = None,
    eligible_cve_severities: tuple[str, ...] = ("Critical", "Important"),
    now: datetime | None = None,
) -> BuildPlan:
    invalid_severities = set(eligible_cve_severities) - set(CVE_SEVERITIES)
    if not eligible_cve_severities or invalid_severities:
        raise ValueError("eligible CVE severities must be known and non-empty")
    eligible = sorted(
        {
            kernel
            for kernel in snapshot.kernels
            if kernel.arch == architecture and kernel.distro_stream == distro_stream
        }
    )
    if base.arch != architecture or base.distro_stream != distro_stream:
        raise ValueError(
            f"base {base.nvra} does not match {distro_stream}/{architecture}"
        )
    targets = [kernel for kernel in eligible if kernel.same_family(base) and base < kernel]
    if target_kernel is not None:
        if target_kernel not in targets:
            raise ValueError(
                f"requested target {target_kernel.nvra} is not an available kernel "
                f"newer than base {base.nvra}"
            )
        target = target_kernel
    else:
        target = targets[-1] if targets else None
    jobs: list[BuildJob] = []
    if target is not None:
        complete = _metadata_complete(base, target, snapshot)
        decisions = (
            _interval_policy_decisions(
                base,
                target,
                snapshot.advisories,
                eligible_cve_severities,
            )
            if complete
            else ()
        )
        cves = tuple(
            decision.cve
            for decision in decisions
            if decision.disposition == "required"
        )
        ticket_evidence = (
            _interval_ticket_evidence(
                base,
                target,
                snapshot.advisories,
                frozenset(cves),
            )
            if complete
            else ()
        )
        jobs.append(
            BuildJob(
                base=base,
                target=target,
                cves=cves,
                status=(
                    "metadata-pending"
                    if not complete
                    else "planned" if cves else "no-work"
                ),
                backend=_backend_for(base),
                cve_ticket_ids=ticket_evidence,
                cve_policy_decisions=decisions,
            )
        )
    timestamp = now or datetime.now(timezone.utc)
    return BuildPlan(
        generated_at=timestamp.isoformat().replace("+00:00", "Z"),
        base=base,
        target=target,
        jobs=tuple(jobs),
    )


def resolve_base_kernel(config: Config) -> KernelRelease:
    identity = config.base_kernel
    if identity == "running":
        try:
            completed = subprocess.run(
                [*shlex.split(config.uname_command), "-r"],
                check=True,
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise ValueError(f"cannot determine running base kernel: {error}") from error
        identity = completed.stdout.strip()
    return KernelRelease.from_uname(identity)
