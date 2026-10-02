from __future__ import annotations

import fcntl
import hashlib
import inspect
import json
import re
import shlex
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from .config import Config
from .escalation import (
    SecurityCoverageError,
    escalate_security_gap,
    request_build_failure_review,
)
from .models import BuildJob, KernelRelease
from .packaging import package_name, package_name_from_nvra
from .planner import create_plan, resolve_base_kernel
from .publication import PublicationResult, publish_repository
from .runner import JobResult, run_job
from .sources import DnfRepositorySource, RepositorySnapshot
from .state import write_json_atomic


BuildFunction = Callable[..., JobResult]
PublishFunction = Callable[..., PublicationResult]


@dataclass(frozen=True)
class ReconcileResult:
    target: str
    built: int
    published: int
    covered: int
    no_work: int
    metadata_pending: int
    awaiting_signature: int = 0


def _empty_registry() -> dict[str, object]:
    return {
        "schema_version": 1,
        "family_releases": {},
        "jobs": {},
    }


def _read_registry(path: Path) -> dict[str, object]:
    if not path.exists():
        return _empty_registry()
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError("registry root must be an object")
    if value.get("schema_version") != 1:
        raise ValueError("unsupported registry schema")
    if not isinstance(value.get("family_releases"), dict):
        raise ValueError("registry family_releases must be an object")
    if not isinstance(value.get("jobs"), dict):
        raise ValueError("registry jobs must be an object")
    return value


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(moment: datetime) -> str:
    return moment.isoformat().replace("+00:00", "Z")


def _parse_iso(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if moment.tzinfo is None:
        return None
    return moment.astimezone(timezone.utc)


def _metadata_pending_error(
    *,
    job: BuildJob,
    snapshot: RepositorySnapshot,
    state_dir: Path,
    timeout_seconds: int,
    now: datetime,
) -> SecurityCoverageError:
    path = state_dir / "metadata-pending.json"
    signature = [job.base.nvra, job.target.nvra]
    previous: object = None
    try:
        previous = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        previous = None
    first_seen = None
    if isinstance(previous, dict) and previous.get("signature") == signature:
        first_seen = _parse_iso(previous.get("first_seen"))
    if first_seen is None or first_seen > now:
        first_seen = now
    age_seconds = max(0, int((now - first_seen).total_seconds()))

    target_notices = sorted(
        notice.advisory_id
        for notice in snapshot.notices
        if notice.kernel == job.target
    )
    security_kernels = {
        notice.kernel
        for notice in snapshot.notices
        if notice.kind == "security"
        and notice.kernel.same_family(job.base)
        and job.base < notice.kernel
        and (notice.kernel < job.target or notice.kernel == job.target)
    }
    cve_kernels = {
        advisory.kernel
        for advisory in snapshot.advisories
        if advisory.kernel.same_family(job.base)
    }
    missing_cve_releases = sorted(
        kernel.nvra for kernel in security_kernels - cve_kernels
    )
    if not target_notices:
        pending_reason = "missing-target-updateinfo"
        reason = (
            f"kernel {job.target.nvra} is available but has no updateinfo "
            "notice, so its security status cannot be determined"
        )
    else:
        pending_reason = "incomplete-security-cve-data"
        reason = (
            "security updateinfo has no complete CVE detail for: "
            + ", ".join(missing_cve_releases)
        )

    timed_out = age_seconds >= timeout_seconds
    failure_kind = (
        "repository-metadata-timeout"
        if timed_out
        else "repository-metadata-pending"
    )
    if timed_out:
        reason += (
            f"; metadata deadline exceeded after {age_seconds} seconds "
            f"(limit {timeout_seconds})"
        )
    record = {
        "schema_version": 1,
        "signature": signature,
        "base": job.base.nvra,
        "target": job.target.nvra,
        "first_seen": _iso(first_seen),
        "last_seen": _iso(now),
        "age_seconds": age_seconds,
        "timeout_seconds": timeout_seconds,
        "timed_out": timed_out,
        "pending_reason": pending_reason,
        "target_notices": target_notices,
        "missing_cve_releases": missing_cve_releases,
    }
    write_json_atomic(path, record)
    return SecurityCoverageError(
        reason,
        base=job.base,
        target=job.target,
        failure_stage="metadata",
        failure_kind=failure_kind,
        diagnostics={**record, "state_file": str(path)},
    )


def _job_signature(job: BuildJob) -> dict[str, object]:
    return {
        "base": job.base.nvra,
        "target": job.target.nvra,
        "cves": list(job.cves),
    }


def _entry_family(entry: dict[str, object]) -> str | None:
    family = entry.get("family")
    if isinstance(family, str) and family:
        return family
    signature = entry.get("signature")
    if isinstance(signature, dict) and isinstance(signature.get("base"), str):
        try:
            return package_name_from_nvra(str(signature["base"]))
        except ValueError:
            return None
    return None


def _within_grace(last_active: object, now: datetime, grace_seconds: int) -> bool:
    if not isinstance(last_active, str):
        return False
    try:
        moment = datetime.fromisoformat(last_active.replace("Z", "+00:00"))
    except ValueError:
        return False
    return (now - moment).total_seconds() <= grace_seconds


def _compute_pinned(
    registry: dict[str, object],
    plan_families: set[str],
    now: datetime,
    grace_seconds: int,
) -> list[Path]:
    """Pin the newest built release of every in-window or within-grace family.

    Superseded releases and families that have been out of the support window
    for longer than the grace period are dropped, bounding repository growth.
    """
    jobs = registry["jobs"]
    assert isinstance(jobs, dict)
    activity = registry.get("family_activity", {})
    if not isinstance(activity, dict):
        activity = {}
    newest: dict[str, tuple[int, Path]] = {}
    for entry in jobs.values():
        if not isinstance(entry, dict):
            continue
        if entry.get("status") == "awaiting-signature":
            # Not yet signed: must never be pinned into a published version.
            continue
        rpm = _registry_rpm(entry)
        if rpm is None:
            continue
        family = _entry_family(entry)
        if family is None:
            continue
        release = int(entry.get("rpm_release", 0))
        current = newest.get(family)
        if current is None or release > current[0]:
            newest[family] = (release, rpm)
    pinned: list[Path] = []
    for family, (_release, rpm) in sorted(newest.items()):
        if family in plan_families or _within_grace(
            activity.get(family), now, grace_seconds
        ):
            pinned.append(rpm)
    return pinned


def _registry_rpm(entry: dict[str, object]) -> Path | None:
    for key in ("published_rpm", "rpm"):
        value = entry.get(key)
        if isinstance(value, str) and Path(value).is_file():
            return Path(value)
    return None


def _allocate_release(
    registry: dict[str, object],
    job: BuildJob,
) -> tuple[dict[str, object], int]:
    jobs = registry["jobs"]
    families = registry["family_releases"]
    assert isinstance(jobs, dict)
    assert isinstance(families, dict)
    signature = _job_signature(job)
    existing = jobs.get(job.job_id)
    if isinstance(existing, dict) and existing.get("signature") == signature:
        return existing, int(existing["rpm_release"])
    family = package_name(job)
    release = int(families.get(family, 0)) + 1
    families[family] = release
    entry: dict[str, object] = {
        "signature": signature,
        "family": family,
        "rpm_release": release,
        "status": "allocated",
    }
    jobs[job.job_id] = entry
    return entry, release


def _published_coverage(
    registry: dict[str, object],
    job: BuildJob,
) -> tuple[str, dict[str, object]] | None:
    jobs = registry["jobs"]
    assert isinstance(jobs, dict)
    required = set(job.cves)
    for job_id, entry in jobs.items():
        if job_id == job.job_id:
            continue
        if not isinstance(entry, dict) or entry.get("status") != "published":
            continue
        signature = entry.get("signature")
        rpm = _registry_rpm(entry)
        if (
            not isinstance(signature, dict)
            or signature.get("base") != job.base.nvra
            or not isinstance(signature.get("cves"), list)
            or rpm is None
        ):
            continue
        published_cves = {
            str(cve)
            for cve in signature["cves"]
        }
        if required <= published_cves:
            return str(job_id), entry
    return None


def _latest_published_security_coverage(
    registry: dict[str, object], job: BuildJob
) -> tuple[set[str], dict[str, object] | None]:
    jobs = registry["jobs"]
    assert isinstance(jobs, dict)
    latest: tuple[int, dict[str, object]] | None = None
    for entry in jobs.values():
        if not isinstance(entry, dict) or entry.get("status") != "published":
            continue
        signature = entry.get("signature")
        if (
            not isinstance(signature, dict)
            or signature.get("base") != job.base.nvra
            or not isinstance(signature.get("cves"), list)
            or _registry_rpm(entry) is None
        ):
            continue
        candidate = (int(entry.get("rpm_release", 0)), entry)
        if latest is None or candidate[0] > latest[0]:
            latest = candidate
    if latest is None:
        return set(), None
    signature = latest[1]["signature"]
    assert isinstance(signature, dict)
    cves = signature["cves"]
    assert isinstance(cves, list)
    return {str(cve) for cve in cves}, latest[1]


_CHANGED_SECTION = re.compile(
    r"ERROR: changed section (?P<section>\S+) not selected for inclusion"
)
_UNSUPPORTED_OBJECT = re.compile(
    r"ERROR: (?P<object>\S+\.o): \d+ unsupported section change\(s\)"
)
_TERMINAL_BUILD_FAILURE_KINDS = frozenset({"unsupported-elf-section"})


def _build_failure_diagnostics(
    *, job: BuildJob, workspace: Path, registry: dict[str, object], error: Exception
) -> tuple[tuple[str, ...], str, dict[str, object]]:
    published_cves, published_entry = _latest_published_security_coverage(
        registry, job
    )
    uncovered = tuple(sorted(set(job.cves) - published_cves))
    log_candidates = (
        workspace / "kpatch-cache" / "build.log",
        workspace / "build.log",
    )
    log = next((path for path in log_candidates if path.is_file()), None)
    unsupported: list[dict[str, object]] = []
    pending_sections: list[str] = []
    if log is not None:
        with log.open(encoding="utf-8", errors="replace") as handle:
            for line in handle:
                if "Extracting new and modified ELF sections" in line:
                    unsupported.clear()
                    pending_sections.clear()
                section_match = _CHANGED_SECTION.search(line)
                if section_match:
                    pending_sections.append(section_match.group("section"))
                    continue
                object_match = _UNSUPPORTED_OBJECT.search(line)
                if object_match:
                    unsupported.append(
                        {
                            "object": object_match.group("object"),
                            "sections": pending_sections[-8:],
                        }
                    )
                    pending_sections.clear()

    selection_path = workspace / "selection.json"
    selected_patches: list[dict[str, object]] = []
    if selection_path.is_file():
        try:
            selection = json.loads(selection_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            selection = None
        if isinstance(selection, dict):
            raw_patches = selection.get("selected_patches")
            if isinstance(raw_patches, list):
                for value in raw_patches:
                    if not isinstance(value, dict):
                        continue
                    patch_cves = value.get("cves")
                    if not isinstance(patch_cves, list):
                        continue
                    matching = sorted(set(map(str, patch_cves)) & set(uncovered))
                    if matching and isinstance(value.get("patch"), str):
                        selected_patches.append(
                            {"patch": value["patch"], "cves": matching}
                        )

    failure_kind = (
        "unsupported-elf-section" if unsupported else "livepatch-build-failure"
    )
    object_names = ", ".join(
        str(value["object"]) for value in unsupported
    )
    if object_names:
        reason = (
            "kpatch cannot safely represent required security fixes: "
            f"unsupported ELF section changes in {object_names}"
        )
    else:
        reason = f"livepatch build failed: {error}"

    severity = {
        decision.cve: decision.severity
        for decision in job.cve_policy_decisions
        if decision.cve in uncovered
    }
    published: dict[str, object] | None = None
    if published_entry is not None:
        signature = published_entry.get("signature")
        published = {
            "target": (
                signature.get("target") if isinstance(signature, dict) else None
            ),
            "cves": sorted(published_cves),
            "rpm_release": published_entry.get("rpm_release"),
            "rpm": str(_registry_rpm(published_entry)),
        }
    diagnostics: dict[str, object] = {
        "job_id": job.job_id,
        "backend": job.backend,
        "error": str(error),
        "uncovered_cve_severity": severity,
        "unsupported_changes": unsupported,
        "selected_patches": selected_patches,
        "last_published_coverage": published,
        "evidence": {
            "workspace": str(workspace),
            "selection_manifest": str(selection_path),
            "aggregate_patch": str(workspace / "source.patch"),
            "build_log": str(log) if log is not None else None,
        },
    }
    return uncovered, failure_kind, {"reason": reason, **diagnostics}


def _target_is_at_or_after(failed_target: object, job: BuildJob) -> bool:
    if not isinstance(failed_target, str):
        return False
    try:
        return KernelRelease.from_uname(failed_target) <= job.target
    except ValueError:
        return False


def _terminal_build_gap(
    registry: dict[str, object], job: BuildJob, state_dir: Path
) -> dict[str, object] | None:
    """Find a proven same-base livepatchability gap inherited by ``job``.

    Only explicitly classified, deterministic kpatch limitations are terminal.
    Generic build failures remain retryable.  The escalation-file fallback
    recognises failures recorded before terminal metadata was added to the
    registry, provided the referenced failed job is still retained.
    """
    required = set(job.cves)
    published_cves, _published_entry = _latest_published_security_coverage(
        registry, job
    )
    jobs = registry["jobs"]
    assert isinstance(jobs, dict)
    candidates: list[dict[str, object]] = []
    for failed_job_id, entry in jobs.items():
        if not isinstance(entry, dict) or entry.get("status") != "failed":
            continue
        signature = entry.get("signature")
        failure_kind = entry.get("failure_kind")
        uncovered = entry.get("uncovered_cves")
        if (
            not isinstance(signature, dict)
            or signature.get("base") != job.base.nvra
            or failure_kind not in _TERMINAL_BUILD_FAILURE_KINDS
            or not isinstance(uncovered, list)
            or not _target_is_at_or_after(signature.get("target"), job)
        ):
            continue
        terminal_cves = {str(cve) for cve in uncovered} - published_cves
        inherited = sorted(required & terminal_cves if required else terminal_cves)
        if inherited:
            candidates.append(
                {
                    "failed_job_id": str(failed_job_id),
                    "failed_target": signature.get("target"),
                    "failure_kind": failure_kind,
                    "cves": inherited,
                    "diagnostics": entry.get("failure_diagnostics", {}),
                    "source": "registry",
                }
            )

    if not candidates:
        escalation_path = state_dir / "escalation.json"
        try:
            report = json.loads(escalation_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            report = None
        if isinstance(report, dict):
            diagnostics = report.get("diagnostics")
            failed_job_id = (
                diagnostics.get("job_id")
                if isinstance(diagnostics, dict)
                else None
            )
            failed_entry = jobs.get(failed_job_id)
            report_cves = report.get("cves")
            if (
                report.get("failure_stage") == "build"
                and report.get("failure_kind")
                in _TERMINAL_BUILD_FAILURE_KINDS
                and report.get("base") == job.base.nvra
                and isinstance(failed_job_id, str)
                and isinstance(failed_entry, dict)
                and failed_entry.get("status") == "failed"
                and isinstance(report_cves, list)
                and _target_is_at_or_after(report.get("target"), job)
            ):
                terminal_cves = {
                    str(cve) for cve in report_cves
                } - published_cves
                inherited = sorted(
                    required & terminal_cves if required else terminal_cves
                )
                if inherited:
                    candidates.append(
                        {
                            "failed_job_id": failed_job_id,
                            "failed_target": report.get("target"),
                            "failure_kind": report.get("failure_kind"),
                            "cves": inherited,
                            "diagnostics": diagnostics,
                            "source": "escalation-record",
                        }
                    )

    if not candidates:
        return None
    return max(
        candidates,
        key=lambda value: KernelRelease.from_uname(str(value["failed_target"])),
    )


def _terminal_gap_error(
    job: BuildJob, terminal_gap: dict[str, object]
) -> SecurityCoverageError:
    gap_cves = tuple(str(cve) for cve in terminal_gap["cves"])
    original_diagnostics = terminal_gap.get("diagnostics")
    severity = {
        decision.cve: decision.severity
        for decision in job.cve_policy_decisions
        if decision.cve in gap_cves
    }
    if not severity and isinstance(original_diagnostics, dict):
        original_severity = original_diagnostics.get("uncovered_cve_severity")
        if isinstance(original_severity, dict):
            severity = {
                str(cve): str(value)
                for cve, value in original_severity.items()
                if str(cve) in gap_cves
            }
    return SecurityCoverageError(
        "required security fixes are already proven unpatchable "
        f"for base {job.base.nvra}; refusing a redundant build",
        base=job.base,
        target=job.target,
        cves=gap_cves,
        failure_stage="build",
        failure_kind="inherited-terminal-build-gap",
        diagnostics={
            "build_skipped": True,
            "failed_job_id": terminal_gap["failed_job_id"],
            "failed_target": terminal_gap["failed_target"],
            "original_failure_kind": terminal_gap["failure_kind"],
            "uncovered_cve_severity": severity,
            "source": terminal_gap["source"],
            "original_diagnostics": (
                original_diagnostics
                if isinstance(original_diagnostics, dict)
                else {}
            ),
        },
    )


def _backfill_patch_digests(
    registry: dict[str, object], work_root: Path
) -> bool:
    """Migrate retained pre-digest jobs without changing published artefacts."""
    changed = False
    jobs = registry["jobs"]
    assert isinstance(jobs, dict)
    for job_id, entry in jobs.items():
        if (
            not isinstance(entry, dict)
            or entry.get("status") != "published"
            or isinstance(entry.get("patch_sha256"), str)
        ):
            continue
        patch = work_root / str(job_id) / "source.patch"
        if not patch.is_file():
            continue
        entry["patch_sha256"] = hashlib.sha256(patch.read_bytes()).hexdigest()
        changed = True
    return changed


def _published_effective_coverage(
    registry: dict[str, object], job: BuildJob, patch_sha256: str
) -> tuple[str, dict[str, object]] | None:
    jobs = registry["jobs"]
    assert isinstance(jobs, dict)
    for job_id, entry in jobs.items():
        if not isinstance(entry, dict) or entry.get("status") != "published":
            continue
        signature = entry.get("signature")
        if (
            isinstance(signature, dict)
            and signature.get("base") == job.base.nvra
            and entry.get("patch_sha256") == patch_sha256
            and _registry_rpm(entry) is not None
        ):
            return str(job_id), entry
    return None


def _recalculate_family_release(
    registry: dict[str, object], family: str
) -> None:
    jobs = registry["jobs"]
    families = registry["family_releases"]
    assert isinstance(jobs, dict)
    assert isinstance(families, dict)
    releases = [
        int(entry.get("rpm_release", 0))
        for entry in jobs.values()
        if isinstance(entry, dict)
        and _entry_family(entry) == family
        and entry.get("status") != "covered"
    ]
    families[family] = max(releases, default=0)


def _run_rpm_command(path: Path, template: str, description: str) -> None:
    if not template:
        return
    command = shlex.split(template.format(rpm=str(path)))
    if not command:
        raise ValueError(f"RPM {description} command is empty")
    try:
        subprocess.run(
            command,
            check=True,
            timeout=300,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise ValueError(f"RPM {description} failed: {error}") from error


def _rpm_has_signature(path: Path, rpm_command: str) -> bool:
    try:
        completed = subprocess.run(
            [
                rpm_command,
                "-qp",
                "--qf",
                (
                    "%{RSAHEADER:pgpsig}\n"
                    "%{DSAHEADER:pgpsig}\n"
                    "%{SIGPGP:pgpsig}\n"
                    "%{SIGGPG:pgpsig}\n"
                ),
                str(path),
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise ValueError(f"RPM signature-header query failed: {error}") from error
    return any(
        line.strip() and line.strip() != "(none)"
        for line in completed.stdout.splitlines()
    )


def _sign_and_verify_rpm(
    path: Path,
    sign_template: str,
    verify_template: str,
    rpm_command: str,
) -> None:
    if not verify_template:
        raise ValueError("RPM signature verification command is empty")
    _run_rpm_command(path, sign_template, "signing")
    _run_rpm_command(path, verify_template, "signature verification")
    if not _rpm_has_signature(path, rpm_command):
        raise ValueError("RPM has no OpenPGP signature header after signing")


def _promote_signed_entries(registry: dict[str, object], config: Config) -> int:
    """Promote 'awaiting-signature' entries once an operator has manually
    signed the RPM in place.

    This is the manual-signing counterpart to `_sign_and_verify_rpm`: when
    `require_rpm_signing` is set but no `rpm_sign_command_template` is
    configured, `reconcile_repository` builds and packages a job as normal
    but holds it as 'awaiting-signature' rather than publishing it unsigned.
    An operator signs the RPM at its registry-recorded path out of band
    (e.g. `rpm --addsign`); the next reconcile run notices the signature
    here and hands the entry back to the ordinary 'built' -> publish path.
    """
    jobs = registry["jobs"]
    assert isinstance(jobs, dict)
    promoted = 0
    for entry in jobs.values():
        if not isinstance(entry, dict) or entry.get("status") != "awaiting-signature":
            continue
        rpm = _registry_rpm(entry)
        if rpm is None or not rpm.is_file():
            continue
        if not _rpm_has_signature(rpm, config.rpm_command):
            continue
        if config.rpm_verify_command_template:
            _run_rpm_command(
                rpm, config.rpm_verify_command_template, "signature verification"
            )
        entry["status"] = "built"
        entry.pop("error", None)
        promoted += 1
    return promoted


def reconcile_repository(
    *,
    config: Config,
    state_dir: Path,
    work_root: Path,
    repository_root: Path,
    snapshot: RepositorySnapshot | None = None,
    build_function: BuildFunction = run_job,
    publish_function: PublishFunction = publish_repository,
) -> ReconcileResult:
    state_dir.mkdir(parents=True, exist_ok=True)
    lock_path = state_dir / "reconcile.lock"
    with lock_path.open("a+") as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ValueError("another reconcile run is active") from error
        live_snapshot = snapshot
        base_kernel = resolve_base_kernel(config)
        if live_snapshot is None:
            try:
                live_snapshot = DnfRepositorySource(
                    config.dnf_command,
                    config.kernel_package,
                    config.architecture,
                    config.cve_severity_url_template,
                    base_kernel,
                ).collect()
            except SecurityCoverageError as error:
                # A required in-interval security fix cannot be classified, so
                # no livepatch can be produced. Record and signal the gap (and
                # hand off to operator automation if configured), then fail
                # loudly — publish nothing and let the timer alert.
                escalate_security_gap(
                    config=config, state_dir=state_dir, error=error
                )
                raise
        plan = create_plan(
            live_snapshot,
            architecture=config.architecture,
            distro_stream=config.distro_stream,
            base=base_kernel,
            eligible_cve_severities=config.eligible_cve_severities,
        )
        write_json_atomic(state_dir / "snapshot.json", live_snapshot.to_dict())
        write_json_atomic(state_dir / "plan.json", plan.to_dict())
        metadata_pending_path = state_dir / "metadata-pending.json"
        if not any(job.status == "metadata-pending" for job in plan.jobs):
            metadata_pending_path.unlink(missing_ok=True)
        registry_path = state_dir / "registry.json"
        registry = _read_registry(registry_path)
        if _promote_signed_entries(registry, config):
            write_json_atomic(registry_path, registry)
        if _backfill_patch_digests(registry, work_root):
            write_json_atomic(registry_path, registry)
        now = _now()
        plan_families = {package_name(job) for job in plan.jobs}
        activity = registry.setdefault("family_activity", {})
        assert isinstance(activity, dict)
        # A registry created before family lifecycle tracking has no demotion
        # timestamps. Start its grace period now rather than retiring every
        # historical family immediately on the first upgraded reconcile.
        for entry in registry["jobs"].values():
            if isinstance(entry, dict):
                family = _entry_family(entry)
                if family is not None:
                    activity.setdefault(family, _iso(now))
        for family in plan_families:
            activity[family] = _iso(now)
        write_json_atomic(registry_path, registry)
        built_count = 0
        covered = 0
        no_work = 0
        metadata_pending = 0
        pending_builds: list[
            tuple[BuildJob, dict[str, object], int]
        ] = []
        completed_builds: list[
            tuple[BuildJob, dict[str, object], Path]
        ] = []
        for job in plan.jobs:
            terminal_gap = _terminal_build_gap(registry, job, state_dir)
            if terminal_gap is not None and job.status != "planned":
                coverage_error = _terminal_gap_error(job, terminal_gap)
                escalate_security_gap(
                    config=config, state_dir=state_dir, error=coverage_error
                )
                raise coverage_error
            if job.status == "no-work":
                no_work += 1
                continue
            if job.status == "metadata-pending":
                metadata_pending += 1
                coverage_error = _metadata_pending_error(
                    job=job,
                    snapshot=live_snapshot,
                    state_dir=state_dir,
                    timeout_seconds=config.metadata_pending_timeout_seconds,
                    now=now,
                )
                escalate_security_gap(
                    config=config, state_dir=state_dir, error=coverage_error
                )
                raise coverage_error
            coverage = _published_coverage(registry, job)
            if coverage is not None:
                covered_by, published_entry = coverage
                jobs = registry["jobs"]
                assert isinstance(jobs, dict)
                jobs[job.job_id] = {
                    "signature": _job_signature(job),
                    "family": package_name(job),
                    "rpm_release": published_entry["rpm_release"],
                    "rpm": str(_registry_rpm(published_entry)),
                    "status": "covered",
                    "covered_by": covered_by,
                }
                write_json_atomic(registry_path, registry)
                covered += 1
                continue
            if terminal_gap is not None:
                coverage_error = _terminal_gap_error(job, terminal_gap)
                escalate_security_gap(
                    config=config, state_dir=state_dir, error=coverage_error
                )
                raise coverage_error
            if config.rpm_sign_command_template and not config.rpm_verify_command_template:
                # An automatic signer without a verifier can't prove its own
                # output is trustworthy -- fail before burning a build on it.
                # No sign template at all is a supported, deliberate
                # configuration: require_rpm_signing then holds completed
                # builds as 'awaiting-signature' for manual signing instead.
                raise ValueError(
                    "RPM signing command is configured without a "
                    "verification command template"
                )
            entry, rpm_release = _allocate_release(registry, job)
            if (
                entry.get("status") in {"built", "published"}
                and _registry_rpm(entry) is not None
            ):
                continue
            completed_rpm = _registry_rpm(entry)
            if entry.get("status") == "build-complete" and completed_rpm:
                completed_builds.append((job, entry, completed_rpm))
                continue
            write_json_atomic(registry_path, registry)
            pending_builds.append((job, entry, rpm_release))

        # The running-builder profile has one exact base and at most one
        # cumulative target, so any pending jobs are built one at a time. There
        # is no build concurrency to orchestrate. Per-job workspace isolation
        # (a private kpatch CACHEDIR and a writable source copy) still matters
        # for a single build: kpatch-build truncates its cache build.log and
        # patches its --sourcedir in place, so it must never run against the
        # shared cache or the immutable prepared source.
        build_errors: list[tuple[BuildJob, Exception]] = []
        for job, entry, rpm_release in pending_builds:
            try:
                build_options: dict[str, object] = {
                    "config": config,
                    "work_root": work_root,
                    "rpm_release": rpm_release,
                }
                if "reusable_patch_sha256" in inspect.signature(
                    build_function
                ).parameters:
                    jobs = registry["jobs"]
                    assert isinstance(jobs, dict)
                    build_options["reusable_patch_sha256"] = frozenset(
                        str(candidate["patch_sha256"])
                        for candidate in jobs.values()
                        if isinstance(candidate, dict)
                        and candidate.get("status") == "published"
                        and isinstance(candidate.get("patch_sha256"), str)
                        and isinstance(candidate.get("signature"), dict)
                        and candidate["signature"].get("base") == job.base.nvra
                    )
                result = build_function(job, **build_options)
                if result.status == "effective-no-change":
                    if result.patch_sha256 is None:
                        raise ValueError(
                            f"job {job.job_id} returned no effective patch digest"
                        )
                    effective = _published_effective_coverage(
                        registry, job, result.patch_sha256
                    )
                    if effective is None:
                        raise ValueError(
                            f"job {job.job_id} reported unchanged patch content "
                            "without a matching published module"
                        )
                    covered_by, published_entry = effective
                    published_rpm = _registry_rpm(published_entry)
                    assert published_rpm is not None
                    entry.update(
                        {
                            "status": "covered",
                            "covered_by": covered_by,
                            "rpm_release": published_entry["rpm_release"],
                            "rpm": str(published_rpm),
                            "patch_sha256": result.patch_sha256,
                            "effective_no_change": True,
                        }
                    )
                    _recalculate_family_release(registry, package_name(job))
                    covered += 1
                    write_json_atomic(registry_path, registry)
                    continue
                if result.rpm is None:
                    raise ValueError(f"job {job.job_id} returned no RPM")
                rpm = Path(result.rpm)
                if not rpm.is_file():
                    raise ValueError(
                        f"job {job.job_id} returned a missing RPM: {rpm}"
                    )
                entry["status"] = "build-complete"
                entry["rpm"] = str(rpm)
                if result.patch_sha256 is not None:
                    entry["patch_sha256"] = result.patch_sha256
                for key in (
                    "error",
                    "failure_stage",
                    "failure_kind",
                    "uncovered_cves",
                    "terminal_for_base",
                    "failure_diagnostics",
                ):
                    entry.pop(key, None)
                completed_builds.append((job, entry, rpm))
                built_count += 1
            except Exception as error:
                entry["status"] = "failed"
                entry["error"] = str(error)
                build_errors.append((job, error))
            write_json_atomic(registry_path, registry)

        if build_errors:
            details = "; ".join(
                f"{job.job_id}: {error}" for job, error in build_errors
            )
            failed_job, build_error = build_errors[0]
            uncovered, failure_kind, diagnostics = _build_failure_diagnostics(
                job=failed_job,
                workspace=work_root / failed_job.job_id,
                registry=registry,
                error=build_error,
            )
            reason = str(diagnostics.pop("reason"))
            if len(build_errors) > 1:
                diagnostics["all_build_failures"] = details
            coverage_error = SecurityCoverageError(
                reason,
                base=failed_job.base,
                target=failed_job.target,
                cves=uncovered,
                failure_stage="build",
                failure_kind=failure_kind,
                diagnostics=diagnostics,
            )
            jobs = registry["jobs"]
            assert isinstance(jobs, dict)
            failed_entry = jobs.get(failed_job.job_id)
            if isinstance(failed_entry, dict):
                failed_entry["failure_stage"] = "build"
                failed_entry["failure_kind"] = failure_kind
                failed_entry["uncovered_cves"] = list(uncovered)
                failed_entry["terminal_for_base"] = (
                    failure_kind in _TERMINAL_BUILD_FAILURE_KINDS
                )
                failed_entry["failure_diagnostics"] = diagnostics
                write_json_atomic(registry_path, registry)
            terminal = failure_kind in _TERMINAL_BUILD_FAILURE_KINDS
            review = (
                {"under_review": False, "expired": True}
                if terminal
                else request_build_failure_review(
                    config=config, state_dir=state_dir, error=coverage_error, now=now
                )
            )
            if not review["under_review"]:
                escalate_security_gap(
                    config=config, state_dir=state_dir, error=coverage_error
                )
            raise coverage_error

        if completed_builds:
            repository_root.mkdir(parents=True, exist_ok=True)
            signing_lock_path = repository_root / "signing.lock"
            with signing_lock_path.open("a+") as signing_lock:
                fcntl.flock(signing_lock.fileno(), fcntl.LOCK_EX)
                for job, entry, rpm in completed_builds:
                    try:
                        if config.rpm_sign_command_template:
                            _sign_and_verify_rpm(
                                rpm,
                                config.rpm_sign_command_template,
                                config.rpm_verify_command_template,
                                config.rpm_command,
                            )
                            entry["status"] = "built"
                        elif config.require_rpm_signing:
                            # Built and packaged, but signing is manual: hold
                            # here until an operator signs the RPM in place
                            # and a later reconcile run promotes it (see
                            # _promote_signed_entries).
                            entry["status"] = "awaiting-signature"
                        else:
                            entry["status"] = "built"
                        entry.pop("error", None)
                    except Exception as error:
                        entry["status"] = "failed"
                        entry["error"] = str(error)
                        write_json_atomic(registry_path, registry)
                        raise ValueError(
                            f"RPM finalisation failed for {job.job_id}: {error}"
                        ) from error
                    write_json_atomic(registry_path, registry)
        jobs = registry["jobs"]
        assert isinstance(jobs, dict)
        ready = [
            Path(entry["rpm"])
            for entry in jobs.values()
            if isinstance(entry, dict)
            and entry.get("status") == "built"
            and isinstance(entry.get("rpm"), str)
            and Path(entry["rpm"]).is_file()
        ]
        published = 0
        pinned = tuple(
            _compute_pinned(
                registry,
                plan_families,
                now,
                config.repository_family_grace_seconds,
            )
        )
        desired_pin_names = sorted(path.name for path in pinned)
        previous_pin_names = registry.get("published_pin_names", [])
        pins_changed = previous_pin_names != desired_pin_names
        if ready or pins_changed:
            profile_id = config.repository_profile or (
                f"{config.distro_stream}-{config.architecture}"
            )
            publication = publish_function(
                repository_root,
                ready,
                createrepo_command=config.createrepo_command,
                profile_id=profile_id,
                pinned_rpms=pinned,
                retain_versions=config.repository_retain_versions,
                minimum_age_seconds=config.repository_minimum_age_seconds,
            )
            ready_values = {str(path) for path in ready}
            for entry in jobs.values():
                if not isinstance(entry, dict):
                    continue
                existing = _registry_rpm(entry)
                if existing is not None:
                    stable = publication.objects_by_name.get(existing.name)
                    if stable is not None:
                        entry["published_rpm"] = str(stable.resolve())
                if (
                    entry.get("status") == "built"
                    and entry.get("rpm") in ready_values
                ):
                    entry["status"] = "published"
                    source = Path(str(entry["rpm"]))
                    published_rpm = publication.objects_by_name.get(source.name)
                    if published_rpm is None:
                        raise ValueError(
                            f"published repository omitted RPM: {source.name}"
                        )
                    entry["published_rpm"] = str(published_rpm.resolve())
                    published += 1
            registry["published_pin_names"] = desired_pin_names
            write_json_atomic(registry_path, registry)
        awaiting_signature = sum(
            1
            for entry in jobs.values()
            if isinstance(entry, dict) and entry.get("status") == "awaiting-signature"
        )
        return ReconcileResult(
            target=plan.target.nvra if plan.target is not None else plan.base.nvra,
            built=built_count,
            published=published,
            covered=covered,
            no_work=no_work,
            metadata_pending=metadata_pending,
            awaiting_signature=awaiting_signature,
        )
