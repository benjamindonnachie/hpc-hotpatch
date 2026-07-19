from __future__ import annotations

import fcntl
import hashlib
import inspect
import json
import shlex
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from .config import Config
from .escalation import SecurityCoverageError, escalate_security_gap
from .models import BuildJob
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
    signatures = {
        line.strip()
        for line in completed.stdout.splitlines()
        if line.strip() and line.strip() != "(none)"
    }
    if not signatures:
        raise ValueError("RPM has no OpenPGP signature header after signing")


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
        registry_path = state_dir / "registry.json"
        registry = _read_registry(registry_path)
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
            if job.status == "no-work":
                no_work += 1
                continue
            if job.status == "metadata-pending":
                metadata_pending += 1
                continue
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
            if (
                config.require_rpm_signing
                and (
                    not config.rpm_sign_command_template
                    or not config.rpm_verify_command_template
                )
            ):
                raise ValueError(
                    "RPM signing is required but its signing or verification "
                    "command template is empty"
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
        build_errors: list[tuple[str, Exception]] = []
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
                entry.pop("error", None)
                completed_builds.append((job, entry, rpm))
                built_count += 1
            except Exception as error:
                entry["status"] = "failed"
                entry["error"] = str(error)
                build_errors.append((job.job_id, error))
            write_json_atomic(registry_path, registry)

        if build_errors:
            details = "; ".join(
                f"{job_id}: {error}" for job_id, error in build_errors
            )
            raise ValueError(f"one or more livepatch builds failed: {details}")

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
        return ReconcileResult(
            target=plan.target.nvra if plan.target is not None else plan.base.nvra,
            built=built_count,
            published=published,
            covered=covered,
            no_work=no_work,
            metadata_pending=metadata_pending,
        )
