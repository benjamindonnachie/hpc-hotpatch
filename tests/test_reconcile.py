from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import shlex
import shutil
import tempfile
import threading
import time
import unittest
from unittest import mock

from livepatch_repo.config import Config
from livepatch_repo.escalation import SecurityCoverageError
from livepatch_repo.models import (
    AdvisoryFix,
    BuildJob,
    KernelRelease,
    RepositoryNotice,
)
from livepatch_repo.packaging import package_name
from livepatch_repo.reconcile import (
    _build_failure_diagnostics,
    _compute_pinned,
    reconcile_repository,
)
from livepatch_repo.publication import PublicationResult, publish_repository
from livepatch_repo.runner import JobResult
from livepatch_repo.sources import RepositorySnapshot


class TestPinComputation(unittest.TestCase):
    def _entry(self, tmp: Path, family: str, release: int, name: str) -> dict:
        rpm = tmp / name
        rpm.write_bytes(name.encode())
        return {
            "family": family,
            "rpm_release": release,
            "status": "published",
            "published_rpm": str(rpm),
        }

    def test_keeps_only_newest_release_per_in_window_family(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            tmp = Path(temporary)
            family = "kpatch-patch-5_14_0-687_24_1"
            registry = {
                "jobs": {
                    "a": self._entry(tmp, family, 1, "old.rpm"),
                    "b": self._entry(tmp, family, 2, "new.rpm"),
                },
                "family_activity": {},
            }
            pinned = _compute_pinned(
                registry, {family}, datetime.now(timezone.utc), 1209600
            )
            self.assertEqual([path.name for path in pinned], ["new.rpm"])

    def test_obsolete_family_is_kept_within_grace_and_dropped_after(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            tmp = Path(temporary)
            family = "kpatch-patch-5_14_0-600_1_1"
            now = datetime.now(timezone.utc)
            registry = {
                "jobs": {"a": self._entry(tmp, family, 3, "aged.rpm")},
                "family_activity": {
                    family: (now - timedelta(days=5)).isoformat().replace(
                        "+00:00", "Z"
                    )
                },
            }
            within = _compute_pinned(registry, set(), now, 14 * 86400)
            self.assertEqual([path.name for path in within], ["aged.rpm"])
            expired = _compute_pinned(registry, set(), now, 3 * 86400)
            self.assertEqual(expired, [])


class TestReconcile(unittest.TestCase):
    def setUp(self) -> None:
        self.base = KernelRelease(
            "kernel-core", "0", "5.14.0", "687.24.1.el9_8", "x86_64"
        )
        self.target = KernelRelease(
            "kernel-core", "0", "5.14.0", "687.26.1.el9_8", "x86_64"
        )
        self.snapshot = RepositorySnapshot(
            (self.base, self.target),
            (AdvisoryFix("CVE-2026-12345", self.target, "Important"),),
            (
                RepositoryNotice("ALSA-2026:10000", "security", self.target),
            ),
        )
        self.config = Config(
            dnf_command="dnf",
            kernel_package="kernel-core",
            architecture="x86_64",
            distro_stream="el9_8",
            base_kernel=self.base.nvra,
            selector_command_template="selector",
            kpatch_build_command="kpatch-build",
            klp_build_command_template="",
            modinfo_command="modinfo",
            rpmbuild_command="rpmbuild",
        )

    def test_build_failure_reports_only_newly_uncovered_cves(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rpm = root / "published.rpm"
            rpm.write_bytes(b"rpm")
            job = BuildJob(
                self.base,
                self.target,
                ("CVE-2026-12345", "CVE-2026-43499"),
                "planned",
                "kpatch-build",
            )
            registry = {
                "jobs": {
                    "published": {
                        "status": "published",
                        "rpm_release": 3,
                        "published_rpm": str(rpm),
                        "signature": {
                            "base": self.base.nvra,
                            "target": "5.14.0-687.25.1.el9_8.x86_64",
                            "cves": ["CVE-2026-12345"],
                        },
                    }
                }
            }
            workspace = root / job.job_id
            cache = workspace / "kpatch-cache"
            cache.mkdir(parents=True)
            (cache / "build.log").write_text(
                "Extracting new and modified ELF sections\n"
                "ERROR: changed section .sched.text not selected for inclusion\n"
                "ERROR: changed section .rela.sched.text not selected for inclusion\n"
                "ERROR: kernel/locking/rtmutex_api.o: 2 unsupported section change(s)\n",
                encoding="utf-8",
            )
            (workspace / "selection.json").write_text(
                json.dumps(
                    {
                        "selected_patches": [
                            {
                                "patch": "1766-rtmutex.patch",
                                "cves": ["CVE-2026-43499"],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            cves, kind, diagnostics = _build_failure_diagnostics(
                job=job,
                workspace=workspace,
                registry=registry,
                error=ValueError("kpatch failed"),
            )

            self.assertEqual(cves, ("CVE-2026-43499",))
            self.assertEqual(kind, "unsupported-elf-section")
            self.assertEqual(
                diagnostics["unsupported_changes"],
                [
                    {
                        "object": "kernel/locking/rtmutex_api.o",
                        "sections": [".sched.text", ".rela.sched.text"],
                    }
                ],
            )
            self.assertEqual(
                diagnostics["selected_patches"],
                [{"patch": "1766-rtmutex.patch", "cves": ["CVE-2026-43499"]}],
            )
            self.assertEqual(
                diagnostics["last_published_coverage"]["rpm_release"], 3
            )

    def test_successful_job_is_not_rebuilt_on_next_reconcile(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            releases: list[int] = []
            publications: list[tuple[str, ...]] = []

            def build(job, *, config, work_root, rpm_release):
                releases.append(rpm_release)
                rpm = work_root / f"result-{rpm_release}.rpm"
                rpm.parent.mkdir(parents=True, exist_ok=True)
                rpm.write_bytes(b"rpm")
                return JobResult(job.job_id, "built", str(rpm))

            def publish(repository_root, rpms, **kwargs):
                publications.append(tuple(path.name for path in rpms))
                objects = repository_root / "objects"
                objects.mkdir(parents=True, exist_ok=True)
                result = {}
                for rpm in rpms:
                    target = objects / rpm.name
                    shutil.copy2(rpm, target)
                    result[rpm.name] = target
                return PublicationResult(
                    repository_root / "current", result, (), ()
                )

            first = reconcile_repository(
                config=self.config,
                state_dir=root / "state",
                work_root=root / "work",
                repository_root=root / "repo",
                snapshot=self.snapshot,
                build_function=build,
                publish_function=publish,
            )
            second = reconcile_repository(
                config=self.config,
                state_dir=root / "state",
                work_root=root / "work",
                repository_root=root / "repo",
                snapshot=self.snapshot,
                build_function=build,
                publish_function=publish,
            )
            self.assertEqual((first.built, first.published), (1, 1))
            self.assertEqual((second.built, second.published), (0, 0))
            self.assertEqual(second.covered, 0)
            self.assertEqual(releases, [1])
            self.assertEqual(publications, [("result-1.rpm",)])
            registry = json.loads(
                (root / "state" / "registry.json").read_text(encoding="utf-8")
            )
            entry = next(iter(registry["jobs"].values()))
            self.assertEqual(entry["status"], "published")
            self.assertNotIn("covered_by", entry)

    def test_identical_effective_patch_reuses_published_module(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first_target = KernelRelease(
                "kernel-core", "0", "5.14.0", "687.25.1.el9_8", "x86_64"
            )
            first_snapshot = RepositorySnapshot(
                (self.base, first_target),
                (AdvisoryFix("CVE-2026-11111", first_target, "Important"),),
                (RepositoryNotice("ALSA-2026:11111", "security", first_target),),
            )
            second_snapshot = RepositorySnapshot(
                (self.base, first_target, self.target),
                (
                    AdvisoryFix("CVE-2026-11111", first_target, "Important"),
                    AdvisoryFix("CVE-2026-22222", self.target, "Important"),
                ),
                (
                    RepositoryNotice("ALSA-2026:11111", "security", first_target),
                    RepositoryNotice("ALSA-2026:22222", "security", self.target),
                ),
            )
            patch_sha256 = "a" * 64
            seen_reusable: list[frozenset[str]] = []

            def build(
                job,
                *,
                config,
                work_root,
                rpm_release,
                reusable_patch_sha256=frozenset(),
            ):
                seen_reusable.append(reusable_patch_sha256)
                if not reusable_patch_sha256:
                    rpm = work_root / f"first-{rpm_release}.rpm"
                    rpm.parent.mkdir(parents=True, exist_ok=True)
                    rpm.write_bytes(b"rpm")
                    return JobResult(
                        job.job_id, "built", str(rpm), patch_sha256
                    )
                self.assertEqual(reusable_patch_sha256, {patch_sha256})
                return JobResult(
                    job.job_id,
                    "effective-no-change",
                    None,
                    patch_sha256,
                )

            def publish(repository_root, rpms, **kwargs):
                objects = repository_root / "objects"
                objects.mkdir(parents=True, exist_ok=True)
                mapped = {}
                for rpm in rpms:
                    stable = objects / rpm.name
                    shutil.copy2(rpm, stable)
                    mapped[rpm.name] = stable
                return PublicationResult(
                    repository_root / "current", mapped, (), ()
                )

            first = reconcile_repository(
                config=self.config,
                state_dir=root / "state",
                work_root=root / "work",
                repository_root=root / "repo",
                snapshot=first_snapshot,
                build_function=build,
                publish_function=publish,
            )
            second = reconcile_repository(
                config=self.config,
                state_dir=root / "state",
                work_root=root / "work",
                repository_root=root / "repo",
                snapshot=second_snapshot,
                build_function=build,
                publish_function=publish,
            )

            self.assertEqual((first.built, first.published), (1, 1))
            self.assertEqual((second.built, second.published), (0, 0))
            self.assertEqual(second.covered, 1)
            self.assertEqual(seen_reusable, [frozenset(), {patch_sha256}])
            registry = json.loads(
                (root / "state" / "registry.json").read_text()
            )
            entries = list(registry["jobs"].values())
            covered = next(
                entry for entry in entries if entry["status"] == "covered"
            )
            self.assertTrue(covered["effective_no_change"])
            self.assertEqual(covered["patch_sha256"], patch_sha256)
            family = covered["family"]
            self.assertEqual(registry["family_releases"][family], 1)

    def test_security_coverage_gap_escalates_and_reraises(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / "state"
            marker = root / "notify.txt"
            script = root / "notify.sh"
            script.write_text(
                f'#!/bin/sh\nprintf "%s|%s" "$1" "$2" > "{marker}"\n',
                encoding="utf-8",
            )
            script.chmod(0o755)
            config = Config(
                **{
                    **self.config.__dict__,
                    "security_escalation_command_template": (
                        f"{script} {{base}} {{cves}}"
                    ),
                }
            )
            error = SecurityCoverageError(
                "security data has no severity for: CVE-2026-99999",
                base=self.base,
                target=self.target,
                cves=("CVE-2026-99999",),
            )

            class FailingSource:
                def __init__(self, *args, **kwargs):
                    pass

                def collect(self):
                    raise error

            with mock.patch(
                "livepatch_repo.reconcile.DnfRepositorySource", FailingSource
            ):
                with self.assertRaises(SecurityCoverageError):
                    reconcile_repository(
                        config=config,
                        state_dir=state,
                        work_root=root / "work",
                        repository_root=root / "repo",
                    )

            record = json.loads(
                (state / "escalation.json").read_text(encoding="utf-8")
            )
            self.assertEqual(record["cves"], ["CVE-2026-99999"])
            self.assertEqual(record["base"], self.base.nvra)
            self.assertEqual(record["target"], self.target.nvra)
            self.assertEqual(record["action"], "command")
            # No RPM repository is published when coverage cannot be confirmed.
            self.assertFalse((root / "repo" / "current").exists())
            self.assertEqual(
                marker.read_text(encoding="utf-8"),
                f"{self.base.nvra}|CVE-2026-99999",
            )

    def test_single_running_base_produces_one_build(self) -> None:
        releases = tuple(
            KernelRelease(
                "kernel-core",
                "0",
                "5.14.0",
                f"687.{number}.1.el9_8",
                "x86_64",
            )
            for number in range(20, 26)
        )
        snapshot = RepositorySnapshot(
            releases,
            (AdvisoryFix("CVE-2026-54321", releases[-1], "Important"),),
            (
                RepositoryNotice(
                    "ALSA-2026:20000", "security", releases[-1]
                ),
            ),
        )
        config = Config(
            **{
                **self.config.__dict__,
                "base_kernel": releases[0].nvra,
            }
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            guard = threading.Lock()
            active = 0
            maximum = 0
            bases: list[str] = []

            def build(job, *, config, work_root, rpm_release):
                nonlocal active, maximum
                with guard:
                    active += 1
                    maximum = max(maximum, active)
                try:
                    time.sleep(0.05)
                    name = (
                        f"{package_name(job)}-0-{rpm_release}."
                        f"{job.base.distro_stream}.{job.base.arch}.rpm"
                    )
                    rpm = work_root / job.job_id / name
                    rpm.parent.mkdir(parents=True, exist_ok=True)
                    rpm.write_bytes(job.base.nvra.encode())
                    with guard:
                        bases.append(job.base.nvra)
                    return JobResult(job.job_id, "built", str(rpm))
                finally:
                    with guard:
                        active -= 1

            def publish(repository_root, rpms, **kwargs):
                objects = repository_root / "objects"
                objects.mkdir(parents=True, exist_ok=True)
                mapped = {}
                for rpm in rpms:
                    stable = objects / rpm.name
                    shutil.copy2(rpm, stable)
                    mapped[rpm.name] = stable
                return PublicationResult(
                    repository_root / "current", mapped, (), ()
                )

            result = reconcile_repository(
                config=config,
                state_dir=root / "state",
                work_root=root / "work",
                repository_root=root / "repo",
                snapshot=snapshot,
                build_function=build,
                publish_function=publish,
            )

            self.assertEqual((result.built, result.published), (1, 1))
            self.assertEqual(maximum, 1)
            self.assertEqual(bases, [releases[0].nvra])
            registry = json.loads(
                (root / "state" / "registry.json").read_text(encoding="utf-8")
            )
            families = {
                entry["family"] for entry in registry["jobs"].values()
            }
            self.assertEqual(len(families), 1)
            self.assertEqual(
                {entry["rpm_release"] for entry in registry["jobs"].values()},
                {1},
            )

    def test_single_base_failure_is_recorded_and_does_not_publish(self) -> None:
        releases = tuple(
            KernelRelease(
                "kernel-core",
                "0",
                "5.14.0",
                f"687.{number}.1.el9_8",
                "x86_64",
            )
            for number in range(22, 26)
        )
        snapshot = RepositorySnapshot(
            releases,
            (AdvisoryFix("CVE-2026-54321", releases[-1], "Important"),),
            (
                RepositoryNotice(
                    "ALSA-2026:20000", "security", releases[-1]
                ),
            ),
        )
        config = Config(
            **{
                **self.config.__dict__,
                "base_kernel": releases[1].nvra,
            }
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            def build(job, *, config, work_root, rpm_release):
                time.sleep(0.02)
                if job.base == releases[1]:
                    raise ValueError("deliberate build failure")
                rpm = work_root / job.job_id / f"{package_name(job)}.rpm"
                rpm.parent.mkdir(parents=True, exist_ok=True)
                rpm.write_bytes(b"rpm")
                return JobResult(job.job_id, "built", str(rpm))

            with self.assertRaisesRegex(ValueError, "deliberate build failure"):
                reconcile_repository(
                    config=config,
                    state_dir=root / "state",
                    work_root=root / "work",
                    repository_root=root / "repo",
                    snapshot=snapshot,
                    build_function=build,
                    publish_function=lambda *args, **kwargs: (_ for _ in ()).throw(
                        AssertionError("failed build must not publish")
                    ),
                )

            registry = json.loads(
                (root / "state" / "registry.json").read_text(encoding="utf-8")
            )
            statuses = sorted(
                entry["status"] for entry in registry["jobs"].values()
            )
            self.assertEqual(statuses, ["failed"])

    def test_build_failure_review_holds_off_escalation_until_grace_expires(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            counter = root / "review-count"
            script = root / "review.sh"
            script.write_text(
                f'#!/bin/sh\nprintf x >> "{counter}"\n', encoding="utf-8"
            )
            script.chmod(0o755)

            def build(job, *, config, work_root, rpm_release):
                raise ValueError("deliberate build failure")

            def unexpected(*args, **kwargs):
                raise AssertionError("must not publish a failed build")

            common = dict(
                state_dir=root / "state",
                work_root=root / "work",
                repository_root=root / "repo",
                snapshot=self.snapshot,
                build_function=build,
                publish_function=unexpected,
            )
            escalation_path = root / "state" / "escalation.json"
            review_path = root / "state" / "build-failure-review.json"

            reviewed_config = Config(
                **{
                    **self.config.__dict__,
                    "build_failure_review_command_template": f"{script} {{base}}",
                }
            )
            with self.assertRaises(ValueError):
                reconcile_repository(config=reviewed_config, **common)
            self.assertFalse(escalation_path.exists())
            self.assertTrue(review_path.is_file())
            self.assertEqual(counter.read_text(encoding="utf-8"), "x")

            # Same failure recurs on the next tick, still within the grace
            # window: no re-dispatch, still no escalation.
            with self.assertRaises(ValueError):
                reconcile_repository(config=reviewed_config, **common)
            self.assertFalse(escalation_path.exists())
            self.assertEqual(counter.read_text(encoding="utf-8"), "x")

            # Grace window forced to zero: the same failure now escalates for
            # real, exactly as if no review were configured.
            expired_config = Config(
                **{
                    **reviewed_config.__dict__,
                    "build_failure_review_grace_seconds": 0,
                }
            )
            with self.assertRaises(ValueError):
                reconcile_repository(config=expired_config, **common)
            self.assertTrue(escalation_path.is_file())

    def test_failed_job_reuses_allocated_release(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            releases: list[int] = []

            def fail(job, *, config, work_root, rpm_release):
                releases.append(rpm_release)
                raise ValueError("synthetic build failure")

            for _ in range(2):
                with self.assertRaisesRegex(ValueError, "synthetic"):
                    reconcile_repository(
                        config=self.config,
                        state_dir=root / "state",
                        work_root=root / "work",
                        repository_root=root / "repo",
                        snapshot=self.snapshot,
                        build_function=fail,
                    )
            self.assertEqual(releases, [1, 1])
            registry = json.loads(
                (root / "state" / "registry.json").read_text(encoding="utf-8")
            )
            entry = next(iter(registry["jobs"].values()))
            self.assertEqual(entry["status"], "failed")
            self.assertEqual(entry["rpm_release"], 1)

    def test_new_bugfix_target_reuses_published_cve_coverage(self) -> None:
        security_target = KernelRelease(
            "kernel-core", "0", "5.14.0", "687.25.1.el9_8", "x86_64"
        )
        first_snapshot = RepositorySnapshot(
            (self.base, security_target),
            (
                AdvisoryFix("CVE-2026-12345", security_target, "Important"),
            ),
            (
                RepositoryNotice(
                    "ALSA-2026:10000",
                    "security",
                    security_target,
                ),
            ),
        )
        second_snapshot = RepositorySnapshot(
            (self.base, security_target, self.target),
            (
                AdvisoryFix("CVE-2026-12345", security_target, "Important"),
            ),
            (
                RepositoryNotice(
                    "ALSA-2026:10000",
                    "security",
                    security_target,
                ),
                RepositoryNotice(
                    "ALBA-2026:10001",
                    "bugfix",
                    self.target,
                ),
            ),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            builds: list[str] = []

            def build(job, *, config, work_root, rpm_release):
                builds.append(job.target.nvra)
                rpm = work_root / f"result-{rpm_release}.rpm"
                rpm.parent.mkdir(parents=True, exist_ok=True)
                rpm.write_bytes(b"rpm")
                return JobResult(job.job_id, "built", str(rpm))

            def publish(repository_root, rpms, **kwargs):
                current = repository_root / "current"
                packages = current / "Packages"
                packages.mkdir(parents=True, exist_ok=True)
                objects = repository_root / "objects"
                objects.mkdir(parents=True, exist_ok=True)
                result = {}
                for rpm in rpms:
                    shutil.copy2(rpm, packages / rpm.name)
                    target = objects / rpm.name
                    shutil.copy2(rpm, target)
                    result[rpm.name] = target
                return PublicationResult(current, result, (), ())

            reconcile_repository(
                config=self.config,
                state_dir=root / "state",
                work_root=root / "work",
                repository_root=root / "repo",
                snapshot=first_snapshot,
                build_function=build,
                publish_function=publish,
            )
            for rpm in (root / "work").rglob("*.rpm"):
                rpm.unlink()
            result = reconcile_repository(
                config=self.config,
                state_dir=root / "state",
                work_root=root / "work",
                repository_root=root / "repo",
                snapshot=second_snapshot,
                build_function=build,
                publish_function=publish,
            )
            self.assertEqual(builds, [security_target.nvra])
            self.assertEqual(result.covered, 1)
            self.assertEqual(result.no_work, 0)
            registry = json.loads(
                (root / "state" / "registry.json").read_text(encoding="utf-8")
            )
            covered = [
                entry
                for entry in registry["jobs"].values()
                if entry["status"] == "covered"
            ]
            self.assertEqual(len(covered), 1)
            self.assertIn("covered_by", covered[0])
            self.assertIn(
                "/repo/objects/",
                covered[0]["rpm"],
            )

    def test_bugfix_target_inherits_terminal_build_gap_without_rebuild(self) -> None:
        failed_target = KernelRelease(
            "kernel-core", "0", "5.14.0", "687.25.1.el9_8", "x86_64"
        )
        failed_snapshot = RepositorySnapshot(
            (self.base, failed_target),
            (AdvisoryFix("CVE-2026-43499", failed_target, "Important"),),
            (
                RepositoryNotice(
                    "ALSA-2026:10000", "security", failed_target
                ),
            ),
        )
        later_snapshot = RepositorySnapshot(
            (self.base, failed_target, self.target),
            (AdvisoryFix("CVE-2026-43499", failed_target, "Important"),),
            (
                RepositoryNotice(
                    "ALSA-2026:10000", "security", failed_target
                ),
                RepositoryNotice("ALBA-2026:10001", "bugfix", self.target),
            ),
        )
        metadata_pending_snapshot = RepositorySnapshot(
            (self.base, failed_target, self.target),
            (AdvisoryFix("CVE-2026-43499", failed_target, "Important"),),
            (
                RepositoryNotice(
                    "ALSA-2026:10000", "security", failed_target
                ),
            ),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            builds: list[str] = []

            def unsupported(job, *, config, work_root, rpm_release):
                builds.append(job.target.nvra)
                cache = work_root / job.job_id / "kpatch-cache"
                cache.mkdir(parents=True)
                (cache / "build.log").write_text(
                    "Extracting new and modified ELF sections\n"
                    "ERROR: changed section .sched.text not selected for inclusion\n"
                    "ERROR: kernel/locking/rtmutex_api.o: 1 unsupported section change(s)\n",
                    encoding="utf-8",
                )
                raise ValueError("create-diff-object failed")

            common = {
                "config": self.config,
                "state_dir": root / "state",
                "work_root": root / "work",
                "repository_root": root / "repo",
            }
            with self.assertRaises(SecurityCoverageError) as first:
                reconcile_repository(
                    snapshot=failed_snapshot,
                    build_function=unsupported,
                    **common,
                )
            self.assertEqual(first.exception.failure_kind, "unsupported-elf-section")

            def unexpected(*args, **kwargs):
                raise AssertionError("terminal same-base gap must skip kpatch-build")

            with self.assertRaises(SecurityCoverageError) as pending:
                reconcile_repository(
                    snapshot=metadata_pending_snapshot,
                    build_function=unexpected,
                    **common,
                )
            self.assertEqual(
                pending.exception.failure_kind,
                "inherited-terminal-build-gap",
            )
            self.assertEqual(
                pending.exception.diagnostics["uncovered_cve_severity"],
                {"CVE-2026-43499": "Important"},
            )

            with self.assertRaises(SecurityCoverageError) as inherited:
                reconcile_repository(
                    snapshot=later_snapshot,
                    build_function=unexpected,
                    **common,
                )
            self.assertEqual(
                inherited.exception.failure_kind,
                "inherited-terminal-build-gap",
            )
            self.assertEqual(inherited.exception.cves, ("CVE-2026-43499",))
            self.assertTrue(inherited.exception.diagnostics["build_skipped"])
            self.assertEqual(
                inherited.exception.diagnostics["failed_target"],
                failed_target.nvra,
            )
            self.assertEqual(builds, [failed_target.nvra])
            registry = json.loads(
                (root / "state" / "registry.json").read_text(encoding="utf-8")
            )
            self.assertEqual(list(registry["family_releases"].values()), [1])
            self.assertEqual(len(registry["jobs"]), 1)
            entry = next(iter(registry["jobs"].values()))
            self.assertTrue(entry["terminal_for_base"])
            self.assertEqual(entry["uncovered_cves"], ["CVE-2026-43499"])

    def test_legacy_escalation_record_stops_later_redundant_build(self) -> None:
        failed_target = KernelRelease(
            "kernel-core", "0", "5.14.0", "687.25.1.el9_8", "x86_64"
        )
        failed_snapshot = RepositorySnapshot(
            (self.base, failed_target),
            (AdvisoryFix("CVE-2026-43499", failed_target, "Important"),),
            (RepositoryNotice("ALSA-2026:10000", "security", failed_target),),
        )
        later_snapshot = RepositorySnapshot(
            (self.base, failed_target, self.target),
            (AdvisoryFix("CVE-2026-43499", failed_target, "Important"),),
            (
                RepositoryNotice("ALSA-2026:10000", "security", failed_target),
                RepositoryNotice("ALBA-2026:10001", "bugfix", self.target),
            ),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            def unsupported(job, *, config, work_root, rpm_release):
                cache = work_root / job.job_id / "kpatch-cache"
                cache.mkdir(parents=True)
                (cache / "build.log").write_text(
                    "Extracting new and modified ELF sections\n"
                    "ERROR: changed section .sched.text not selected for inclusion\n"
                    "ERROR: kernel/locking/rtmutex_api.o: 1 unsupported section change(s)\n",
                    encoding="utf-8",
                )
                raise ValueError("create-diff-object failed")

            common = {
                "config": self.config,
                "state_dir": root / "state",
                "work_root": root / "work",
                "repository_root": root / "repo",
            }
            with self.assertRaises(SecurityCoverageError):
                reconcile_repository(
                    snapshot=failed_snapshot,
                    build_function=unsupported,
                    **common,
                )
            registry_path = root / "state" / "registry.json"
            registry = json.loads(registry_path.read_text(encoding="utf-8"))
            entry = next(iter(registry["jobs"].values()))
            for key in (
                "failure_stage",
                "failure_kind",
                "uncovered_cves",
                "terminal_for_base",
                "failure_diagnostics",
            ):
                entry.pop(key)
            registry_path.write_text(json.dumps(registry), encoding="utf-8")

            with self.assertRaises(SecurityCoverageError) as inherited:
                reconcile_repository(
                    snapshot=later_snapshot,
                    build_function=lambda *args, **kwargs: (_ for _ in ()).throw(
                        AssertionError("legacy terminal gap must skip build")
                    ),
                    **common,
                )
            self.assertEqual(
                inherited.exception.diagnostics["source"],
                "escalation-record",
            )

    def test_superseded_release_drops_from_published_repository(self) -> None:
        t1 = KernelRelease("kernel-core", "0", "5.14.0", "687.25.1.el9_8", "x86_64")
        t2 = self.target  # 687.26.1
        run1 = RepositorySnapshot(
            (self.base, t1),
            (AdvisoryFix("CVE-2026-00001", t1, "Important"),),
            (RepositoryNotice("ALSA-2026:10000", "security", t1),),
        )
        run2 = RepositorySnapshot(
            (self.base, t1, t2),
            (
                AdvisoryFix("CVE-2026-00001", t1, "Important"),
                AdvisoryFix("CVE-2026-00002", t2, "Important"),
            ),
            (
                RepositoryNotice("ALSA-2026:10000", "security", t1),
                RepositoryNotice("ALSA-2026:10001", "security", t2),
            ),
        )
        config = self.config
        base_pkg = "kpatch-patch-5_14_0-687_24_1"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            createrepo = root / "fake-createrepo"
            createrepo.write_text(
                "#!/bin/sh\n"
                "mkdir -p \"$1/repodata\"\n"
                "touch \"$1/repodata/repomd.xml\"\n",
                encoding="utf-8",
            )
            createrepo.chmod(0o755)

            def build(job, *, config, work_root, rpm_release):
                name = (
                    f"{package_name(job)}-0-{rpm_release}."
                    f"{job.base.distro_stream}.{job.base.arch}.rpm"
                )
                rpm = work_root / job.job_id / name
                rpm.parent.mkdir(parents=True, exist_ok=True)
                rpm.write_bytes(name.encode())
                return JobResult(job.job_id, "built", str(rpm))

            def publish(repository_root, rpms, **kwargs):
                kwargs["createrepo_command"] = str(createrepo)
                return publish_repository(repository_root, rpms, **kwargs)

            common = dict(
                config=config,
                state_dir=root / "state",
                work_root=root / "work",
                repository_root=root / "repo",
                build_function=build,
                publish_function=publish,
            )
            reconcile_repository(snapshot=run1, **common)
            reconcile_repository(snapshot=run2, **common)

            packages = sorted(
                path.name
                for path in ((root / "repo" / "current").resolve() / "Packages").glob(
                    "*.rpm"
                )
            )
            # Base family keeps only release 2; release 1 is superseded and gone.
            self.assertIn(f"{base_pkg}-0-2.el9_8.x86_64.rpm", packages)
            self.assertNotIn(f"{base_pkg}-0-1.el9_8.x86_64.rpm", packages)
            self.assertEqual(len(packages), 1)

    def test_idle_reconcile_publishes_expired_family_removal(self) -> None:
        idle = RepositorySnapshot(
            (self.base, self.target),
            (),
            (RepositoryNotice("ALBA-2026:10001", "bugfix", self.target),),
        )
        config = Config(
            **{
                **self.config.__dict__,
                "repository_family_grace_seconds": 60,
            }
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rpm = root / "obsolete.rpm"
            rpm.write_bytes(b"obsolete")
            state = root / "state"
            state.mkdir()
            (state / "registry.json").write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "family_releases": {"obsolete-family": 1},
                        "family_activity": {
                            "obsolete-family": "2000-01-01T00:00:00Z"
                        },
                        "published_pin_names": [rpm.name],
                        "jobs": {
                            "old": {
                                "family": "obsolete-family",
                                "rpm_release": 1,
                                "status": "published",
                                "published_rpm": str(rpm),
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            publications: list[tuple[tuple[str, ...], tuple[str, ...]]] = []

            def publish(repository_root, rpms, **kwargs):
                publications.append(
                    (
                        tuple(path.name for path in rpms),
                        tuple(path.name for path in kwargs["pinned_rpms"]),
                    )
                )
                return PublicationResult(
                    repository_root / "current", {}, (), ()
                )

            result = reconcile_repository(
                config=config,
                state_dir=state,
                work_root=root / "work",
                repository_root=root / "repo",
                snapshot=idle,
                build_function=lambda *args, **kwargs: (_ for _ in ()).throw(
                    AssertionError("build should not run")
                ),
                publish_function=publish,
            )

            self.assertEqual(result.built, 0)
            self.assertEqual(publications, [((), ())])
            registry = json.loads(
                (state / "registry.json").read_text(encoding="utf-8")
            )
            self.assertEqual(registry["published_pin_names"], [])

    def test_expired_family_is_reclaimed_from_pool_and_current(self) -> None:
        b1 = self.base  # 687.24.1
        t1 = KernelRelease("kernel-core", "0", "5.14.0", "687.25.1.el9_8", "x86_64")
        b2 = KernelRelease("kernel-core", "0", "5.14.0", "700.1.1.el9_8", "x86_64")
        t2 = KernelRelease("kernel-core", "0", "5.14.0", "700.2.1.el9_8", "x86_64")
        run1 = RepositorySnapshot(
            (b1, t1),
            (AdvisoryFix("CVE-2026-00001", t1, "Important"),),
            (RepositoryNotice("ALSA-2026:10000", "security", t1),),
        )
        run2 = RepositorySnapshot(
            (b1, t1, b2, t2),
            (
                AdvisoryFix("CVE-2026-00001", t1, "Important"),
                AdvisoryFix("CVE-2026-00002", t2, "Important"),
            ),
            (
                RepositoryNotice("ALSA-2026:10000", "security", t1),
                RepositoryNotice("ALSA-2026:20000", "security", t2),
            ),
        )
        # Updating the builder from b1 to b2 changes the single active family;
        # grace 0 expires b1 immediately.
        config = Config(
            **{
                **self.config.__dict__,
                "repository_family_grace_seconds": 0,
                "repository_retain_versions": 1,
                "repository_minimum_age_seconds": 0,
            }
        )
        b1_pkg = "kpatch-patch-5_14_0-687_24_1-0-1.el9_8.x86_64.rpm"
        b2_pkg = "kpatch-patch-5_14_0-700_1_1-0-1.el9_8.x86_64.rpm"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            createrepo = root / "fake-createrepo"
            createrepo.write_text(
                "#!/bin/sh\n"
                "mkdir -p \"$1/repodata\"\n"
                "touch \"$1/repodata/repomd.xml\"\n",
                encoding="utf-8",
            )
            createrepo.chmod(0o755)

            def build(job, *, config, work_root, rpm_release):
                name = (
                    f"{package_name(job)}-0-{rpm_release}."
                    f"{job.base.distro_stream}.{job.base.arch}.rpm"
                )
                rpm = work_root / job.job_id / name
                rpm.parent.mkdir(parents=True, exist_ok=True)
                rpm.write_bytes(name.encode())
                return JobResult(job.job_id, "built", str(rpm))

            def publish(repository_root, rpms, **kwargs):
                kwargs["createrepo_command"] = str(createrepo)
                return publish_repository(repository_root, rpms, **kwargs)

            common = dict(
                state_dir=root / "state",
                work_root=root / "work",
                repository_root=root / "repo",
                build_function=build,
                publish_function=publish,
            )
            reconcile_repository(snapshot=run1, config=config, **common)
            objects_dir = root / "repo" / "objects" / "sha256"
            self.assertIn(
                b1_pkg,
                [p.name for d in objects_dir.glob("*") for p in d.glob("*.rpm")],
            )
            updated_config = Config(
                **{**config.__dict__, "base_kernel": b2.nvra}
            )
            reconcile_repository(snapshot=run2, config=updated_config, **common)

            current = (root / "repo" / "current").resolve()
            served = sorted(p.name for p in (current / "Packages").glob("*.rpm"))
            self.assertEqual(served, [b2_pkg])
            pooled = sorted(
                p.name for d in objects_dir.glob("*") for p in d.glob("*.rpm")
            )
            self.assertEqual(pooled, [b2_pkg])

    def test_metadata_pending_alerts_immediately_then_times_out(self) -> None:
        pending = RepositorySnapshot((self.base, self.target), (), ())
        start = datetime(2026, 7, 20, 12, 0, tzinfo=timezone.utc)
        config = Config(
            **{
                **self.config.__dict__,
                "metadata_pending_timeout_seconds": 60,
            }
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            def unexpected(*args, **kwargs):
                raise AssertionError("build should not run")

            common = {
                "config": config,
                "state_dir": root / "state",
                "work_root": root / "work",
                "repository_root": root / "repo",
                "snapshot": pending,
                "build_function": unexpected,
            }
            with mock.patch(
                "livepatch_repo.reconcile._now", return_value=start
            ):
                with self.assertRaises(SecurityCoverageError) as immediate:
                    reconcile_repository(**common)
            self.assertEqual(
                immediate.exception.failure_kind,
                "repository-metadata-pending",
            )
            state = json.loads(
                (root / "state" / "metadata-pending.json").read_text()
            )
            self.assertEqual(state["age_seconds"], 0)
            self.assertFalse(state["timed_out"])
            self.assertEqual(state["pending_reason"], "missing-target-updateinfo")
            self.assertFalse((root / "work").exists())

            with mock.patch(
                "livepatch_repo.reconcile._now",
                return_value=start + timedelta(seconds=60),
            ):
                with self.assertRaises(SecurityCoverageError) as timed_out:
                    reconcile_repository(**common)
            self.assertEqual(
                timed_out.exception.failure_kind,
                "repository-metadata-timeout",
            )
            self.assertEqual(timed_out.exception.diagnostics["age_seconds"], 60)
            escalation = json.loads(
                (root / "state" / "escalation.json").read_text()
            )
            self.assertEqual(
                escalation["failure_kind"], "repository-metadata-timeout"
            )

    def test_complete_bugfix_metadata_clears_pending_alert_without_build(self) -> None:
        pending = RepositorySnapshot((self.base, self.target), (), ())
        complete = RepositorySnapshot(
            (self.base, self.target),
            (),
            (RepositoryNotice("ALBA-2026:10001", "bugfix", self.target),),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            def unexpected(*args, **kwargs):
                raise AssertionError("build should not run")

            common = {
                "config": self.config,
                "state_dir": root / "state",
                "work_root": root / "work",
                "repository_root": root / "repo",
                "build_function": unexpected,
            }
            with self.assertRaises(SecurityCoverageError):
                reconcile_repository(snapshot=pending, **common)
            pending_path = root / "state" / "metadata-pending.json"
            self.assertTrue(pending_path.is_file())

            result = reconcile_repository(snapshot=complete, **common)
            self.assertEqual(result.no_work, 1)
            self.assertEqual(result.built, 0)
            self.assertFalse(pending_path.exists())
            registry = json.loads(
                (root / "state" / "registry.json").read_text()
            )
            self.assertEqual(registry["jobs"], {})

    def test_signing_without_sign_template_holds_awaiting_signature(self) -> None:
        # require_rpm_signing with no rpm_sign_command_template is a
        # deliberate configuration for manual signing: the build must still
        # run autonomously, and the result must be held unpublished rather
        # than either failing the run or publishing unsigned.
        config = Config(
            **{
                **self.config.__dict__,
                "require_rpm_signing": True,
            }
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            def build(job, *, config, work_root, rpm_release):
                rpm = work_root / "unsigned.rpm"
                rpm.parent.mkdir(parents=True, exist_ok=True)
                rpm.write_bytes(b"rpm")
                return JobResult(job.job_id, "built", str(rpm))

            def unexpected(*args, **kwargs):
                raise AssertionError("unsigned RPM must not be published")

            result = reconcile_repository(
                config=config,
                state_dir=root / "state",
                work_root=root / "work",
                repository_root=root / "repo",
                snapshot=self.snapshot,
                build_function=build,
                publish_function=unexpected,
            )
            self.assertEqual(result.built, 1)
            self.assertEqual(result.published, 0)
            self.assertEqual(result.awaiting_signature, 1)
            registry = json.loads(
                (root / "state" / "registry.json").read_text(encoding="utf-8")
            )
            entry = next(iter(registry["jobs"].values()))
            self.assertEqual(entry["status"], "awaiting-signature")

    def test_manually_signed_rpm_is_promoted_and_published_on_next_reconcile(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            signed_marker = root / "signed"
            checker = root / "checker"
            # Reports unsigned until the marker file exists, simulating an
            # operator running `rpm --addsign` between reconcile runs.
            checker.write_text(
                "#!/bin/sh\n"
                f"if [ -e {shlex.quote(str(signed_marker))} ]; then\n"
                "  printf 'sigheader\\n(none)\\n(none)\\n(none)\\n'\n"
                "else\n"
                "  printf '(none)\\n(none)\\n(none)\\n(none)\\n'\n"
                "fi\n",
                encoding="utf-8",
            )
            checker.chmod(0o755)
            verifier = root / "verifier"
            verifier.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            verifier.chmod(0o755)
            config = Config(
                **{
                    **self.config.__dict__,
                    "require_rpm_signing": True,
                    "rpm_command": str(checker),
                    "rpm_verify_command_template": f"{verifier} {{rpm}}",
                }
            )

            def build(job, *, config, work_root, rpm_release):
                rpm = work_root / "unsigned.rpm"
                rpm.parent.mkdir(parents=True, exist_ok=True)
                rpm.write_bytes(b"rpm")
                return JobResult(job.job_id, "built", str(rpm))

            published_rpms: list[Path] = []

            def publish(repository_root, rpms, **kwargs):
                published_rpms.extend(rpms)
                return PublicationResult(
                    current=repository_root / "current",
                    objects_by_name={rpm.name: rpm for rpm in rpms},
                    removed_versions=(),
                    removed_objects=(),
                )

            common = dict(
                config=config,
                state_dir=root / "state",
                work_root=root / "work",
                repository_root=root / "repo",
                snapshot=self.snapshot,
                build_function=build,
                publish_function=publish,
            )
            first = reconcile_repository(**common)
            self.assertEqual(first.awaiting_signature, 1)
            self.assertEqual(first.published, 0)
            self.assertEqual(published_rpms, [])

            # Operator signs the RPM in place between reconcile runs.
            signed_marker.touch()

            second = reconcile_repository(**common)
            self.assertEqual(second.awaiting_signature, 0)
            self.assertEqual(second.published, 1)
            self.assertEqual(len(published_rpms), 1)
            registry = json.loads(
                (root / "state" / "registry.json").read_text(encoding="utf-8")
            )
            entry = next(iter(registry["jobs"].values()))
            self.assertEqual(entry["status"], "published")

    def test_signature_verification_failure_blocks_publication(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            signer = root / "signer"
            verifier = root / "verifier"
            signer.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            verifier.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
            signer.chmod(0o755)
            verifier.chmod(0o755)
            config = Config(
                **{
                    **self.config.__dict__,
                    "require_rpm_signing": True,
                    "rpm_sign_command_template": f"{signer} {{rpm}}",
                    "rpm_verify_command_template": f"{verifier} {{rpm}}",
                }
            )

            def build(job, *, config, work_root, rpm_release):
                rpm = work_root / "unsigned.rpm"
                rpm.parent.mkdir(parents=True, exist_ok=True)
                rpm.write_bytes(b"rpm")
                return JobResult(job.job_id, "built", str(rpm))

            def unexpected(*args, **kwargs):
                raise AssertionError("unverified RPM must not be published")

            with self.assertRaisesRegex(
                ValueError,
                "signature verification failed",
            ):
                reconcile_repository(
                    config=config,
                    state_dir=root / "state",
                    work_root=root / "work",
                    repository_root=root / "repo",
                    snapshot=self.snapshot,
                    build_function=build,
                    publish_function=unexpected,
                )
            registry = json.loads(
                (root / "state" / "registry.json").read_text(encoding="utf-8")
            )
            entry = next(iter(registry["jobs"].values()))
            self.assertEqual(entry["status"], "failed")

    def test_digest_only_rpm_is_rejected_after_checksig_success(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            success = root / "success"
            digest_only_rpm = root / "rpm"
            success.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            digest_only_rpm.write_text(
                "#!/bin/sh\n"
                "printf '(none)\\n(none)\\n(none)\\n(none)\\n'\n",
                encoding="utf-8",
            )
            success.chmod(0o755)
            digest_only_rpm.chmod(0o755)
            config = Config(
                **{
                    **self.config.__dict__,
                    "require_rpm_signing": True,
                    "rpm_sign_command_template": f"{success} {{rpm}}",
                    "rpm_verify_command_template": f"{success} {{rpm}}",
                    "rpm_command": str(digest_only_rpm),
                }
            )

            def build(job, *, config, work_root, rpm_release):
                rpm = work_root / "digest-only.rpm"
                rpm.parent.mkdir(parents=True, exist_ok=True)
                rpm.write_bytes(b"rpm")
                return JobResult(job.job_id, "built", str(rpm))

            with self.assertRaisesRegex(
                ValueError,
                "no OpenPGP signature header",
            ):
                reconcile_repository(
                    config=config,
                    state_dir=root / "state",
                    work_root=root / "work",
                    repository_root=root / "repo",
                    snapshot=self.snapshot,
                    build_function=build,
                )


if __name__ == "__main__":
    unittest.main()
