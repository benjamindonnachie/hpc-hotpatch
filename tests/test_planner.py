from datetime import datetime, timezone
import unittest

from livepatch_repo.models import AdvisoryFix, KernelRelease, RepositoryNotice
from livepatch_repo.planner import create_plan
from livepatch_repo.sources import RepositorySnapshot


def kernel(release: str, *, version: str = "5.14.0") -> KernelRelease:
    return KernelRelease("kernel-core", "0", version, release, "x86_64")


def notice(
    release: KernelRelease,
    *,
    kind: str = "bugfix",
    advisory_id: str = "ALBA-2026:10000",
) -> RepositoryNotice:
    return RepositoryNotice(advisory_id, kind, release)


class TestBuildPlanner(unittest.TestCase):
    def test_no_newer_kernel_is_an_idle_plan(self) -> None:
        base = kernel("687.26.1.el9_8")
        plan = create_plan(
            RepositorySnapshot((base,), (), ()),
            architecture="x86_64",
            distro_stream="el9_8",
            base=base,
        )
        self.assertEqual(plan.base, base)
        self.assertIsNone(plan.target)
        self.assertEqual(plan.jobs, ())

    def test_controlled_test_can_select_an_intermediate_target(self) -> None:
        releases = tuple(
            kernel(f"687.{number}.1.el9_8") for number in range(22, 27)
        )
        plan = create_plan(
            RepositorySnapshot(releases, (), (notice(releases[1]),)),
            architecture="x86_64",
            distro_stream="el9_8",
            base=releases[0],
            target_kernel=releases[1],
        )
        self.assertEqual(plan.target, releases[1])
        self.assertEqual(plan.jobs[0].base, releases[0])

    def test_skipped_intermediate_security_release_is_included(self) -> None:
        releases = tuple(
            kernel(release)
            for release in (
                "687.22.1.el9_8",
                "687.23.1.el9_8",
                "687.24.1.el9_8",
                "687.25.1.el9_8",
            )
        )
        snapshot = RepositorySnapshot(
            kernels=releases,
            advisories=(
                AdvisoryFix("CVE-2026-12345", releases[2], "Important"),
            ),
            notices=(
                notice(
                    releases[2],
                    kind="security",
                    advisory_id="ALSA-2026:9999",
                ),
                notice(releases[-1]),
            ),
        )
        plan = create_plan(
            snapshot,
            architecture="x86_64",
            distro_stream="el9_8",
            base=releases[0],
            now=datetime(2026, 7, 16, tzinfo=timezone.utc),
        )
        self.assertEqual(plan.target.release, "687.25.1.el9_8")
        self.assertEqual(len(plan.jobs), 1)
        self.assertEqual(plan.jobs[0].base, releases[0])
        self.assertEqual(plan.jobs[0].cves, ("CVE-2026-12345",))

    def test_advisory_ticket_evidence_is_carried_into_job(self) -> None:
        releases = (
            kernel("687.22.1.el9_8"),
            kernel("687.23.1.el9_8"),
        )
        snapshot = RepositorySnapshot(
            kernels=releases,
            advisories=(
                AdvisoryFix(
                    "CVE-2026-53266",
                    releases[-1],
                    "Important",
                    "RHSA-2026:36645",
                    ("182344",),
                ),
            ),
            notices=(
                notice(
                    releases[-1],
                    kind="security",
                    advisory_id="ALSA-2026:36645",
                ),
            ),
        )
        plan = create_plan(
            snapshot,
            architecture="x86_64",
            distro_stream="el9_8",
            base=releases[0],
        )
        self.assertEqual(
            plan.jobs[0].cve_ticket_ids,
            (("CVE-2026-53266", ("182344",)),),
        )

    def test_explicit_base_produces_exactly_one_job(self) -> None:
        releases = tuple(
            kernel(f"687.{number}.1.el9_8") for number in range(18, 26)
        )
        snapshot = RepositorySnapshot(
            releases,
            (AdvisoryFix("CVE-2026-12345", releases[-1], "Important"),),
            (
                notice(
                    releases[-1],
                    kind="security",
                    advisory_id="ALSA-2026:9999",
                ),
            ),
        )
        plan = create_plan(
            snapshot,
            architecture="x86_64",
            distro_stream="el9_8",
            base=releases[2],
        )
        self.assertEqual([job.base for job in plan.jobs], [releases[2]])

    def test_empty_interval_is_explicit_no_work(self) -> None:
        releases = (
            kernel("687.24.1.el9_8"),
            kernel("687.25.1.el9_8"),
        )
        plan = create_plan(
            RepositorySnapshot(releases, (), (notice(releases[-1]),)),
            architecture="x86_64",
            distro_stream="el9_8",
            base=releases[0],
        )
        self.assertEqual(plan.jobs[0].status, "no-work")
        self.assertEqual(plan.jobs[0].cves, ())

    def test_only_critical_and_important_cves_are_required(self) -> None:
        releases = (
            kernel("687.24.1.el9_8"),
            kernel("687.25.1.el9_8"),
        )
        snapshot = RepositorySnapshot(
            releases,
            (
                AdvisoryFix("CVE-2026-00001", releases[-1], "Critical"),
                AdvisoryFix("CVE-2026-00002", releases[-1], "Important"),
                AdvisoryFix("CVE-2026-00003", releases[-1], "Moderate"),
                AdvisoryFix("CVE-2026-00004", releases[-1], "Low"),
            ),
            (
                notice(
                    releases[-1],
                    kind="security",
                    advisory_id="ALSA-2026:10001",
                ),
            ),
        )
        plan = create_plan(
            snapshot,
            architecture="x86_64",
            distro_stream="el9_8",
            base=releases[0],
        )
        job = plan.jobs[0]
        self.assertEqual(
            job.cves,
            ("CVE-2026-00001", "CVE-2026-00002"),
        )
        self.assertEqual(
            [decision.to_dict() for decision in job.cve_policy_decisions],
            [
                {
                    "cve": "CVE-2026-00001",
                    "severity": "Critical",
                    "disposition": "required",
                },
                {
                    "cve": "CVE-2026-00002",
                    "severity": "Important",
                    "disposition": "required",
                },
                {
                    "cve": "CVE-2026-00003",
                    "severity": "Moderate",
                    "disposition": "below-policy",
                },
                {
                    "cve": "CVE-2026-00004",
                    "severity": "Low",
                    "disposition": "below-policy",
                },
            ],
        )

    def test_below_policy_only_interval_is_auditable_no_work(self) -> None:
        releases = (
            kernel("687.24.1.el9_8"),
            kernel("687.25.1.el9_8"),
        )
        plan = create_plan(
            RepositorySnapshot(
                releases,
                (AdvisoryFix("CVE-2026-00003", releases[-1], "Moderate"),),
                (
                    notice(
                        releases[-1],
                        kind="security",
                        advisory_id="ALSA-2026:10001",
                    ),
                ),
            ),
            architecture="x86_64",
            distro_stream="el9_8",
            base=releases[0],
        )
        self.assertEqual(plan.jobs[0].status, "no-work")
        self.assertEqual(plan.jobs[0].cves, ())
        self.assertEqual(
            plan.jobs[0].cve_policy_decisions[0].disposition,
            "below-policy",
        )

    def test_configured_severity_override_is_honoured(self) -> None:
        releases = (
            kernel("687.24.1.el9_8"),
            kernel("687.25.1.el9_8"),
        )
        plan = create_plan(
            RepositorySnapshot(
                releases,
                (AdvisoryFix("CVE-2026-00003", releases[-1], "Moderate"),),
                (
                    notice(
                        releases[-1],
                        kind="security",
                        advisory_id="ALSA-2026:10001",
                    ),
                ),
            ),
            architecture="x86_64",
            distro_stream="el9_8",
            base=releases[0],
            eligible_cve_severities=("Critical", "Important", "Moderate"),
        )
        self.assertEqual(plan.jobs[0].status, "planned")
        self.assertEqual(plan.jobs[0].cves, ("CVE-2026-00003",))

    def test_retained_advisory_for_unavailable_intermediate_is_included(self) -> None:
        base = kernel("687.23.1.el9_8")
        target = kernel("687.25.1.el9_8")
        unavailable_fix = kernel("687.24.1.el9_8")
        plan = create_plan(
            RepositorySnapshot(
                (base, target),
                (
                    AdvisoryFix(
                        "CVE-2026-54321", unavailable_fix, "Critical"
                    ),
                ),
                (
                    notice(
                        unavailable_fix,
                        kind="security",
                        advisory_id="ALSA-2026:9999",
                    ),
                    notice(target),
                ),
            ),
            architecture="x86_64",
            distro_stream="el9_8",
            base=base,
        )
        self.assertEqual(plan.jobs[0].status, "planned")
        self.assertEqual(plan.jobs[0].cves, ("CVE-2026-54321",))

    def test_el10_selects_klp_backend(self) -> None:
        releases = (
            kernel("1.el10_0", version="6.12.0"),
            kernel("2.el10_0", version="6.12.0"),
        )
        plan = create_plan(
            RepositorySnapshot(
                releases,
                (
                    AdvisoryFix(
                        "CVE-2026-12345", releases[-1], "Important"
                    ),
                ),
                (
                    notice(
                        releases[-1],
                        kind="security",
                        advisory_id="ALSA-2026:9999",
                    ),
                ),
            ),
            architecture="x86_64",
            distro_stream="el10_0",
            base=releases[0],
        )
        self.assertEqual(plan.jobs[0].backend, "klp-build")

    def test_new_kernel_without_advisory_is_metadata_pending(self) -> None:
        releases = (
            kernel("687.25.1.el9_8"),
            kernel("687.26.1.el9_8"),
        )
        plan = create_plan(
            RepositorySnapshot(releases, (), ()),
            architecture="x86_64",
            distro_stream="el9_8",
            base=releases[0],
        )
        self.assertEqual(plan.jobs[0].status, "metadata-pending")

    def test_security_notice_without_cves_is_metadata_pending(self) -> None:
        releases = (
            kernel("687.25.1.el9_8"),
            kernel("687.26.1.el9_8"),
        )
        plan = create_plan(
            RepositorySnapshot(
                releases,
                (),
                (
                    notice(
                        releases[-1],
                        kind="security",
                        advisory_id="ALSA-2026:10001",
                    ),
                ),
            ),
            architecture="x86_64",
            distro_stream="el9_8",
            base=releases[0],
        )
        self.assertEqual(plan.jobs[0].status, "metadata-pending")


if __name__ == "__main__":
    unittest.main()
