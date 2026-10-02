import unittest

from livepatch_repo.escalation import SecurityCoverageError
from livepatch_repo.models import AdvisoryFix, KernelRelease, RepositoryNotice
from livepatch_repo.sources import (
    DnfRepositorySource,
    associate_local_advisory_ids,
    parse_advisory_security_cves,
    parse_advisory_ticket_evidence,
    parse_cve_severities,
    parse_cve_vex_severity,
    parse_notices,
    parse_repoquery,
    parse_updateinfo,
)


REPOQUERY = """\
kernel-core\t0\t5.14.0\t687.23.1.el9_8\tx86_64
kernel-core\t0\t5.14.0\t687.24.1.el9_8\tx86_64
kernel-core\t0\t5.14.0\t687.25.1.el9_8\tx86_64
"""


class TestRepositoryParsing(unittest.TestCase):
    def test_collection_rates_only_selected_base_target_interval(self) -> None:
        base = KernelRelease(
            "kernel-core", "0", "5.14.0", "687.23.1.el9_8", "x86_64"
        )
        target = KernelRelease(
            "kernel-core", "0", "5.14.0", "687.24.1.el9_8", "x86_64"
        )

        class FakeSource(DnfRepositorySource):
            requested_cves: tuple[str, ...] = ()

            def _run(self, arguments: list[str]) -> str:
                if "repoquery" in arguments:
                    return REPOQUERY
                if "--with-cve" in arguments:
                    return (
                        "i CVE-2022-1966 Important/Sec. "
                        "kernel-core-5.14.0-687.22.1.el9_8.x86_64\n"
                        "i CVE-2026-12345 Important/Sec. "
                        "kernel-core-5.14.0-687.24.1.el9_8.x86_64\n"
                    )
                return (
                    "i ALSA-2026:10000 Important/Sec. "
                    "kernel-core-5.14.0-687.24.1.el9_8.x86_64\n"
                )

            def _cve_severities(self, cves: tuple[str, ...]) -> dict[str, str]:
                self.requested_cves = cves
                return {cve: "Important" for cve in cves}

        source = FakeSource("dnf", "kernel-core", "x86_64", "https://x/{cves}", base, target)
        snapshot = source.collect()
        self.assertEqual(source.requested_cves, ("CVE-2026-12345",))
        self.assertEqual([item.cve for item in snapshot.advisories], ["CVE-2026-12345"])

    def test_repoquery_rows(self) -> None:
        kernels = parse_repoquery(REPOQUERY, "kernel-core")
        self.assertEqual(kernels[-1].release, "687.25.1.el9_8")

    def test_updateinfo_rows_match_available_kernel(self) -> None:
        kernels = parse_repoquery(REPOQUERY, "kernel-core")
        rows = (
            "i CVE-2026-12345 Important/Sec. "
            "kernel-core-5.14.0-687.24.1.el9_8.x86_64\n"
        )
        advisories = parse_updateinfo(rows)
        self.assertEqual(advisories[0].cve, "CVE-2026-12345")
        self.assertEqual(advisories[0].severity, "Important")
        self.assertEqual(advisories[0].kernel.release, "687.24.1.el9_8")

    def test_updateinfo_cve_retains_preceding_advisory_identity(self) -> None:
        rows = (
            "i RHSA-2026:36645 Important/Sec. "
            "kernel-core-5.14.0-687.23.1.el9_8.x86_64\n"
            "i CVE-2026-53266 Important/Sec. "
            "kernel-core-5.14.0-687.23.1.el9_8.x86_64\n"
        )
        advisories = parse_updateinfo(rows)
        self.assertEqual(advisories[0].advisory_id, "RHSA-2026:36645")

    def test_advisory_description_correlates_cve_to_exact_jira(self) -> None:
        details = """\
  Update ID: RHSA-2026:36645
Description: Security update.
           :
           : Security Fix(es):
           :
           :   * kernel: Linux kernel: netfilter: ebtables SNAT target writes to shared memory pages during ARP hardware address rewrite (CVE-2026-53266)
           :
           : Bug Fix(es) and Enhancement(s):
           :
           :   * kernel: Linux kernel: netfilter: ebtables SNAT target writes to shared memory pages during ARP hardware address rewrite [almalinux-9.8.z] (JIRA:AlmaLinux-182344)
   Severity: Important
"""
        evidence = parse_advisory_ticket_evidence(details)
        self.assertEqual(
            evidence[("RHSA-2026:36645", "CVE-2026-53266")],
            ("182344",),
        )

    def test_security_cves_are_recovered_from_advisory_description(self) -> None:
        details = """\
  Update ID: ALSA-2026:43307
Description: Security update.
           :
           : Security Fix(es):
           :
           :   * kernel: structured reference (CVE-2026-46215)
           :   * kernel: missing structured reference (CVE-2026-46099)
           :
           : Bug Fix(es) and Enhancement(s):
           :
           :   * unrelated fix (JIRA:RHEL-183980)
   Severity: Important
"""
        self.assertEqual(
            parse_advisory_security_cves(details),
            {
                "ALSA-2026:43307": (
                    "CVE-2026-46099",
                    "CVE-2026-46215",
                )
            },
        )

    def test_collection_recovers_cve_omitted_from_structured_references(self) -> None:
        base = KernelRelease(
            "kernel-core", "0", "5.14.0", "687.23.1.el9_8", "x86_64"
        )
        target = KernelRelease(
            "kernel-core", "0", "5.14.0", "687.24.1.el9_8", "x86_64"
        )

        class FakeSource(DnfRepositorySource):
            requested_cves: tuple[str, ...] = ()

            def _run(self, arguments: list[str]) -> str:
                if "repoquery" in arguments:
                    return REPOQUERY
                if "--with-cve" in arguments:
                    return (
                        "i ALSA-2026:43307 Important/Sec. "
                        "kernel-core-5.14.0-687.24.1.el9_8.x86_64\n"
                        "i CVE-2026-46215 Important/Sec. "
                        "kernel-core-5.14.0-687.24.1.el9_8.x86_64\n"
                    )
                if "info" in arguments:
                    return """\
  Update ID: ALSA-2026:43307
Description: Security update.
           :
           : Security Fix(es):
           :
           :   * kernel: omitted reference (CVE-2026-46099)
           :   * kernel: retained reference (CVE-2026-46215)
   Severity: Important
"""
                return (
                    "i ALSA-2026:43307 Important/Sec. "
                    "kernel-core-5.14.0-687.24.1.el9_8.x86_64\n"
                )

            def _cve_severities(self, cves: tuple[str, ...]) -> dict[str, str]:
                self.requested_cves = cves
                return {cve: "Important" for cve in cves}

        source = FakeSource(
            "dnf",
            "kernel-core",
            "x86_64",
            "https://x/{cves}",
            base,
            target,
        )
        snapshot = source.collect()
        self.assertEqual(
            source.requested_cves,
            ("CVE-2026-46099", "CVE-2026-46215"),
        )
        self.assertEqual(
            [item.cve for item in snapshot.advisories],
            ["CVE-2026-46099", "CVE-2026-46215"],
        )

    def test_local_alsa_notice_replaces_unresolvable_rhsa_alias(self) -> None:
        release = parse_repoquery(REPOQUERY, "kernel-core")[0]
        advisories = (
            AdvisoryFix(
                "CVE-2026-53266", release, "Important", "RHSA-2026:36645"
            ),
        )
        notices = (
            RepositoryNotice("ALSA-2026:36645", "security", release),
        )
        associated = associate_local_advisory_ids(advisories, notices)
        self.assertEqual(associated[0].advisory_id, "ALSA-2026:36645")

    def test_unparseable_cve_row_fails_closed(self) -> None:
        kernels = parse_repoquery(REPOQUERY, "kernel-core")
        with self.assertRaisesRegex(ValueError, "could not parse"):
            parse_updateinfo("CVE-2026-12345 kernel-core-malformed")

    def test_cve_row_without_vendor_severity_fails_closed(self) -> None:
        rows = (
            "i CVE-2026-12345 Unknown/Sec. "
            "kernel-core-5.14.0-687.24.1.el9_8.x86_64\n"
        )
        with self.assertRaisesRegex(ValueError, "could not parse"):
            parse_updateinfo(rows)

    def test_individual_cve_severities_are_parsed_by_exact_identity(self) -> None:
        output = """[
          {"CVE": "CVE-2026-43074", "severity": "moderate"},
          {"CVE": "CVE-2026-46242", "severity": "important"}
        ]"""
        self.assertEqual(
            parse_cve_severities(
                output,
                ("CVE-2026-43074", "CVE-2026-46242"),
            ),
            {
                "CVE-2026-43074": "Moderate",
                "CVE-2026-46242": "Important",
            },
        )

    def test_missing_individual_cve_severity_fails_closed(self) -> None:
        with self.assertRaisesRegex(SecurityCoverageError, "no severity") as caught:
            parse_cve_severities(
                '[{"CVE":"CVE-2026-46242","severity":"important"}]',
                ("CVE-2026-43074", "CVE-2026-46242"),
            )
        self.assertEqual(caught.exception.cves, ("CVE-2026-43074",))

    def test_missing_legacy_severity_can_be_deferred_to_vex(self) -> None:
        self.assertEqual(
            parse_cve_severities(
                '[{"CVE":"CVE-2026-46242","severity":"important"}]',
                ("CVE-2026-43074", "CVE-2026-46242"),
                require_complete=False,
            ),
            {"CVE-2026-46242": "Important"},
        )

    def test_vex_aggregate_severity_is_parsed_by_exact_identity(self) -> None:
        output = """{
          "document": {
            "tracking": {"id": "CVE-2025-54518"},
            "aggregate_severity": {"text": "Important"}
          }
        }"""
        self.assertEqual(
            parse_cve_vex_severity(output, "CVE-2025-54518"),
            "Important",
        )

    def test_vex_wrong_identity_fails_closed(self) -> None:
        output = """{
          "document": {
            "tracking": {"id": "CVE-2025-00000"},
            "aggregate_severity": {"text": "Important"}
          }
        }"""
        with self.assertRaisesRegex(ValueError, "unexpected CVE"):
            parse_cve_vex_severity(output, "CVE-2025-54518")

    def test_unrecognised_cve_severity_fails_closed(self) -> None:
        with self.assertRaises(SecurityCoverageError) as caught:
            parse_cve_severities(
                '[{"CVE":"CVE-2026-46242","severity":"unknown"}]',
                ("CVE-2026-46242",),
            )
        self.assertEqual(caught.exception.cves, ("CVE-2026-46242",))

    def test_unrelated_package_cve_rows_are_ignored(self) -> None:
        kernels = parse_repoquery(REPOQUERY, "kernel-core")
        rows = (
            "i CVE-2024-6501 Low/Sec. "
            "NetworkManager-1:1.48.10-2.el9_5.alma.1.x86_64\n"
            "i CVE-2026-22979 Important/Sec. "
            "kernel-core-5.14.0-687.25.1.el9_8.x86_64\n"
        )
        advisories = parse_updateinfo(rows)
        self.assertEqual(len(advisories), 1)
        self.assertEqual(advisories[0].cve, "CVE-2026-22979")

    def test_retained_advisory_need_not_have_downloadable_kernel(self) -> None:
        kernels = parse_repoquery(REPOQUERY, "kernel-core")
        rows = (
            "i CVE-2026-54321 Important/Sec. "
            "kernel-core-5.14.0-687.22.1.el9_8.x86_64\n"
        )
        advisories = parse_updateinfo(rows)
        self.assertEqual(advisories[0].kernel.release, "687.22.1.el9_8")

    def test_security_and_bugfix_notices_are_classified(self) -> None:
        rows = (
            "i ALSA-2026:38491 Important/Sec. "
            "kernel-core-5.14.0-687.25.1.el9_8.x86_64\n"
            "i RHBA-2026:39332 bugfix "
            "kernel-core-5.14.0-687.26.1.el9_8.x86_64\n"
        )
        notices = parse_notices(rows)
        self.assertEqual(
            [(item.kind, item.kernel.release) for item in notices],
            [
                ("security", "687.25.1.el9_8"),
                ("bugfix", "687.26.1.el9_8"),
            ],
        )


if __name__ == "__main__":
    unittest.main()
