import json
from pathlib import Path
import tempfile
import unittest

from livepatch_repo.models import BuildJob, KernelRelease
from livepatch_repo.selection import (
    selection_invocation,
    validate_selection,
    write_advisory_evidence,
    write_requested_cves,
)


def job() -> BuildJob:
    base = KernelRelease(
        "kernel-core", "0", "5.14.0", "687.24.1.el9_8", "x86_64"
    )
    target = KernelRelease(
        "kernel-core", "0", "5.14.0", "687.25.1.el9_8", "x86_64"
    )
    return BuildJob(
        base,
        target,
        ("CVE-2026-12345",),
        "planned",
        "kpatch-build",
        (("CVE-2026-12345", ("182344",)),),
    )


class TestSelectionAdapter(unittest.TestCase):
    def test_complete_manifest_is_accepted(self) -> None:
        build_job = job()
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            command, paths = selection_invocation(
                build_job,
                workspace=workspace,
                command_template=(
                    "selector --base {base} --target {target} "
                    "--patch {patch} --manifest {selection_manifest} "
                    "--advisory-evidence {advisory_evidence}"
                ),
            )
            self.assertEqual(command[0], "selector")
            write_requested_cves(build_job, paths.requested_cves)
            write_advisory_evidence(build_job, paths.advisory_evidence)
            paths.patch.write_text("diff --git a/a b/a\n", encoding="utf-8")
            source = workspace / "base-source"
            source.mkdir()
            paths.manifest.write_text(
                json.dumps(
                    {
                        "base": build_job.base.nvra,
                        "target": build_job.target.nvra,
                        "covered_cves": list(build_job.cves),
                        "base_source_tree": str(source),
                    }
                ),
                encoding="utf-8",
            )
            value = validate_selection(build_job, paths)
            self.assertEqual(value["covered_cves"], list(build_job.cves))
            self.assertEqual(
                paths.requested_cves.read_text(encoding="utf-8"),
                "CVE-2026-12345\n",
            )
            evidence = json.loads(
                paths.advisory_evidence.read_text(encoding="utf-8")
            )
            self.assertEqual(
                evidence["cve_ticket_ids"],
                {"CVE-2026-12345": ["182344"]},
            )

    def test_partial_coverage_fails_closed(self) -> None:
        build_job = job()
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            _, paths = selection_invocation(
                build_job,
                workspace=workspace,
                command_template="selector {patch} {selection_manifest}",
            )
            paths.patch.write_text("diff", encoding="utf-8")
            paths.manifest.write_text(
                json.dumps(
                    {
                        "base": build_job.base.nvra,
                        "target": build_job.target.nvra,
                        "covered_cves": [],
                        "base_source_tree": str(workspace),
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "did not cover"):
                validate_selection(build_job, paths)


if __name__ == "__main__":
    unittest.main()
