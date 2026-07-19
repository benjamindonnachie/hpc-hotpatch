import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from livepatch_repo.models import BuildJob, KernelRelease
from livepatch_repo.packaging import (
    find_built_rpm,
    package_name,
    prepare_rpmbuild,
    rpmbuild_invocation,
)


@unittest.skipUnless(
    shutil.which("rpmbuild") and shutil.which("rpm") and Path("/bin/true").is_file(),
    "RPM integration tools are not available",
)
class TestRpmIntegration(unittest.TestCase):
    def test_real_rpmbuild_reports_exact_identity_and_scriptlets(self) -> None:
        base = KernelRelease(
            "kernel-core", "0", "5.14.0", "687.24.1.el9_8", "x86_64"
        )
        target = KernelRelease(
            "kernel-core", "0", "5.14.0", "687.25.1.el9_8", "x86_64"
        )
        job = BuildJob(
            base,
            target,
            ("CVE-2026-12345",),
            "planned",
            "kpatch-build",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            module = root / f"{job.module_name}.ko"
            shutil.copy2("/bin/true", module)
            manifest = root / "selection.json"
            manifest.write_text(
                json.dumps({"covered_cves": list(job.cves)}),
                encoding="utf-8",
            )
            inputs = prepare_rpmbuild(
                job,
                module=module,
                selection_manifest=manifest,
                topdir=root / "rpmbuild",
                rpm_release=7,
            )
            completed = subprocess.run(
                rpmbuild_invocation(inputs, "rpmbuild"),
                check=True,
                capture_output=True,
                text=True,
                timeout=300,
            )
            output = tuple(
                line + "\n"
                for line in (completed.stdout + completed.stderr).splitlines()
            )
            rpm = find_built_rpm(inputs, output)
            identity = subprocess.run(
                (
                    "rpm",
                    "-qp",
                    "--qf",
                    "%{NAME}\\t%{VERSION}\\t%{RELEASE}\\t%{ARCH}",
                    str(rpm),
                ),
                check=True,
                capture_output=True,
                text=True,
                timeout=60,
            ).stdout
            self.assertEqual(
                identity,
                f"{package_name(job)}\t0\t7.el9_8\tx86_64",
            )
            scripts = subprocess.run(
                ("rpm", "-qp", "--scripts", str(rpm)),
                check=True,
                capture_output=True,
                text=True,
                timeout=60,
            ).stdout
            self.assertIn(
                f"kpatch install --kernel-version {job.base.nvra}",
                scripts,
            )
            self.assertIn(
                f'if [ "$(uname -r)" = "{job.base.nvra}" ]; then',
                scripts,
            )
            self.assertIn("systemctl restart kpatch.service", scripts)
            self.assertIn(
                f"kpatch uninstall --kernel-version {job.base.nvra} "
                f"{job.module_name}",
                scripts,
            )
