"""Execute the packaged %post/%preun scriptlet logic with a recording fake
kpatch, so the correctness-critical install/load-guard/uninstall behaviour is
verified without a real kernel, RPM database or kpatch binary."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from livepatch_repo.models import BuildJob, KernelRelease
from livepatch_repo.packaging import scriptlet_texts


def _kernel(release: str) -> KernelRelease:
    return KernelRelease("kernel-core", "0", "5.14.0", release, "x86_64")


class TestScriptletBehaviour(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.root = Path(self._temporary.name)
        self.log = self.root / "kpatch.log"
        self.fake_kpatch = self.root / "kpatch"
        self.fake_kpatch.write_text(
            f'#!/bin/sh\necho "$@" >> "{self.log}"\n', encoding="utf-8"
        )
        self.fake_kpatch.chmod(0o755)
        self.bindir = self.root / "bin"
        self.bindir.mkdir()

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def _uname(self, running: str) -> None:
        uname = self.bindir / "uname"
        uname.write_text(f'#!/bin/sh\necho "{running}"\n', encoding="utf-8")
        uname.chmod(0o755)

    def _run(self, snippet: str) -> list[str]:
        if self.log.exists():
            self.log.unlink()
        localised = snippet.replace("/usr/sbin/kpatch", str(self.fake_kpatch))
        localised = localised.replace("/usr/bin/systemctl", str(self.fake_kpatch))
        subprocess.run(
            ["/bin/sh", "-c", localised],
            check=True,
            env={**os.environ, "PATH": f"{self.bindir}:{os.environ['PATH']}"},
            timeout=30,
        )
        if not self.log.exists():
            return []
        return [line for line in self.log.read_text().splitlines() if line]

    def test_post_restarts_loader_only_on_matching_running_kernel(self) -> None:
        job = BuildJob(
            _kernel("687.24.1.el9_8"),
            _kernel("687.25.1.el9_8"),
            ("CVE-2026-12345",),
            "planned",
            "kpatch-build",
        )
        post, _ = scriptlet_texts(job, job.module_name)

        self._uname(job.base.nvra)
        matching = self._run(post)
        self.assertEqual(len(matching), 2)
        self.assertTrue(
            matching[0].startswith(f"install --kernel-version {job.base.nvra}")
        )
        self.assertEqual(matching[1], "restart kpatch.service")

        self._uname("9.9.9-other.el9_8.x86_64")
        other = self._run(post)
        self.assertEqual(len(other), 1)
        self.assertTrue(
            other[0].startswith(f"install --kernel-version {job.base.nvra}")
        )

    def test_preun_uninstalls_the_packages_own_module(self) -> None:
        job = BuildJob(
            _kernel("687.24.1.el9_8"),
            _kernel("687.25.1.el9_8"),
            ("CVE-2026-12345",),
            "planned",
            "kpatch-build",
        )
        _, preun = scriptlet_texts(job, job.module_name)
        self._uname(job.base.nvra)
        calls = self._run(preun)
        self.assertEqual(
            calls,
            [f"uninstall --kernel-version {job.base.nvra} {job.module_name}"],
        )

    def test_upgrade_supersession_targets_distinct_modules(self) -> None:
        base = _kernel("687.24.1.el9_8")
        old = BuildJob(base, _kernel("687.25.1.el9_8"), ("CVE-2026-1",),
                       "planned", "kpatch-build")
        new = BuildJob(base, _kernel("687.26.1.el9_8"), ("CVE-2026-1", "CVE-2026-2"),
                       "planned", "kpatch-build")
        self.assertNotEqual(old.module_name, new.module_name)

        new_post, _ = scriptlet_texts(new, new.module_name)
        _, old_preun = scriptlet_texts(old, old.module_name)

        # RPM upgrade order: the new package's %post runs, then the old
        # package's %preun. The loader service is restarted for the new
        # module; the old module (a distinct name) is then uninstalled from
        # persistent storage.
        self._uname(base.nvra)
        loaded = self._run(new_post)
        self.assertTrue(any(f"{new.module_name}.ko" in call for call in loaded))
        self.assertIn("restart kpatch.service", loaded)
        removed = self._run(old_preun)
        self.assertEqual(
            removed,
            [f"uninstall --kernel-version {base.nvra} {old.module_name}"],
        )


if __name__ == "__main__":
    unittest.main()
