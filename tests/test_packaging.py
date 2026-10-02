import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from livepatch_repo.models import BuildJob, KernelRelease
from livepatch_repo.packaging import (
    package_name,
    prepare_rpmbuild,
    scriptlet_texts,
)


class TestRpmPackaging(unittest.TestCase):
    def setUp(self) -> None:
        base = KernelRelease(
            "kernel-core", "0", "5.14.0", "687.24.1.el9_8", "x86_64"
        )
        target = KernelRelease(
            "kernel-core", "0", "5.14.0", "687.25.1.el9_8", "x86_64"
        )
        self.job = BuildJob(
            base,
            target,
            ("CVE-2026-12345",),
            "planned",
            "kpatch-build",
        )

    def test_spec_provides_exact_base_and_installs_through_kpatch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            module = root / "module.ko"
            module.write_bytes(b"module")
            manifest = root / "selection.json"
            manifest.write_text(json.dumps({"covered": True}), encoding="utf-8")
            inputs = prepare_rpmbuild(
                self.job,
                module=module,
                selection_manifest=manifest,
                topdir=root / "rpmbuild",
                rpm_release=3,
            )
            spec = inputs.spec.read_text(encoding="utf-8")
            self.assertIn(
                f"Name:           {package_name(self.job)}",
                spec,
            )
            self.assertIn(
                f"Provides:       kpatch-patch = {self.job.base.nvra}",
                spec,
            )
            self.assertIn(
                f"Requires:       kernel-uname-r = {self.job.base.nvra}",
                spec,
            )
            self.assertIn(
                f"/usr/sbin/kpatch install --kernel-version "
                f"{self.job.base.nvra} %{{_libdir}}/kpatch/"
                f"{self.job.module_name}.ko",
                spec,
            )
            self.assertIn(
                f'if [ "$(uname -r)" = "{self.job.base.nvra}" ]; then',
                spec,
            )
            self.assertIn("/usr/bin/systemctl restart kpatch.service", spec)
            self.assertIn("Requires(post): systemd", spec)
            self.assertIn("%posttrans", spec)
            self.assertEqual(
                spec.count(
                    f"/usr/sbin/kpatch install --kernel-version "
                    f"{self.job.base.nvra} %{{_libdir}}/kpatch/"
                    f"{self.job.module_name}.ko"
                ),
                2,
            )
            self.assertIn(
                f"kpatch uninstall --kernel-version {self.job.base.nvra} "
                f"{self.job.module_name}",
                spec,
            )
            self.assertIn("Release:        3.el9_8", spec)

    def test_package_name_matches_kpatch_dnf_native_convention(self) -> None:
        self.assertEqual(
            package_name(self.job),
            "kpatch-patch-5_14_0-687_24_1",
        )

    def test_existing_module_identity_can_be_preserved_for_migration(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            module = root / "module.ko"
            module.write_bytes(b"module")
            manifest = root / "selection.json"
            manifest.write_text("{}", encoding="utf-8")
            legacy_name = "klp_cve_5_14_0_687_24_legacy"
            inputs = prepare_rpmbuild(
                self.job,
                module=module,
                selection_manifest=manifest,
                topdir=root / "rpmbuild",
                rpm_release=1,
                module_name=legacy_name,
            )
            spec = inputs.spec.read_text(encoding="utf-8")
            self.assertEqual(inputs.module_source.name, f"{legacy_name}.ko")
            self.assertIn(f"{legacy_name}.ko", spec)
            self.assertIn(
                f"kpatch uninstall --kernel-version {self.job.base.nvra} "
                f"{legacy_name}",
                spec,
            )

    def test_release_must_be_positive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            module = root / "module.ko"
            module.write_bytes(b"module")
            manifest = root / "selection.json"
            manifest.write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "at least 1"):
                prepare_rpmbuild(
                    self.job,
                    module=module,
                    selection_manifest=manifest,
                    topdir=root / "rpmbuild",
                    rpm_release=0,
                )

    def test_scriptlets_guard_load_and_remove_old_module_on_upgrade(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            recorder = root / "kpatch"
            uname = root / "uname"
            log = root / "calls"
            recorder.write_text(
                "#!/bin/sh\n"
                f"printf '%s\\n' \"$*\" >> {log}\n",
                encoding="utf-8",
            )
            recorder.chmod(0o755)
            uname.write_text(
                "#!/bin/sh\n"
                f"printf '%s\\n' '{self.job.base.nvra}'\n",
                encoding="utf-8",
            )
            uname.chmod(0o755)
            old_module = "klp_old_target_digest"
            new_module = "klp_new_target_digest"
            post, _ = scriptlet_texts(self.job, new_module)
            _, old_preun = scriptlet_texts(self.job, old_module)
            script = (
                post.replace("/usr/sbin/kpatch", str(recorder))
                .replace("/usr/bin/systemctl", str(recorder))
                .replace("uname -r", f"{uname} -r")
                .replace("%{_libdir}", "/usr/lib64")
                + "\n"
                + old_preun.replace("/usr/sbin/kpatch", str(recorder))
                + "\n"
            )
            subprocess.run(("/bin/sh", "-c", script), check=True)
            self.assertEqual(
                log.read_text(encoding="utf-8").splitlines(),
                [
                    (
                        f"install --kernel-version {self.job.base.nvra} "
                        f"/usr/lib64/kpatch/{new_module}.ko"
                    ),
                    "restart kpatch.service",
                    (
                        f"uninstall --kernel-version {self.job.base.nvra} "
                        f"{old_module}"
                    ),
                ],
            )
            log.unlink()
            uname.write_text(
                "#!/bin/sh\nprintf '%s\\n' 'different-kernel'\n",
                encoding="utf-8",
            )
            subprocess.run(
                (
                    "/bin/sh",
                    "-c",
                    post.replace("/usr/sbin/kpatch", str(recorder))
                    .replace("/usr/bin/systemctl", str(recorder))
                    .replace("uname -r", f"{uname} -r")
                    .replace("%{_libdir}", "/usr/lib64"),
                ),
                check=True,
            )
            self.assertEqual(
                log.read_text(encoding="utf-8").splitlines(),
                [
                    (
                        f"install --kernel-version {self.job.base.nvra} "
                        f"/usr/lib64/kpatch/{new_module}.ko"
                    )
                ],
            )

    def test_posttrans_repairs_same_module_name_upgrade(self) -> None:
        post, preun = scriptlet_texts(self.job, self.job.module_name)
        self.assertIn(f"{self.job.module_name}.ko", post)
        self.assertIn(f" {self.job.module_name} || :", preun)

        # The generated spec repeats %post as %posttrans.  Therefore an old
        # release which uninstalls the same module name during upgrade is
        # followed by a final install/restart of the new payload.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            module = root / "module.ko"
            module.write_bytes(b"module")
            manifest = root / "selection.json"
            manifest.write_text("{}", encoding="utf-8")
            inputs = prepare_rpmbuild(
                self.job,
                module=module,
                selection_manifest=manifest,
                topdir=root / "rpmbuild",
                rpm_release=2,
            )
            spec = inputs.spec.read_text(encoding="utf-8")
            posttrans = spec.split("%posttrans\n", 1)[1].split("\n%files", 1)[0]
            self.assertIn(
                f'[ -d "/sys/module/{self.job.module_name}" ]', posttrans
            )
            self.assertIn(
                f"/usr/sbin/kpatch force unload {self.job.module_name} || :",
                posttrans,
            )
            self.assertTrue(posttrans.strip().endswith(post.strip()))


if __name__ == "__main__":
    unittest.main()
