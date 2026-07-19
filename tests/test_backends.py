from pathlib import Path
import tempfile
import unittest

from livepatch_repo.backends import build_invocation
from livepatch_repo.models import BuildJob, KernelRelease


class TestBuilderAdapters(unittest.TestCase):
    def test_kpatch_command_uses_atomic_replace_default(self) -> None:
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
            patch = root / "source.patch"
            patch.write_text("diff", encoding="utf-8")
            source = root / "source"
            source.mkdir()
            config = root / "config"
            config.write_text("CONFIG_LIVEPATCH=y\n", encoding="utf-8")
            vmlinux = root / "vmlinux"
            vmlinux.write_bytes(b"vmlinux")
            invocation = build_invocation(
                job,
                patch=patch,
                output_dir=root / "output",
                selection={"base_source_tree": str(source)},
                kpatch_build_command="kpatch-build",
                kpatch_config_template=str(config),
                kpatch_vmlinux_template=str(vmlinux),
                klp_build_command_template="",
            )
        self.assertEqual(invocation.command[0], "kpatch-build")
        self.assertIn("--sourcedir", invocation.command)
        self.assertIn("--config", invocation.command)
        self.assertIn("--vmlinux", invocation.command)
        self.assertIn("--name", invocation.command)
        self.assertNotIn("--non-replace", invocation.command)
        self.assertLessEqual(len(job.module_name), 55)
        self.assertEqual(
            job.module_name,
            "klp_687_24_1_el9_8_to_687_25_1",
        )

    def test_klp_requires_field_verified_template(self) -> None:
        base = KernelRelease(
            "kernel-core", "0", "6.12.0", "1.el10_0", "x86_64"
        )
        target = KernelRelease(
            "kernel-core", "0", "6.12.0", "2.el10_0", "x86_64"
        )
        job = BuildJob(
            base,
            target,
            ("CVE-2026-12345",),
            "planned",
            "klp-build",
        )
        with tempfile.TemporaryDirectory() as temporary:
            patch = Path(temporary) / "source.patch"
            patch.write_text("diff", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "not configured"):
                build_invocation(
                    job,
                    patch=patch,
                    output_dir=Path(temporary) / "output",
                    selection={},
                    kpatch_build_command="kpatch-build",
                    kpatch_config_template="/boot/config-{base}",
                    kpatch_vmlinux_template=(
                        "/usr/lib/debug/lib/modules/{base}/vmlinux"
                    ),
                    klp_build_command_template="",
                )


if __name__ == "__main__":
    unittest.main()
