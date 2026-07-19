from pathlib import Path
import os
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "sbin" / "install.sh"


class TestCentralInstaller(unittest.TestCase):
    def test_staged_install_preserves_operator_configuration(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            staged = Path(temporary) / "root"
            subprocess.run(
                ["bash", str(INSTALLER), "--root", str(staged)],
                check=True,
                capture_output=True,
                text=True,
            )
            package = (
                staged
                / "opt"
                / "livepatch-repo"
                / "livepatch_repo"
                / "__main__.py"
            )
            config = (
                staged / "etc" / "livepatch-repo" / "el9_8-x86_64.conf"
            )
            service = (
                staged
                / "etc"
                / "systemd"
                / "system"
                / "livepatch-repo-refresh@.service"
            )
            self.assertTrue(package.is_file())
            self.assertTrue(service.is_file())
            self.assertEqual(os.stat(config).st_mode & 0o777, 0o640)
            config.write_text("operator configuration\n", encoding="utf-8")
            subprocess.run(
                ["bash", str(INSTALLER), "--root", str(staged)],
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertEqual(
                config.read_text(encoding="utf-8"),
                "operator configuration\n",
            )
            self.assertTrue(
                (
                    staged
                    / "var/lib/livepatch-repo/el9_8-x86_64/state"
                ).is_dir()
            )
            self.assertTrue(
                (staged / "srv/livepatch-repo/alma/9/x86_64").is_dir()
            )

    def test_unknown_argument_fails(self) -> None:
        completed = subprocess.run(
            ["bash", str(INSTALLER), "--unknown"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn("unknown argument", completed.stderr)

    def test_dry_run_does_not_enable_timer_by_default(self) -> None:
        completed = subprocess.run(
            ["bash", str(INSTALLER), "--dry-run"],
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertNotIn("systemctl enable", completed.stdout)
        self.assertIn("timer was not enabled", completed.stderr)


if __name__ == "__main__":
    unittest.main()
