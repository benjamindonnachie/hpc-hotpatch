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
                (staged / "var/lib/klp-policy/build/el9_8-x86_64").is_dir()
            )
            self.assertTrue((staged / "srv/klp/repo").is_dir())

            environment = (
                staged / "etc" / "livepatch-repo" / "el9_8-x86_64.env"
            )
            env_text = environment.read_text(encoding="utf-8")
            self.assertIn(f"REPOSITORY_ROOT={staged}/srv/klp/repo", env_text)
            self.assertIn(
                f"WORK_ROOT={staged}/var/lib/klp-policy/build/el9_8-x86_64",
                env_text,
            )
            self.assertIn(
                f"STATE_DIR={staged}/var/lib/livepatch-repo/el9_8-x86_64/state",
                env_text,
            )

            service_text = service.read_text(encoding="utf-8")
            self.assertIn("User=klp-build", service_text)
            self.assertIn("Group=klp-build", service_text)
            self.assertIn("${WORK_ROOT}", service_text)
            self.assertIn("${STATE_DIR}", service_text)
            self.assertIn("${REPOSITORY_ROOT}", service_text)

    def test_paths_and_build_account_are_customisable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            staged = Path(temporary) / "root"
            custom_work = Path(temporary) / "big-disk" / "work"
            custom_repo = Path(temporary) / "served" / "repo"
            custom_state = Path(temporary) / "state-area"
            subprocess.run(
                [
                    "bash",
                    str(INSTALLER),
                    "--root",
                    str(staged),
                    "--work-root",
                    str(custom_work),
                    "--repository-root",
                    str(custom_repo),
                    "--state-dir",
                    str(custom_state),
                    "--build-user",
                    "custom-klp",
                    "--build-group",
                    "custom-klp-grp",
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            environment = (
                staged / "etc" / "livepatch-repo" / "el9_8-x86_64.env"
            )
            env_text = environment.read_text(encoding="utf-8")
            self.assertIn(f"WORK_ROOT={custom_work}", env_text)
            self.assertIn(f"REPOSITORY_ROOT={custom_repo}", env_text)
            self.assertIn(f"STATE_DIR={custom_state}", env_text)
            self.assertTrue(custom_work.is_dir())
            self.assertTrue(custom_repo.is_dir())
            self.assertTrue(custom_state.is_dir())

            service = (
                staged
                / "etc"
                / "systemd"
                / "system"
                / "livepatch-repo-refresh@.service"
            )
            service_text = service.read_text(encoding="utf-8")
            self.assertIn("User=custom-klp", service_text)
            self.assertIn("Group=custom-klp-grp", service_text)

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
