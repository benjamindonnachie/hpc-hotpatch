import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from livepatch_repo.cli import main
from livepatch_repo.config import load_config
from livepatch_repo.escalation import SecurityCoverageError


ROOT = Path(__file__).resolve().parents[1]


class TestPlanningCli(unittest.TestCase):
    def test_fixture_plan_is_written_atomically(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "state" / "plan.json"
            completed = Mock(stdout="5.14.0-687.22.1.el9_8.x86_64\n")
            with patch("livepatch_repo.planner.subprocess.run", return_value=completed):
                result = main(
                    [
                        "plan",
                        "--config",
                        str(ROOT / "etc" / "livepatch-repo.conf.example"),
                        "--snapshot",
                        str(ROOT / "tests" / "fixtures" / "skipped-security.json"),
                        "--output",
                        str(output),
                    ]
                )
            self.assertEqual(result, 0)
            value = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(value["schema_version"], 2)
            self.assertEqual(value["base"]["release"], "687.22.1.el9_8")
            self.assertEqual(len(value["jobs"]), 1)
            self.assertTrue(all(job["status"] == "planned" for job in value["jobs"]))
            self.assertEqual(list(output.parent.glob("*.tmp")), [])
            config = load_config(ROOT / "etc" / "livepatch-repo.conf.example")
            self.assertEqual(
                config.eligible_cve_severities,
                ("Critical", "Important"),
            )
            self.assertEqual(config.metadata_pending_timeout_seconds, 86400)

    def test_reconcile_security_gap_has_distinct_exit_status(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch(
                "livepatch_repo.cli.reconcile_repository",
                side_effect=SecurityCoverageError("terminal build gap"),
            ):
                result = main(
                    [
                        "reconcile",
                        "--config",
                        str(ROOT / "etc" / "livepatch-repo.conf.example"),
                        "--state-dir",
                        str(root / "state"),
                        "--work-root",
                        str(root / "work"),
                        "--repository-root",
                        str(root / "repo"),
                    ]
                )
            self.assertEqual(result, 3)

    def test_reconcile_resolves_relative_paths_to_absolute(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "work").mkdir()
            original_cwd = Path.cwd()
            captured: dict[str, Path] = {}

            def _capture(**kwargs):
                captured.update(kwargs)
                return Mock(
                    target="test",
                    built=0,
                    published=0,
                    covered=0,
                    no_work=0,
                    metadata_pending=0,
                )

            try:
                os.chdir(root)
                with patch(
                    "livepatch_repo.cli.reconcile_repository", side_effect=_capture
                ):
                    result = main(
                        [
                            "reconcile",
                            "--config",
                            str(ROOT / "etc" / "livepatch-repo.conf.example"),
                            "--state-dir",
                            "state",
                            "--work-root",
                            "work",
                            "--repository-root",
                            "repo",
                        ]
                    )
            finally:
                os.chdir(original_cwd)
            self.assertEqual(result, 0)
            self.assertTrue(captured["state_dir"].is_absolute())
            self.assertTrue(captured["work_root"].is_absolute())
            self.assertTrue(captured["repository_root"].is_absolute())
            self.assertEqual(captured["state_dir"], root / "state")
            self.assertEqual(captured["work_root"], root / "work")
            self.assertEqual(captured["repository_root"], root / "repo")


if __name__ == "__main__":
    unittest.main()
