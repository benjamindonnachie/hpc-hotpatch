import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from livepatch_repo.cli import main
from livepatch_repo.config import load_config


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


if __name__ == "__main__":
    unittest.main()
