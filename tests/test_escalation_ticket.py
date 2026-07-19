import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from urllib.parse import parse_qs, urlparse

from livepatch_repo import escalation_ticket as et


_REPORT = {
    "schema_version": 1,
    "kind": "security-coverage-gap",
    "raised_at": "2026-07-19T16:00:00Z",
    "base": "5.14.0-687.22.1.el9_8.x86_64",
    "target": "5.14.0-687.25.1.el9_8.x86_64",
    "cves": ["CVE-2026-40002", "CVE-2026-40001"],
    "reason": "security data has no severity for: CVE-2026-40001",
    "signature": [None, None, []],
    "action": "command",
}


class TestTicketConstruction(unittest.TestCase):
    def test_build_ticket_fields(self) -> None:
        ticket = et.build_ticket(_REPORT)
        self.assertEqual(ticket["schema_version"], et.TICKET_SCHEMA_VERSION)
        self.assertEqual(ticket["kind"], "fleet-reboot-request")
        self.assertEqual(ticket["base"], _REPORT["base"])
        self.assertEqual(ticket["target"], _REPORT["target"])
        # CVEs are normalised and sorted.
        self.assertEqual(
            ticket["cves"], ["CVE-2026-40001", "CVE-2026-40002"]
        )
        self.assertEqual(ticket["source"]["system"], "central-livepatch-repo")
        self.assertEqual(ticket["source"]["report_kind"], "security-coverage-gap")

    def test_ticket_id_is_stable_and_order_independent(self) -> None:
        a = et.build_ticket(_REPORT)["ticket_id"]
        shuffled = {**_REPORT, "cves": ["CVE-2026-40001", "CVE-2026-40002"]}
        b = et.build_ticket(shuffled)["ticket_id"]
        self.assertEqual(a, b)

    def test_ticket_id_changes_with_cves(self) -> None:
        a = et.build_ticket(_REPORT)["ticket_id"]
        wider = {**_REPORT, "cves": _REPORT["cves"] + ["CVE-2026-40003"]}
        self.assertNotEqual(a, et.build_ticket(wider)["ticket_id"])

    def test_build_ticket_rejects_bad_cves(self) -> None:
        with self.assertRaises(ValueError):
            et.build_ticket({**_REPORT, "cves": "not-a-list"})


class TestTriggerRequest(unittest.TestCase):
    def test_request_url_and_form(self) -> None:
        ticket = et.build_ticket(_REPORT)
        request = et.trigger_request(
            "https://gitlab.example.com/",
            "42",
            "secret-token",
            "main",
            et.pipeline_variables(ticket),
        )
        self.assertEqual(request.method, "POST")
        self.assertEqual(
            urlparse(request.full_url).path,
            "/api/v4/projects/42/trigger/pipeline",
        )
        form = parse_qs(request.data.decode())
        self.assertEqual(form["token"], ["secret-token"])
        self.assertEqual(form["ref"], ["main"])
        self.assertEqual(form["variables[LP_BASE]"], [_REPORT["base"]])
        self.assertEqual(
            form["variables[LP_CVES]"],
            ["CVE-2026-40001,CVE-2026-40002"],
        )
        self.assertEqual(form["variables[LP_TICKET_ID]"], [ticket["ticket_id"]])


class TestCli(unittest.TestCase):
    def _report_file(self, tmp: Path) -> Path:
        path = tmp / "escalation.json"
        path.write_text(json.dumps(_REPORT), encoding="utf-8")
        return path

    def test_unconfigured_is_alert_only_noop(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report = self._report_file(Path(temporary))
            out, err = io.StringIO(), io.StringIO()
            with mock.patch("sys.stdout", out), mock.patch("sys.stderr", err):
                # No GitLab env/args → not configured.
                code = et.main(["--report", str(report), "--gitlab-url", "",
                                "--project-id", "", "--trigger-token", ""])
            self.assertEqual(code, 0)
            emitted = json.loads(out.getvalue())
            self.assertFalse(emitted["sent"])
            self.assertIn("not configured", err.getvalue())

    def test_configured_sends_trigger(self) -> None:
        sent = {}

        def fake_sender(request):
            sent["url"] = request.full_url
            sent["form"] = parse_qs(request.data.decode())
            return '{"id": 1234, "status": "created"}'

        with tempfile.TemporaryDirectory() as temporary:
            report = self._report_file(Path(temporary))
            out = io.StringIO()
            with mock.patch("sys.stdout", out):
                code = et.main(
                    [
                        "--report", str(report),
                        "--gitlab-url", "https://gitlab.example.com",
                        "--project-id", "42",
                        "--trigger-token", "secret",
                        "--ref", "main",
                    ],
                    sender=fake_sender,
                )
            self.assertEqual(code, 0)
            self.assertTrue(json.loads(out.getvalue())["sent"])
            self.assertIn("/api/v4/projects/42/trigger/pipeline", sent["url"])
            self.assertEqual(sent["form"]["token"], ["secret"])
            self.assertEqual(
                sent["form"]["variables[LP_TARGET]"], [_REPORT["target"]]
            )

    def test_send_failure_returns_nonzero(self) -> None:
        def failing_sender(request):
            raise OSError("connection refused")

        with tempfile.TemporaryDirectory() as temporary:
            report = self._report_file(Path(temporary))
            with mock.patch("sys.stdout", io.StringIO()), mock.patch(
                "sys.stderr", io.StringIO()
            ):
                code = et.main(
                    [
                        "--report", str(report),
                        "--gitlab-url", "https://gitlab.example.com",
                        "--project-id", "42",
                        "--trigger-token", "secret",
                    ],
                    sender=failing_sender,
                )
            self.assertEqual(code, 1)

    def test_dry_run_never_sends(self) -> None:
        def exploding_sender(request):
            raise AssertionError("dry-run must not send")

        with tempfile.TemporaryDirectory() as temporary:
            report = self._report_file(Path(temporary))
            with mock.patch("sys.stdout", io.StringIO()):
                code = et.main(
                    [
                        "--report", str(report),
                        "--gitlab-url", "https://gitlab.example.com",
                        "--project-id", "42",
                        "--trigger-token", "secret",
                        "--dry-run",
                    ],
                    sender=exploding_sender,
                )
            self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
