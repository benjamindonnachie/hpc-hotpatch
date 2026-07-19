import json
import tempfile
import unittest
from pathlib import Path

from livepatch_repo.config import Config
from livepatch_repo.escalation import (
    SecurityCoverageError,
    escalate_security_gap,
)
from livepatch_repo.models import KernelRelease


def _kernel(release: str) -> KernelRelease:
    return KernelRelease("kernel-core", "0", "5.14.0", release, "x86_64")


_BASE_CONFIG = dict(
    dnf_command="dnf",
    kernel_package="kernel-core",
    architecture="x86_64",
    distro_stream="el9_8",
    selector_command_template="sel",
    kpatch_build_command="kpatch-build",
    klp_build_command_template="",
    modinfo_command="modinfo",
    rpmbuild_command="rpmbuild",
)


class TestSecurityEscalation(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.state = Path(self._temporary.name)
        self.base = _kernel("687.22.1.el9_8")
        self.target = _kernel("687.25.1.el9_8")
        self.error = SecurityCoverageError(
            "security data has no severity for: CVE-2026-40001",
            base=self.base,
            target=self.target,
            cves=("CVE-2026-40001",),
        )

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def _config(self, **overrides) -> Config:
        return Config(**{**_BASE_CONFIG, **overrides})

    def _record(self) -> dict:
        return json.loads(
            (self.state / "escalation.json").read_text(encoding="utf-8")
        )

    def test_alert_only_writes_durable_record_without_command(self) -> None:
        config = self._config()  # no escalation command
        record = escalate_security_gap(
            config=config, state_dir=self.state, error=self.error
        )
        self.assertEqual(record["action"], "alert-only")
        self.assertEqual(record["kind"], "security-coverage-gap")
        self.assertIsNone(record["notified_at"])
        on_disk = self._record()
        self.assertEqual(on_disk["base"], self.base.nvra)
        self.assertEqual(on_disk["target"], self.target.nvra)
        self.assertEqual(on_disk["cves"], ["CVE-2026-40001"])

    def test_configured_command_receives_gap_context(self) -> None:
        marker = self.state / "escalation-call.txt"
        script = self.state / "notify.sh"
        script.write_text(
            "#!/bin/sh\n"
            f'printf "%s|%s|%s|%s\\n" "$1" "$2" "$3" "$4" > "{marker}"\n',
            encoding="utf-8",
        )
        script.chmod(0o755)
        config = self._config(
            security_escalation_command_template=(
                f"{script} {{base}} {{target}} {{cves}} {{report}}"
            )
        )
        record = escalate_security_gap(
            config=config, state_dir=self.state, error=self.error
        )
        self.assertEqual(record["action"], "command")
        self.assertIsNotNone(record["notified_at"])
        fields = marker.read_text(encoding="utf-8").strip().split("|")
        self.assertEqual(fields[0], self.base.nvra)
        self.assertEqual(fields[1], self.target.nvra)
        self.assertEqual(fields[2], "CVE-2026-40001")
        self.assertEqual(fields[3], str(self.state / "escalation.json"))

    def test_identical_gap_is_not_notified_twice(self) -> None:
        counter = self.state / "count"
        script = self.state / "count.sh"
        script.write_text(
            f'#!/bin/sh\nprintf x >> "{counter}"\n', encoding="utf-8"
        )
        script.chmod(0o755)
        config = self._config(
            security_escalation_command_template=f"{script} {{base}}"
        )
        escalate_security_gap(config=config, state_dir=self.state, error=self.error)
        escalate_security_gap(config=config, state_dir=self.state, error=self.error)
        self.assertEqual(counter.read_text(encoding="utf-8"), "x")

    def test_changed_gap_notifies_again(self) -> None:
        counter = self.state / "count"
        script = self.state / "count.sh"
        script.write_text(
            f'#!/bin/sh\nprintf x >> "{counter}"\n', encoding="utf-8"
        )
        script.chmod(0o755)
        config = self._config(
            security_escalation_command_template=f"{script} {{base}}"
        )
        escalate_security_gap(config=config, state_dir=self.state, error=self.error)
        wider = SecurityCoverageError(
            "security data has no severity for: CVE-2026-40001, CVE-2026-40002",
            base=self.base,
            target=self.target,
            cves=("CVE-2026-40001", "CVE-2026-40002"),
        )
        escalate_security_gap(config=config, state_dir=self.state, error=wider)
        self.assertEqual(counter.read_text(encoding="utf-8"), "xx")

    def test_command_failure_is_recorded_and_not_raised(self) -> None:
        config = self._config(
            security_escalation_command_template="/nonexistent/notify {base}"
        )
        record = escalate_security_gap(
            config=config, state_dir=self.state, error=self.error
        )
        self.assertIn("command_error", record)
        self.assertIsNone(record["notified_at"])


if __name__ == "__main__":
    unittest.main()
