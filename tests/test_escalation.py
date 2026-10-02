from datetime import datetime, timedelta, timezone
import json
import tempfile
import unittest
from pathlib import Path

from livepatch_repo.config import Config
from livepatch_repo.escalation import (
    SecurityCoverageError,
    escalate_security_gap,
    request_build_failure_review,
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

    def test_build_stage_notifies_after_metadata_stage_for_same_cve(self) -> None:
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
        build_error = SecurityCoverageError(
            "kpatch rejected an ELF section change",
            base=self.base,
            target=self.target,
            cves=("CVE-2026-40001",),
            failure_stage="build",
            failure_kind="unsupported-elf-section",
        )
        escalate_security_gap(
            config=config, state_dir=self.state, error=build_error
        )
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

    def test_build_failure_diagnostics_are_persisted(self) -> None:
        error = SecurityCoverageError(
            "unsupported ELF section change in kernel/futex/requeue.o",
            base=self.base,
            target=self.target,
            cves=("CVE-2026-43499",),
            failure_stage="build",
            failure_kind="unsupported-elf-section",
            diagnostics={
                "unsupported_changes": [
                    {
                        "object": "kernel/futex/requeue.o",
                        "sections": [".relaruntime_ptr_USER_PTR_MAX"],
                    }
                ]
            },
        )

        record = escalate_security_gap(
            config=self._config(), state_dir=self.state, error=error
        )

        self.assertEqual(record["failure_stage"], "build")
        self.assertEqual(record["failure_kind"], "unsupported-elf-section")
        self.assertEqual(
            record["diagnostics"]["unsupported_changes"][0]["object"],
            "kernel/futex/requeue.o",
        )


class TestBuildFailureReview(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.state = Path(self._temporary.name)
        self.base = _kernel("687.22.1.el9_8")
        self.target = _kernel("687.25.1.el9_8")
        self.error = SecurityCoverageError(
            "livepatch build failed: unreconcilable difference",
            base=self.base,
            target=self.target,
            cves=("CVE-2026-40001",),
            failure_stage="build",
            failure_kind="livepatch-build-failure",
        )
        self.now = datetime(2026, 8, 16, 9, 0, tzinfo=timezone.utc)

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def _config(self, **overrides) -> Config:
        return Config(**{**_BASE_CONFIG, **overrides})

    def test_unconfigured_escalates_immediately(self) -> None:
        result = request_build_failure_review(
            config=self._config(),
            state_dir=self.state,
            error=self.error,
            now=self.now,
        )
        self.assertFalse(result["under_review"])
        self.assertTrue(result["expired"])

    def test_first_occurrence_dispatches_and_holds_off_escalation(self) -> None:
        marker = self.state / "review-call.txt"
        script = self.state / "review.sh"
        script.write_text(
            f'#!/bin/sh\nprintf "%s|%s" "$1" "$2" > "{marker}"\n',
            encoding="utf-8",
        )
        script.chmod(0o755)
        config = self._config(
            build_failure_review_command_template=f"{script} {{base}} {{reason}}"
        )
        result = request_build_failure_review(
            config=config, state_dir=self.state, error=self.error, now=self.now
        )
        self.assertTrue(result["under_review"])
        self.assertFalse(result["expired"])
        self.assertTrue(marker.is_file())
        fields = marker.read_text(encoding="utf-8").split("|")
        self.assertEqual(fields[0], self.base.nvra)

    def test_repeat_failure_within_grace_holds_without_redispatching(self) -> None:
        counter = self.state / "count"
        script = self.state / "count.sh"
        script.write_text(
            f'#!/bin/sh\nprintf x >> "{counter}"\n', encoding="utf-8"
        )
        script.chmod(0o755)
        config = self._config(
            build_failure_review_command_template=f"{script} {{base}}",
            build_failure_review_grace_seconds=3600,
        )
        request_build_failure_review(
            config=config, state_dir=self.state, error=self.error, now=self.now
        )
        later = request_build_failure_review(
            config=config,
            state_dir=self.state,
            error=self.error,
            now=self.now + timedelta(minutes=30),
        )
        self.assertTrue(later["under_review"])
        self.assertEqual(counter.read_text(encoding="utf-8"), "x")

    def test_escalates_once_grace_window_elapses(self) -> None:
        script = self.state / "review.sh"
        script.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        script.chmod(0o755)
        config = self._config(
            build_failure_review_command_template=f"{script} {{base}}",
            build_failure_review_grace_seconds=3600,
        )
        request_build_failure_review(
            config=config, state_dir=self.state, error=self.error, now=self.now
        )
        expired = request_build_failure_review(
            config=config,
            state_dir=self.state,
            error=self.error,
            now=self.now + timedelta(hours=2),
        )
        self.assertFalse(expired["under_review"])
        self.assertTrue(expired["expired"])

    def test_dispatch_failure_does_not_hold_off_escalation(self) -> None:
        config = self._config(
            build_failure_review_command_template="/nonexistent/reviewer {base}"
        )
        result = request_build_failure_review(
            config=config, state_dir=self.state, error=self.error, now=self.now
        )
        self.assertFalse(result["under_review"])

    def test_new_failure_signature_resets_grace_window(self) -> None:
        script = self.state / "review.sh"
        script.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        script.chmod(0o755)
        config = self._config(
            build_failure_review_command_template=f"{script} {{base}}",
            build_failure_review_grace_seconds=3600,
        )
        request_build_failure_review(
            config=config, state_dir=self.state, error=self.error, now=self.now
        )
        different = SecurityCoverageError(
            "a completely different failure",
            base=self.base,
            target=self.target,
            cves=("CVE-2026-99999",),
            failure_stage="build",
            failure_kind="livepatch-build-failure",
        )
        result = request_build_failure_review(
            config=config,
            state_dir=self.state,
            error=different,
            now=self.now + timedelta(hours=2),
        )
        self.assertTrue(result["under_review"])


if __name__ == "__main__":
    unittest.main()
