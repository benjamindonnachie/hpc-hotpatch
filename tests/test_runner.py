import json
import hashlib
import io
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock

from livepatch_repo.config import Config
from livepatch_repo.models import BuildJob, KernelRelease
from livepatch_repo.packaging import package_name
from livepatch_repo.runner import CommandResult, CommandRunner, run_job


class FakeRunner(CommandRunner):
    def __init__(self, job: BuildJob):
        self.job = job
        self.commands: list[tuple[str, ...]] = []
        self.run_options: list[dict[str, object]] = []

    def run(self, command, *, log: Path, **kwargs) -> CommandResult:
        command = tuple(command)
        self.commands.append(command)
        self.run_options.append(dict(kwargs))
        log.parent.mkdir(parents=True, exist_ok=True)
        log.write_text(log.read_text(encoding="utf-8") if log.exists() else "")
        if command[0] == "selector":
            patch = Path(command[command.index("--patch") + 1])
            manifest = Path(command[command.index("--manifest") + 1])
            patch.write_text("diff --git a/a b/a\n", encoding="utf-8")
            source = manifest.parent / "base-source"
            source.mkdir(exist_ok=True)
            (source / "source-marker").write_text("immutable input\n")
            manifest.write_text(
                json.dumps(
                    {
                        "base": self.job.base.nvra,
                        "target": self.job.target.nvra,
                        "covered_cves": list(self.job.cves),
                        "base_source_tree": str(source),
                    }
                ),
                encoding="utf-8",
            )
        elif command[0] == "kpatch-build":
            output = Path(command[command.index("--output") + 1])
            output.mkdir(parents=True, exist_ok=True)
            (output / f"{self.job.module_name}.ko").write_bytes(b"module")
        elif command[0] == "rpmbuild":
            topdir = Path(command[command.index("--define") + 1].split(" ", 1)[1])
            rpm_dir = topdir / "RPMS" / self.job.base.arch
            rpm_dir.mkdir(parents=True, exist_ok=True)
            rpm = (
                rpm_dir
                / f"{package_name(self.job)}-0-1.el9_8.{self.job.base.arch}.rpm"
            )
            rpm.write_bytes(b"rpm")
            return CommandResult((f"Wrote: {rpm}\n",), 0.01)
        else:
            raise AssertionError(f"unexpected command: {command}")
        return CommandResult((), 0.01)

    def output(self, command) -> str:
        command = tuple(command)
        if command[1:3] == ("-F", "name"):
            return self.job.module_name
        if command[1:3] == ("-F", "vermagic"):
            return f"{self.job.base.nvra} SMP mod_unload"
        if command[1:3] == ("-qp", "--qf"):
            return (
                f"{package_name(self.job)}\t0\t1.el9_8\t"
                f"{self.job.base.arch}"
            )
        raise AssertionError(f"unexpected output command: {command}")


class TestJobRunner(unittest.TestCase):
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
        self.config = Config(
            dnf_command="dnf",
            kernel_package="kernel-core",
            architecture="x86_64",
            distro_stream="el9_8",
            selector_command_template=(
                "selector --patch {patch} --manifest {selection_manifest}"
            ),
            kpatch_build_command="kpatch-build",
            klp_build_command_template="",
            modinfo_command="modinfo",
            rpmbuild_command="rpmbuild",
        )

    def test_complete_job_reaches_built_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config_file = root / "config"
            config_file.write_text("CONFIG_LIVEPATCH=y\n", encoding="utf-8")
            vmlinux = root / "vmlinux"
            vmlinux.write_bytes(b"vmlinux")
            config = Config(
                **{
                    **self.config.__dict__,
                    "kpatch_config_template": str(config_file),
                    "kpatch_vmlinux_template": str(vmlinux),
                }
            )
            result = run_job(
                self.job,
                config=config,
                work_root=root,
                rpm_release=1,
                runner=FakeRunner(self.job),
            )
            self.assertEqual(result.status, "built")
            self.assertTrue(Path(result.rpm).is_file())
            status = json.loads(
                (
                    root / self.job.job_id / "status.json"
                ).read_text(encoding="utf-8")
            )
            self.assertEqual(status["status"], "built")

    def test_kpatch_build_uses_private_source_and_cache(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config_file = root / "config"
            config_file.write_text("CONFIG_LIVEPATCH=y\n", encoding="utf-8")
            vmlinux = root / "vmlinux"
            vmlinux.write_bytes(b"vmlinux")
            config = Config(
                **{
                    **self.config.__dict__,
                    "kpatch_config_template": str(config_file),
                    "kpatch_vmlinux_template": str(vmlinux),
                }
            )
            runner = FakeRunner(self.job)

            run_job(
                self.job,
                config=config,
                work_root=root,
                rpm_release=1,
                runner=runner,
            )

            index = next(
                number
                for number, command in enumerate(runner.commands)
                if command[0] == "kpatch-build"
            )
            command = runner.commands[index]
            workspace = root / self.job.job_id
            self.assertEqual(
                Path(command[command.index("--sourcedir") + 1]).resolve(),
                (workspace / "build-source").resolve(),
            )
            self.assertEqual(
                runner.run_options[index]["environment"],
                {"CACHEDIR": str((workspace / "kpatch-cache").resolve())},
            )
            self.assertEqual(
                (workspace / "build-source" / "source-marker").read_text(),
                "immutable input\n",
            )

    def test_identical_effective_patch_skips_builder_and_packaging(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner = FakeRunner(self.job)
            patch_sha256 = hashlib.sha256(
                b"diff --git a/a b/a\n"
            ).hexdigest()

            result = run_job(
                self.job,
                config=self.config,
                work_root=root,
                rpm_release=2,
                runner=runner,
                reusable_patch_sha256=frozenset({patch_sha256}),
            )

            self.assertEqual(result.status, "effective-no-change")
            self.assertIsNone(result.rpm)
            self.assertEqual(result.patch_sha256, patch_sha256)
            self.assertEqual([command[0] for command in runner.commands], ["selector"])
            status = json.loads(
                (root / self.job.job_id / "status.json").read_text()
            )
            self.assertEqual(status["status"], "effective-no-change")
            self.assertEqual(status["patch_sha256"], patch_sha256)

    def test_each_job_keeps_its_own_build_paths(self) -> None:
        # Jobs run sequentially, but each must still receive a fully isolated
        # workspace (private kpatch cache and writable source) keyed by job id,
        # so re-running a base never mutates another job's build tree.
        older = KernelRelease(
            "kernel-core", "0", "5.14.0", "687.23.1.el9_8", "x86_64"
        )
        second = BuildJob(
            older,
            self.job.target,
            self.job.cves,
            "planned",
            "kpatch-build",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config_file = root / "config"
            config_file.write_text("CONFIG_LIVEPATCH=y\n", encoding="utf-8")
            vmlinux = root / "vmlinux"
            vmlinux.write_bytes(b"vmlinux")
            config = Config(
                **{
                    **self.config.__dict__,
                    "kpatch_config_template": str(config_file),
                    "kpatch_vmlinux_template": str(vmlinux),
                }
            )

            def execute(job):
                return run_job(
                    job,
                    config=config,
                    work_root=root,
                    rpm_release=1,
                    runner=FakeRunner(job),
                )

            results = tuple(execute(job) for job in (self.job, second))

            self.assertEqual(len({result.rpm for result in results}), 2)
            for job in (self.job, second):
                workspace = root / job.job_id
                for private in (
                    "build.log",
                    "build-source",
                    "kpatch-cache",
                    "module",
                    "rpmbuild",
                ):
                    self.assertTrue((workspace / private).exists())

    def test_selector_failure_is_recorded(self) -> None:
        config = Config(
            **{
                **self.config.__dict__,
                "selector_command_template": "",
            }
        )
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, "not configured"):
                run_job(
                    self.job,
                    config=config,
                    work_root=Path(temporary),
                    rpm_release=1,
                    runner=FakeRunner(self.job),
                )
            status = json.loads(
                (
                    Path(temporary) / self.job.job_id / "status.json"
                ).read_text(encoding="utf-8")
            )
            self.assertEqual(status["status"], "failed")

    def test_streaming_command_timeout_kills_process_group(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            started = time.monotonic()
            with self.assertRaisesRegex(ValueError, "timed out"):
                CommandRunner().run(
                    ("/bin/sh", "-c", "sleep 30"),
                    log=Path(temporary) / "timeout.log",
                    timeout_seconds=1,
                    termination_grace_seconds=1,
                )
            self.assertLess(time.monotonic() - started, 5)

    def test_timeout_reaps_lingering_child_when_leader_already_exited(self) -> None:
        # The main command exits quickly but spawns a background descendant that
        # keeps the stdout pipe open past the deadline. The group as a whole has
        # exceeded the phase deadline, so the run must kill it and time out.
        with tempfile.TemporaryDirectory() as temporary:
            started = time.monotonic()
            with self.assertRaisesRegex(ValueError, "timed out"):
                CommandRunner().run(
                    ("/bin/sh", "-c", "sleep 30 & echo done"),
                    log=Path(temporary) / "linger.log",
                    timeout_seconds=1,
                    termination_grace_seconds=1,
                )
            self.assertLess(time.monotonic() - started, 5)

    def test_streaming_output_flushes_console_and_log_immediately(self) -> None:
        class RecordingConsole(io.StringIO):
            def __init__(self) -> None:
                super().__init__()
                self.flushes = 0

            def flush(self) -> None:
                self.flushes += 1
                super().flush()

        with tempfile.TemporaryDirectory() as temporary:
            console = RecordingConsole()
            log = Path(temporary) / "stream.log"
            with mock.patch("sys.stdout", console):
                result = CommandRunner().run(
                    ("/bin/sh", "-c", "printf 'first\\nsecond\\n'"),
                    log=log,
                    timeout_seconds=5,
                    termination_grace_seconds=1,
                )
            self.assertEqual(result.output_lines, ("first\n", "second\n"))
            self.assertEqual(console.getvalue(), "first\nsecond\n")
            self.assertGreaterEqual(console.flushes, 2)
            self.assertIn("first\nsecond\n", log.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
