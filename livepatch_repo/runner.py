from __future__ import annotations

import json
import hashlib
import os
import queue
import shlex
import signal
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping, Sequence

from .backends import build_invocation
from .config import Config
from .models import BuildJob
from .packaging import (
    find_built_rpm,
    package_name,
    prepare_rpmbuild,
    rpmbuild_invocation,
)
from .selection import (
    selection_invocation,
    validate_selection,
    write_advisory_evidence,
    write_requested_cves,
)
from .state import write_json_atomic


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class JobResult:
    job_id: str
    status: str
    rpm: str | None
    patch_sha256: str | None = None


@dataclass(frozen=True)
class CommandResult:
    output_lines: tuple[str, ...]
    elapsed_seconds: float


class CommandRunner:
    def run(
        self,
        command: Sequence[str],
        *,
        log: Path,
        timeout_seconds: int,
        termination_grace_seconds: int,
        environment: Mapping[str, str] | None = None,
        output_prefix: str = "",
    ) -> CommandResult:
        if timeout_seconds < 1:
            raise ValueError("command timeout must be at least one second")
        if termination_grace_seconds < 0:
            raise ValueError("command termination grace cannot be negative")
        log.parent.mkdir(parents=True, exist_ok=True)
        started = time.monotonic()
        output_lines: list[str] = []
        with log.open("a", encoding="utf-8") as handle:
            handle.write(f"$ {shlex.join(command)}\n")
            handle.flush()
            process = subprocess.Popen(
                list(command),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                start_new_session=True,
                env=(
                    {**os.environ, **environment}
                    if environment is not None
                    else None
                ),
            )
            assert process.stdout is not None
            lines: queue.Queue[str | None] = queue.Queue()

            def read_output() -> None:
                try:
                    for line in process.stdout:
                        lines.put(line)
                finally:
                    lines.put(None)

            reader = threading.Thread(target=read_output, daemon=True)
            reader.start()
            stream_finished = False
            timed_out = False
            while not stream_finished or process.poll() is None:
                remaining = timeout_seconds - (time.monotonic() - started)
                if remaining <= 0:
                    # The deadline covers the complete process group and its
                    # output stream, not merely the direct child. A leader can
                    # exit while a descendant keeps stdout open indefinitely.
                    timed_out = True
                    try:
                        os.killpg(process.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                    reader.join(timeout=termination_grace_seconds)
                    if reader.is_alive():
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                    break
                try:
                    line = lines.get(timeout=max(0.01, min(0.25, remaining)))
                except queue.Empty:
                    continue
                if line is None:
                    stream_finished = True
                    continue
                print(f"{output_prefix}{line}", end="", flush=True)
                handle.write(line)
                handle.flush()
                output_lines.append(line)
            while True:
                try:
                    line = lines.get_nowait()
                except queue.Empty:
                    break
                if line is not None:
                    print(f"{output_prefix}{line}", end="", flush=True)
                    handle.write(line)
                    output_lines.append(line)
            return_code = process.wait()
            process.stdout.close()
            reader.join(timeout=1)
        elapsed = time.monotonic() - started
        if timed_out:
            raise ValueError(
                f"command timed out after {timeout_seconds}s: {command[0]}"
            )
        if return_code:
            raise ValueError(
                f"command failed with exit {return_code}: {command[0]}"
            )
        return CommandResult(tuple(output_lines), elapsed)

    def output(self, command: Sequence[str]) -> str:
        try:
            completed = subprocess.run(
                list(command),
                check=True,
                capture_output=True,
                text=True,
                timeout=60,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise ValueError(f"command failed: {command[0]}: {error}") from error
        return completed.stdout.strip()


def _write_status(
    path: Path,
    job: BuildJob,
    status: str,
    *,
    error: str | None = None,
    rpm: Path | None = None,
    patch_sha256: str | None = None,
) -> None:
    value: dict[str, object] = {
        "schema_version": 1,
        "updated_at": _now(),
        "job": job.to_dict(),
        "status": status,
    }
    if error is not None:
        value["error"] = error
    if rpm is not None:
        value["rpm"] = str(rpm)
    if patch_sha256 is not None:
        value["patch_sha256"] = patch_sha256
    write_json_atomic(path, value)


def _verify_module(
    job: BuildJob, output_dir: Path, runner: CommandRunner, modinfo: str
) -> Path:
    modules = sorted(output_dir.rglob("*.ko"))
    if len(modules) != 1:
        raise ValueError(f"builder produced {len(modules)} kernel modules; expected 1")
    module = modules[0]
    embedded_name = runner.output((modinfo, "-F", "name", str(module)))
    if embedded_name != job.module_name:
        raise ValueError(
            f"module embeds name {embedded_name!r}, expected {job.module_name!r}"
        )
    vermagic = runner.output((modinfo, "-F", "vermagic", str(module)))
    if not vermagic.split() or vermagic.split()[0] != job.base.nvra:
        raise ValueError(
            f"module vermagic {vermagic!r} does not match base {job.base.nvra!r}"
        )
    return module


def _verify_rpm(
    job: BuildJob,
    rpm_release: int,
    rpm: Path,
    runner: CommandRunner,
    rpm_command: str,
) -> None:
    identity = runner.output(
        (
            rpm_command,
            "-qp",
            "--qf",
            "%{NAME}\\t%{VERSION}\\t%{RELEASE}\\t%{ARCH}",
            str(rpm),
        )
    ).split("\t")
    expected = (
        package_name(job),
        "0",
        f"{rpm_release}.{job.base.distro_stream}",
        job.base.arch,
    )
    if tuple(identity) != expected:
        raise ValueError(
            f"built RPM identity {tuple(identity)!r} does not match {expected!r}"
        )


def _materialise_build_source(source: Path, destination: Path) -> None:
    """Copy immutable prepared input into a private writable job tree."""
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True)
    completed = subprocess.run(
        [
            "cp",
            "-a",
            "--reflink=auto",
            f"{source}/.",
            f"{destination}/",
        ],
        capture_output=True,
        check=False,
        timeout=1800,
    )
    if completed.returncode == 0:
        return
    shutil.rmtree(destination)
    shutil.copytree(source, destination, symlinks=True)


def run_job(
    job: BuildJob,
    *,
    config: Config,
    work_root: Path,
    rpm_release: int,
    runner: CommandRunner | None = None,
    reusable_patch_sha256: frozenset[str] = frozenset(),
) -> JobResult:
    if job.status != "planned":
        raise ValueError("only planned jobs can be executed")
    command_runner = runner or CommandRunner()
    workspace = work_root / job.job_id
    workspace.mkdir(parents=True, exist_ok=True)
    status_path = workspace / "status.json"
    log_path = workspace / "build.log"
    output_prefix = f"[{job.job_id}] "
    _write_status(status_path, job, "selecting")
    try:
        selector, selection_paths = selection_invocation(
            job,
            workspace=workspace,
            command_template=config.selector_command_template,
        )
        write_requested_cves(job, selection_paths.requested_cves)
        write_advisory_evidence(job, selection_paths.advisory_evidence)
        command_runner.run(
            selector,
            log=log_path,
            timeout_seconds=config.selector_timeout_seconds,
            termination_grace_seconds=config.command_termination_grace_seconds,
            output_prefix=output_prefix,
        )
        selection = validate_selection(job, selection_paths)
        patch_sha256 = hashlib.sha256(selection_paths.patch.read_bytes()).hexdigest()
        selection_evidence = workspace / "selection-proof.json"
        selection_evidence.write_text(
            json.dumps(
                {
                    **selection,
                    "job_id": job.job_id,
                    "prospective_module_name": job.module_name,
                    "patch_sha256": patch_sha256,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        if patch_sha256 in reusable_patch_sha256:
            _write_status(
                status_path,
                job,
                "effective-no-change",
                patch_sha256=patch_sha256,
            )
            return JobResult(
                job.job_id,
                "effective-no-change",
                None,
                patch_sha256,
            )
        _write_status(status_path, job, "building")

        output_dir = workspace / "module"
        output_dir.mkdir(exist_ok=True)
        build_selection = selection
        build_environment = None
        if job.backend == "kpatch-build":
            build_source = workspace / "build-source"
            _materialise_build_source(
                Path(str(selection["base_source_tree"])), build_source
            )
            build_selection = {
                **selection,
                "base_source_tree": str(build_source.resolve()),
            }
            cache = workspace / "kpatch-cache"
            cache.mkdir(exist_ok=True)
            build_environment = {"CACHEDIR": str(cache.resolve())}
        invocation = build_invocation(
            job,
            patch=selection_paths.patch,
            output_dir=output_dir,
            selection=build_selection,
            kpatch_build_command=config.kpatch_build_command,
            kpatch_config_template=config.kpatch_config_template,
            kpatch_vmlinux_template=config.kpatch_vmlinux_template,
            klp_build_command_template=config.klp_build_command_template,
        )
        command_runner.run(
            invocation.command,
            log=log_path,
            timeout_seconds=config.builder_timeout_seconds,
            termination_grace_seconds=config.command_termination_grace_seconds,
            environment=build_environment,
            output_prefix=output_prefix,
        )
        module = _verify_module(
            job, output_dir, command_runner, config.modinfo_command
        )

        evidence = workspace / "package-selection.json"
        evidence.write_text(
            json.dumps(
                {
                    **selection,
                    "job_id": job.job_id,
                    "module_name": job.module_name,
                    "rpm_release": rpm_release,
                    "patch_sha256": patch_sha256,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        _write_status(status_path, job, "packaging")
        package_inputs = prepare_rpmbuild(
            job,
            module=module,
            selection_manifest=evidence,
            topdir=workspace / "rpmbuild",
            rpm_release=rpm_release,
        )
        package_result = command_runner.run(
            rpmbuild_invocation(package_inputs, config.rpmbuild_command),
            log=log_path,
            timeout_seconds=config.packaging_timeout_seconds,
            termination_grace_seconds=config.command_termination_grace_seconds,
            output_prefix=output_prefix,
        )
        rpm = find_built_rpm(package_inputs, package_result.output_lines)
        _verify_rpm(job, rpm_release, rpm, command_runner, config.rpm_command)
        _write_status(
            status_path,
            job,
            "built",
            rpm=rpm,
            patch_sha256=patch_sha256,
        )
        return JobResult(job.job_id, "built", str(rpm), patch_sha256)
    except Exception as error:
        _write_status(status_path, job, "failed", error=str(error))
        raise
