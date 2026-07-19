from __future__ import annotations

import shlex
from dataclasses import dataclass
from pathlib import Path

from .models import BuildJob


@dataclass(frozen=True)
class BuildInvocation:
    command: tuple[str, ...]

    def shell_display(self) -> str:
        return shlex.join(self.command)


def build_invocation(
    job: BuildJob,
    *,
    patch: Path,
    output_dir: Path,
    selection: dict[str, object],
    kpatch_build_command: str,
    kpatch_config_template: str,
    kpatch_vmlinux_template: str,
    klp_build_command_template: str,
) -> BuildInvocation:
    if job.status != "planned":
        raise ValueError("cannot build a no-work job")
    if not patch.is_file():
        raise ValueError(f"selected aggregate patch does not exist: {patch}")

    if job.backend == "kpatch-build":
        source_dir = Path(str(selection["base_source_tree"]))
        values = {
            "base": job.base.nvra,
            "target": job.target.nvra,
            "module_name": job.module_name,
        }
        config = Path(kpatch_config_template.format_map(values))
        vmlinux = Path(kpatch_vmlinux_template.format_map(values))
        for label, path, expected in (
            ("base source tree", source_dir, "directory"),
            ("base kernel config", config, "file"),
            ("base kernel vmlinux", vmlinux, "file"),
        ):
            exists = path.is_dir() if expected == "directory" else path.is_file()
            if not exists:
                raise ValueError(f"{label} does not exist: {path}")
        return BuildInvocation(
            (
                kpatch_build_command,
                "--sourcedir",
                str(source_dir),
                "--config",
                str(config),
                "--vmlinux",
                str(vmlinux),
                "--name",
                job.module_name,
                "--output",
                str(output_dir),
                str(patch),
            )
        )
    if job.backend == "klp-build":
        if not klp_build_command_template:
            raise ValueError(
                "EL10 klp-build command template is not configured; "
                "confirm the AlmaLinux 10 CLI before enabling builds"
            )
        values = {
            "patch": str(patch),
            "base": job.base.nvra,
            "target": job.target.nvra,
            "module_name": job.module_name,
            "output_dir": str(output_dir),
        }
        command = tuple(
            token.format_map(values)
            for token in shlex.split(klp_build_command_template)
        )
        if not command:
            raise ValueError("klp-build command template produced an empty command")
        return BuildInvocation(command)
    raise ValueError(f"unknown build backend: {job.backend}")
