from __future__ import annotations

import json
import shlex
from dataclasses import dataclass
from pathlib import Path

from .models import BuildJob


@dataclass(frozen=True)
class SelectionPaths:
    patch: Path
    manifest: Path
    requested_cves: Path
    advisory_evidence: Path


def selection_invocation(
    job: BuildJob,
    *,
    workspace: Path,
    command_template: str,
) -> tuple[tuple[str, ...], SelectionPaths]:
    if not command_template:
        raise ValueError(
            "selector command template is not configured; extract or wrap the "
            "CVE-targeted selector before running builds"
        )
    paths = SelectionPaths(
        patch=workspace / "source.patch",
        manifest=workspace / "selection.json",
        requested_cves=workspace / "requested-cves.txt",
        advisory_evidence=workspace / "advisory-evidence.json",
    )
    values = {
        "base": job.base.nvra,
        "target": job.target.nvra,
        "workspace": str(workspace),
        "patch": str(paths.patch),
        "selection_manifest": str(paths.manifest),
        "requested_cves": str(paths.requested_cves),
        "advisory_evidence": str(paths.advisory_evidence),
        "module_name": job.module_name,
    }
    command = tuple(
        token.format_map(values) for token in shlex.split(command_template)
    )
    if not command:
        raise ValueError("selector command template produced an empty command")
    return command, paths


def write_requested_cves(job: BuildJob, path: Path) -> None:
    path.write_text("".join(f"{cve}\n" for cve in job.cves), encoding="utf-8")


def write_advisory_evidence(job: BuildJob, path: Path) -> None:
    value = {
        "schema_version": 1,
        "cve_ticket_ids": {
            cve: list(ticket_ids)
            for cve, ticket_ids in job.cve_ticket_ids
        },
    }
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def validate_selection(job: BuildJob, paths: SelectionPaths) -> dict[str, object]:
    if not paths.patch.is_file() or paths.patch.stat().st_size == 0:
        raise ValueError("selector did not produce a non-empty aggregate patch")
    if not paths.manifest.is_file():
        raise ValueError("selector did not produce selection.json")
    with paths.manifest.open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError("selection manifest root must be an object")
    if value.get("base") != job.base.nvra:
        raise ValueError("selection manifest base does not match the job")
    if value.get("target") != job.target.nvra:
        raise ValueError("selection manifest target does not match the job")
    covered = value.get("covered_cves")
    if not isinstance(covered, list):
        raise ValueError("selection manifest covered_cves must be a list")
    covered_set = {str(cve).upper() for cve in covered}
    required_set = set(job.cves)
    missing = sorted(required_set - covered_set)
    if missing:
        raise ValueError(
            "selector did not cover required CVE(s): " + ", ".join(missing)
        )
    unexpected = sorted(covered_set - required_set)
    if unexpected:
        raise ValueError(
            "selector claimed CVEs outside the planned interval: "
            + ", ".join(unexpected)
        )
    if job.backend == "kpatch-build":
        source_value = value.get("base_source_tree")
        if not isinstance(source_value, str) or not source_value:
            raise ValueError(
                "selection manifest does not identify the prepared base source tree"
            )
        source_tree = Path(source_value)
        if not source_tree.is_absolute() or not source_tree.is_dir():
            raise ValueError(
                "selection manifest base_source_tree is not an existing "
                "absolute directory"
            )
    return value
