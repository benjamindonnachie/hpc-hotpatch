from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .config import load_config
from .escalation import SecurityCoverageError
from .models import KernelRelease
from .planner import create_plan, resolve_base_kernel
from .planner import BuildPlan
from .runner import run_job
from .reconcile import reconcile_repository
from .sources import DnfRepositorySource, RepositorySnapshot
from .state import write_json_atomic


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="livepatch-repo",
        description="Plan cumulative livepatch builds from kernel repository metadata.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="collect DNF repository metadata")
    scan.add_argument("--config", type=Path, required=True)
    scan.add_argument("--output", type=Path, required=True)

    plan = subparsers.add_parser("plan", help="create a supported-base build plan")
    plan.add_argument("--config", type=Path, required=True)
    plan.add_argument("--snapshot", type=Path, required=True)
    plan.add_argument("--output", type=Path, required=True)
    plan.add_argument(
        "--target-kernel",
        help="controlled-test override; exact target uname -r (default: latest)",
    )

    refresh = subparsers.add_parser(
        "refresh", help="collect metadata and atomically refresh central state"
    )
    refresh.add_argument("--config", type=Path, required=True)
    refresh.add_argument("--state-dir", type=Path, required=True)

    execute = subparsers.add_parser(
        "run-job", help="select, build and package one planned livepatch job"
    )
    execute.add_argument("--config", type=Path, required=True)
    execute.add_argument("--plan", type=Path, required=True)
    execute.add_argument("--job-id", required=True)
    execute.add_argument("--work-root", type=Path, required=True)
    execute.add_argument("--rpm-release", type=int, required=True)

    reconcile = subparsers.add_parser(
        "reconcile",
        help="refresh metadata, execute missing jobs and publish the RPM repository",
    )
    reconcile.add_argument("--config", type=Path, required=True)
    reconcile.add_argument("--state-dir", type=Path, required=True)
    reconcile.add_argument("--work-root", type=Path, required=True)
    reconcile.add_argument("--repository-root", type=Path, required=True)
    return parser


def main(arguments: list[str] | None = None) -> int:
    options = _parser().parse_args(arguments)
    # Resolve every path argument to absolute up front. Downstream code
    # (notably rpmbuild scriptlets, which `cd` into %_builddir) breaks on
    # paths that are still relative to the CLI's invocation directory once
    # a subprocess changes its own working directory.
    for name, value in vars(options).items():
        if isinstance(value, Path):
            setattr(options, name, value.resolve())
    try:
        config = load_config(options.config)
        if options.command == "reconcile":
            result = reconcile_repository(
                config=config,
                state_dir=options.state_dir,
                work_root=options.work_root,
                repository_root=options.repository_root,
            )
            print(
                f"Reconciled {result.target}: built {result.built}, "
                f"published {result.published}, covered {result.covered}, "
                f"no-work {result.no_work}, "
                f"metadata-pending {result.metadata_pending}, "
                f"awaiting-signature {result.awaiting_signature}"
            )
            return 0
        if options.command == "run-job":
            plan = BuildPlan.read(options.plan)
            result = run_job(
                plan.job(options.job_id),
                config=config,
                work_root=options.work_root,
                rpm_release=options.rpm_release,
            )
            print(f"Built job {result.job_id}: {result.rpm}")
            return 0
        if options.command in {"scan", "refresh"}:
            base_kernel = resolve_base_kernel(config)
            source = DnfRepositorySource(
                config.dnf_command,
                config.kernel_package,
                config.architecture,
                config.cve_severity_url_template,
                base_kernel,
            )
            snapshot = source.collect()
            if options.command == "scan":
                write_json_atomic(options.output, snapshot.to_dict())
                print(
                    f"Collected {len(snapshot.kernels)} kernels and "
                    f"{len(snapshot.advisories)} CVE fix rows into {options.output}"
                )
                return 0
        else:
            snapshot = RepositorySnapshot.read(options.snapshot)
        plan = create_plan(
            snapshot,
            architecture=config.architecture,
            distro_stream=config.distro_stream,
            base=(base_kernel if options.command == "refresh" else resolve_base_kernel(config)),
            target_kernel=(
                KernelRelease.from_uname(options.target_kernel)
                if options.command == "plan" and options.target_kernel
                else None
            ),
            eligible_cve_severities=config.eligible_cve_severities,
        )
        if options.command == "refresh":
            snapshot_output = options.state_dir / "snapshot.json"
            plan_output = options.state_dir / "plan.json"
            write_json_atomic(snapshot_output, snapshot.to_dict())
            write_json_atomic(plan_output, plan.to_dict())
        else:
            plan_output = options.output
            write_json_atomic(plan_output, plan.to_dict())
        planned = sum(job.status == "planned" for job in plan.jobs)
        no_work = sum(job.status == "no-work" for job in plan.jobs)
        pending = sum(job.status == "metadata-pending" for job in plan.jobs)
        target = plan.target.nvra if plan.target is not None else "no newer kernel"
        print(
            f"Base {plan.base.nvra}, target {target}: {planned} build(s), "
            f"{no_work} proven no-work base(s), "
            f"{pending} metadata-pending base(s); wrote {plan_output}"
        )
        return 0
    except SecurityCoverageError as error:
        # Distinct exit code so a timer/OnFailure hook can tell a security
        # coverage gap (fleet exposed, no livepatch coming) apart from an
        # ordinary error. The durable record is in <state-dir>/escalation.json.
        print(
            f"livepatch-repo: SECURITY COVERAGE GAP: {error}",
            file=sys.stderr,
        )
        return 3
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"livepatch-repo: error: {error}", file=sys.stderr)
        return 1
