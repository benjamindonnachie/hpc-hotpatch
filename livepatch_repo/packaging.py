from __future__ import annotations

import re
import shutil
from dataclasses import dataclass
from pathlib import Path

from .models import BuildJob


def _compose_package_name(version: str, release: str) -> str:
    match = re.match(r"(.*)\.el.*", release)
    if match is None:
        raise ValueError(
            f"kernel release is incompatible with kpatch-dnf naming: {release!r}"
        )
    kernel_version = version.replace(".", "_")
    kernel_release = match.group(1).replace(".", "_")
    return f"kpatch-patch-{kernel_version}-{kernel_release}"


def package_name(job: BuildJob) -> str:
    return _compose_package_name(job.base.version, job.base.release)


def package_name_from_nvra(nvra: str) -> str:
    """Derive the package family name from a ``version-release.arch`` string."""
    body, dot, _arch = nvra.rpartition(".")
    if not dot:
        raise ValueError(f"kernel nvra has no architecture suffix: {nvra!r}")
    version, dash, release = body.partition("-")
    if not dash:
        raise ValueError(f"kernel nvra has no release component: {nvra!r}")
    return _compose_package_name(version, release)


@dataclass(frozen=True)
class PackageInputs:
    topdir: Path
    spec: Path
    module_source: Path
    manifest_source: Path
    expected_rpm_filename: str


def scriptlet_texts(job: BuildJob, module_name: str) -> tuple[str, str]:
    module_file = f"{module_name}.ko"
    post = (
        f"/usr/sbin/kpatch install --kernel-version {job.base.nvra} "
        f"%{{_libdir}}/kpatch/{module_file}\n"
        f'if [ "$(uname -r)" = "{job.base.nvra}" ]; then\n'
        # Delegate activation to the distribution service.  A direct kpatch
        # invocation from an RPM scriptlet reaches insmod in kmod_t, which
        # Alma SELinux denies module_load access to kpatch_var_lib_t.  The
        # packaged service enters kpatch_t and is the supported load path.
        # Restart is required because this oneshot service remains active
        # after boot and must execute again for a newly persisted module.
        "    /usr/bin/systemctl restart kpatch.service\n"
        "fi"
    )
    preun = (
        f"/usr/sbin/kpatch uninstall --kernel-version {job.base.nvra} "
        f"{module_name} || :"
    )
    return post, preun


def _spec_text(job: BuildJob, rpm_release: int, module_name: str) -> str:
    name = package_name(job)
    module_file = f"{module_name}.ko"
    manifest_file = f"{module_name}.json"
    cve_text = " ".join(job.cves)
    post, preun = scriptlet_texts(job, module_name)
    posttrans = (
        f'if [ "$(uname -r)" = "{job.base.nvra}" ] && '
        f'[ -d "/sys/module/{module_name}" ]; then\n'
        f"    /usr/sbin/kpatch force unload {module_name} || :\n"
        "fi\n"
        f"{post}"
    )
    return f"""\
Name:           {name}
Version:        0
Release:        {rpm_release}.{job.base.distro_stream}
Summary:        Cumulative livepatch for {job.base.nvra}
License:        GPL-2.0-only
BuildArch:      {job.base.arch}
Source0:        {module_file}
Source1:        {manifest_file}
Requires:       kpatch
Requires:       kernel-uname-r = {job.base.nvra}
Requires(post): systemd
Provides:       kpatch-patch = {job.base.nvra}

%description
Cumulative kernel livepatch for base {job.base.nvra}, carrying security
fixes through {job.target.nvra}. Covered CVEs: {cve_text}

%prep

%build

%install
install -D -m 0644 %{{SOURCE0}} %{{buildroot}}%{{_libdir}}/kpatch/{module_file}
install -D -m 0644 %{{SOURCE1}} %{{buildroot}}%{{_datadir}}/{name}/{manifest_file}

%post
{post}

%preun
{preun}

# RPM runs the old package's %preun after the new package's %post during an
# upgrade.  Reassert the new module after that removal step, which is required
# when a corrected RPM reuses the same livepatch module name.
%posttrans
{posttrans}

%files
%{{_libdir}}/kpatch/{module_file}
%{{_datadir}}/{name}/{manifest_file}

%changelog
* Thu Jul 16 2026 Central Livepatch Builder <root@localhost> - 0-{rpm_release}
- Cumulative security state through {job.target.nvra}
"""


def prepare_rpmbuild(
    job: BuildJob,
    *,
    module: Path,
    selection_manifest: Path,
    topdir: Path,
    rpm_release: int,
    module_name: str | None = None,
) -> PackageInputs:
    if rpm_release < 1:
        raise ValueError("RPM release must be at least 1")
    if not module.is_file():
        raise ValueError(f"module does not exist: {module}")
    if not selection_manifest.is_file():
        raise ValueError(f"selection manifest does not exist: {selection_manifest}")
    effective_module_name = module_name or job.module_name
    if not re.fullmatch(r"[A-Za-z0-9_]{1,55}", effective_module_name):
        raise ValueError(
            "module name must contain 1-55 ASCII letters, digits, or underscores"
        )
    for directory in ("BUILD", "BUILDROOT", "RPMS", "SOURCES", "SPECS", "SRPMS"):
        (topdir / directory).mkdir(parents=True, exist_ok=True)
    module_source = topdir / "SOURCES" / f"{effective_module_name}.ko"
    manifest_source = topdir / "SOURCES" / f"{effective_module_name}.json"
    shutil.copy2(module, module_source)
    shutil.copy2(selection_manifest, manifest_source)
    spec = topdir / "SPECS" / f"{package_name(job)}.spec"
    spec.write_text(
        _spec_text(job, rpm_release, effective_module_name),
        encoding="utf-8",
    )
    expected = (
        f"{package_name(job)}-0-{rpm_release}.{job.base.distro_stream}."
        f"{job.base.arch}.rpm"
    )
    return PackageInputs(topdir, spec, module_source, manifest_source, expected)


def rpmbuild_invocation(inputs: PackageInputs, command: str) -> tuple[str, ...]:
    return (
        command,
        "-bb",
        "--define",
        f"_topdir {inputs.topdir}",
        str(inputs.spec),
    )


def find_built_rpm(
    inputs: PackageInputs,
    output_lines: tuple[str, ...],
) -> Path:
    wrote = [
        Path(line.split("Wrote:", 1)[1].strip())
        for line in output_lines
        if line.lstrip().startswith("Wrote:")
    ]
    matches = [
        path
        for path in wrote
        if path.name == inputs.expected_rpm_filename and path.is_file()
    ]
    if len(matches) != 1:
        raise ValueError(
            f"rpmbuild did not report exactly one "
            f"{inputs.expected_rpm_filename!r}; found {len(matches)}"
        )
    return matches[0]
