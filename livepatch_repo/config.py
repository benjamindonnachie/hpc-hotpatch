from __future__ import annotations

import configparser
from dataclasses import dataclass
from pathlib import Path

from .models import CVE_SEVERITIES


@dataclass(frozen=True)
class Config:
    dnf_command: str
    kernel_package: str
    architecture: str
    distro_stream: str
    selector_command_template: str
    kpatch_build_command: str
    klp_build_command_template: str
    modinfo_command: str
    rpmbuild_command: str
    base_kernel: str = "running"
    uname_command: str = "uname"
    rpm_command: str = "rpm"
    createrepo_command: str = "createrepo_c"
    rpm_sign_command_template: str = ""
    rpm_verify_command_template: str = "rpmkeys --checksig {rpm}"
    require_rpm_signing: bool = False
    kpatch_config_template: str = "/boot/config-{base}"
    kpatch_vmlinux_template: str = (
        "/usr/lib/debug/lib/modules/{base}/vmlinux"
    )
    repository_profile: str = ""
    repository_retain_versions: int = 4
    repository_minimum_age_seconds: int = 86400
    repository_family_grace_seconds: int = 1209600
    selector_timeout_seconds: int = 7200
    builder_timeout_seconds: int = 86400
    packaging_timeout_seconds: int = 1800
    command_termination_grace_seconds: int = 30
    eligible_cve_severities: tuple[str, ...] = ("Critical", "Important")
    cve_severity_url_template: str = (
        "https://access.redhat.com/hydra/rest/securitydata/"
        "cve.json?ids={cves}&per_page=1000"
    )
    security_escalation_command_template: str = ""
    security_escalation_timeout_seconds: int = 300
    metadata_pending_timeout_seconds: int = 86400
    build_failure_review_command_template: str = ""
    build_failure_review_timeout_seconds: int = 300
    build_failure_review_grace_seconds: int = 86400


def load_config(path: Path) -> Config:
    parser = configparser.ConfigParser()
    if not parser.read(path):
        raise ValueError(f"configuration file not found: {path}")
    try:
        eligible_cve_severities = tuple(
            item.strip().title()
            for item in parser.get(
                "policy",
                "eligible_cve_severities",
                fallback="Critical,Important",
            ).split(",")
            if item.strip()
        )
        if not eligible_cve_severities:
            raise ValueError("eligible_cve_severities must not be empty")
        unknown_severities = sorted(
            set(eligible_cve_severities) - set(CVE_SEVERITIES)
        )
        if unknown_severities:
            raise ValueError(
                "eligible_cve_severities contains unsupported value(s): "
                + ", ".join(unknown_severities)
            )
        config = Config(
            dnf_command=parser.get("repository", "dnf_command"),
            kernel_package=parser.get("repository", "kernel_package"),
            architecture=parser.get("repository", "architecture"),
            distro_stream=parser.get("repository", "distro_stream"),
            repository_profile=parser.get(
                "repository", "profile", fallback=""
            ).strip(),
            base_kernel=parser.get(
                "policy", "base_kernel", fallback="running"
            ).strip(),
            uname_command=parser.get(
                "policy", "uname_command", fallback="uname"
            ).strip(),
            eligible_cve_severities=tuple(dict.fromkeys(eligible_cve_severities)),
            cve_severity_url_template=parser.get(
                "policy",
                "cve_severity_url_template",
                fallback=(
                    "https://access.redhat.com/hydra/rest/securitydata/"
                    "cve.json?ids={cves}&per_page=1000"
                ),
            ).strip(),
            security_escalation_command_template=parser.get(
                "policy",
                "security_escalation_command_template",
                fallback="",
            ).strip(),
            security_escalation_timeout_seconds=parser.getint(
                "policy",
                "security_escalation_timeout_seconds",
                fallback=300,
            ),
            metadata_pending_timeout_seconds=parser.getint(
                "policy",
                "metadata_pending_timeout_seconds",
                fallback=86400,
            ),
            build_failure_review_command_template=parser.get(
                "policy",
                "build_failure_review_command_template",
                fallback="",
            ).strip(),
            build_failure_review_timeout_seconds=parser.getint(
                "policy",
                "build_failure_review_timeout_seconds",
                fallback=300,
            ),
            build_failure_review_grace_seconds=parser.getint(
                "policy",
                "build_failure_review_grace_seconds",
                fallback=86400,
            ),
            selector_command_template=parser.get(
                "builders", "selector_command_template", fallback=""
            ).strip(),
            kpatch_build_command=parser.get(
                "builders", "kpatch_build_command", fallback="kpatch-build"
            ),
            kpatch_config_template=parser.get(
                "builders",
                "kpatch_config_template",
                fallback="/boot/config-{base}",
            ).strip(),
            kpatch_vmlinux_template=parser.get(
                "builders",
                "kpatch_vmlinux_template",
                fallback="/usr/lib/debug/lib/modules/{base}/vmlinux",
            ).strip(),
            klp_build_command_template=parser.get(
                "builders", "klp_build_command_template", fallback=""
            ).strip(),
            modinfo_command=parser.get(
                "builders", "modinfo_command", fallback="modinfo"
            ),
            rpmbuild_command=parser.get(
                "builders", "rpmbuild_command", fallback="rpmbuild"
            ),
            selector_timeout_seconds=parser.getint(
                "builders", "selector_timeout_seconds", fallback=7200
            ),
            builder_timeout_seconds=parser.getint(
                "builders", "builder_timeout_seconds", fallback=86400
            ),
            packaging_timeout_seconds=parser.getint(
                "builders", "packaging_timeout_seconds", fallback=1800
            ),
            command_termination_grace_seconds=parser.getint(
                "builders", "termination_grace_seconds", fallback=30
            ),
            rpm_command=parser.get(
                "publication", "rpm_command", fallback="rpm"
            ),
            createrepo_command=parser.get(
                "publication", "createrepo_command", fallback="createrepo_c"
            ),
            rpm_sign_command_template=parser.get(
                "publication", "rpm_sign_command_template", fallback=""
            ).strip(),
            rpm_verify_command_template=parser.get(
                "publication",
                "rpm_verify_command_template",
                fallback="rpmkeys --checksig {rpm}",
            ).strip(),
            require_rpm_signing=parser.getboolean(
                "publication", "require_rpm_signing", fallback=True
            ),
            repository_retain_versions=parser.getint(
                "publication", "retain_versions", fallback=4
            ),
            repository_minimum_age_seconds=parser.getint(
                "publication", "minimum_retention_age_seconds", fallback=86400
            ),
            repository_family_grace_seconds=parser.getint(
                "publication", "family_grace_seconds", fallback=1209600
            ),
        )
        for label, value, minimum in (
            ("retain_versions", config.repository_retain_versions, 1),
            (
                "minimum_retention_age_seconds",
                config.repository_minimum_age_seconds,
                0,
            ),
            (
                "family_grace_seconds",
                config.repository_family_grace_seconds,
                0,
            ),
            ("selector_timeout_seconds", config.selector_timeout_seconds, 1),
            ("builder_timeout_seconds", config.builder_timeout_seconds, 1),
            ("packaging_timeout_seconds", config.packaging_timeout_seconds, 1),
            (
                "security_escalation_timeout_seconds",
                config.security_escalation_timeout_seconds,
                1,
            ),
            (
                "metadata_pending_timeout_seconds",
                config.metadata_pending_timeout_seconds,
                1,
            ),
            (
                "build_failure_review_timeout_seconds",
                config.build_failure_review_timeout_seconds,
                1,
            ),
            (
                "build_failure_review_grace_seconds",
                config.build_failure_review_grace_seconds,
                0,
            ),
            (
                "termination_grace_seconds",
                config.command_termination_grace_seconds,
                0,
            ),
        ):
            if value < minimum:
                raise ValueError(f"{label} must be at least {minimum}")
        if not config.base_kernel:
            raise ValueError("base_kernel must be 'running' or an exact uname -r")
        if config.base_kernel == "running" and not config.uname_command:
            raise ValueError("uname_command must not be empty for a running base")
        if "{cves}" not in config.cve_severity_url_template:
            raise ValueError("cve_severity_url_template must contain {cves}")
        if not config.cve_severity_url_template.startswith("https://"):
            raise ValueError("cve_severity_url_template must use HTTPS")
        for label, template in (
            (
                "security_escalation_command_template",
                config.security_escalation_command_template,
            ),
            (
                "build_failure_review_command_template",
                config.build_failure_review_command_template,
            ),
        ):
            if not template:
                continue
            import shlex

            sample = {
                "base": "",
                "target": "",
                "cves": "",
                "reason": "",
                "report": "",
            }
            try:
                for token in shlex.split(template):
                    token.format_map(sample)
            except (KeyError, ValueError) as error:
                raise ValueError(
                    f"{label} has an unknown or malformed placeholder: {error}"
                )
        return config
    except (configparser.Error, ValueError) as error:
        raise ValueError(f"invalid configuration {path}: {error}") from error
