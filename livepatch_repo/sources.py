from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass, replace
from pathlib import Path
from urllib.request import Request, urlopen

from .escalation import SecurityCoverageError
from .models import AdvisoryFix, KernelRelease, RepositoryNotice


ADVISORY_RE = re.compile(
    r"\b(?P<cve>CVE-[0-9]{4}-[0-9]+)\b.*?"
    r"\b(?P<severity>Critical|Important|Moderate|Low)/Sec(?:urity)?\.?\s+"
    r".*?\bkernel-core-"
    r"(?:(?P<epoch>[0-9]+):)?"
    r"(?P<version>[^-\s]+)-(?P<release>[^\s]+)\.(?P<arch>[A-Za-z0-9_]+)\s*$",
    re.IGNORECASE,
)
NOTICE_RE = re.compile(
    r"\b(?P<advisory>(?:RH|AL)[SBE]A-[0-9]{4}:[0-9]+)\b.*\bkernel-core-"
    r"(?:(?P<epoch>[0-9]+):)?"
    r"(?P<version>[^-\s]+)-(?P<release>[^\s]+)\.(?P<arch>[A-Za-z0-9_]+)\s*$",
    re.IGNORECASE,
)
ADVISORY_ID_RE = re.compile(r"(?:RH|AL)[SBE]A-[0-9]{4}:[0-9]+")
TICKET_ID_RE = re.compile(
    r"(?:JIRA:AlmaLinux-|(?:JIRA:)?RHEL-)(?P<ticket>[0-9]+)",
    re.IGNORECASE,
)
RED_HAT_VEX_URL_TEMPLATE = (
    "https://security.access.redhat.com/data/csaf/v2/vex-feed/"
    "{year}/{cve_lower}.json"
)


@dataclass(frozen=True)
class RepositorySnapshot:
    kernels: tuple[KernelRelease, ...]
    advisories: tuple[AdvisoryFix, ...]
    notices: tuple[RepositoryNotice, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "kernels": [kernel.to_dict() for kernel in self.kernels],
            "advisories": [advisory.to_dict() for advisory in self.advisories],
            "notices": [notice.to_dict() for notice in self.notices],
        }

    @classmethod
    def from_dict(cls, value: dict[str, object]) -> "RepositorySnapshot":
        kernel_values = value.get("kernels")
        advisory_values = value.get("advisories")
        notice_values = value.get("notices", [])
        if not isinstance(kernel_values, list) or not isinstance(advisory_values, list):
            raise ValueError("snapshot requires kernels and advisories lists")
        if not isinstance(notice_values, list):
            raise ValueError("snapshot notices must be a list")
        kernels = tuple(KernelRelease.from_dict(item) for item in kernel_values)
        advisories: list[AdvisoryFix] = []
        for item in advisory_values:
            if not isinstance(item, dict):
                raise ValueError("advisory rows must be objects")
            kernel_value = item.get("kernel")
            if not isinstance(kernel_value, dict):
                raise ValueError("advisory kernel must be an object")
            kernel = KernelRelease.from_dict(kernel_value)
            raw_tickets = item.get("ticket_ids", [])
            if not isinstance(raw_tickets, list):
                raise ValueError("advisory ticket_ids must be a list")
            severity = item.get("severity")
            if not isinstance(severity, str) or not severity.strip():
                raise ValueError("advisory severity must be a non-empty string")
            advisory_id = item.get("advisory_id")
            advisories.append(
                AdvisoryFix(
                    str(item["cve"]),
                    kernel,
                    severity,
                    str(advisory_id) if advisory_id is not None else None,
                    tuple(str(ticket) for ticket in raw_tickets),
                    str(item.get("severity_source", "legacy-snapshot")),
                )
            )
        notices: list[RepositoryNotice] = []
        for item in notice_values:
            if not isinstance(item, dict):
                raise ValueError("notice rows must be objects")
            kernel_value = item.get("kernel")
            if not isinstance(kernel_value, dict):
                raise ValueError("notice kernel must be an object")
            notices.append(
                RepositoryNotice(
                    str(item["advisory_id"]),
                    str(item["kind"]),
                    KernelRelease.from_dict(kernel_value),
                )
            )
        return cls(
            kernels=kernels,
            advisories=tuple(advisories),
            notices=tuple(notices),
        )

    @classmethod
    def read(cls, path: Path) -> "RepositorySnapshot":
        with path.open(encoding="utf-8") as handle:
            value = json.load(handle)
        if not isinstance(value, dict):
            raise ValueError("snapshot root must be an object")
        return cls.from_dict(value)


def parse_repoquery(output: str, package_name: str) -> tuple[KernelRelease, ...]:
    kernels: set[KernelRelease] = set()
    for line_number, raw_line in enumerate(output.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        fields = line.split("\t")
        if len(fields) != 5:
            raise ValueError(f"repoquery line {line_number} has {len(fields)} fields")
        name, epoch, version, release, arch = fields
        if name != package_name:
            continue
        kernels.add(KernelRelease(name, epoch or "0", version, release, arch))
    if not kernels:
        raise ValueError(f"repository returned no {package_name} kernels")
    return tuple(sorted(kernels))


def parse_updateinfo(output: str) -> tuple[AdvisoryFix, ...]:
    # Advisories are deliberately NOT filtered against currently downloadable
    # kernels: retained updateinfo for a skipped intermediate release must still
    # participate in the (base, target] interval. Do not reintroduce such a
    # filter — it would silently drop fixes first shipped in a skipped kernel.
    advisories: set[AdvisoryFix] = set()
    unmatched_cve_rows: list[str] = []
    current_advisory: dict[KernelRelease, str] = {}
    for raw_line in output.splitlines():
        notice_match = NOTICE_RE.search(raw_line)
        if notice_match is not None:
            notice_kernel = KernelRelease(
                "kernel-core",
                notice_match.group("epoch") or "0",
                notice_match.group("version"),
                notice_match.group("release"),
                notice_match.group("arch"),
            )
            current_advisory[notice_kernel] = notice_match.group(
                "advisory"
            ).upper()
        if not re.search(r"\bCVE-[0-9]{4}-[0-9]+\b", raw_line, re.IGNORECASE):
            continue
        if "kernel-core-" not in raw_line:
            continue
        match = ADVISORY_RE.search(raw_line)
        if match is None:
            unmatched_cve_rows.append(raw_line.strip())
            continue
        kernel = KernelRelease(
            "kernel-core",
            match.group("epoch") or "0",
            match.group("version"),
            match.group("release"),
            match.group("arch"),
        )
        advisories.add(
            AdvisoryFix(
                match.group("cve"),
                kernel,
                match.group("severity"),
                current_advisory.get(kernel),
                severity_source="dnf-advisory",
            )
        )
    if unmatched_cve_rows:
        example = unmatched_cve_rows[0]
        raise ValueError(f"could not parse CVE updateinfo row: {example}")
    return tuple(sorted(advisories, key=lambda item: (item.kernel, item.cve)))


def _normalise_advisory_subject(value: str) -> str:
    value = re.sub(r"\(CVE-[0-9]{4}-[0-9]+\)", "", value, flags=re.I)
    value = re.sub(r"\[[^]]+\]", "", value)
    value = TICKET_ID_RE.sub("", value)
    value = re.sub(r"\(\s*\)", "", value)
    while True:
        stripped = re.sub(
            r"^(?:kernel|linux kernel)\s*:\s*",
            "",
            value.strip(),
            flags=re.I,
        )
        if stripped == value.strip():
            break
        value = stripped
    return " ".join(re.sub(r"[^a-z0-9]+", " ", value.lower()).split())


def _description_bullets(
    lines: list[str], heading: str
) -> tuple[str, ...]:
    active = False
    bullets: list[str] = []
    current = ""
    for raw_line in lines:
        line = raw_line.strip()
        if line == heading:
            if current:
                bullets.append(current)
                current = ""
            active = True
            continue
        if line.endswith(":") and line in {
            "Security Fix(es):",
            "Bug Fix(es) and Enhancement(s):",
        }:
            if current:
                bullets.append(current)
                current = ""
            active = False
            continue
        if not active or not line:
            continue
        if line.startswith("* "):
            if current:
                bullets.append(current)
            current = line[2:]
        elif current:
            current += " " + line
    if current:
        bullets.append(current)
    return tuple(bullets)


def parse_advisory_ticket_evidence(
    output: str,
) -> dict[tuple[str, str], tuple[str, ...]]:
    sections: dict[str, list[str]] = {}
    current_id: str | None = None
    in_description = False
    for raw_line in output.splitlines():
        update_match = re.match(r"\s*Update ID:\s*(\S+)", raw_line)
        if update_match:
            candidate = update_match.group(1).upper()
            current_id = candidate if ADVISORY_ID_RE.fullmatch(candidate) else None
            in_description = False
            if current_id is not None:
                sections.setdefault(current_id, [])
            continue
        if current_id is None:
            continue
        description_match = re.match(r"\s*Description:\s?(.*)", raw_line)
        if description_match:
            in_description = True
            sections[current_id].append(description_match.group(1))
            continue
        if in_description:
            continuation = re.match(r"\s*:\s?(.*)", raw_line)
            if continuation:
                sections[current_id].append(continuation.group(1))
                continue
            if raw_line.strip():
                in_description = False

    evidence: dict[tuple[str, str], set[str]] = {}
    for advisory_id, lines in sections.items():
        security = _description_bullets(lines, "Security Fix(es):")
        bugfixes = _description_bullets(
            lines, "Bug Fix(es) and Enhancement(s):"
        )
        bug_subjects: list[tuple[str, frozenset[str]]] = []
        for bullet in bugfixes:
            tickets = frozenset(
                match.group("ticket") for match in TICKET_ID_RE.finditer(bullet)
            )
            if tickets:
                bug_subjects.append((_normalise_advisory_subject(bullet), tickets))
        for bullet in security:
            cves = frozenset(item.upper() for item in re.findall(
                r"CVE-[0-9]{4}-[0-9]+", bullet, flags=re.I
            ))
            subject = _normalise_advisory_subject(bullet)
            matches = [tickets for value, tickets in bug_subjects if value == subject]
            if len(matches) != 1:
                continue
            for cve in cves:
                evidence.setdefault((advisory_id, cve), set()).update(matches[0])
    return {key: tuple(sorted(value)) for key, value in evidence.items()}


def parse_advisory_security_cves(
    output: str,
) -> dict[str, tuple[str, ...]]:
    sections: dict[str, list[str]] = {}
    current_id: str | None = None
    in_description = False
    for raw_line in output.splitlines():
        update_match = re.match(r"\s*Update ID:\s*(\S+)", raw_line)
        if update_match:
            candidate = update_match.group(1).upper()
            current_id = candidate if ADVISORY_ID_RE.fullmatch(candidate) else None
            in_description = False
            if current_id is not None:
                sections.setdefault(current_id, [])
            continue
        if current_id is None:
            continue
        description_match = re.match(r"\s*Description:\s?(.*)", raw_line)
        if description_match:
            in_description = True
            sections[current_id].append(description_match.group(1))
            continue
        if in_description:
            continuation = re.match(r"\s*:\s?(.*)", raw_line)
            if continuation:
                sections[current_id].append(continuation.group(1))
                continue
            if raw_line.strip():
                in_description = False

    result: dict[str, tuple[str, ...]] = {}
    for advisory_id, lines in sections.items():
        cves = {
            item.upper()
            for bullet in _description_bullets(lines, "Security Fix(es):")
            for item in re.findall(
                r"CVE-[0-9]{4}-[0-9]+", bullet, flags=re.I
            )
        }
        result[advisory_id] = tuple(sorted(cves))
    return result


def parse_notices(output: str) -> tuple[RepositoryNotice, ...]:
    notices: set[RepositoryNotice] = set()
    unmatched: list[str] = []
    for raw_line in output.splitlines():
        if "kernel-core-" not in raw_line:
            continue
        if not re.search(r"\b(?:RH|AL)[SBE]A-[0-9]{4}:[0-9]+\b", raw_line):
            continue
        match = NOTICE_RE.search(raw_line)
        if match is None:
            unmatched.append(raw_line.strip())
            continue
        advisory_id = match.group("advisory").upper()
        marker = advisory_id[2]
        kind = {
            "S": "security",
            "B": "bugfix",
            "E": "enhancement",
        }[marker]
        notices.add(
            RepositoryNotice(
                advisory_id,
                kind,
                KernelRelease(
                    "kernel-core",
                    match.group("epoch") or "0",
                    match.group("version"),
                    match.group("release"),
                    match.group("arch"),
                ),
            )
        )
    if unmatched:
        raise ValueError(f"could not parse kernel advisory row: {unmatched[0]}")
    return tuple(
        sorted(notices, key=lambda item: (item.kernel, item.advisory_id))
    )


def associate_local_advisory_ids(
    advisories: tuple[AdvisoryFix, ...],
    notices: tuple[RepositoryNotice, ...],
) -> tuple[AdvisoryFix, ...]:
    security_ids: dict[KernelRelease, set[str]] = {}
    for notice in notices:
        if notice.kind == "security":
            security_ids.setdefault(notice.kernel, set()).add(notice.advisory_id)
    associated: list[AdvisoryFix] = []
    for advisory in advisories:
        candidates = security_ids.get(advisory.kernel, set())
        selected: str | None = None
        if advisory.advisory_id is not None:
            suffix = advisory.advisory_id.rsplit("-", 1)[-1]
            matching = sorted(
                candidate
                for candidate in candidates
                if candidate.rsplit("-", 1)[-1] == suffix
            )
            if len(matching) == 1:
                selected = matching[0]
        if selected is None and len(candidates) == 1:
            selected = next(iter(candidates))
        associated.append(
            replace(advisory, advisory_id=selected or advisory.advisory_id)
        )
    return tuple(associated)


def parse_cve_severities(
    output: str,
    expected_cves: tuple[str, ...],
    *,
    require_complete: bool = True,
) -> dict[str, str]:
    try:
        value = json.loads(output)
    except json.JSONDecodeError as error:
        raise ValueError("invalid CVE severity security data") from error
    if not isinstance(value, list):
        raise ValueError("CVE severity security data is not a list")
    expected = {cve.upper() for cve in expected_cves}
    result: dict[str, str] = {}
    for item in value:
        if not isinstance(item, dict):
            raise ValueError("CVE severity security data rows must be objects")
        cve = str(item.get("CVE", "")).upper()
        if cve not in expected:
            raise ValueError(f"unexpected CVE in security data: {cve!r}")
        if cve in result:
            raise ValueError(f"duplicate CVE in security data: {cve}")
        severity = str(item.get("severity", "")).strip().title()
        if severity not in {"Critical", "Important", "Moderate", "Low"}:
            raise SecurityCoverageError(
                f"security data has no recognised severity for {cve}",
                cves=(cve,),
            )
        result[cve] = severity
    missing = sorted(expected - set(result))
    if missing and require_complete:
        raise SecurityCoverageError(
            "security data has no severity for: " + ", ".join(missing),
            cves=tuple(missing),
        )
    return result


def parse_cve_vex_severity(output: str, expected_cve: str) -> str:
    try:
        value = json.loads(output)
    except json.JSONDecodeError as error:
        raise ValueError("invalid CVE VEX security data") from error
    if not isinstance(value, dict):
        raise ValueError("CVE VEX security data is not an object")
    document = value.get("document")
    if not isinstance(document, dict):
        raise ValueError("CVE VEX security data has no document")
    tracking = document.get("tracking")
    actual_cve = tracking.get("id") if isinstance(tracking, dict) else None
    if str(actual_cve).upper() != expected_cve.upper():
        raise ValueError(f"unexpected CVE in VEX security data: {actual_cve!r}")
    aggregate = document.get("aggregate_severity")
    severity = (
        str(aggregate.get("text", "")).strip().title()
        if isinstance(aggregate, dict)
        else ""
    )
    if severity not in {"Critical", "Important", "Moderate", "Low"}:
        raise SecurityCoverageError(
            f"VEX security data has no recognised severity for {expected_cve}",
            cves=(expected_cve,),
        )
    return severity


class DnfRepositorySource:
    def __init__(
        self,
        dnf_command: str,
        package_name: str,
        architecture: str,
        cve_severity_url_template: str,
        base_kernel: KernelRelease,
        target_kernel: KernelRelease | None = None,
    ):
        self.dnf_command = dnf_command
        self.package_name = package_name
        self.architecture = architecture
        self.cve_severity_url_template = cve_severity_url_template
        self.base_kernel = base_kernel
        self.target_kernel = target_kernel

    def _run(self, arguments: list[str]) -> str:
        completed = subprocess.run(
            [self.dnf_command, *arguments],
            check=True,
            capture_output=True,
            text=True,
            timeout=300,
        )
        return completed.stdout

    def _cve_severities(self, cves: tuple[str, ...]) -> dict[str, str]:
        result: dict[str, str] = {}
        for offset in range(0, len(cves), 50):
            chunk = cves[offset : offset + 50]
            try:
                url = self.cve_severity_url_template.format(cves=",".join(chunk))
            except (KeyError, ValueError) as error:
                raise ValueError("invalid cve_severity_url_template") from error
            if not url.startswith("https://"):
                raise ValueError("cve_severity_url_template must use HTTPS")
            request = Request(url, headers={"User-Agent": "livepatch-repo/1"})
            try:
                with urlopen(request, timeout=30) as response:
                    payload = response.read().decode("utf-8")
            except OSError as error:
                raise ValueError(
                    "could not fetch individual CVE severities: " + str(error)
                ) from error
            result.update(
                parse_cve_severities(payload, chunk, require_complete=False)
            )
        for cve in sorted(set(cves) - set(result)):
            year = cve.split("-", 2)[1]
            url = RED_HAT_VEX_URL_TEMPLATE.format(
                year=year,
                cve_lower=cve.lower(),
            )
            request = Request(url, headers={"User-Agent": "livepatch-repo/1"})
            try:
                with urlopen(request, timeout=30) as response:
                    payload = response.read().decode("utf-8")
            except OSError as error:
                raise SecurityCoverageError(
                    f"security data has no severity for: {cve}",
                    cves=(cve,),
                ) from error
            result[cve] = parse_cve_vex_severity(payload, cve)
        return result

    def collect(self) -> RepositorySnapshot:
        repoquery = self._run(
            [
                "-q",
                "repoquery",
                "--available",
                f"--archlist={self.architecture}",
                "--qf",
                "%{name}\\t%{epoch}\\t%{version}\\t%{release}\\t%{arch}",
                self.package_name,
            ]
        )
        kernels = parse_repoquery(repoquery, self.package_name)
        targets = tuple(
            kernel
            for kernel in kernels
            if kernel.same_family(self.base_kernel) and self.base_kernel < kernel
        )
        interval_target = self.target_kernel or (targets[-1] if targets else None)
        if interval_target is not None and interval_target not in targets:
            raise ValueError(
                f"requested target {interval_target.nvra} is not available and "
                f"newer than base {self.base_kernel.nvra}"
            )
        updateinfo = self._run(
            ["-q", "updateinfo", "list", "--all", "--with-cve", self.package_name]
        )
        # Retained updateinfo EVRs deliberately remain valid even when their
        # exact intermediate kernel RPM is no longer downloadable.
        advisories = parse_updateinfo(updateinfo)
        advisories = tuple(
            advisory
            for advisory in advisories
            if interval_target is not None
            and advisory.kernel.same_family(self.base_kernel)
            and self.base_kernel < advisory.kernel
            and advisory.kernel <= interval_target
        )
        notice_output = self._run(
            ["-q", "updateinfo", "list", "--all", self.package_name]
        )
        notices = parse_notices(notice_output)
        notices = tuple(
            notice
            for notice in notices
            if interval_target is not None
            and notice.kernel.same_family(self.base_kernel)
            and self.base_kernel < notice.kernel
            and notice.kernel <= interval_target
        )
        advisories = associate_local_advisory_ids(advisories, notices)
        security_notices = {
            notice.advisory_id: notice
            for notice in notices
            if notice.kind == "security"
        }
        detail_output = ""
        if security_notices:
            detail_output = self._run(
                ["-q", "updateinfo", "info", *sorted(security_notices)]
            )
            description_cves = parse_advisory_security_cves(detail_output)
            existing = {
                (advisory.kernel, advisory.cve) for advisory in advisories
            }
            recovered = [
                AdvisoryFix(
                    cve,
                    notice.kernel,
                    "Low",
                    advisory_id,
                    severity_source="advisory-description-pending",
                )
                for advisory_id, notice in security_notices.items()
                for cve in description_cves.get(advisory_id, ())
                if (notice.kernel, cve) not in existing
            ]
            advisories = tuple(
                sorted(
                    (*advisories, *recovered),
                    key=lambda item: (item.kernel, item.cve),
                )
            )
        try:
            cve_severities = self._cve_severities(
                tuple(sorted({advisory.cve for advisory in advisories}))
            )
        except SecurityCoverageError as error:
            # Attach the interval endpoints so the escalation record and any
            # operator automation know which base is exposed and which target
            # kernel to update, drain and reboot into.
            raise SecurityCoverageError(
                str(error),
                base=self.base_kernel,
                target=interval_target,
                cves=error.cves,
            ) from error
        advisories = tuple(
            replace(
                advisory,
                severity=cve_severities[advisory.cve],
                severity_source="redhat-security-data-api",
            )
            for advisory in advisories
        )
        if detail_output:
            ticket_evidence = parse_advisory_ticket_evidence(detail_output)
            advisories = tuple(
                replace(
                    advisory,
                    ticket_ids=ticket_evidence.get(
                        (advisory.advisory_id or "", advisory.cve), ()
                    ),
                )
                for advisory in advisories
            )
        return RepositorySnapshot(
            kernels=kernels,
            advisories=advisories,
            notices=notices,
        )
