from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass
from functools import total_ordering
from typing import Any

from .rpmver import evr_cmp


STREAM_RE = re.compile(r"(el(?P<major>[0-9]+)(?:_[0-9]+)?)")
ARCHES = frozenset({"x86_64", "aarch64", "ppc64le", "s390x"})
CVE_SEVERITIES = ("Critical", "Important", "Moderate", "Low")


@total_ordering
@dataclass(frozen=True)
class KernelRelease:
    name: str
    epoch: str
    version: str
    release: str
    arch: str

    def __post_init__(self) -> None:
        if self.name != "kernel-core":
            raise ValueError(f"unsupported kernel package: {self.name!r}")
        if not self.version or not self.release:
            raise ValueError("kernel version and release must be non-empty")
        if self.arch not in ARCHES:
            raise ValueError(f"unsupported architecture: {self.arch!r}")
        try:
            int(self.epoch or "0")
        except ValueError as error:
            raise ValueError(f"invalid epoch: {self.epoch!r}") from error
        if self.distro_stream is None:
            raise ValueError(f"release has no EL stream: {self.release!r}")

    @property
    def distro_stream(self) -> str | None:
        match = STREAM_RE.search(self.release)
        return match.group(1) if match else None

    @property
    def distro_major(self) -> int:
        match = STREAM_RE.search(self.release)
        if match is None:
            raise ValueError(f"release has no EL major: {self.release!r}")
        return int(match.group("major"))

    @property
    def evr(self) -> str:
        epoch = f"{self.epoch}:" if self.epoch not in {"", "0"} else ""
        return f"{epoch}{self.version}-{self.release}"

    @property
    def nvra(self) -> str:
        return f"{self.version}-{self.release}.{self.arch}"

    @property
    def nevra(self) -> str:
        return f"{self.name}-{self.evr}.{self.arch}"

    def same_family(self, other: "KernelRelease") -> bool:
        return (
            self.name == other.name
            and self.version == other.version
            and self.arch == other.arch
            and self.distro_stream == other.distro_stream
        )

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, KernelRelease):
            return NotImplemented
        return (
            evr_cmp(
                self.epoch,
                self.version,
                self.release,
                other.epoch,
                other.version,
                other.release,
            )
            < 0
        )

    def to_dict(self) -> dict[str, str]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "KernelRelease":
        return cls(
            name=str(value["name"]),
            epoch=str(value.get("epoch", "0")),
            version=str(value["version"]),
            release=str(value["release"]),
            arch=str(value["arch"]),
        )

    @classmethod
    def from_uname(cls, value: str) -> "KernelRelease":
        """Parse the exact ``uname -r`` identity used by kpatch."""
        identity = value.strip()
        try:
            version, remainder = identity.split("-", 1)
            release, arch = remainder.rsplit(".", 1)
        except ValueError as error:
            raise ValueError(f"invalid kernel uname identity: {value!r}") from error
        return cls("kernel-core", "0", version, release, arch)


@dataclass(frozen=True)
class AdvisoryFix:
    cve: str
    kernel: KernelRelease
    severity: str
    advisory_id: str | None = None
    ticket_ids: tuple[str, ...] = ()
    severity_source: str = "unspecified"

    def __post_init__(self) -> None:
        if not re.fullmatch(r"CVE-[0-9]{4}-[0-9]+", self.cve.upper()):
            raise ValueError(f"invalid CVE identifier: {self.cve!r}")
        object.__setattr__(self, "cve", self.cve.upper())
        canonical_severity = self.severity.strip().title()
        if canonical_severity not in CVE_SEVERITIES:
            raise ValueError(f"invalid CVE severity: {self.severity!r}")
        object.__setattr__(self, "severity", canonical_severity)
        if not self.severity_source.strip():
            raise ValueError("CVE severity source must be non-empty")
        if self.advisory_id is not None and not re.fullmatch(
            r"(?:RH|AL)[SBE]A-[0-9]{4}:[0-9]+", self.advisory_id
        ):
            raise ValueError(f"invalid advisory identifier: {self.advisory_id!r}")
        normalised_tickets = tuple(sorted(set(self.ticket_ids)))
        if any(not re.fullmatch(r"[0-9]+", item) for item in normalised_tickets):
            raise ValueError("advisory ticket identifiers must be numeric")
        object.__setattr__(self, "ticket_ids", normalised_tickets)

    def to_dict(self) -> dict[str, object]:
        return {
            "cve": self.cve,
            "kernel": self.kernel.to_dict(),
            "severity": self.severity,
            "advisory_id": self.advisory_id,
            "ticket_ids": list(self.ticket_ids),
            "severity_source": self.severity_source,
        }


@dataclass(frozen=True)
class CvePolicyDecision:
    cve: str
    severity: str
    disposition: str

    def __post_init__(self) -> None:
        cve = self.cve.upper()
        if not re.fullmatch(r"CVE-[0-9]{4}-[0-9]+", cve):
            raise ValueError(f"invalid CVE identifier: {self.cve!r}")
        severity = self.severity.strip().title()
        if severity not in CVE_SEVERITIES:
            raise ValueError(f"invalid CVE severity: {self.severity!r}")
        if self.disposition not in {"required", "below-policy"}:
            raise ValueError(f"invalid CVE policy disposition: {self.disposition!r}")
        object.__setattr__(self, "cve", cve)
        object.__setattr__(self, "severity", severity)

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True)
class RepositoryNotice:
    advisory_id: str
    kind: str
    kernel: KernelRelease

    def __post_init__(self) -> None:
        if self.kind not in {"security", "bugfix", "enhancement"}:
            raise ValueError(f"invalid advisory kind: {self.kind!r}")
        if not re.fullmatch(r"(?:RH|AL)[SBE]A-[0-9]{4}:[0-9]+", self.advisory_id):
            raise ValueError(f"invalid advisory identifier: {self.advisory_id!r}")

    def to_dict(self) -> dict[str, object]:
        return {
            "advisory_id": self.advisory_id,
            "kind": self.kind,
            "kernel": self.kernel.to_dict(),
        }


@dataclass(frozen=True)
class BuildJob:
    base: KernelRelease
    target: KernelRelease
    cves: tuple[str, ...]
    status: str
    backend: str
    cve_ticket_ids: tuple[tuple[str, tuple[str, ...]], ...] = ()
    cve_policy_decisions: tuple[CvePolicyDecision, ...] = ()

    def __post_init__(self) -> None:
        if self.status not in {"planned", "no-work", "metadata-pending"}:
            raise ValueError(f"invalid initial job status: {self.status}")
        if self.status == "planned" and not self.cves:
            raise ValueError("planned jobs require at least one CVE")
        if self.status != "planned" and self.cves:
            raise ValueError(f"{self.status} jobs cannot contain CVEs")
        if not self.base.same_family(self.target):
            raise ValueError("base and target are not in the same kernel family")
        if not self.base < self.target:
            raise ValueError("build target must be newer than its base")
        normalised_evidence = tuple(
            sorted(
                (
                    cve.upper(),
                    tuple(sorted(set(ticket_ids))),
                )
                for cve, ticket_ids in self.cve_ticket_ids
            )
        )
        if any(cve not in self.cves for cve, _ in normalised_evidence):
            raise ValueError("ticket evidence references a CVE outside the job")
        if any(
            not re.fullmatch(r"[0-9]+", ticket)
            for _, ticket_ids in normalised_evidence
            for ticket in ticket_ids
        ):
            raise ValueError("job ticket identifiers must be numeric")
        object.__setattr__(self, "cve_ticket_ids", normalised_evidence)
        normalised_decisions = tuple(
            sorted(self.cve_policy_decisions, key=lambda item: item.cve)
        )
        if len({item.cve for item in normalised_decisions}) != len(
            normalised_decisions
        ):
            raise ValueError("job CVE policy decisions contain duplicates")
        required = {
            item.cve
            for item in normalised_decisions
            if item.disposition == "required"
        }
        if normalised_decisions and required != set(self.cves):
            raise ValueError("required CVE policy decisions must match job CVEs")
        object.__setattr__(self, "cve_policy_decisions", normalised_decisions)

    @property
    def job_id(self) -> str:
        pair = f"{self.base.nevra}\0{self.target.nevra}".encode()
        digest = hashlib.sha256(pair).hexdigest()[:16]
        return f"{self.base.distro_stream}-{self.base.arch}-{digest}"

    @property
    def module_name(self) -> str:
        base = re.sub(r"[^A-Za-z0-9]", "_", self.base.release)
        # The EL stream is already visible in the base.  Keeping only the
        # target erratum release makes `kpatch list` concise and meaningful.
        target_release = self.target.release.split(".el", 1)[0]
        target = re.sub(r"[^A-Za-z0-9]", "_", target_release)
        readable = f"klp_{base}_to_{target}"
        if len(readable) <= 55:
            return readable
        # Non-EL providers may have unusually long release strings. Preserve
        # as much readable identity as possible and use a suffix only to avoid
        # truncation collisions.
        digest = hashlib.sha256(readable.encode()).hexdigest()[:8]
        return f"{readable[:46]}_{digest}"

    def to_dict(self) -> dict[str, object]:
        return {
            "job_id": self.job_id,
            "base": self.base.to_dict(),
            "target": self.target.to_dict(),
            "cves": list(self.cves),
            "status": self.status,
            "backend": self.backend,
            "module_name": self.module_name,
            "cve_ticket_ids": {
                cve: list(ticket_ids)
                for cve, ticket_ids in self.cve_ticket_ids
            },
            "cve_policy_decisions": [
                decision.to_dict() for decision in self.cve_policy_decisions
            ],
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "BuildJob":
        cves = value.get("cves")
        if not isinstance(cves, list):
            raise ValueError("build job cves must be a list")
        raw_evidence = value.get("cve_ticket_ids", {})
        if not isinstance(raw_evidence, dict):
            raise ValueError("build job cve_ticket_ids must be an object")
        evidence: list[tuple[str, tuple[str, ...]]] = []
        for cve, ticket_ids in raw_evidence.items():
            if not isinstance(ticket_ids, list):
                raise ValueError("build job ticket identifiers must be lists")
            evidence.append((str(cve), tuple(str(item) for item in ticket_ids)))
        raw_decisions = value.get("cve_policy_decisions", [])
        if not isinstance(raw_decisions, list):
            raise ValueError("build job cve_policy_decisions must be a list")
        decisions: list[CvePolicyDecision] = []
        for item in raw_decisions:
            if not isinstance(item, dict):
                raise ValueError("build job CVE policy decisions must be objects")
            decisions.append(
                CvePolicyDecision(
                    str(item["cve"]),
                    str(item["severity"]),
                    str(item["disposition"]),
                )
            )
        return cls(
            base=KernelRelease.from_dict(value["base"]),
            target=KernelRelease.from_dict(value["target"]),
            cves=tuple(str(cve) for cve in cves),
            status=str(value["status"]),
            backend=str(value["backend"]),
            cve_ticket_ids=tuple(evidence),
            cve_policy_decisions=tuple(decisions),
        )
