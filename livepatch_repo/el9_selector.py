from __future__ import annotations

import argparse
import filecmp
import fcntl
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence


CVE_RE = re.compile(r"CVE-[0-9]{4}-[0-9]+", re.IGNORECASE)
TICKET_RE = re.compile(r"\[(?P<ticket>(?:RHEL-|BZ-)?[0-9]+)\]")
APPLY_RE = re.compile(r"^\s*Apply[A-Za-z]*Patch\b")
PATCH_DECLARATION_RE = re.compile(r"^\s*Patch[0-9]*:\s*(?P<patch>\S+\.patch)")
MODULE_NAME_RE = re.compile(r"^[A-Za-z0-9_]{1,55}$")
KERNEL_RE = re.compile(
    r"^(?P<version>[0-9]+\.[0-9]+\.[0-9]+)-(?P<release>.+)\.(?P<arch>[^.]+)$"
)
MAKE_VERSION_RE = re.compile(
    r"^(?P<name>VERSION|PATCHLEVEL|SUBLEVEL)\s*=\s*(?P<value>[0-9]+)\s*$",
    re.MULTILINE,
)
EXTRAVERSION_RE = re.compile(r"^EXTRAVERSION\s*=.*$", re.MULTILINE)
REMOVAL_RE = re.compile(r"\b(?:drop|dropped|remove|removed|supersed|revert)", re.I)


@dataclass(frozen=True)
class SourceInputs:
    tree: Path
    sources: Path
    spec: Path


@dataclass(frozen=True)
class ChangelogEntry:
    text: str
    slug: str
    stripped_slug: str
    subject_key: str
    cves: frozenset[str]
    all_cves: frozenset[str]
    tickets: frozenset[str]


@dataclass(frozen=True)
class SelectedPatch:
    path: Path
    origins: tuple[str, ...]
    cves: tuple[str, ...]


@dataclass(frozen=True)
class FoldedSourceGroup:
    tickets: tuple[str, ...]
    cves: tuple[str, ...]
    paths: tuple[str, ...]
    patch: str = ""
    selected_hunks: tuple[tuple[str, tuple[str, ...]], ...] = ()

    @property
    def ticket(self) -> str:
        """Return the stable manifest label for this ticket series."""
        return "+".join(self.tickets)


def _run(
    command: Sequence[str],
    *,
    capture: bool = False,
    stdin: bytes | None = None,
) -> subprocess.CompletedProcess[str] | subprocess.CompletedProcess[bytes]:
    print(f"$ {' '.join(command)}", file=sys.stderr)
    return subprocess.run(
        list(command),
        input=stdin,
        check=True,
        capture_output=capture,
        text=stdin is None,
        timeout=1800,
    )


def _nvr(kernel: str) -> str:
    if "." not in kernel:
        raise ValueError(f"kernel has no architecture suffix: {kernel!r}")
    return kernel.rsplit(".", 1)[0]


def _arch(kernel: str) -> str:
    return kernel.rsplit(".", 1)[-1]


def _find_one(root: Path, pattern: str) -> Path:
    matches = sorted(root.glob(pattern))
    if len(matches) != 1:
        raise ValueError(
            f"expected one {pattern!r} below {root}; found {len(matches)}"
        )
    return matches[0]


def _find_source_tree(build_root: Path) -> Path:
    matches = sorted(
        path
        for path in build_root.glob("**/linux-*")
        if path.is_dir() and len(path.relative_to(build_root).parts) <= 2
    )
    if len(matches) != 1:
        raise ValueError(
            f"expected one linux-* source tree below {build_root}; "
            f"found {len(matches)}"
        )
    return matches[0]


def prepare_kernel_release(tree: Path, kernel: str) -> None:
    """Apply the exact RPM kernel release as Alma's spec does before %build."""
    match = KERNEL_RE.fullmatch(kernel)
    if match is None:
        raise ValueError(f"invalid kernel version-release-architecture: {kernel!r}")
    makefile = tree / "Makefile"
    text = makefile.read_text(encoding="utf-8")
    components = {
        item.group("name"): item.group("value")
        for item in MAKE_VERSION_RE.finditer(text)
    }
    if set(components) != {"VERSION", "PATCHLEVEL", "SUBLEVEL"}:
        raise ValueError(f"cannot determine source version from {makefile}")
    source_version = ".".join(
        components[name] for name in ("VERSION", "PATCHLEVEL", "SUBLEVEL")
    )
    if source_version != match.group("version"):
        raise ValueError(
            f"source version {source_version!r} does not match kernel "
            f"{match.group('version')!r}"
        )
    exact_release = (
        f"{match.group('version')}-{match.group('release')}.{match.group('arch')}"
    )
    replacement = f"EXTRAVERSION = -{match.group('release')}.{match.group('arch')}"
    text, replacements = EXTRAVERSION_RE.subn(replacement, text)
    if replacements != 1:
        raise ValueError(
            f"expected one EXTRAVERSION assignment in {makefile}; found {replacements}"
        )
    makefile.write_text(text, encoding="utf-8")

    release_file = tree / "include" / "config" / "kernel.release"
    uts_file = tree / "include" / "generated" / "utsrelease.h"
    if release_file.is_file():
        current = release_file.read_text(encoding="utf-8").strip()
        if current != exact_release:
            release_file.unlink()
    if uts_file.is_file():
        current = uts_file.read_text(encoding="utf-8").strip()
        if current != f'#define UTS_RELEASE "{exact_release}"':
            uts_file.unlink()


def _prepared_source(cache: Path, kernel: str) -> SourceInputs:
    topdir = cache / "rpmbuild"
    tree = _find_source_tree(topdir / "BUILD")
    # Upgrade caches produced before exact Alma EXTRAVERSION preparation. The
    # caller holds the exact-NVR lock, so this one-time migration is safe.
    makefile = tree / "Makefile"
    match = KERNEL_RE.fullmatch(kernel)
    if match is None:
        raise ValueError(f"invalid kernel version-release-architecture: {kernel!r}")
    expected = f"EXTRAVERSION = -{match.group('release')}.{match.group('arch')}"
    exact_release = (
        f"{match.group('version')}-{match.group('release')}.{match.group('arch')}"
    )
    release_file = tree / "include" / "config" / "kernel.release"
    uts_file = tree / "include" / "generated" / "utsrelease.h"
    stale_release = release_file.is_file() and (
        release_file.read_text(encoding="utf-8").strip() != exact_release
    )
    stale_uts = uts_file.is_file() and (
        uts_file.read_text(encoding="utf-8").strip()
        != f'#define UTS_RELEASE "{exact_release}"'
    )
    if (
        expected not in makefile.read_text(encoding="utf-8").splitlines()
        or stale_release
        or stale_uts
    ):
        prepare_kernel_release(tree, kernel)
    return SourceInputs(
        tree=tree,
        sources=topdir / "SOURCES",
        spec=_find_one(topdir / "SPECS", "*.spec"),
    )


def prepare_source(
    kernel: str,
    *,
    source_cache: Path,
    source_repo: str,
    dnf_command: str,
    rpm_command: str,
    rpmbuild_command: str,
) -> SourceInputs:
    nvr = _nvr(kernel)
    source_cache.mkdir(parents=True, exist_ok=True)
    cache = source_cache / nvr
    lock_path = source_cache / f".{nvr}.lock"
    with lock_path.open("a+") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        stamp = cache / "rpmbuild" / ".prep-complete"
        if stamp.is_file():
            return _prepared_source(cache, kernel)

        temporary = Path(
            tempfile.mkdtemp(prefix=f".{nvr}.prepare-", dir=source_cache)
        )
        try:
            topdir = temporary / "rpmbuild"
            download = [
                dnf_command,
                "download",
                "--source",
                "--downloaddir",
                str(temporary),
            ]
            if source_repo:
                download.extend(("--enablerepo", source_repo))
            download.append(f"kernel-{nvr}")
            _run(download)
            srpm = _find_one(temporary, f"kernel-{nvr}.src.rpm")
            _run(
                [
                    rpm_command,
                    "-ivh",
                    "--define",
                    f"_topdir {topdir}",
                    str(srpm),
                ]
            )
            spec = _find_one(topdir / "SPECS", "*.spec")
            _run(
                [
                    rpmbuild_command,
                    "-bp",
                    "--nodeps",
                    "--without",
                    "configchecks",
                    "--define",
                    f"_topdir {topdir}",
                    str(spec),
                ]
            )
            tree = _find_source_tree(topdir / "BUILD")
            prepare_kernel_release(tree, kernel)
            (topdir / ".prep-complete").touch()
            if cache.exists():
                shutil.rmtree(cache)
            os.replace(temporary, cache)
        finally:
            shutil.rmtree(temporary, ignore_errors=True)
        return _prepared_source(cache, kernel)


def _clean_token(token: str) -> str:
    return token.strip("\"'(),;")


def patch_order(
    spec: Path,
    sources: Path,
    *,
    architecture: str,
    evaluation: str,
    workspace: Path,
    rpmspec_command: str,
) -> tuple[Path, ...]:
    parse_spec = spec
    if evaluation == "required":
        evaluated = workspace / f"{spec.stem}.evaluated.spec"
        completed = _run(
            [rpmspec_command, "-P", "--target", architecture, str(spec)],
            capture=True,
        )
        assert isinstance(completed.stdout, str)
        evaluated.write_text(completed.stdout, encoding="utf-8")
        parse_spec = evaluated
    elif evaluation != "static":
        raise ValueError("spec evaluation must be required or static")
    applied: list[str] = []
    declarations: list[str] = []
    for line in parse_spec.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("%changelog"):
            break
        declaration = PATCH_DECLARATION_RE.match(line)
        if declaration:
            declarations.append(_clean_token(declaration.group("patch")))
        if APPLY_RE.match(line):
            for token in line.split():
                candidate = _clean_token(token)
                if candidate.endswith(".patch"):
                    applied.append(candidate)
                    break
    names = applied or (declarations if evaluation == "static" else [])
    names = list(dict.fromkeys(names))
    if not names:
        raise ValueError(f"no concrete applied patch sequence in {spec}")
    paths = tuple(sources / name for name in names)
    missing = [str(path) for path in paths if not path.is_file()]
    if missing:
        raise ValueError("spec references missing patch: " + missing[0])
    return paths


def _slug(value: str) -> str:
    return re.sub(r"^-|-$", "", re.sub(r"[^a-z0-9]+", "-", value.lower()))


def _strip_cve_prefix(value: str) -> str:
    return re.sub(r"^(?:cve-[0-9]{4}-[0-9]+-)+", "", value)


def _ticket_id(value: str) -> str:
    match = re.search(r"([0-9]+)$", value)
    if match is None:
        raise ValueError(f"ticket has no numeric identifier: {value!r}")
    return match.group(1)


def _subject_key(value: str) -> str:
    value = re.sub(r"^\[PATCH[^]]*\]\s*", "", value, flags=re.IGNORECASE)
    value = re.sub(
        r"\s+\(CVE-[0-9]{4}-[0-9]+\)$",
        "",
        value,
        flags=re.IGNORECASE,
    )
    return " ".join(value.lower().split())


def _patch_subject(path: Path) -> str:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    for index, line in enumerate(lines):
        if not line.startswith("Subject:"):
            continue
        parts = [line.split(":", 1)[1].strip()]
        for continuation in lines[index + 1 :]:
            if not continuation[:1].isspace():
                break
            parts.append(continuation.strip())
        return " ".join(parts)
    return ""


def changelog_entries(spec: Path, base: str) -> tuple[ChangelogEntry, ...]:
    lines = spec.read_text(encoding="utf-8", errors="replace").splitlines()
    try:
        start = lines.index("%changelog") + 1
    except ValueError as error:
        raise ValueError(f"spec has no %changelog: {spec}") from error
    full = f"[{_nvr(base)}]"
    short = re.sub(r"\.el[0-9][0-9_]*$", "", _nvr(base))
    delta: list[str] = []
    found = False
    for line in lines[start:]:
        if line.startswith("*") and (full in line or line.endswith(f" - {short}")):
            found = True
            break
        delta.append(line)
    if not found:
        raise ValueError(
            f"base release {_nvr(base)} is absent from target changelog"
        )
    folded: list[str] = []
    current = ""
    for line in delta:
        if line.startswith("- "):
            if current:
                folded.append(current)
            current = line
        elif line.startswith("*"):
            if current:
                folded.append(current)
                current = ""
        elif current and line[:1].isspace() and line.strip():
            current += " " + line.strip()
    if current:
        folded.append(current)
    entries: list[ChangelogEntry] = []
    for text in folded:
        braces = " ".join(re.findall(r"\{[^}]*\}", text))
        cves = frozenset(item.upper() for item in CVE_RE.findall(braces))
        all_cves = frozenset(item.upper() for item in CVE_RE.findall(text))
        tickets = frozenset(
            match.group("ticket") for match in TICKET_RE.finditer(text)
        )
        raw_subject = text[2:]
        raw_subject = re.sub(
            r" \([^)]*\) \[(?:RHEL-|BZ-)?[0-9]+\].*$",
            "",
            raw_subject,
        )
        slug = _slug(text[2:])
        entries.append(
            ChangelogEntry(
                text=text,
                slug=slug,
                stripped_slug=_strip_cve_prefix(slug),
                subject_key=_subject_key(raw_subject),
                cves=cves,
                all_cves=all_cves,
                tickets=tickets,
            )
        )
    return tuple(entries)


def _normalised_patch_name(path: Path) -> str:
    return re.sub(r"^[0-9]+-", "", path.name)


def _matching_entries(
    patch: Path,
    entries: Sequence[ChangelogEntry],
) -> tuple[ChangelogEntry, ...]:
    subject = _subject_key(_patch_subject(patch))
    if subject:
        return tuple(entry for entry in entries if entry.subject_key == subject)
    stem = _slug(_normalised_patch_name(patch).removesuffix(".patch"))
    stripped = _strip_cve_prefix(stem)
    return tuple(
        entry
        for entry in entries
        if entry.slug == stem
        or (len(stem) >= 15 and entry.slug.startswith(stem))
        or (len(stripped) >= 15 and entry.stripped_slug.startswith(stripped))
    )


def select_patches(
    running_order: Sequence[Path],
    target_order: Sequence[Path],
    entries: Sequence[ChangelogEntry],
    requested_cves: frozenset[str],
    advisory_ticket_ids: dict[str, frozenset[str]],
) -> tuple[SelectedPatch, ...]:
    by_name: dict[str, list[Path]] = {}
    for path in running_order:
        by_name.setdefault(_normalised_patch_name(path), []).append(path)
    series_ticket_ids = frozenset(
        _ticket_id(ticket)
        for entry in entries
        if entry.cves & requested_cves
        for ticket in entry.tickets
    ) | frozenset(
        ticket
        for ticket_ids in advisory_ticket_ids.values()
        for ticket in ticket_ids
    )
    selected: list[SelectedPatch] = []
    for patch in target_order:
        same_name = by_name.get(_normalised_patch_name(patch), [])
        if any(filecmp.cmp(patch, candidate, shallow=False) for candidate in same_name):
            continue
        matches = _matching_entries(patch, entries)
        if len(matches) > 1:
            identified = set().union(*(entry.all_cves for entry in matches))
            braced = set().union(*(entry.cves for entry in matches))
            if len(identified) != 1 or braced != identified:
                raise ValueError(
                    f"ambiguous changelog mapping for {patch.name}: "
                    f"{len(matches)} entries"
                )
        origins: list[str] = []
        cves = {
            item.upper()
            for item in CVE_RE.findall(patch.name)
            if item.upper() in requested_cves
        }
        if cves:
            origins.append("filename")
        matched_cves = set().union(*(entry.cves for entry in matches))
        matched_requested = matched_cves & requested_cves
        if matched_requested:
            origins.append("changelog")
            cves.update(matched_requested)
        matching_tickets = set().union(*(entry.tickets for entry in matches))
        matching_ticket_ids = {_ticket_id(ticket) for ticket in matching_tickets}
        evidence_cves = {
            cve
            for cve, ticket_ids in advisory_ticket_ids.items()
            if matching_ticket_ids & ticket_ids
        }
        if evidence_cves:
            origins.extend(
                f"advisory-ticket({ticket})"
                for ticket in sorted(
                    matching_ticket_ids
                    & set().union(
                        *(advisory_ticket_ids[cve] for cve in evidence_cves)
                    )
                )
            )
            cves.update(evidence_cves)
        for ticket in sorted(matching_tickets):
            if _ticket_id(ticket) in series_ticket_ids:
                origins.append(f"series({ticket})")
        if origins:
            selected.append(
                SelectedPatch(
                    patch,
                    tuple(dict.fromkeys(origins)),
                    tuple(sorted(cves)),
                )
            )
    covered = frozenset(cve for patch in selected for cve in patch.cves)
    missing = sorted(requested_cves - covered)
    if missing:
        raise ValueError(
            "requested CVE(s) have no selected patch: " + ", ".join(missing)
        )
    if not selected:
        raise ValueError("selector produced no security patches")
    return tuple(selected)


def select_superseded_patches(
    running_order: Sequence[Path],
    target_order: Sequence[Path],
    entries: Sequence[ChangelogEntry],
    requested_cves: frozenset[str],
) -> tuple[SelectedPatch, ...]:
    target_names = {path.name for path in target_order}
    evidence: dict[str, set[str]] = {}
    for entry in entries:
        cves = entry.all_cves & requested_cves
        if not cves or not REMOVAL_RE.search(entry.text):
            continue
        for parenthesised in re.findall(r"\(([^)]*)\)", entry.text):
            for number in re.findall(r"(?<![0-9])([0-9]{3,})(?![0-9])", parenthesised):
                evidence.setdefault(number, set()).update(cves)
    superseded: list[SelectedPatch] = []
    for patch in running_order:
        match = re.match(r"(?P<number>[0-9]+)-", patch.name)
        if match is None or patch.name in target_names:
            continue
        cves = evidence.get(match.group("number"))
        if cves:
            superseded.append(
                SelectedPatch(
                    patch,
                    (f"superseded-changelog({match.group('number')})",),
                    tuple(sorted(cves)),
                )
            )
    return tuple(superseded)


def _patch_fingerprint(path: Path) -> str | None:
    completed = subprocess.run(
        ["git", "patch-id", "--stable"],
        input=path.read_bytes(),
        capture_output=True,
        check=False,
        timeout=60,
    )
    if completed.returncode:
        return None
    ids: list[str] = []
    for line in completed.stdout.splitlines():
        fields = line.split()
        if fields and re.fullmatch(rb"[0-9a-f]{40}", fields[0]):
            ids.append(fields[0].decode())
    return f"{len(ids)}:{','.join(ids)}" if ids else None


def _patch_paths(path: Path) -> tuple[str, ...]:
    found: list[str] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        candidates: Iterable[str] = ()
        if line.startswith("diff --git a/"):
            fields = line.split()
            candidates = fields[2:4]
        elif line.startswith("--- a/") or line.startswith("+++ b/"):
            candidates = (line.split()[1],)
        for candidate in candidates:
            candidate = re.sub(r"^[ab]/", "", candidate)
            relative = Path(candidate)
            if candidate != "/dev/null" and (
                relative.is_absolute()
                or not relative.parts
                or any(part in {"", ".", ".."} for part in relative.parts)
            ):
                raise ValueError(f"patch contains unsafe path: {candidate!r}")
            if candidate != "/dev/null" and candidate not in found:
                found.append(candidate)
    return tuple(found)


def _run_patch(tree: Path, patch: Path, *arguments: str) -> tuple[int, str]:
    completed = subprocess.run(
        ["patch", "-p1", "--batch", *arguments, "--directory", str(tree)],
        input=patch.read_bytes(),
        capture_output=True,
        check=False,
        timeout=300,
    )
    return completed.returncode, (completed.stdout + completed.stderr).decode(
        errors="replace"
    )


def _dirty_patch_output(output: str) -> bool:
    return bool(
        re.search(
            r"FAILED|Reversed \(or previously applied\)|Assuming -R|"
            r"previously applied patch|malformed",
            output,
            flags=re.IGNORECASE,
        )
    )


def _baseline_unchanged(
    base_tree: Path,
    validation_tree: Path,
    paths: Sequence[str],
) -> bool:
    if not paths:
        return False
    for relative in paths:
        base = base_tree / relative
        validation = validation_tree / relative
        if base.exists() != validation.exists():
            return False
        if base.exists() and (
            base.is_dir()
            or validation.is_dir()
            or not filecmp.cmp(base, validation, shallow=False)
        ):
            return False
    return True


def _copy_validation_tree(source: Path, destination: Path) -> None:
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


def _copy_aggregate_paths(
    source: Path, destination: Path, paths: Iterable[str]
) -> None:
    destination.mkdir(parents=True)
    for relative in sorted(paths):
        source_path = source / relative
        destination_path = destination / relative
        if not source_path.exists() and not source_path.is_symlink():
            continue
        if source_path.is_dir():
            raise ValueError(f"aggregate path is a directory: {relative}")
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        if source_path.is_symlink():
            destination_path.symlink_to(os.readlink(source_path))
        else:
            shutil.copy2(source_path, destination_path)


def _aggregate_tree_diff(
    base_tree: Path,
    final_tree: Path,
    paths: Iterable[str],
    *,
    workspace: Path,
    output: Path,
) -> None:
    allowed = set(paths)
    if not allowed:
        raise ValueError("aggregate source path list is empty")
    aggregate_base = workspace / f"aggregate-base-{os.getpid()}"
    aggregate_final = workspace / f"aggregate-final-{os.getpid()}"
    try:
        _copy_aggregate_paths(base_tree, aggregate_base, allowed)
        _copy_aggregate_paths(final_tree, aggregate_final, allowed)
        completed = subprocess.run(
            [
                "git",
                "-c",
                "core.quotePath=false",
                "diff",
                "--no-index",
                "--binary",
                "--no-renames",
                "--src-prefix=a/",
                "--dst-prefix=b/",
                str(aggregate_base),
                str(aggregate_final),
            ],
            capture_output=True,
            check=False,
            timeout=300,
        )
        if completed.returncode not in {0, 1}:
            raise ValueError("git could not generate the aggregate diff")
        aggregate = completed.stdout.decode(errors="surrogateescape")
        source_prefix = f"a/{str(aggregate_base).lstrip('/')}/"
        final_prefix = f"b/{str(aggregate_final).lstrip('/')}/"
        aggregate = aggregate.replace(source_prefix, "a/").replace(
            final_prefix, "b/"
        )
        if not aggregate:
            raise ValueError("validated security series has no net source change")
        for match in re.finditer(
            r"^diff --git a/(?P<old>\S+) b/(?P<new>\S+)$",
            aggregate,
            flags=re.MULTILINE,
        ):
            if match.group("old") != match.group("new"):
                raise ValueError("aggregate contains a rename or ambiguous path")
            if match.group("old") not in allowed:
                raise ValueError(
                    f"aggregate contains undeclared path: {match.group('old')}"
                )
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            aggregate,
            encoding="utf-8",
            errors="surrogateescape",
        )
    finally:
        shutil.rmtree(aggregate_base, ignore_errors=True)
        shutil.rmtree(aggregate_final, ignore_errors=True)


def validate_and_aggregate(
    running_tree: Path,
    running_order: Sequence[Path],
    selected: Sequence[SelectedPatch],
    superseded: Sequence[SelectedPatch],
    *,
    workspace: Path,
    output: Path,
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    validation = workspace / f"validation-{os.getpid()}"
    _copy_validation_tree(running_tree, validation)
    running_ids: dict[str, Path] = {}
    for patch in running_order:
        fingerprint = _patch_fingerprint(patch)
        if fingerprint:
            running_ids.setdefault(fingerprint, patch)
    applied: list[SelectedPatch] = []
    already_present: list[str] = []
    reversed_patches: list[str] = []
    try:
        for item in reversed(superseded):
            rc, output_text = _run_patch(
                validation,
                item.path,
                "--dry-run",
                "-R",
            )
            if rc or _dirty_patch_output(output_text):
                raise ValueError(
                    f"superseded base patch cannot be reversed: {item.path.name}"
                )
            rc, output_text = _run_patch(
                validation,
                item.path,
                "-R",
                "--no-backup-if-mismatch",
            )
            if rc or _dirty_patch_output(output_text):
                raise ValueError(
                    f"superseded base patch failed to reverse: {item.path.name}"
                )
            reversed_patches.append(item.path.name)
        for item in selected:
            rc, output_text = _run_patch(
                validation,
                item.path,
                "--dry-run",
                "--forward",
            )
            if rc == 0 and not _dirty_patch_output(output_text):
                rc, output_text = _run_patch(
                    validation,
                    item.path,
                    "--forward",
                    "--no-backup-if-mismatch",
                )
                if rc or _dirty_patch_output(output_text):
                    raise ValueError(
                        f"patch validated but did not apply: {item.path.name}"
                    )
                applied.append(item)
                continue
            fingerprint = _patch_fingerprint(item.path)
            paths = _patch_paths(item.path)
            if (
                fingerprint
                and fingerprint in running_ids
                and _baseline_unchanged(running_tree, validation, paths)
            ):
                already_present.append(item.path.name)
                continue
            reverse_rc, reverse_output = _run_patch(
                validation,
                item.path,
                "--dry-run",
                "-R",
            )
            if reverse_rc == 0 and not _dirty_patch_output(reverse_output):
                already_present.append(item.path.name)
                continue
            raise ValueError(
                f"selected patch neither applies nor is fully present: "
                f"{item.path.name}"
            )
        if not applied:
            raise ValueError(
                "all selected security patches are already present in the base"
            )
        allowed = {
            path
            for item in (*applied, *superseded)
            for path in _patch_paths(item.path)
        }
        if not allowed:
            raise ValueError("applicable patches expose no affected paths")
        _aggregate_tree_diff(
            running_tree,
            validation,
            allowed,
            workspace=workspace,
            output=output,
        )
        return (
            tuple(item.path.name for item in applied),
            tuple(already_present),
            tuple(reversed_patches),
        )
    finally:
        shutil.rmtree(validation, ignore_errors=True)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _text_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="surrogateescape")).hexdigest()


def _file_diff(
    base_path: Path, target_path: Path, relative: str, *, context: int = 3
) -> str:
    completed = subprocess.run(
        [
            "git",
            "-c",
            "core.quotePath=false",
            "diff",
            "--no-index",
            "--binary",
            "--no-renames",
            f"--unified={context}",
            "--src-prefix=a/",
            "--dst-prefix=b/",
            str(base_path),
            str(target_path),
        ],
        capture_output=True,
        check=False,
        timeout=300,
    )
    if completed.returncode not in {0, 1}:
        raise ValueError(f"git could not diff folded-source file: {relative}")
    diff = completed.stdout.decode(errors="surrogateescape")
    diff = diff.replace(
        f"a/{str(base_path).lstrip('/')}", f"a/{relative}"
    ).replace(
        f"b/{str(target_path).lstrip('/')}", f"b/{relative}"
    )
    if not diff:
        raise ValueError(f"folded-source file is unchanged between releases: {relative}")
    return diff


def _select_diff_hunks(
    diff: str, requested_hashes: Sequence[str], relative: str
) -> tuple[str, tuple[str, ...]]:
    starts = [match.start() for match in re.finditer(r"^@@ ", diff, re.MULTILINE)]
    if not starts:
        raise ValueError(f"folded-source hunk selection requires a text diff: {relative}")
    header = diff[: starts[0]]
    hunks = tuple(
        diff[start : starts[index + 1] if index + 1 < len(starts) else len(diff)]
        for index, start in enumerate(starts)
    )
    available = {_text_sha256(hunk): hunk for hunk in hunks}
    selected: list[str] = []
    normalised: list[str] = []
    for value in requested_hashes:
        digest = str(value).lower()
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError(f"invalid folded-source hunk SHA-256 for {relative}")
        if digest in normalised:
            raise ValueError(f"duplicate folded-source hunk SHA-256 for {relative}")
        try:
            selected.append(available[digest])
        except KeyError as error:
            raise ValueError(
                f"folded-source hunk SHA-256 mismatch for {relative}: {digest}"
            ) from error
        normalised.append(digest)
    return header + "".join(selected), tuple(normalised)


def _drop_added_line(patch: str, line: str, relative: str) -> str:
    needle = f"+{line}\n"
    if patch.count(needle) != 1:
        raise ValueError(
            "folded-source adaptation line must occur exactly once "
            f"for {relative}: {line!r}"
        )
    position = patch.index(needle)
    hunk_start = patch.rfind("\n@@ ", 0, position)
    hunk_start = 0 if hunk_start < 0 else hunk_start + 1
    header_end = patch.find("\n", hunk_start)
    header = patch[hunk_start:header_end]
    match = re.match(
        r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(.*)$", header
    )
    if match is None:
        raise ValueError(f"cannot recount adapted folded-source hunk for {relative}")
    old_start, old_count, new_start, new_count, suffix = match.groups()
    adjusted_new_count = int(new_count or "1") - 1
    if adjusted_new_count < 0:
        raise ValueError(f"invalid adapted folded-source hunk count for {relative}")
    adjusted_header = (
        f"@@ -{old_start},{old_count or '1'} "
        f"+{new_start},{adjusted_new_count} @@{suffix}"
    )
    patch = patch[:hunk_start] + adjusted_header + patch[header_end:]
    return patch.replace(needle, "", 1)


def _write_folded_patch(groups: Sequence[FoldedSourceGroup], output: Path) -> None:
    patch = "".join(group.patch for group in groups)
    if not patch:
        raise ValueError("folded-source hunk evidence produced no patch")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(patch, encoding="utf-8", errors="surrogateescape")


def _safe_relative_file(tree: Path, value: object) -> tuple[str, Path]:
    relative = Path(str(value))
    if (
        relative.is_absolute()
        or not relative.parts
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise ValueError(f"folded-source evidence contains unsafe path: {value!r}")
    path = tree / relative
    if not path.is_file() or path.is_symlink():
        raise ValueError(
            f"folded-source evidence path is not a regular source file: {relative}"
        )
    return relative.as_posix(), path


def load_folded_source_evidence(
    path: Path,
    *,
    base: str,
    target: str,
    base_tree: Path,
    target_tree: Path,
    entries: Sequence[ChangelogEntry],
    requested_cves: frozenset[str],
    advisory_ticket_ids: dict[str, frozenset[str]],
) -> tuple[FoldedSourceGroup, ...]:
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict) or value.get("schema_version") not in {1, 2}:
        raise ValueError("folded-source evidence requires schema_version 1 or 2")
    schema_version = value["schema_version"]
    diff_context = value.get("diff_context", 3)
    if diff_context not in {0, 1, 3}:
        raise ValueError("folded-source diff_context must be 0, 1, or 3")
    if value.get("base") != base or value.get("target") != target:
        raise ValueError("folded-source evidence base/target does not match the job")
    raw_groups = value.get("groups")
    if not isinstance(raw_groups, list) or not raw_groups:
        raise ValueError("folded-source evidence groups must be a non-empty list")
    groups: list[FoldedSourceGroup] = []
    covered: set[str] = set()
    declared_paths: set[str] = set()
    for raw_group in raw_groups:
        if not isinstance(raw_group, dict):
            raise ValueError("folded-source evidence group must be an object")
        has_ticket = "ticket" in raw_group
        has_tickets = "tickets" in raw_group
        if has_ticket == has_tickets:
            raise ValueError(
                "folded-source group requires exactly one of ticket or tickets"
            )
        if has_tickets:
            if schema_version != 2:
                raise ValueError("folded-source tickets require schema_version 2")
            raw_tickets = raw_group["tickets"]
            if not isinstance(raw_tickets, list) or not raw_tickets:
                raise ValueError("folded-source tickets must be a non-empty list")
            tickets = tuple(str(item) for item in raw_tickets)
        else:
            tickets = (str(raw_group["ticket"]),)
        invalid_tickets = [
            ticket
            for ticket in tickets
            if not re.fullmatch(r"(?:RHEL-|BZ-)?[0-9]+", ticket)
        ]
        if invalid_tickets:
            raise ValueError(
                f"invalid folded-source ticket: {invalid_tickets[0]!r}"
            )
        if len(set(tickets)) != len(tickets):
            raise ValueError("folded-source tickets must not contain duplicates")
        ticket_label = "+".join(tickets)
        raw_cves = raw_group.get("cves")
        if not isinstance(raw_cves, list) or not raw_cves:
            raise ValueError(f"folded-source group {ticket_label} has no CVEs")
        cves = tuple(sorted({str(item).upper() for item in raw_cves}))
        invalid = [cve for cve in cves if not CVE_RE.fullmatch(cve)]
        if invalid:
            raise ValueError(f"invalid folded-source CVE: {invalid[0]}")
        unexpected = sorted(set(cves) - requested_cves)
        if unexpected:
            raise ValueError(
                "folded-source evidence CVE is outside the request: "
                + unexpected[0]
            )
        duplicate_cves = sorted(set(cves) & covered)
        if duplicate_cves:
            raise ValueError(
                "folded-source evidence CVE is declared more than once: "
                + duplicate_cves[0]
            )
        for cve in cves:
            proved_tickets = {
                ticket
                for ticket in tickets
                if any(
                    cve in entry.cves and ticket in entry.tickets
                    for entry in entries
                )
                or (
                    _ticket_id(ticket)
                    in advisory_ticket_ids.get(cve, frozenset())
                    and any(ticket in entry.tickets for entry in entries)
                )
            }
            if not proved_tickets:
                raise ValueError(
                    f"folded-source evidence lacks changelog or advisory-ticket proof for "
                    f"{cve}/{ticket_label}"
                )
        raw_files = raw_group.get("files")
        if not isinstance(raw_files, list) or not raw_files:
            raise ValueError(f"folded-source group {ticket_label} has no files")
        paths: list[str] = []
        patches: list[str] = []
        selected_hunks: list[tuple[str, tuple[str, ...]]] = []
        for raw_file in raw_files:
            if not isinstance(raw_file, dict):
                raise ValueError(
                    f"folded-source group {ticket_label} file must be an object"
                )
            relative, base_path = _safe_relative_file(
                base_tree, raw_file.get("path")
            )
            target_relative, target_path = _safe_relative_file(
                target_tree, raw_file.get("path")
            )
            if target_relative != relative:
                raise ValueError("folded-source file path normalisation mismatch")
            if relative in declared_paths:
                raise ValueError(
                    f"folded-source file is declared more than once: {relative}"
                )
            expected_base = str(raw_file.get("base_sha256", "")).lower()
            expected_target = str(raw_file.get("target_sha256", "")).lower()
            if not re.fullmatch(r"[0-9a-f]{64}", expected_base):
                raise ValueError(
                    f"invalid folded-source base SHA-256 for {relative}"
                )
            if not re.fullmatch(r"[0-9a-f]{64}", expected_target):
                raise ValueError(
                    f"invalid folded-source target SHA-256 for {relative}"
                )
            actual_base = _sha256(base_path)
            actual_target = _sha256(target_path)
            if actual_base != expected_base:
                raise ValueError(
                    f"folded-source base SHA-256 mismatch for {relative}"
                )
            if actual_target != expected_target:
                raise ValueError(
                    f"folded-source target SHA-256 mismatch for {relative}"
                )
            diff = _file_diff(
                base_path, target_path, relative, context=diff_context
            )
            if schema_version == 2:
                raw_hunks = raw_file.get("hunks")
                if not isinstance(raw_hunks, list) or not raw_hunks:
                    raise ValueError(
                        f"folded-source schema 2 file has no hunks: {relative}"
                    )
                selected_patch, hashes = _select_diff_hunks(
                    diff, raw_hunks, relative
                )
                drop_added_lines = raw_file.get("drop_added_lines", [])
                if not isinstance(drop_added_lines, list) or not all(
                    isinstance(line, str) and "\n" not in line
                    for line in drop_added_lines
                ):
                    raise ValueError(
                        f"invalid folded-source drop_added_lines for {relative}"
                    )
                for line in drop_added_lines:
                    selected_patch = _drop_added_line(
                        selected_patch, line, relative
                    )
                patches.append(selected_patch)
                selected_hunks.append((relative, hashes))
            elif "hunks" in raw_file:
                raise ValueError("folded-source hunks require schema_version 2")
            paths.append(relative)
            declared_paths.add(relative)
        groups.append(
            FoldedSourceGroup(
                tickets,
                cves,
                tuple(paths),
                "".join(patches),
                tuple(selected_hunks),
            )
        )
        covered.update(cves)
    missing = sorted(requested_cves - covered)
    if missing:
        raise ValueError(
            "folded-source evidence does not cover requested CVE(s): "
            + ", ".join(missing)
        )
    return tuple(groups)


def _requested_cves(path: Path) -> frozenset[str]:
    values = {
        line.strip().upper()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    }
    invalid = sorted(value for value in values if not CVE_RE.fullmatch(value))
    if invalid:
        raise ValueError("invalid requested CVE: " + invalid[0])
    if not values:
        raise ValueError("requested CVE list is empty")
    return frozenset(values)


def _advisory_ticket_evidence(
    path: Path | None,
    requested_cves: frozenset[str],
) -> dict[str, frozenset[str]]:
    if path is None:
        return {}
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise ValueError("advisory evidence requires schema_version 1")
    raw_evidence = value.get("cve_ticket_ids")
    if not isinstance(raw_evidence, dict):
        raise ValueError("advisory evidence cve_ticket_ids must be an object")
    evidence: dict[str, frozenset[str]] = {}
    for raw_cve, raw_tickets in raw_evidence.items():
        cve = str(raw_cve).upper()
        if not CVE_RE.fullmatch(cve):
            raise ValueError(f"invalid advisory evidence CVE: {raw_cve}")
        if cve not in requested_cves:
            raise ValueError(f"advisory evidence CVE is outside the request: {cve}")
        if not isinstance(raw_tickets, list):
            raise ValueError(f"advisory evidence tickets must be a list: {cve}")
        tickets = frozenset(str(ticket) for ticket in raw_tickets)
        invalid = sorted(ticket for ticket in tickets if not ticket.isdigit())
        if invalid:
            raise ValueError(f"invalid advisory ticket identifier: {invalid[0]}")
        if tickets:
            evidence[cve] = tickets
    return evidence


def select(args: argparse.Namespace) -> None:
    if not MODULE_NAME_RE.fullmatch(args.module_name):
        raise ValueError("module name must contain 1-55 letters, digits or underscores")
    if _arch(args.base) != _arch(args.target):
        raise ValueError("base and target architectures differ")
    workspace = args.workspace
    workspace.mkdir(parents=True, exist_ok=True)
    requested = _requested_cves(args.requested_cves)
    advisory_ticket_ids = _advisory_ticket_evidence(
        args.advisory_evidence,
        requested,
    )
    base = prepare_source(
        args.base,
        source_cache=args.source_cache,
        source_repo=args.source_repo,
        dnf_command=args.dnf_command,
        rpm_command=args.rpm_command,
        rpmbuild_command=args.rpmbuild_command,
    )
    target = prepare_source(
        args.target,
        source_cache=args.source_cache,
        source_repo=args.source_repo,
        dnf_command=args.dnf_command,
        rpm_command=args.rpm_command,
        rpmbuild_command=args.rpmbuild_command,
    )
    running_order = patch_order(
        base.spec,
        base.sources,
        architecture=_arch(args.base),
        evaluation=args.spec_evaluation,
        workspace=workspace,
        rpmspec_command=args.rpmspec_command,
    )
    target_order = patch_order(
        target.spec,
        target.sources,
        architecture=_arch(args.target),
        evaluation=args.spec_evaluation,
        workspace=workspace,
        rpmspec_command=args.rpmspec_command,
    )
    entries = changelog_entries(target.spec, args.base)
    folded_groups: tuple[FoldedSourceGroup, ...] = ()
    try:
        selected = select_patches(
            running_order,
            target_order,
            entries,
            requested,
            advisory_ticket_ids,
        )
    except ValueError as error:
        if (
            args.folded_source_evidence is None
            or not str(error).startswith(
                "requested CVE(s) have no selected patch:"
            )
        ):
            raise
        folded_groups = load_folded_source_evidence(
            args.folded_source_evidence,
            base=args.base,
            target=args.target,
            base_tree=base.tree,
            target_tree=target.tree,
            entries=entries,
            requested_cves=requested,
            advisory_ticket_ids=advisory_ticket_ids,
        )
        if any(group.patch for group in folded_groups):
            _write_folded_patch(folded_groups, args.patch)
        else:
            _aggregate_tree_diff(
                base.tree,
                target.tree,
                (
                    relative
                    for group in folded_groups
                    for relative in group.paths
                ),
                workspace=workspace,
                output=args.patch,
            )
        selected = ()
        applied = tuple(f"folded-source:{group.ticket}" for group in folded_groups)
        already_present = ()
        reversed_patches = ()
    else:
        superseded = select_superseded_patches(
            running_order,
            target_order,
            entries,
            requested,
        )
        applied, already_present, reversed_patches = validate_and_aggregate(
            base.tree,
            running_order,
            selected,
            superseded,
            workspace=workspace,
            output=args.patch,
        )
    report = (
        [
            {
                "patch": item.path.name,
                "origins": list(item.origins),
                "cves": list(item.cves),
            }
            for item in selected
        ]
        if selected
        else [
            {
                "patch": f"folded-source:{group.ticket}",
                "origins": ["operator-folded-source-evidence", f"series({group.ticket})"],
                "cves": list(group.cves),
                "paths": list(group.paths),
                "selected_hunks": {
                    relative: list(hashes)
                    for relative, hashes in group.selected_hunks
                },
            }
            for group in folded_groups
        ]
    )
    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    args.manifest.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "selector": "central-el9-cve-selector",
                "base": args.base,
                "target": args.target,
                "module_name": args.module_name,
                "base_source_tree": str(base.tree.resolve()),
                "covered_cves": sorted(requested),
                "advisory_ticket_evidence": {
                    cve: sorted(ticket_ids)
                    for cve, ticket_ids in sorted(advisory_ticket_ids.items())
                },
                "selected_patches": report,
                "applied_patches": list(applied),
                "already_present_patches": list(already_present),
                "reversed_superseded_patches": list(reversed_patches),
                "folded_source_evidence": (
                    str(args.folded_source_evidence.resolve())
                    if folded_groups
                    else None
                ),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Select and validate cumulative EL9 CVE livepatch input"
    )
    parser.add_argument("--base", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--patch", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--requested-cves", type=Path, required=True)
    parser.add_argument("--advisory-evidence", type=Path)
    parser.add_argument("--folded-source-evidence", type=Path)
    parser.add_argument("--module-name", required=True)
    parser.add_argument(
        "--source-cache",
        type=Path,
        default=Path("/var/lib/livepatch-repo/source-cache"),
    )
    parser.add_argument("--source-repo", default="baseos-source")
    parser.add_argument(
        "--spec-evaluation",
        choices=("required", "static"),
        default="required",
    )
    parser.add_argument("--dnf-command", default="dnf")
    parser.add_argument("--rpm-command", default="rpm")
    parser.add_argument("--rpmbuild-command", default="rpmbuild")
    parser.add_argument("--rpmspec-command", default="rpmspec")
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    try:
        select(_parser().parse_args(arguments))
        return 0
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"central-el9-selector: error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
