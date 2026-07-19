from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import shutil
import subprocess
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

from .state import write_json_atomic


@dataclass(frozen=True)
class PublicationResult:
    current: Path
    objects_by_name: dict[str, Path]
    removed_versions: tuple[Path, ...]
    removed_objects: tuple[Path, ...]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def _object_path(repository_root: Path, digest: str, name: str) -> Path:
    return repository_root / "objects" / "sha256" / digest / name


def _import_object(repository_root: Path, source: Path) -> tuple[str, Path]:
    if not source.is_file():
        raise ValueError(f"RPM does not exist: {source}")
    digest = _digest(source)
    target = _object_path(repository_root, digest, source.name)
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        if _digest(target) != digest:
            raise ValueError(f"corrupt repository object: {target}")
        return digest, target
    temporary = target.parent / f".{target.name}-{uuid.uuid4().hex}"
    shutil.copy2(source, temporary)
    if _digest(temporary) != digest:
        temporary.unlink(missing_ok=True)
        raise ValueError(f"RPM changed while importing: {source}")
    os.replace(temporary, target)
    return digest, target


def _materialise_object(source: Path, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.link(source, target)
        return
    except OSError:
        pass
    completed = subprocess.run(
        ["cp", "-a", "--reflink=auto", str(source), str(target)],
        check=False,
        capture_output=True,
        timeout=300,
    )
    if completed.returncode != 0:
        shutil.copy2(source, target)


def _read_pin_manifest(path: Path) -> list[tuple[str, str]]:
    with path.open(encoding="utf-8") as handle:
        document = json.load(handle)
    objects = document.get("objects")
    if not isinstance(objects, list):
        raise ValueError(f"invalid repository pin manifest: {path}")
    pins: list[tuple[str, str]] = []
    for item in objects:
        if not isinstance(item, dict) or "name" not in item or "sha256" not in item:
            raise ValueError(f"invalid repository pin manifest object: {path}")
        pins.append((str(item["name"]), str(item["sha256"])))
    return pins


def _write_profile_pins(
    repository_root: Path,
    profile_id: str,
    objects: dict[str, tuple[str, Path]],
) -> None:
    pins = repository_root / "profiles" / f"{profile_id}.json"
    write_json_atomic(
        pins,
        {
            "schema_version": 1,
            "updated_at": _now(),
            "objects": [
                {"name": name, "sha256": digest}
                for name, (digest, _) in sorted(objects.items())
            ],
        },
    )


def _referenced_digests(repository_root: Path) -> set[str]:
    referenced: set[str] = set()
    for manifest in (
        list((repository_root / "versions").glob("repo-*/manifest.json"))
        + list((repository_root / "profiles").glob("*.json"))
    ):
        try:
            with manifest.open(encoding="utf-8") as handle:
                value = json.load(handle)
            objects = value.get("objects")
            if isinstance(objects, list):
                referenced.update(
                    str(item["sha256"])
                    for item in objects
                    if isinstance(item, dict) and "sha256" in item
                )
        except (OSError, ValueError, json.JSONDecodeError):
            raise ValueError(f"could not read repository references: {manifest}")
    return referenced


def _prune(
    repository_root: Path,
    *,
    retain_versions: int,
    minimum_age_seconds: int,
) -> tuple[tuple[Path, ...], tuple[Path, ...]]:
    if retain_versions < 1:
        raise ValueError("repository retention count must be at least 1")
    if minimum_age_seconds < 0:
        raise ValueError("repository minimum retention age cannot be negative")
    current = (repository_root / "current").resolve()
    versions = sorted(
        (repository_root / "versions").glob("repo-*"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    retained = set(versions[:retain_versions])
    retained.add(current)
    cutoff = time.time() - minimum_age_seconds
    removed_versions: list[Path] = []
    for version in versions:
        if version in retained or version.stat().st_mtime > cutoff:
            continue
        shutil.rmtree(version)
        removed_versions.append(version)

    referenced = _referenced_digests(repository_root)
    removed_objects: list[Path] = []
    for digest_dir in (repository_root / "objects" / "sha256").glob("*"):
        if not digest_dir.is_dir() or digest_dir.name in referenced:
            continue
        if digest_dir.stat().st_mtime > cutoff:
            continue
        shutil.rmtree(digest_dir)
        removed_objects.append(digest_dir)
    return tuple(removed_versions), tuple(removed_objects)


def publish_repository(
    repository_root: Path,
    rpms: Sequence[Path],
    *,
    createrepo_command: str,
    profile_id: str = "default",
    pinned_rpms: Sequence[Path] = (),
    retain_versions: int = 4,
    minimum_age_seconds: int = 86400,
) -> PublicationResult:
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", profile_id):
        raise ValueError("repository profile contains unsafe characters")
    repository_root.mkdir(parents=True, exist_ok=True)
    lock_path = repository_root / "publication.lock"
    with lock_path.open("a+") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        versions = repository_root / "versions"
        versions.mkdir(parents=True, exist_ok=True)
        current = repository_root / "current"
        objects: dict[str, tuple[str, Path]] = {}
        # Preserve every other profile's authoritative pinned objects. This
        # profile contributes only its own pin/build set, so superseded and
        # expired releases it no longer pins fall out of the new version.
        profiles_dir = repository_root / "profiles"
        if profiles_dir.is_dir():
            for pin_file in sorted(profiles_dir.glob("*.json")):
                if pin_file.stem == profile_id:
                    continue
                for name, digest in _read_pin_manifest(pin_file):
                    path = _object_path(repository_root, digest, name)
                    if not path.is_file():
                        raise ValueError(
                            f"referenced repository object is missing: {path}"
                        )
                    existing = objects.get(name)
                    if existing is not None and existing[0] != digest:
                        raise ValueError(f"conflicting RPM filename: {name}")
                    objects[name] = (digest, path)
        profile_objects: dict[str, tuple[str, Path]] = {}
        for source in list(pinned_rpms) + list(rpms):
            if not source.is_file():
                continue
            digest, path = _import_object(repository_root, source)
            existing = objects.get(source.name)
            if existing is not None and existing[0] != digest:
                raise ValueError(f"conflicting RPM filename: {source.name}")
            objects[source.name] = (digest, path)
            profile_objects[source.name] = (digest, path)

        version_name = f"repo-{uuid.uuid4().hex}"
        staging = versions / version_name
        packages = staging / "Packages"
        try:
            for name, (_, source) in sorted(objects.items()):
                _materialise_object(source, packages / name)
            write_json_atomic(
                staging / "manifest.json",
                {
                    "schema_version": 1,
                    "created_at": _now(),
                    "objects": [
                        {"name": name, "sha256": digest}
                        for name, (digest, _) in sorted(objects.items())
                    ],
                },
            )
            subprocess.run(
                [createrepo_command, str(staging)],
                check=True,
                timeout=300,
            )
            if not (staging / "repodata" / "repomd.xml").is_file():
                raise ValueError("createrepo did not produce repodata/repomd.xml")
            temporary_link = repository_root / f".current-{uuid.uuid4().hex}"
            os.symlink(Path("versions") / version_name, temporary_link)
            os.replace(temporary_link, current)
            _write_profile_pins(repository_root, profile_id, profile_objects)
            removed_versions, removed_objects = _prune(
                repository_root,
                retain_versions=retain_versions,
                minimum_age_seconds=minimum_age_seconds,
            )
            return PublicationResult(
                current=current,
                objects_by_name={
                    name: path for name, (_, path) in objects.items()
                },
                removed_versions=removed_versions,
                removed_objects=removed_objects,
            )
        except BaseException:
            if not current.is_symlink() or current.resolve() != staging:
                shutil.rmtree(staging, ignore_errors=True)
            raise
