from pathlib import Path
import json
import multiprocessing
import os
import tempfile
import time
import unittest

from livepatch_repo.publication import publish_repository


def _publish_process(
    repository: str,
    rpm: str,
    command: str,
    profile: str,
) -> None:
    publish_repository(
        Path(repository),
        (Path(rpm),),
        createrepo_command=command,
        profile_id=profile,
        minimum_age_seconds=0,
    )


class TestRepositoryPublication(unittest.TestCase):
    def test_publication_atomically_retains_existing_rpms(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            command = root / "fake-createrepo"
            command.write_text(
                "#!/bin/sh\n"
                "mkdir -p \"$1/repodata\"\n"
                "touch \"$1/repodata/repomd.xml\"\n",
                encoding="utf-8",
            )
            command.chmod(0o755)
            first = root / "first.rpm"
            second = root / "second.rpm"
            first.write_bytes(b"first")
            second.write_bytes(b"second")
            repository = root / "repository"
            first_result = publish_repository(
                repository,
                (first,),
                createrepo_command=str(command),
                profile_id="el9_8-x86_64",
                minimum_age_seconds=0,
            )
            first_target = (repository / "current").resolve()
            # A still-pinned package is retained across the atomic promotion.
            second_result = publish_repository(
                repository,
                (second,),
                createrepo_command=str(command),
                profile_id="el9_8-x86_64",
                pinned_rpms=(first,),
                minimum_age_seconds=0,
            )
            second_target = (repository / "current").resolve()
            self.assertNotEqual(first_target, second_target)
            self.assertEqual(
                sorted(path.name for path in (second_target / "Packages").glob("*.rpm")),
                ["first.rpm", "second.rpm"],
            )
            self.assertTrue((second_target / "repodata" / "repomd.xml").is_file())
            self.assertTrue(first_result.objects_by_name["first.rpm"].is_file())
            self.assertEqual(
                second_result.objects_by_name["first.rpm"].resolve(),
                first_result.objects_by_name["first.rpm"].resolve(),
            )

    def test_unpinned_superseded_package_is_dropped(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            command = root / "fake-createrepo"
            command.write_text(
                "#!/bin/sh\n"
                "mkdir -p \"$1/repodata\"\n"
                "touch \"$1/repodata/repomd.xml\"\n",
                encoding="utf-8",
            )
            command.chmod(0o755)
            first = root / "old.rpm"
            second = root / "new.rpm"
            first.write_bytes(b"old")
            second.write_bytes(b"new")
            repository = root / "repository"
            publish_repository(
                repository,
                (first,),
                createrepo_command=str(command),
                profile_id="el9_8-x86_64",
                minimum_age_seconds=0,
            )
            # The same profile republishes without pinning the superseded RPM.
            publish_repository(
                repository,
                (second,),
                createrepo_command=str(command),
                profile_id="el9_8-x86_64",
                minimum_age_seconds=0,
            )
            current = (repository / "current").resolve()
            self.assertEqual(
                sorted(path.name for path in (current / "Packages").glob("*.rpm")),
                ["new.rpm"],
            )

    def test_empty_profile_update_retires_its_packages_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            command = root / "fake-createrepo"
            command.write_text(
                "#!/bin/sh\n"
                "mkdir -p \"$1/repodata\"\n"
                "touch \"$1/repodata/repomd.xml\"\n",
                encoding="utf-8",
            )
            command.chmod(0o755)
            old = root / "old-stream.rpm"
            other = root / "other-stream.rpm"
            old.write_bytes(b"old")
            other.write_bytes(b"other")
            repository = root / "repository"
            publish_repository(
                repository,
                (old,),
                createrepo_command=str(command),
                profile_id="el9_8-x86_64",
                minimum_age_seconds=0,
            )
            publish_repository(
                repository,
                (other,),
                createrepo_command=str(command),
                profile_id="el9_9-x86_64",
                minimum_age_seconds=0,
            )

            publish_repository(
                repository,
                (),
                createrepo_command=str(command),
                profile_id="el9_8-x86_64",
                pinned_rpms=(),
                minimum_age_seconds=0,
            )

            current = (repository / "current").resolve()
            self.assertEqual(
                [path.name for path in (current / "Packages").glob("*.rpm")],
                ["other-stream.rpm"],
            )
            pins = json.loads(
                (repository / "profiles" / "el9_8-x86_64.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(pins["objects"], [])

    def test_superseded_object_is_reclaimed_from_pool_and_current(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            command = root / "fake-createrepo"
            command.write_text(
                "#!/bin/sh\n"
                "mkdir -p \"$1/repodata\"\n"
                "touch \"$1/repodata/repomd.xml\"\n",
                encoding="utf-8",
            )
            command.chmod(0o755)
            old = root / "old.rpm"
            new = root / "new.rpm"
            old.write_bytes(b"old")
            new.write_bytes(b"new")
            repository = root / "repository"
            first = publish_repository(
                repository,
                (old,),
                createrepo_command=str(command),
                profile_id="el9_8-x86_64",
                retain_versions=1,
                minimum_age_seconds=0,
            )
            old_object = first.objects_by_name["old.rpm"]
            self.assertTrue(old_object.is_file())
            # Republish without pinning old.rpm: it is superseded.
            second = publish_repository(
                repository,
                (new,),
                createrepo_command=str(command),
                profile_id="el9_8-x86_64",
                retain_versions=1,
                minimum_age_seconds=0,
            )
            current = (repository / "current").resolve()
            # Gone from the served repository...
            self.assertEqual(
                sorted(path.name for path in (current / "Packages").glob("*.rpm")),
                ["new.rpm"],
            )
            # ...and reclaimed from the content-addressed object pool.
            self.assertFalse(old_object.exists())
            self.assertIn(old_object.parent, second.removed_objects)
            pooled = sorted(
                path.name
                for digest in (repository / "objects" / "sha256").glob("*")
                for path in digest.glob("*.rpm")
            )
            self.assertEqual(pooled, ["new.rpm"])

    def test_retention_keeps_count_and_age_floor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            command = root / "fake-createrepo"
            command.write_text(
                "#!/bin/sh\n"
                "mkdir -p \"$1/repodata\"\n"
                "touch \"$1/repodata/repomd.xml\"\n",
                encoding="utf-8",
            )
            command.chmod(0o755)
            repository = root / "repository"
            for number in range(3):
                rpm = root / f"package-{number}.rpm"
                rpm.write_bytes(str(number).encode())
                publish_repository(
                    repository,
                    (rpm,),
                    createrepo_command=str(command),
                    profile_id="el9_8-x86_64",
                    retain_versions=2,
                    minimum_age_seconds=3600,
                )
            versions = sorted((repository / "versions").glob("repo-*"))
            self.assertEqual(len(versions), 3)
            old = min(versions, key=lambda path: path.stat().st_mtime)
            old_time = time.time() - 7200
            os.utime(old, (old_time, old_time))
            rpm = root / "package-3.rpm"
            rpm.write_bytes(b"3")
            result = publish_repository(
                repository,
                (rpm,),
                createrepo_command=str(command),
                profile_id="el9_8-x86_64",
                retain_versions=2,
                minimum_age_seconds=3600,
            )
            self.assertIn(old, result.removed_versions)
            self.assertFalse(old.exists())

    def test_repository_lock_prevents_stale_snapshot_package_loss(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repository"
            entered = root / "entered"
            release = root / "release"
            slow = root / "slow-createrepo"
            slow.write_text(
                "#!/bin/sh\n"
                f"touch {entered}\n"
                f"while [ ! -e {release} ]; do sleep 0.05; done\n"
                "mkdir -p \"$1/repodata\"\n"
                "touch \"$1/repodata/repomd.xml\"\n",
                encoding="utf-8",
            )
            fast = root / "fast-createrepo"
            fast.write_text(
                "#!/bin/sh\n"
                "mkdir -p \"$1/repodata\"\n"
                "touch \"$1/repodata/repomd.xml\"\n",
                encoding="utf-8",
            )
            slow.chmod(0o755)
            fast.chmod(0o755)
            first = root / "first.rpm"
            second = root / "second.rpm"
            first.write_bytes(b"first")
            second.write_bytes(b"second")
            context = multiprocessing.get_context("fork")
            publisher_a = context.Process(
                target=_publish_process,
                args=(
                    str(repository),
                    str(first),
                    str(slow),
                    "el9_8-x86_64",
                ),
            )
            publisher_b = context.Process(
                target=_publish_process,
                args=(
                    str(repository),
                    str(second),
                    str(fast),
                    "el9_9-x86_64",
                ),
            )
            publisher_a.start()
            deadline = time.time() + 10
            while not entered.exists() and time.time() < deadline:
                time.sleep(0.05)
            self.assertTrue(entered.exists())
            publisher_b.start()
            time.sleep(0.2)
            self.assertTrue(publisher_b.is_alive())
            release.touch()
            publisher_a.join(10)
            publisher_b.join(10)
            self.assertEqual(publisher_a.exitcode, 0)
            self.assertEqual(publisher_b.exitcode, 0)
            self.assertEqual(
                sorted(
                    path.name
                    for path in (repository / "current" / "Packages").glob("*.rpm")
                ),
                ["first.rpm", "second.rpm"],
            )


if __name__ == "__main__":
    unittest.main()
