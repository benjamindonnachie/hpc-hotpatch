from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest
from unittest import mock

from livepatch_repo.el9_selector import (
    _copy_aggregate_paths,
    changelog_entries,
    load_folded_source_evidence,
    main,
    prepare_kernel_release,
    prepare_source,
)


BASE = "5.14.0-687.24.1.el9_8.x86_64"
TARGET = "5.14.0-687.25.1.el9_8.x86_64"


def git_patch(subject: str, old: str, new: str) -> str:
    return textwrap.dedent(
        f"""\
        From 0000000000000000000000000000000000000000 Mon Sep 17 00:00:00 2001
        Subject: [PATCH] {subject}

        diff --git a/security.txt b/security.txt
        index 3367afd..3e75765 100644
        --- a/security.txt
        +++ b/security.txt
        @@ -1 +1 @@
        -{old}
        +{new}
        """
    )


class TestEl9Selector(unittest.TestCase):
    def _kernel_cache(
        self,
        root: Path,
        kernel: str,
        *,
        patches: dict[str, str],
        changelog: str,
    ) -> None:
        nvr = kernel.rsplit(".", 1)[0]
        topdir = root / nvr / "rpmbuild"
        sources = topdir / "SOURCES"
        specs = topdir / "SPECS"
        tree = topdir / "BUILD" / "kernel-build" / "linux-test"
        sources.mkdir(parents=True)
        specs.mkdir()
        tree.mkdir(parents=True)
        (tree / "security.txt").write_text("old\n", encoding="utf-8")
        (tree / "Makefile").write_text(
            "VERSION = 5\n"
            "PATCHLEVEL = 14\n"
            "SUBLEVEL = 0\n"
            "EXTRAVERSION =\n",
            encoding="utf-8",
        )
        declarations = []
        for number, (name, content) in enumerate(patches.items(), start=1):
            (sources / name).write_text(content, encoding="utf-8")
            declarations.append(f"Patch{number}: {name}")
        (specs / "kernel.spec").write_text(
            "\n".join(declarations)
            + "\n%prep\n"
            + "\n%changelog\n"
            + changelog,
            encoding="utf-8",
        )
        (topdir / ".prep-complete").touch()

    def test_prepares_exact_kernel_release_and_invalidates_stale_markers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            tree = Path(temporary)
            (tree / "Makefile").write_text(
                "VERSION = 5\n"
                "PATCHLEVEL = 14\n"
                "SUBLEVEL = 0\n"
                "EXTRAVERSION =\n",
                encoding="utf-8",
            )
            release_file = tree / "include" / "config" / "kernel.release"
            uts_file = tree / "include" / "generated" / "utsrelease.h"
            release_file.parent.mkdir(parents=True)
            uts_file.parent.mkdir(parents=True)
            release_file.write_text("5.14.0\n", encoding="utf-8")
            uts_file.write_text('#define UTS_RELEASE "5.14.0"\n', encoding="utf-8")

            prepare_kernel_release(tree, BASE)

            self.assertIn(
                "EXTRAVERSION = -687.24.1.el9_8.x86_64",
                (tree / "Makefile").read_text(encoding="utf-8"),
            )
            self.assertFalse(release_file.exists())
            self.assertFalse(uts_file.exists())

    def test_folded_source_evidence_builds_pinned_ticket_scoped_diff(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cache = root / "cache"
            unrelated = git_patch("unrelated maintenance", "old", "maintenance")
            self._kernel_cache(
                cache,
                BASE,
                patches={"0001-unrelated.patch": unrelated},
                changelog=(
                    "* Tue Jul 14 2026 Builder [5.14.0-687.24.1.el9_8]\n"
                ),
            )
            self._kernel_cache(
                cache,
                TARGET,
                patches={"0001-unrelated.patch": unrelated},
                changelog=(
                    "* Wed Jul 15 2026 Builder [5.14.0-687.25.1.el9_8]\n"
                    "- drm: security fix (Dev) [RHEL-179886] "
                    "{CVE-2026-46215}\n"
                    "* Tue Jul 14 2026 Builder [5.14.0-687.24.1.el9_8]\n"
                ),
            )
            base_tree = (
                cache
                / BASE.rsplit(".", 1)[0]
                / "rpmbuild/BUILD/kernel-build/linux-test"
            )
            target_tree = (
                cache
                / TARGET.rsplit(".", 1)[0]
                / "rpmbuild/BUILD/kernel-build/linux-test"
            )
            relative = Path("drivers/gpu/drm/drm_gem.c")
            (base_tree / relative).parent.mkdir(parents=True)
            (target_tree / relative).parent.mkdir(parents=True)
            (base_tree / relative).write_text("old implementation\n", encoding="utf-8")
            (target_tree / relative).write_text(
                "fixed implementation\n", encoding="utf-8"
            )

            def digest(path: Path) -> str:
                return hashlib.sha256(path.read_bytes()).hexdigest()

            workspace = root / "workspace"
            workspace.mkdir()
            requested = workspace / "requested.txt"
            requested.write_text("CVE-2026-46215\n", encoding="utf-8")
            evidence = workspace / "folded-source.json"
            evidence.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "base": BASE,
                        "target": TARGET,
                        "groups": [
                            {
                                "ticket": "RHEL-179886",
                                "cves": ["CVE-2026-46215"],
                                "files": [
                                    {
                                        "path": relative.as_posix(),
                                        "base_sha256": digest(base_tree / relative),
                                        "target_sha256": digest(target_tree / relative),
                                    }
                                ],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            manifest = workspace / "selection.json"
            patch = workspace / "source.patch"
            result = main(
                [
                    "--base",
                    BASE,
                    "--target",
                    TARGET,
                    "--workspace",
                    str(workspace),
                    "--patch",
                    str(patch),
                    "--manifest",
                    str(manifest),
                    "--requested-cves",
                    str(requested),
                    "--folded-source-evidence",
                    str(evidence),
                    "--module-name",
                    "klp_test_folded",
                    "--source-cache",
                    str(cache),
                    "--spec-evaluation",
                    "static",
                ]
            )
            self.assertEqual(result, 0)
            self.assertIn(
                "drivers/gpu/drm/drm_gem.c",
                patch.read_text(encoding="utf-8"),
            )
            value = json.loads(manifest.read_text(encoding="utf-8"))
            self.assertEqual(
                value["applied_patches"],
                ["folded-source:RHEL-179886"],
            )
            self.assertEqual(
                value["selected_patches"][0]["origins"],
                [
                    "operator-folded-source-evidence",
                    "series(RHEL-179886)",
                ],
            )
            raw_evidence = json.loads(evidence.read_text(encoding="utf-8"))
            raw_evidence["groups"][0]["files"][0]["target_sha256"] = "0" * 64
            evidence.write_text(json.dumps(raw_evidence), encoding="utf-8")
            target_spec = (
                cache
                / TARGET.rsplit(".", 1)[0]
                / "rpmbuild/SPECS/kernel.spec"
            )
            with self.assertRaisesRegex(ValueError, "target SHA-256 mismatch"):
                load_folded_source_evidence(
                    evidence,
                    base=BASE,
                    target=TARGET,
                    base_tree=base_tree,
                    target_tree=target_tree,
                    entries=changelog_entries(target_spec, BASE),
                    requested_cves=frozenset({"CVE-2026-46215"}),
                )

    def test_rejects_source_version_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            tree = Path(temporary)
            (tree / "Makefile").write_text(
                "VERSION = 6\n"
                "PATCHLEVEL = 1\n"
                "SUBLEVEL = 0\n"
                "EXTRAVERSION =\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "does not match kernel"):
                prepare_kernel_release(tree, BASE)

    def test_concurrent_cold_prepare_runs_once_and_promotes_atomically(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cache = Path(temporary) / "cache"
            calls: list[str] = []

            def fake_run(command, **kwargs):
                command = list(command)
                calls.append(command[0])
                if command[0] == "dnf":
                    destination = Path(
                        command[command.index("--downloaddir") + 1]
                    )
                    nvr = BASE.rsplit(".", 1)[0]
                    (destination / f"kernel-{nvr}.src.rpm").write_bytes(b"srpm")
                else:
                    topdir = Path(
                        command[command.index("--define") + 1].split(" ", 1)[1]
                    )
                    if command[0] == "rpm":
                        (topdir / "SPECS").mkdir(parents=True)
                        (topdir / "SOURCES").mkdir()
                        (topdir / "SPECS" / "kernel.spec").write_text(
                            "%prep\n", encoding="utf-8"
                        )
                    elif command[0] == "rpmbuild":
                        tree = topdir / "BUILD" / "kernel" / "linux-test"
                        tree.mkdir(parents=True)
                        (tree / "Makefile").write_text(
                            "VERSION = 5\n"
                            "PATCHLEVEL = 14\n"
                            "SUBLEVEL = 0\n"
                            "EXTRAVERSION =\n",
                            encoding="utf-8",
                        )
                return subprocess.CompletedProcess(command, 0)

            def prepare():
                return prepare_source(
                    BASE,
                    source_cache=cache,
                    source_repo="",
                    dnf_command="dnf",
                    rpm_command="rpm",
                    rpmbuild_command="rpmbuild",
                )

            with mock.patch(
                "livepatch_repo.el9_selector._run", side_effect=fake_run
            ):
                with ThreadPoolExecutor(max_workers=2) as executor:
                    results = tuple(executor.map(lambda _: prepare(), range(2)))

            self.assertEqual(calls.count("dnf"), 1)
            self.assertEqual(calls.count("rpm"), 1)
            self.assertEqual(calls.count("rpmbuild"), 1)
            self.assertEqual(results[0].tree, results[1].tree)
            self.assertTrue(
                (results[0].tree.parents[2] / ".prep-complete").is_file()
            )
            self.assertFalse(tuple(cache.glob(".*.prepare-*")))

    def test_aggregate_projection_contains_only_selected_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            destination = root / "projected"
            (source / "net").mkdir(parents=True)
            (source / "net" / "selected.c").write_text("selected\n")
            (source / "large-build-output.o").write_bytes(b"unrelated")

            _copy_aggregate_paths(source, destination, {"net/selected.c"})

            self.assertEqual(
                (destination / "net" / "selected.c").read_text(),
                "selected\n",
            )
            self.assertFalse((destination / "large-build-output.o").exists())

    def test_adapter_generates_aggregate_and_exact_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cache = root / "cache"
            common = git_patch("base: common change", "unused", "unused-new")
            security = git_patch("net: fix security issue", "old", "fixed")
            self._kernel_cache(
                cache,
                BASE,
                patches={"0001-base-common.patch": common},
                changelog=(
                    "* Tue Jul 14 2026 Builder - 5.14.0-687.24.1\n"
                    "- old entry\n"
                ),
            )
            self._kernel_cache(
                cache,
                TARGET,
                patches={
                    "0001-base-common.patch": common,
                    "0002-net-fix-security-issue.patch": security,
                },
                changelog=(
                    "* Wed Jul 15 2026 Builder [5.14.0-687.25.1.el9_8]\n"
                    "- net: fix security issue (Dev) [RHEL-12345] "
                    "{CVE-2026-12345}\n"
                    "* Tue Jul 14 2026 Builder [5.14.0-687.24.1.el9_8]\n"
                    "- old entry\n"
                ),
            )
            workspace = root / "workspace"
            requested = workspace / "requested.txt"
            workspace.mkdir()
            requested.write_text("CVE-2026-12345\n", encoding="utf-8")
            patch = workspace / "source.patch"
            manifest = workspace / "selection.json"
            result = main(
                [
                    "--base",
                    BASE,
                    "--target",
                    TARGET,
                    "--workspace",
                    str(workspace),
                    "--patch",
                    str(patch),
                    "--manifest",
                    str(manifest),
                    "--requested-cves",
                    str(requested),
                    "--module-name",
                    "klp_test_1234",
                    "--source-cache",
                    str(cache),
                    "--spec-evaluation",
                    "static",
                ]
            )
            self.assertEqual(result, 0)
            self.assertIn("+fixed", patch.read_text(encoding="utf-8"))
            value = json.loads(manifest.read_text(encoding="utf-8"))
            self.assertEqual(value["covered_cves"], ["CVE-2026-12345"])
            self.assertEqual(
                value["applied_patches"],
                ["0002-net-fix-security-issue.patch"],
            )

    def test_missing_requested_cve_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cache = root / "cache"
            common = git_patch("base: common change", "unused", "unused-new")
            self._kernel_cache(
                cache,
                BASE,
                patches={"0001-base-common.patch": common},
                changelog=(
                    "* Tue Jul 14 2026 Builder [5.14.0-687.24.1.el9_8]\n"
                ),
            )
            self._kernel_cache(
                cache,
                TARGET,
                patches={"0001-base-common.patch": common},
                changelog=(
                    "* Wed Jul 15 2026 Builder [5.14.0-687.25.1.el9_8]\n"
                    "- ordinary bug fix\n"
                    "* Tue Jul 14 2026 Builder [5.14.0-687.24.1.el9_8]\n"
                ),
            )
            workspace = root / "workspace"
            workspace.mkdir()
            requested = workspace / "requested.txt"
            requested.write_text("CVE-2026-99999\n", encoding="utf-8")
            result = main(
                [
                    "--base",
                    BASE,
                    "--target",
                    TARGET,
                    "--workspace",
                    str(workspace),
                    "--patch",
                    str(workspace / "source.patch"),
                    "--manifest",
                    str(workspace / "selection.json"),
                    "--requested-cves",
                    str(requested),
                    "--module-name",
                    "klp_test_1234",
                    "--source-cache",
                    str(cache),
                    "--spec-evaluation",
                    "static",
                ]
            )
            self.assertEqual(result, 1)
            self.assertFalse((workspace / "selection.json").exists())

    def test_advisory_ticket_selects_unbraced_cve_patch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cache = root / "cache"
            common = git_patch("base: common change", "unused", "unused-new")
            security = git_patch(
                "netfilter: bridge: make ebt_snat ARP rewrite writable",
                "old",
                "fixed",
            )
            self._kernel_cache(
                cache,
                BASE,
                patches={"0001-base-common.patch": common},
                changelog=(
                    "* Tue Jul 14 2026 Builder [5.14.0-687.24.1.el9_8]\n"
                ),
            )
            self._kernel_cache(
                cache,
                TARGET,
                patches={
                    "0001-base-common.patch": common,
                    "1740-netfilter-bridge-make-ebt-snat-arp-rewrite-writable.patch": security,
                },
                changelog=(
                    "* Wed Jul 15 2026 Builder [5.14.0-687.25.1.el9_8]\n"
                    "- netfilter: bridge: make ebt_snat ARP rewrite writable "
                    "(CKI Backport Bot) [RHEL-182344]\n"
                    "* Tue Jul 14 2026 Builder [5.14.0-687.24.1.el9_8]\n"
                ),
            )
            workspace = root / "workspace"
            workspace.mkdir()
            requested = workspace / "requested.txt"
            requested.write_text("CVE-2026-53266\n", encoding="utf-8")
            evidence = workspace / "advisory-evidence.json"
            evidence.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "cve_ticket_ids": {"CVE-2026-53266": ["182344"]},
                    }
                ),
                encoding="utf-8",
            )
            manifest = workspace / "selection.json"
            result = main(
                [
                    "--base",
                    BASE,
                    "--target",
                    TARGET,
                    "--workspace",
                    str(workspace),
                    "--patch",
                    str(workspace / "source.patch"),
                    "--manifest",
                    str(manifest),
                    "--requested-cves",
                    str(requested),
                    "--advisory-evidence",
                    str(evidence),
                    "--module-name",
                    "klp_test_53266",
                    "--source-cache",
                    str(cache),
                    "--spec-evaluation",
                    "static",
                ]
            )
            self.assertEqual(result, 0)
            value = json.loads(manifest.read_text(encoding="utf-8"))
            self.assertEqual(value["covered_cves"], ["CVE-2026-53266"])
            self.assertEqual(
                value["selected_patches"][0]["patch"],
                "1740-netfilter-bridge-make-ebt-snat-arp-rewrite-writable.patch",
            )
            self.assertIn(
                "advisory-ticket(182344)",
                value["selected_patches"][0]["origins"],
            )

    def test_series_prerequisite_is_selected_and_applied_in_order(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cache = root / "cache"
            common = git_patch("base: common change", "unused", "unused-new")
            prerequisite = git_patch("net: prepare security fix", "old", "middle")
            security = git_patch("net: complete security fix", "middle", "fixed")
            self._kernel_cache(
                cache,
                BASE,
                patches={"0001-base-common.patch": common},
                changelog=(
                    "* Tue Jul 14 2026 Builder [5.14.0-687.24.1.el9_8]\n"
                ),
            )
            self._kernel_cache(
                cache,
                TARGET,
                patches={
                    "0001-base-common.patch": common,
                    "0002-net-prepare-security-fix.patch": prerequisite,
                    "0003-net-complete-security-fix.patch": security,
                },
                changelog=(
                    "* Wed Jul 15 2026 Builder [5.14.0-687.25.1.el9_8]\n"
                    "- net: prepare security fix (Dev) [RHEL-55555]\n"
                    "- net: complete security fix (Dev) [RHEL-55555] "
                    "{CVE-2026-12345}\n"
                    "* Tue Jul 14 2026 Builder [5.14.0-687.24.1.el9_8]\n"
                ),
            )
            workspace = root / "workspace"
            workspace.mkdir()
            requested = workspace / "requested.txt"
            requested.write_text("CVE-2026-12345\n", encoding="utf-8")
            manifest = workspace / "selection.json"
            result = main(
                [
                    "--base",
                    BASE,
                    "--target",
                    TARGET,
                    "--workspace",
                    str(workspace),
                    "--patch",
                    str(workspace / "source.patch"),
                    "--manifest",
                    str(manifest),
                    "--requested-cves",
                    str(requested),
                    "--module-name",
                    "klp_test_1234",
                    "--source-cache",
                    str(cache),
                    "--spec-evaluation",
                    "static",
                ]
            )
            self.assertEqual(result, 0)
            value = json.loads(manifest.read_text(encoding="utf-8"))
            self.assertEqual(
                value["applied_patches"],
                [
                    "0002-net-prepare-security-fix.patch",
                    "0003-net-complete-security-fix.patch",
                ],
            )
            self.assertIn(
                "series(RHEL-55555)",
                value["selected_patches"][0]["origins"],
            )

    def test_superseded_base_cve_patch_is_reversed_before_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cache = root / "cache"
            ahead = git_patch(
                "eventpoll: ahead CVE fix",
                "old",
                "ahead",
            )
            prerequisite = git_patch(
                "eventpoll: split removal path",
                "old",
                "middle",
            )
            replacement = git_patch(
                "eventpoll: complete replacement CVE fix",
                "middle",
                "fixed",
            )
            self._kernel_cache(
                cache,
                BASE,
                patches={"1712-eventpoll-ahead-cve-fix.patch": ahead},
                changelog=(
                    "* Tue Jul 14 2026 Builder [5.14.0-687.24.1.el9_8]\n"
                ),
            )
            base_tree = (
                cache
                / BASE.rsplit(".", 1)[0]
                / "rpmbuild/BUILD/kernel-build/linux-test/security.txt"
            )
            base_tree.write_text("ahead\n", encoding="utf-8")
            self._kernel_cache(
                cache,
                TARGET,
                patches={
                    "1743-eventpoll-split-removal-path.patch": prerequisite,
                    "1744-eventpoll-complete-replacement-cve-fix.patch": replacement,
                },
                changelog=(
                    "* Wed Jul 15 2026 Builder [5.14.0-687.25.1.el9_8]\n"
                    "- The ahead eventpoll CVE-2026-46242 fix (1712) is "
                    "superseded and dropped\n"
                    "- eventpoll: split removal path (Dev) [RHEL-180773]\n"
                    "- eventpoll: complete replacement CVE fix (Dev) "
                    "[RHEL-180773] {CVE-2026-46242}\n"
                    "* Tue Jul 14 2026 Builder [5.14.0-687.24.1.el9_8]\n"
                ),
            )
            workspace = root / "workspace"
            workspace.mkdir()
            requested = workspace / "requested.txt"
            requested.write_text("CVE-2026-46242\n", encoding="utf-8")
            manifest = workspace / "selection.json"
            patch = workspace / "source.patch"
            result = main(
                [
                    "--base",
                    BASE,
                    "--target",
                    TARGET,
                    "--workspace",
                    str(workspace),
                    "--patch",
                    str(patch),
                    "--manifest",
                    str(manifest),
                    "--requested-cves",
                    str(requested),
                    "--module-name",
                    "klp_test_supersession",
                    "--source-cache",
                    str(cache),
                    "--spec-evaluation",
                    "static",
                ]
            )
            self.assertEqual(result, 0)
            value = json.loads(manifest.read_text(encoding="utf-8"))
            self.assertEqual(
                value["reversed_superseded_patches"],
                ["1712-eventpoll-ahead-cve-fix.patch"],
            )
            aggregate = patch.read_text(encoding="utf-8")
            self.assertIn("-ahead", aggregate)
            self.assertIn("+fixed", aggregate)


if __name__ == "__main__":
    unittest.main()
