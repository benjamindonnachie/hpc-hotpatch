"""End-to-end integration test for the central livepatch pipeline.

This drives the real :func:`reconcile_repository` with the real ``run_job`` and
real ``publish_repository`` against genuine ``rpmbuild``, ``createrepo_c``,
``gpg`` signing and ``dnf`` discovery. Only the two inherently kernel-bound
steps are substituted:

* a fake **selector** that emits a genuine non-empty aggregate patch and a valid
  ``selection.json`` (with a real prepared-source directory), exercising the
  real selection-invocation and validation seam; and
* a fake **kpatch-build**/**modinfo** pair. A real livepatch ``.ko`` needs a
  real running kernel, debuginfo and vmlinux, so that one pairing is covered by
  the separate on-builder kpatch-build field test. The fake builder writes a
  module whose recorded name and vermagic the fake modinfo reports back, so
  ``_verify_module`` runs its real identity checks against consistent data.

Everything downstream of "a verified module exists" — packaging, GPG signing,
signature verification, the OpenPGP-header gate, createrepo publication and
native dnf discovery — is exercised for real. The test skips unless the full
RPM/signing/repository toolchain is installed, so it is a no-op on a
workstation and runs on the dedicated Alma builder.
"""

import json
import os
import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

from livepatch_repo.config import Config
from livepatch_repo.models import (
    AdvisoryFix,
    BuildJob,
    KernelRelease,
    RepositoryNotice,
)
from livepatch_repo.packaging import package_name
from livepatch_repo.reconcile import reconcile_repository
from livepatch_repo.sources import RepositorySnapshot


_REQUIRED_TOOLS = (
    "rpmbuild",
    "rpm",
    "rpmkeys",
    "rpmsign",
    "createrepo_c",
    "modinfo",
    "gpg",
    "dnf",
)

_KEY_NAME = "Central Livepatch QA"
_KEY_EMAIL = "qa@livepatch.invalid"


def _write_executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)


@unittest.skipUnless(
    all(shutil.which(tool) for tool in _REQUIRED_TOOLS),
    "full RPM/signing/repository toolchain is not available",
)
class TestEndToEndPipeline(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.root = Path(self._temporary.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.fixtures = self.root / "fixtures"
        self.fixtures.mkdir()

        self.base = KernelRelease(
            "kernel-core", "0", "5.14.0", "687.22.1.el9_8", "x86_64"
        )
        self.target = KernelRelease(
            "kernel-core", "0", "5.14.0", "687.23.1.el9_8", "x86_64"
        )
        self.cve = "CVE-2026-30001"

        self._write_fake_selector()
        self._write_fake_kpatch_build()
        self._write_fake_modinfo()
        self._write_kernel_inputs()
        self._set_up_signing()

    def tearDown(self) -> None:
        self._temporary.cleanup()

    # -- fake kernel-bound tooling ----------------------------------------

    def _write_fake_selector(self) -> None:
        self.selector = self.bin / "qa-selector.py"
        _write_executable(
            self.selector,
            textwrap.dedent(
                """\
                import argparse, json, os
                p = argparse.ArgumentParser()
                p.add_argument("--base", required=True)
                p.add_argument("--target", required=True)
                p.add_argument("--workspace", required=True)
                p.add_argument("--patch", required=True)
                p.add_argument("--manifest", required=True)
                p.add_argument("--requested-cves", dest="requested", required=True)
                p.add_argument("--advisory-evidence", dest="evidence")
                p.add_argument("--module-name", dest="module_name", required=True)
                a = p.parse_args()
                cves = sorted(
                    line.strip().upper()
                    for line in open(a.requested, encoding="utf-8")
                    if line.strip()
                )
                source = os.path.join(a.workspace, "base-source")
                os.makedirs(source, exist_ok=True)
                with open(os.path.join(source, "Makefile"), "w") as handle:
                    handle.write("# prepared base source tree\\n")
                with open(a.patch, "w", encoding="utf-8") as handle:
                    handle.write(
                        "--- a/kernel/sample.c\\n"
                        "+++ b/kernel/sample.c\\n"
                        "@@ -1 +1 @@\\n"
                        "-int central_qa;\\n"
                        "+int central_qa = 1;\\n"
                    )
                with open(a.manifest, "w", encoding="utf-8") as handle:
                    json.dump(
                        {
                            "schema_version": 1,
                            "selector": "qa-fake-selector",
                            "base": a.base,
                            "target": a.target,
                            "module_name": a.module_name,
                            "base_source_tree": os.path.abspath(source),
                            "covered_cves": cves,
                            "selected_patches": [],
                        },
                        handle,
                        indent=2,
                        sort_keys=True,
                    )
                """
            ),
        )

    def _write_fake_kpatch_build(self) -> None:
        # Derives the exact base from the --config filename (config-<nvra>), so
        # the module it writes and the fake modinfo agree on name and vermagic.
        self.kpatch_build = self.bin / "qa-kpatch-build"
        _write_executable(
            self.kpatch_build,
            textwrap.dedent(
                """\
                #!/bin/sh
                set -e
                name=""; output=""; config=""
                while [ $# -gt 0 ]; do
                  case "$1" in
                    --name) name="$2"; shift 2;;
                    --output) output="$2"; shift 2;;
                    --config) config="$2"; shift 2;;
                    --sourcedir|--vmlinux) shift 2;;
                    *) shift;;
                  esac
                done
                base=$(basename "$config"); base=${base#config-}
                mkdir -p "$output"
                printf 'name=%s\\nvermagic=%s SMP mod_unload modversions\\n' \\
                  "$name" "$base" > "$output/$name.ko"
                """
            ),
        )

    def _write_fake_modinfo(self) -> None:
        # usage mirrors: modinfo -F <field> <module>
        self.modinfo = self.bin / "qa-modinfo"
        _write_executable(
            self.modinfo,
            textwrap.dedent(
                """\
                #!/bin/sh
                field="$2"; module="$3"
                grep "^$field=" "$module" | head -1 | cut -d= -f2-
                """
            ),
        )

    def _write_kernel_inputs(self) -> None:
        # build_invocation checks the config and vmlinux inputs exist. The
        # config filename encodes the base for the fake builder.
        self.kconfig_dir = self.fixtures / "kconfig"
        self.kconfig_dir.mkdir()
        (self.kconfig_dir / f"config-{self.base.nvra}").write_text(
            "CONFIG_LIVEPATCH=y\n", encoding="utf-8"
        )
        self.vmlinux = self.fixtures / "vmlinux"
        self.vmlinux.write_bytes(b"\x7fELF fake vmlinux for QA")

    # -- real GPG signing environment -------------------------------------

    def _set_up_signing(self) -> None:
        self.gnupg_home = self.root / "gnupg"
        self.gnupg_home.mkdir(mode=0o700)
        (self.gnupg_home / "gpg.conf").write_text(
            "pinentry-mode loopback\n", encoding="utf-8"
        )
        (self.gnupg_home / "gpg-agent.conf").write_text(
            "allow-loopback-pinentry\n", encoding="utf-8"
        )
        env = {**os.environ, "GNUPGHOME": str(self.gnupg_home)}
        subprocess.run(
            [
                "gpg",
                "--batch",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
                "--quick-generate-key",
                f"{_KEY_NAME} <{_KEY_EMAIL}>",
                "rsa2048",
                "sign",
                "0",
            ],
            check=True,
            env=env,
            capture_output=True,
            timeout=120,
        )
        self.pubkey = self.root / "qa-pub.asc"
        exported = subprocess.run(
            ["gpg", "--batch", "--armor", "--export", _KEY_EMAIL],
            check=True,
            env=env,
            capture_output=True,
            timeout=60,
        )
        self.pubkey.write_bytes(exported.stdout)

        # Isolated rpm keyring so verification neither reads nor mutates the
        # host database.
        self.rpmdb = self.root / "rpmdb"
        self.rpmdb.mkdir()

        self.sign_script = self.bin / "qa-sign-rpm.sh"
        _write_executable(
            self.sign_script,
            textwrap.dedent(
                f"""\
                #!/bin/sh
                set -e
                export GNUPGHOME="{self.gnupg_home}"
                rpmsign \\
                  --define "_gpg_name {_KEY_EMAIL}" \\
                  --define "_gpg_sign_cmd_extra_args --pinentry-mode loopback --passphrase ''" \\
                  --addsign "$1"
                """
            ),
        )
        self.verify_script = self.bin / "qa-verify-rpm.sh"
        _write_executable(
            self.verify_script,
            textwrap.dedent(
                f"""\
                #!/bin/sh
                set -e
                rpm --dbpath "{self.rpmdb}" --import "{self.pubkey}" 2>/dev/null || true
                out=$(rpmkeys --dbpath "{self.rpmdb}" --checksig "$1")
                echo "$out"
                echo "$out" | grep -qi "NOT OK" && exit 1
                # EL9 rpmkeys reports "digests signatures OK" for a package whose
                # signature verifies against the imported key, versus "digests OK"
                # for a digest-only (unsigned) package.
                echo "$out" | grep -qw "signatures"
                """
            ),
        )

    # -- configuration ----------------------------------------------------

    def _config(self) -> Config:
        selector_template = (
            f"python3 {self.selector} --base {{base}} --target {{target}} "
            f"--workspace {{workspace}} --patch {{patch}} "
            f"--manifest {{selection_manifest}} "
            f"--requested-cves {{requested_cves}} "
            f"--advisory-evidence {{advisory_evidence}} "
            f"--module-name {{module_name}}"
        )
        return Config(
            dnf_command="dnf",
            kernel_package="kernel-core",
            architecture="x86_64",
            distro_stream="el9_8",
            selector_command_template=selector_template,
            kpatch_build_command=str(self.kpatch_build),
            klp_build_command_template="",
            modinfo_command=str(self.modinfo),
            rpmbuild_command="rpmbuild",
            base_kernel=self.base.nvra,
            rpm_command="rpm",
            createrepo_command="createrepo_c",
            rpm_sign_command_template=f"{self.sign_script} {{rpm}}",
            rpm_verify_command_template=f"{self.verify_script} {{rpm}}",
            require_rpm_signing=True,
            kpatch_config_template=str(self.kconfig_dir / "config-{base}"),
            kpatch_vmlinux_template=str(self.vmlinux),
            repository_profile="el9_8-x86_64",
            repository_minimum_age_seconds=0,
        )

    def _snapshot(self) -> RepositorySnapshot:
        return RepositorySnapshot(
            (self.base, self.target),
            (AdvisoryFix(self.cve, self.target, "Important"),),
            (RepositoryNotice("ALSA-2026:30000", "security", self.target),),
        )

    # -- the end-to-end test ----------------------------------------------

    def test_reconcile_builds_signs_publishes_and_is_discoverable(self) -> None:
        config = self._config()
        state = self.root / "state"
        work = self.root / "work"
        repository = self.root / "repository"

        result = reconcile_repository(
            config=config,
            state_dir=state,
            work_root=work,
            repository_root=repository,
            snapshot=self._snapshot(),
        )

        self.assertEqual((result.built, result.published), (1, 1))

        # Registry records exactly one published job with a real RPM path.
        registry = json.loads(
            (state / "registry.json").read_text(encoding="utf-8")
        )
        entries = list(registry["jobs"].values())
        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertEqual(entry["status"], "published")
        published_rpm = Path(entry["published_rpm"])
        self.assertTrue(published_rpm.is_file())

        job = BuildJob(
            self.base, self.target, (self.cve,), "planned", "kpatch-build"
        )
        expected_pkg = package_name(job)
        self.assertEqual(expected_pkg, "kpatch-patch-5_14_0-687_22_1")

        # The published RPM carries a real OpenPGP signature header.
        signature = subprocess.run(
            (
                "rpm",
                "-qp",
                "--qf",
                "%{RSAHEADER:pgpsig}%{SIGPGP:pgpsig}%{SIGGPG:pgpsig}",
                str(published_rpm),
            ),
            check=True,
            capture_output=True,
            text=True,
            timeout=60,
        ).stdout.strip()
        self.assertTrue(signature)
        self.assertNotEqual(signature, "(none)")

        # createrepo produced valid metadata under the promoted current tree.
        current = (repository / "current").resolve()
        self.assertTrue((current / "repodata" / "repomd.xml").is_file())
        packages = sorted(p.name for p in (current / "Packages").glob("*.rpm"))
        self.assertEqual(
            packages, [f"{expected_pkg}-0-1.el9_8.x86_64.rpm"]
        )

        # Native dnf discovery: the package resolves by its kpatch-dnf name and
        # requires the exact base kernel uname-r.
        discovery = subprocess.run(
            (
                "dnf",
                "-q",
                "--disablerepo=*",
                "repoquery",
                f"--repofrompath=qa,file://{current}",
                "--enablerepo=qa",
                "--qf",
                "%{name}\\t%{requires}",
                expected_pkg,
            ),
            check=True,
            capture_output=True,
            text=True,
            timeout=120,
        ).stdout
        self.assertIn(expected_pkg, discovery)
        self.assertIn(f"kernel-uname-r = {self.base.nvra}", discovery)


if __name__ == "__main__":
    unittest.main()
