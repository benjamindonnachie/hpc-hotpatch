# Real kpatch integration automation

## Purpose

The ordinary test suite proves planning, selection contracts, packaging,
scriptlet behaviour and repository publication without compiling a kernel.
The real kpatch integration tier will prove that the checked-in orchestration
can build a genuine EL9 livepatch module for an exact, non-running base kernel
and package it with the expected identity.

This is a scheduled integration test, not a per-commit unit test. A cold
`kpatch-build` performs a full kernel build and can take hours on a small host.

## Test boundaries

The automated test has three deliberately separate concerns:

1. **Pinned build/vermagic regression.** Build a deterministic known patch from
   preserved inputs. This is the primary regression test and must not depend on
   old packages remaining in a live AlmaLinux repository.
2. **Live-repository canary.** Periodically obtain current AlmaLinux metadata
   and inputs to detect provider packaging or repository-layout changes. A
   canary failure must be distinguishable from a product-code regression.
3. **Boot and load validation.** Optionally boot an ephemeral VM into the exact
   base kernel and exercise install, load, replacement and removal. This is a
   higher-risk system test and is not required for the initial build/vermagic
   tier. It is specified in full under *Boot and load system test* below.

The first implementation covers item 1. Item 2 should be added only after the
pinned test is stable. Item 3 remains separate because it requires privileged
kernel-module operations and disposable machine state.

A fourth, cheaper concern is broken out below: a **deterministic selector golden
tier**. The pinned build (item 1) uses a fixture selector and the live canary
(item 2) is non-deterministic, so neither gives repeatable coverage of the real
EL9 selector — the most complex code in the tree. The golden tier runs the real
selector offline against preserved sources and should land before the kpatch
build tier, because it needs no kernel build.

Item 1 stops at the `built` state, so an **optional signed-publication
sub-stage** (also below) extends it through the real `reconcile` signing,
verification and `createrepo_c` publication path using a disposable builder key.

## Pinned fixture

Start with the field-tested transition
`5.14.0-687.24.1.el9_8.x86_64` to
`5.14.0-687.25.1.el9_8.x86_64`. Preserve or record:

* first, the base debuginfo `vmlinux` and matching kernel config, because
  debuginfo is normally the first fixture input to rotate off live mirrors;
* the exact base and target kernel source RPMs;
* a deterministic aggregate source patch and selection manifest;
* the expected CVE set, module name inputs and RPM identity;
* the kpatch, compiler, binutils, dwarves and RPM package versions; and
* SHA-256 digests for every fixture file.

Large RPM and source artefacts should live in a controlled internal artefact
store rather than Git. The repository should contain a small manifest with
their immutable locations, sizes and digests. The test must verify all digests
before unpacking or building.

The fixture must be reconstructible from preserved packages. A pre-expanded
source tree may be retained as a build cache, but it is not the authoritative
fixture because it is too easy for undeclared state to accumulate in it.

## Alma runner

Use a self-hosted AlmaLinux 9 VM or ephemeral VM image matching the fixture's
EL stream and architecture. A VM is preferred to a generic container because
kpatch is sensitive to the distribution toolchain, kernel packaging and
debuginfo layout.

The runner requires:

* `kpatch-build`, `modinfo`, `rpmbuild`, `rpm` and the kernel build toolchain;
* all dependencies needed to prepare the pinned kernel SRPMs;
* approximately 16–32 GiB RAM, 8 or more CPUs and at least 100 GiB scratch
  space for predictable execution;
* network access only to the controlled fixture store during the pinned test;
* a persistent build cache keyed by base kernel, architecture, compiler and
  kpatch version; and
* a job timeout above the measured cold-build duration, while retaining the
  existing per-phase deadlines.

The runner does not need to boot the fixture's base kernel and does not need to
load the resulting module. The exact source tree, config and `vmlinux` are
passed explicitly to `kpatch-build`.

## Checked-in harness

Add an environment-gated test, for example
`tests/test_kpatch_integration.py`, which is skipped unless
`KPATCH_REAL_TEST=1`. Its external inputs should be explicit, for example:

```text
KPATCH_REAL_TEST=1
KPATCH_FIXTURE_MANIFEST=/srv/livepatch-fixtures/el9_8-687.24.1.json
KPATCH_INTEGRATION_WORK_ROOT=/var/tmp/livepatch-integration
```

The harness should use the normal `run_job()` path rather than duplicating its
commands. A small fixture selector can copy the preserved aggregate patch and
emit the pinned selection manifest. This exercises the real backend,
verification and packaging stages while keeping repository metadata discovery
outside the deterministic regression test.

Construct the test `Config` explicitly: point `selector_command_template` at
the fixture selector, point `kpatch_config_template` and
`kpatch_vmlinux_template` at the staged fixture files, and set the real
`kpatch-build`, `modinfo`, `rpmbuild` and `rpm` commands. Invoke `run_job()` with
an explicit positive `rpm_release` so the expected RPM release is deterministic.
The fixture selector must emit a non-empty patch and rewrite
`base_source_tree` to the staged source tree's absolute, existing path; it must
not copy an environment-specific path from the preserved manifest unchanged.

The test succeeds only when:

* fixture digests and declared tool versions pass validation;
* selection identifies the exact base, target and CVE set;
* `kpatch-build` produces exactly one `.ko`;
* `modinfo -F name` equals the requested module name;
* the first field of `modinfo -F vermagic` equals the exact base `uname -r`;
* the RPM name, version, release and architecture match the native contract;
* the RPM contains the selection evidence and module; and
* the complete job reaches the `built` state without using the running kernel
  as an implicit input.

## Deterministic selector golden tier

This tier runs the real `python3 -m livepatch_repo.el9_selector` against
preserved SRPMs with no live repository, so regressions in selection, sequential
applicability validation and aggregate-diff generation are caught repeatably and
separately from `kpatch-build` cost and repository drift. It needs only `git`,
`patch`, `rpm`, `rpmspec` and the staged source trees — no `kpatch-build`,
kernel boot or debuginfo — so it can run on an ordinary AlmaLinux container far
more often than the kernel-build tier, including per pull request.

### Offline staging

Reuse the `5.14.0-687.24.1.el9_8.x86_64` to `5.14.0-687.25.1.el9_8.x86_64`
transition. `prepare_source` skips all download and preparation when
`<source-cache>/<nvr>/rpmbuild/.prep-complete` exists alongside the expanded
`BUILD/linux-*` tree, `SOURCES/` and a single `SPECS/*.spec`. Stage that prepared
`rpmbuild` tree for **both** the base and the target from the preserved SRPMs —
the target tree is required by `prepare_source` even though only the base tree is
diffed — record its digest set, and keep the SRPMs so the cache is
reconstructible.

Provide a cold variant that stages only the SRPMs plus a local DNF source
repository whose configured `baseurl` is `file://...`, so a run also exercises
`dnf download --source`, `rpm -ivh` and `rpmbuild -bp`. `--source-repo` is a
repository ID passed to `dnf --enablerepo`, not a URL: create repository
metadata, configure a named repository ID and pass that ID. Run DNF with every
unrelated repository disabled, using an isolated repository configuration or a
small `--dnf-command` wrapper, and deny network access so an undeclared live
mirror cannot satisfy the test. Never let a warm staged-cache pass hide a cold
prep failure.

### Invocation

Call the module exactly as the runner does through `selector_command_template`,
with `--spec-evaluation required` and explicit `--dnf-command`, `--rpm-command`,
`--rpmbuild-command` and `--rpmspec-command`. Write the aggregate patch and
`selection.json` to a scratch workspace, with `--source-cache` pointing at the
staged tree.

### Golden comparison

* **Manifest.** Compare `schema_version`, `selector`, `base`, `target`,
  `module_name`, `covered_cves`, `selected_patches`, `applied_patches` and
  `already_present_patches` to the golden manifest. Assert `base_source_tree` is
  absolute and exists, but exclude it from equality: it is a cache path and is
  intentionally environment-specific.
* **Aggregate patch.** Assert it is non-empty and that every `diff --git a/X b/X`
  path lies within the affected paths declared by the applied selected patches,
  then compare byte-for-byte to the golden patch. The patch is
  `git diff --no-index` output, so require the recorded `git` version. A tool
  mismatch fails the job as an environment/fixture error; it must never skip the
  golden assertion. Regenerating a golden is an explicit, reviewed maintenance
  change, not an automatic response within the test.

Key both the golden and the cache on the SRPM digests, architecture, `git`, GNU
`patch`, `rpm`, `rpmspec` and `rpmbuild` versions, since those inputs shape the
prepared tree, applicability decisions and emitted diff. Record all of them in
the run evidence.

The fixture suite must exercise both real applicability outcomes. It needs at
least one patch in `applied_patches` and at least one semantically identical,
renamed or renumbered patch in `already_present_patches`, thereby exercising
the stable Git patch-ID path. If the primary `687.24.1` to `687.25.1` transition
does not naturally provide both, add a second preserved selector fixture for
the already-present case rather than manufacturing state inside the primary
fixture.

### Success criteria

The selector golden test succeeds only when:

* fixture digests and declared tool versions pass validation;
* the selector exits `0` with no network access in the warm variant;
* every pinned tool version matches the fixture manifest, otherwise the job
  fails as an environment/fixture error;
* the manifest `base`, `target`, `module_name` and `covered_cves` equal the
  fixture request;
* the `selected_patches`, `applied_patches` and `already_present_patches` lists
  equal the golden manifest;
* `base_source_tree` is an absolute, existing directory; and
* the aggregate patch is non-empty, confined to the selected paths and
  byte-identical to the golden patch.

The selector tier as a whole is not complete until its fixture set has produced
non-empty `applied_patches` and `already_present_patches` results. This may be
one transition or two independently preserved fixtures.

This tier deliberately does not build or verify a `.ko`; that is the kpatch
tier, and `.ko` reproducibility remains a non-goal. It proves only that the real
selection logic reproduces a known-good result from preserved inputs.

### Harness

Add a separate environment-gated test, for example
`tests/test_selector_golden.py`, skipped unless `KPATCH_SELECTOR_GOLDEN=1`, with
explicit inputs such as:

```text
KPATCH_SELECTOR_GOLDEN=1
KPATCH_SELECTOR_FIXTURE=/srv/livepatch-fixtures/el9_8-687.24.1-selector.json
KPATCH_SELECTOR_WORK_ROOT=/var/tmp/livepatch-selector
```

Keep it distinct from the kpatch build harness and the live canary so fixture,
environment, selection and diff failures each report under their own job name.

## Signed publication sub-stage (optional)

The pinned build tier stops at the `built` state, so signing, trust
verification, the OpenPGP signature-header check and `createrepo_c` publication
are never exercised on a real Alma host. This optional sub-stage drives the real
`reconcile_repository` path over a disposable builder key so those behaviours —
the ones the product deliberately hardens against `NOKEY` and digest-only
signatures — are proven end to end. It reuses the same fixture as the pinned
build.

Run it either as a continuation of the kpatch tier, letting `reconcile` build
the RPM through `run_job`, or, for a cheaper container-only check, inject a
`build_function` that returns a preserved golden RPM so only the signing and
publication stages run. In the latter case copy the preserved RPM into the
scratch workspace first: `rpmsign` mutates its input and must never alter the
authoritative fixture.

### Disposable builder key

Create everything under throwaway directories and never touch the host keyring
or the system RPM database:

* generate an ephemeral, unprotected signing key in a private `GNUPGHOME`
  (`gpg --batch --gen-key`) and export its armoured public key;
* import that public key into a throwaway RPM database
  (`rpmkeys --dbpath <tmpdb> --import pubkey.asc`);
* retain a second empty throwaway RPM database to prove that the signed RPM is
  rejected as untrusted (`NOKEY`) before the public key is imported;
* set `rpm_sign_command_template` to sign with the ephemeral key — for example
  `rpmsign --define '_gpg_name <key>' --addsign {rpm}` with `GNUPGHOME`
  exported, adjusted for the host's `rpmsign`/`gpg` — and
  `rpm_verify_command_template` to check against the throwaway database
  (`rpmkeys --dbpath <tmpdb> --checksig {rpm}`); and
* set `require_rpm_signing = true`.

Remove the `GNUPGHOME`, the database and the workspace on exit. Nothing here
requires root.

### Driving reconcile

Feed `reconcile_repository` a synthetic snapshot carrying the fixture's base and
target kernels, the fixture CVE advisory and a matching security notice, so the
plan yields exactly the one fixture job; point `state_dir`, `work_root` and
`repository_root` at scratch paths. Reconcile builds (or is handed) the RPM,
then signs it, independently verifies it, proves a non-empty OpenPGP header, and
publishes it with `createrepo_c` through the atomic `current` symlink. This also
incidentally exercises the digest-addressed object pool and pin/retention layout
against a real `createrepo_c`.

### Success criteria

The sub-stage succeeds only when:

* key generation and public-key import succeed;
* a reconciliation run using a no-op signer and the digest-verifying
  `rpmkeys --checksig` command rejects the unsigned RPM specifically because the
  independent OpenPGP signature-header query finds no signature — the
  verification command itself is allowed to return success for digest-only
  RPMs. The no-op signer must be a non-empty command that does nothing (for
  example `true {rpm}`), not an empty `rpm_sign_command_template`: reconciliation
  only reaches the signing, verification and header check when the sign template
  is non-empty, so an empty template would skip the check entirely instead of
  exercising the rejection;
* the genuinely signed RPM is rejected or reports `NOKEY` against the empty
  throwaway RPM database, then passes `rpmkeys --checksig` only after the
  disposable public key is imported into the trusted throwaway database;
* the signed RPM carries a non-empty OpenPGP signature header;
* `createrepo_c` produces `repodata/repomd.xml`, and `current` is an atomic
  symlink to an immutable version directory containing the package; and
* optionally, a `dnf` client configured with `gpgcheck=1`, the published
  `current` as its `baseurl` and the disposable public key downloads the package
  and validates its signature.

This sub-stage does not load the module or reboot — that remains the
boot-and-load system test (item 3). It proves only the signing, verification and
publication path that `run_job` stops short of.

## Boot and load system test (item 3, optional)

This is the only tier that boots a kernel and performs privileged livepatch
loads, so it runs exclusively on a disposable, snapshot-rollback VM and never on
a shared runner. Unlike the build tiers — where the Alma runner explicitly does
not boot the base kernel — this tier requires the base kernel to be installed
and, for the load paths, actually running. It consumes the signed repository
from the publication sub-stage, so it sits at the top of the dependency chain:
selector golden → kpatch build → signed publication → boot and load.

Provision a throwaway AlmaLinux 9 VM with `kpatch`, `kpatch-dnf`, the fixture's
exact base kernel `5.14.0-687.24.1.el9_8` (B) and at least one newer kernel
installed, and the published `current` configured as a `gpgcheck=1` repository
trusting the disposable public key. Snapshot the VM before each scenario:
module loads, upgrades and reboots are destructive and must be rolled back
between cases.

### Scenarios

These map directly to the AlmaLinux validation checklist in
[rpm-contract.md](rpm-contract.md):

1. **Discovery and signed download (steps 2–3).** With B installed, confirm the
   node resolves `Provides: kpatch-patch = <B uname-r>` for the installed kernel
   (`dnf kpatch install --assumeno`, or stock `kpatch-dnf` discovery) and that
   `dnf` downloads the package under `gpgcheck=1` against the disposable key.
2. **Non-running base install (step 4).** While running a kernel other than B,
   install the base-B package. Assert the module is persisted for B
   (`kpatch list` installed set / `/var/lib/kpatch/<B>`) but not loaded — no
   `/sys/kernel/livepatch/<module_name>` entry — because `%post` skips
   restarting `kpatch.service` when `uname -r` differs from B.
3. **Running base install and transition (step 5).** Set B as the default boot
   target, reboot into B, then install the package. Assert the module loads and
   the distribution-owned `kpatch.service` loads it and the transition
   completes: `/sys/kernel/livepatch/<module_name>/enabled` is
   `1` and `.../transition` returns to `0`. Poll with a timeout; a stuck
   `transition=1` is a failure and blocks any successor.
4. **Cumulative upgrade and supersession (step 6).** Still running B with
   release N loaded, upgrade to release N+1 — a distinct module name covering a
   superset of CVEs. Assert the new module is enabled through livepatch atomic
   replacement and that only the new module remains in persistent storage,
   because the old package's `%preun` runs `kpatch uninstall` for its own module
   name. Do not assert the old module is unloaded from memory: it is left
   disabled, not reversed.
   Before this expensive scenario, also present an intermediate target whose
   validated aggregate patch is byte-identical to release N. Assert that it is
   recorded as `effective_no_change`, retains release N as `covered_by`, and
   invokes neither `kpatch-build` nor `rpmbuild`. Then use a genuinely changed
   target for the release N+1 replacement test.
5. **Reboot persistence (step 7).** Reboot into B again and assert
   `kpatch.service` auto-loads only the latest cumulative module, enabled.
6. **Erasure (step 8).** Remove the package. Assert `%preun` removes the
   persistent module so a later boot will not load it, that no attempt is made
   to reverse the active patch (no scriptlet error or hang), and that a
   subsequent reboot comes up with no managed livepatch.

### Evidence and safety

For every scenario capture `uname -r`, `rpm -q`, `kpatch list`, the contents of
`/sys/kernel/livepatch/*/{enabled,transition}`, the `kpatch.service` journal and
the livepatch `dmesg` lines, before and after the action. Because real
transitions are timing-dependent, poll sysfs state rather than sampling once,
and record the observed transition latency.

This tier does not gate the deterministic regression suite. Keep it on its own
scheduled job with an independent alert, run it only on ephemeral machine state,
and never reuse a VM across cases without a rollback.

## Scheduling and cache policy

Run two variants:

* **Nightly warm-cache:** reuse the verified base-build cache to provide timely
  regression coverage.
* **Weekly cold-cache:** build from preserved packages in a clean workspace to
  prove that the fixture and dependency declaration are complete.

Never allow a warm-cache success to hide a cold-cache failure. Cache keys must
include every input capable of changing generated objects. Old workspaces and
caches need an explicit count-and-age retention policy because kernel trees are
large.

## Evidence and failure reporting

Retain the following for every run, including failures:

* the fixture manifest and verified digests;
* tool and installed-package versions;
* the generated selection manifest and aggregate patch;
* `status.json` and the complete streamed `build.log`;
* the `.ko`, `modinfo` name/vermagic output and resulting RPM when produced;
* elapsed time, peak disk use and cache-hit status; and
* JUnit-compatible test results for the CI system.

Classify failures as fixture acquisition/integrity, environment/dependency,
selection, kpatch build, module verification, RPM packaging, signing/publication
or boot/load. When the signed-publication sub-stage runs, also retain the
disposable public-key fingerprint, the `rpmkeys --checksig` output, the
signature-header query result and `repodata/repomd.xml`. When the boot and load
tier runs, retain per scenario the `kpatch list` output, the
`/sys/kernel/livepatch/*/{enabled,transition}` state, and the `kpatch.service`
journal and livepatch `dmesg` lines. The live canary must use a separate job
name and alert so a temporary repository problem does not look like a pinned
regression failure.

## Implementation sequence

1. Before repository rotation can remove them, capture and checksum the base
   debuginfo `vmlinux` and matching config. Complete the current manual real
   build and retain its source RPMs, other inputs, outputs, timings and tool
   versions as the initial known-good evidence.
2. Land the deterministic selector golden tier first: stage the preserved base
   and target sources, record the golden manifest and aggregate patch, and add
   `tests/test_selector_golden.py`. It runs on an Alma container and gives
   repeatable real-selector coverage before any kernel build exists.
3. Define and checksum the pinned kpatch fixture manifest in the controlled
   artefact store.
4. Add the gated kpatch harness and run it manually from a clean Alma VM.
5. Prove both warm- and cold-cache runs and record their resource ceilings.
6. Add the optional signed-publication sub-stage with a disposable builder key,
   proving signing, trust verification, header presence and `createrepo_c`
   promotion end to end.
7. Register the Alma VM as a scheduled self-hosted runner and archive evidence
   on every run.
8. After the pinned job is stable, add the separately reported current-repo
   canary.
9. Optionally add the boot and load system test on a disposable snapshot-rollback
   VM, consuming the signed repository and reporting under its own job.

The tier is considered automated when a clean scheduled runner can fetch only
the declared fixture, produce and verify the real module and RPM, publish its
test result and evidence, and clean up according to policy without operator
intervention.
