# HPC Hotpatch

**Rebootless kernel security patching for HPC fleets — without an expensive
live-patching subscription.**

HPC Hotpatch monitors kernel and CVE metadata centrally, builds
cumulative livepatches for one exact running kernel, packages them as signed
native-compatible `kpatch` RPMs, and publishes them for ordinary DNF delivery.
Compute nodes consume the repository; they do not compile patches locally.

> [!WARNING]
> HPC Hotpatch is in active development and testing. It has completed
> real AlmaLinux 9 source-selection, `kpatch-build`, RPM packaging, module-load,
> cumulative-replacement, and DNF-delivery tests, but it is not yet presented
> as a finished or generally production-ready service. Validate it in a
> representative non-production environment before considering fleet use.

This central builder never requests or performs a client reboot. An advisory
mapping, selection, build, signing or publication failure is retained as a
central failure and no incomplete RPM is published.

Rebootless operation is the goal, not a claim that every kernel change can be
hotpatched. Unsupported transitions and fixes that cannot be represented safely
still require an explicitly managed kernel upgrade and reboot.

## Background and evolution

This project grew from work on managing an AlmaLinux HPC research-computing
fleet.

The design evolved through three approaches:

1. **Node-local DNF policy.** The first implementation reacted to kernel
   transactions on each compute node, building and loading a livepatch locally
   where possible or initiating scheduler-aware drain/reboot policy.
2. **Central, multi-kernel tracking.** Patch construction then moved to a
   central repository builder which tracked several retained fleet kernels.
   This removed compilation from compute nodes, but multiplied source trees,
   builds, package families, state, and operational complexity as fleet kernels
   diverged.
3. **Upstream-style single-kernel tracking.** The current implementation
   reproduces the useful constraint of upstream `kpatch-dnf`: the builder and
   governed fleet share one exact booted base, and newer security fixes arrive
   as successive cumulative replacements in that base kernel's RPM family.

This repository contains only the current central implementation.

## Credits

HPC Hotpatch has been developed with substantial assistance from
**OpenAI Codex** and **Anthropic Claude**, with **OpenWolf** providing persistent
project context and development memory.

## Licence

This project is licensed under the
[Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International
Licence](https://creativecommons.org/licenses/by-nc-sa/4.0/)
(**CC BY-NC-SA 4.0**). See [`LICENSE`](LICENSE) for the canonical legal text.

Third-party projects and generated artefacts remain subject to their applicable
licences.

## Current implementation

The first implementation slice provides:

* collection of available `kernel-core` releases, CVE advisory rows and strict
  CVE-to-ticket evidence from DNF, plus authoritative individual CVE severity
  from Red Hat Security Data;
* RPM-compatible ordering of kernel EVRs;
* grouping by exact architecture and EL stream;
* selection of the builder's exact running kernel as the single base and the
  newest available kernel in that family as the cumulative target;
* CVE interval calculation using `(base, target]`, so a security fix first
  released in a skipped intermediate kernel is not lost when the newest target
  is bugfix-only;
* Critical/Important-only selection by default, with lower-severity CVEs
  retained as auditable `below-policy` plan decisions;
* explicit `metadata-pending`, `planned` and `no-work` states;
* deterministic job identities and atomic JSON status output;
* production EL9 build jobs through `kpatch-build`, with a provider boundary
  reserved for a future field-verified EL10 adapter;
* an included fail-closed EL9 CVE selector plus a provider-neutral selector
  adapter contract;
* streamed build logs and durable per-job lifecycle state;
* embedded module-name and exact base-kernel vermagic verification;
* generation and execution of a cumulative `kpatch-patch` RPM build;
* locked, retry-safe timed reconciliation with durable RPM release allocation;
* CVE-coverage and effective-patch deduplication across later target kernels;
* required-by-default RPM signing and repository-wide locked publication;
* digest-addressed RPM objects, immutable metadata snapshots, atomic
  `current` promotion and count-plus-age retention;
* phase-specific command deadlines with process-group termination;
* sequential single-base builds with private per-job kpatch caches and writable
  source trees, plus locked atomic exact-NVR source preparation.

The builder tracks one architecture and one exact base, so it emits at most one
cumulative job per reconcile and builds jobs sequentially — there is no build
concurrency and no `max_concurrent_builds` setting. Per-job isolation is still
required so a single kpatch-build run cannot mutate the shared cache or the
immutable prepared source. Signing is serialised and repository publication
retains its repository-wide lock. The isolation details are documented in
[`docs/build-isolation.md`](docs/build-isolation.md).

The EL9 selector is extracted as `python3 -m livepatch_repo.el9_selector`. It
prepares exact SRPM sources, selects the central plan's requested CVEs and
series prerequisites, validates them sequentially, and emits a confined
aggregate net diff plus exact coverage evidence. When a target explicitly
replaces an Alma ahead-of-RHEL CVE patch, validation reverses that exact patch
in a private copy of the retained base before applying the replacement series;
the shared source cache is never modified. The runner invokes it through
the same configurable selector boundary that a future EL10 adapter can use.
For EL9, the runner passes the selector's prepared base source tree together
with the matching config and debuginfo `vmlinux` to `kpatch-build` explicitly,
and load testing is performed on that same running base kernel.
Production publication still requires a site RPM signing command and key.

Operator-facing module names describe the cumulative boundary, for example
`klp_687_22_1_el9_8_to_687_23_1`. The job ID remains a content-derived internal
identifier, but its otherwise opaque digest is not used as the normal module
name.

After every successful selection, the runner hashes the validated aggregate
`source.patch` before copying the kernel source or invoking `kpatch-build`. If
that digest is already published for the same exact base kernel, reconciliation
records the newer target as `covered` with `effective_no_change: true` and
reuses the existing RPM. This still runs the complete fail-closed selector, so
a new advisory cannot be skipped merely because its CVE list or patch filename
looks familiar; only byte-identical effective kernel changes avoid the lengthy
build.

## Quick start

Generate a snapshot on an EL build host:

```bash
python3 -m livepatch_repo scan \
  --config etc/livepatch-repo.conf.example \
  --output state/snapshot.json
```

Create the build plan:

```bash
python3 -m livepatch_repo plan \
  --config etc/livepatch-repo.conf.example \
  --snapshot state/snapshot.json \
  --output state/plan.json
```

`base_kernel = running` is the production setting. For controlled incremental
testing after booting the builder into `.22.1`, the same snapshot can be planned
against successive exact targets without changing the base:

```bash
python3 -m livepatch_repo plan --config etc/livepatch-repo.conf.example \
  --snapshot state/snapshot.json --output state/plan-23.json \
  --target-kernel 5.14.0-687.23.1.el9_8.x86_64
```

Repeat for `.24.1`, `.25.1` and `.26.1`. Each result remains cumulative over
`(.22.1, selected-target]`; it is a new release of the same base-kernel RPM
family, not a patch built for the intermediate kernel. Install each published
revision with native `dnf kpatch install` while the builder is still running
`.22.1`; verify `kpatch list` after every transaction so the test exercises
atomic replacement as well as compilation.

For diagnostics, `refresh` combines metadata collection and planning without
starting builds:

```bash
python3 -m livepatch_repo refresh \
  --config etc/livepatch-repo.conf.example \
  --state-dir state
```

Example systemd service and timer units are provided under `systemd/`. They
run full reconciliation hourly with a random delay and retain missed runs
across reboots. The example assumes this directory is installed at
`/opt/livepatch-repo`.

Install the central host layout with:

```bash
sudo bash sbin/install.sh
```

Edit `/etc/livepatch-repo/el9_8-x86_64.conf` and the matching `.env`, configure
and import the production signing key, then enable the profile timer:

```bash
sudo systemctl enable --now livepatch-repo-refresh@el9_8-x86_64.timer
```

The installer preserves an existing configuration. `--dry-run` previews a
real installation, while `--root /staging/path` builds a package/test image
without invoking systemd. Alternatively, rerun `sbin/install.sh --enable`
after configuring signing; it validates the configuration before invoking
systemd. Timer enablement is never the default.

The equivalent manual command is:

```bash
python3 -m livepatch_repo reconcile \
  --config /etc/livepatch-repo/el9_8-x86_64.conf \
  --state-dir /var/lib/livepatch-repo/el9_8-x86_64/state \
  --work-root /var/lib/livepatch-repo/el9_8-x86_64/jobs \
  --repository-root /srv/livepatch-repo/alma/9/x86_64
```

Every profile run takes an exclusive state lock, refreshes repository and advisory metadata,
and writes the snapshot and plan before doing any build work. The at-most-one
pending job is built in its own workspace with a private kpatch cache, writable
source copy, log, module directory and RPM tree. A failed build records its
outcome, retains the allocated RPM release for retry, and does not publish. An
already published job is not rebuilt. If a newer bugfix-only target produces
the same CVE requirement for a base, the existing cumulative RPM is recorded
as covering the new plan rather than rebuilt under a new target identity.
Registry entries retain the stable digest-addressed RPM object path, so routine
job workspace and repository-snapshot cleanup does not discard coverage
evidence.
Successful RPMs must be signed and independently verified by default, then are
published with `createrepo_c`. The builder RPM database must import the
matching public key so `rpmkeys --checksig` proves the signature rather than
reporting `NOKEY`. Reconciliation also requires a non-empty OpenPGP signature
header because `rpmkeys --checksig` exits successfully for unsigned,
digest-valid RPMs. Set
`require_rpm_signing = false` only for an isolated field test. The repository
consumer path is the shared profile environment root followed by `/current`
(for example `/srv/livepatch-repo/alma/9/x86_64/current`), an atomically
replaced symlink to an immutable version directory.

## Repository topology and retention

One planning profile handles one exact EL minor stream and architecture, for
example `el9_8-x86_64`. Profiles keep separate state and work directories, but
profiles for the same EL major and architecture publish into one shared
repository such as `/srv/livepatch-repo/alma/9/x86_64`.

Expensive selection and compilation may overlap both within and across
profiles. Every kpatch job uses a private `CACHEDIR` and a private writable
source tree, while exact-NVR cache preparation is locked and atomically
promoted. Shared output lines carry the job ID; each job also retains its own
unprefixed `build.log`. Publication takes
`<repository-root>/publication.lock` across the complete pin-set assembly,
object-import, metadata-generation, promotion and retention transaction. This
prevents one profile from publishing a stale snapshot which silently discards
packages added by another profile.

RPMs are stored once under `objects/sha256/<digest>/<filename>`. Immutable
repository versions materialise those objects as hardlinks when the filesystem
permits, otherwise as reflinks or copies. Profile pin manifests and retained
version manifests provide the mark set for object collection. A profile's pin
manifest is authoritative for its own packages: publication reconstructs each
new version from every profile's current pins plus this run's builds, so a
package a profile stops pinning is dropped from `current` while other profiles'
packages are preserved.

Each publication pins only the newest cumulative RPM for the currently active
base-kernel family. A later cumulative release for that base
supersedes the earlier one through livepatch atomic replacement, so the earlier
release is no longer pinned and ages out. When the builder boots a new base,
the old family becomes obsolete; its last release is retained for
`family_grace_seconds` after its final active reconcile, giving a still-booted
node time to reboot away, and then expires. Repository growth is therefore
bounded by the active family, the grace period, and the retained snapshots
rather than accumulating every historical release. Pin-set changes are checked
on every reconcile, including runs which build no RPM, so grace expiry itself
publishes the package removal instead of waiting for an unrelated future build.

`retain_versions` is a count floor. `minimum_retention_age_seconds` is an
independent age floor and must exceed client `metadata_expire` plus conservative
download, retry and clock-skew allowance. The example retains at least four
versions and never removes a demoted version younger than 24 hours.

Execute one planned job after configuring the selector:

```bash
python3 -m livepatch_repo run-job \
  --config /etc/livepatch-repo/el9_8-x86_64.conf \
  --plan /var/lib/livepatch-repo/el9_8-x86_64/state/plan.json \
  --job-id el9_8-x86_64-0123456789abcdef \
  --work-root /var/lib/livepatch-repo/el9_8-x86_64/jobs \
  --rpm-release 1
```

The RPM release is explicit because it must increase monotonically for each
new effective patch in a base-kernel package family. Reconciliation allocates
this value from its promoted package index; an effective-no-change target does
not consume a release.

For development on a machine without DNF, provide a snapshot directly:

```json
{
  "kernels": [
    {
      "name": "kernel-core",
      "epoch": "0",
      "version": "5.14.0",
      "release": "687.24.1.el9_8",
      "arch": "x86_64"
    }
  ],
  "advisories": [
    {
      "cve": "CVE-2026-12345",
      "kernel": {
        "name": "kernel-core",
        "epoch": "0",
        "version": "5.14.0",
        "release": "687.24.1.el9_8",
        "arch": "x86_64"
      }
    }
  ],
  "notices": [
    {
      "advisory_id": "ALSA-2026:12345",
      "kind": "security",
      "kernel": {
        "name": "kernel-core",
        "epoch": "0",
        "version": "5.14.0",
        "release": "687.24.1.el9_8",
        "arch": "x86_64"
      }
    }
  ]
}
```

Run the tests with:

```bash
python3 -m unittest discover tests
```

## Planning semantics

For each configured stream and architecture:

1. Order all available kernels using RPM EVR semantics.
2. Treat the newest release as the cumulative target.
3. Read the one exact livepatch base from the builder's running `uname -r`.
   An explicit identity is permitted only for controlled testing.
4. For that base, discover CVEs whose first fixing package is newer than the
   base and no newer than the target.
5. Resolve each CVE's individual vendor severity from the configured Red Hat
   Security Data batch endpoint. DNF's repeated advisory severity is not used
   as though it were an individual CVE rating.
6. Require only severities listed in `eligible_cve_severities` (Critical and
   Important by default). Retain other interval CVEs in each job's
   `cve_policy_decisions` as `below-policy`.
7. Emit:
   * `planned` when that interval contains security work;
   * `no-work` when metadata was successfully evaluated and the interval is
     empty or contains only below-policy CVEs.

Each target must have an RHSA/RHBA/RHEA or Alma ALSA/ALBA/ALEA advisory
envelope. Every security advisory in `(base, target]` must also have at least
one parsed CVE row. Until those conditions hold, the affected job is
`metadata-pending`: it is neither built nor classified as `no-work`.

Missing, malformed or contradictory in-scope metadata is an error, never
`no-work`, and leaves the previously published repository untouched.
Advisory fixing versions do not need to remain downloadable: retained
updateinfo for an intermediate release still participates in the interval.

### Security-coverage escalation

An in-interval security CVE whose vendor severity cannot be resolved (absent or
unrecognised rating) is a distinct, escalated failure: the interval cannot be
classified, so no livepatch is produced and nodes on the base may be exposed.
The central host **never reboots anything itself**. By default the reconcile:

* logs a prominent `SECURITY-COVERAGE-GAP` line naming the base, target and
  unresolved CVEs;
* writes a durable record to `<state-dir>/escalation.json`; and
* exits with status **3** (distinct from an ordinary error's `1`), so a
  systemd `OnFailure=` or timer hook can route it to alerting.

Operators may additionally set `security_escalation_command_template` to hand
off to their own automation — for example to schedule a kernel update, drain and
reboot into the fixed kernel. The command is invoked once per distinct gap
(deduplicated on base/target/CVEs), receives `{base} {target} {cves} {reason}
{report}`, and must be idempotent and return promptly. Automation of that kind
is not yet in place, so the setting is empty (alert-only) by default. Every
other selection, build, signing or publication failure remains an ordinary
retained central failure with no client action.

The design for that automation — a GitLab-driven, approval-gated fleet reboot
orchestrator for HTCondor, including how it converges a mixed-kernel fleet — is
documented in [`docs/escalation-orchestrator.md`](docs/escalation-orchestrator.md).

## Builder boundary

The stable pipeline contract is independent of the module generator:

* EL9: `kpatch-build`;
* EL10: `klp-build`;
* nodes: cumulative `kpatch-patch` RPMs, installed through ordinary DNF
  automation and loaded by `kpatch.service`.

The product is EL9-only today. The exact EL10 selector, source preparation and
`klp-build` CLI must be confirmed on an AlmaLinux 10 builder. Until then, the
backend boundary remains deliberately non-functional rather than guessing a
command contract.

## Job execution

Each workspace progresses through:

```text
selecting → building → packaging → built
                                ↘ failed
```

Reconciliation records a packaged build result as `build-complete` before
signing. It then signs/verifies the RPM and promotes the registry entry to
`built`; a `build-complete` result survives an interrupted run and is reused
without rebuilding on the next reconcile.

`status.json` is replaced atomically at every transition and retains the
failure reason. `build.log` receives the selector, builder and RPM build
output while also streaming it to the invoking terminal. Selector, builder and
packaging phases have separate configurable deadlines. Timed-out commands run
in their own process group and receive TERM, a grace period, then KILL.

Before an RPM can be produced, the runner proves that:

* the selector generated a non-empty aggregate patch;
* its manifest names the exact base and target;
* the manifest covers exactly the Critical/Important CVEs assigned by the
  central plan; lower-severity `below-policy` entries are not selector inputs;
* the builder produced exactly one `.ko`;
* `modinfo -F name` matches the collision-resistant requested name;
* `modinfo -F vermagic` names the exact base kernel.

The resulting package:

* uses the exact native kpatch-dnf package-name convention;
* `Provides: kpatch-patch = <exact uname-r>`;
* `Requires: kernel-uname-r = <exact uname-r>`;
* installs the module persistently with
  `kpatch install --kernel-version <exact uname-r>`;
* restarts the distribution-owned `kpatch.service` to load it only when that
  base is currently running;
* uninstalls the superseded module from persistent storage during an RPM
  upgrade, after the newer cumulative module has been installed and loaded.

These scriptlets and stock `kpatch-dnf` discovery have been integration-tested
on AlmaLinux 9 with modules for installed, non-running base kernels. Signed
publication tests cover trusted-signature and OpenPGP-header verification,
atomic publication, immutable-object reuse and native DNF discovery without
changing installed or loaded patch state.

The ordinary test suite uses synthetic kernel fixtures but executes real
filesystem copying, `patch`, `git`, spec evaluation and installer shell logic.
It also executes generated package scriptlet logic against recording `kpatch`
and `uname` shims, including old-module cleanup during an upgrade. Real
`kpatch-build`, module vermagic, signed RPM transactions and native DNF
discovery remain Alma VM integration tests. The proposed scheduled automation,
pinned-fixture boundary and evidence requirements are documented in
[`docs/real-kpatch-integration.md`](docs/real-kpatch-integration.md).

## Node consumption

Nodes need no custom site DNF transaction hook. Install a site-adjusted copy of
`etc/livepatch-client.repo.example`, import the repository signing key, install
`kpatch` and `kpatch-dnf`, then enable the stock plugin:

```bash
dnf install kpatch kpatch-dnf
dnf kpatch auto
```

`dnf kpatch auto` immediately installs any matching patches already visible for
installed kernels and enables the stock plugin for future `kernel-core` DNF
transactions. It is transaction-driven, not a repository poller. In
particular, it will not notice the first patch package published after its
matching kernel was installed unless another suitable DNF transaction occurs.

Schedule this idempotent command with a systemd timer on every node to close
that discovery gap:

```bash
dnf -y kpatch install
```

The timer should be persistent across downtime, use a randomised delay across
the fleet, and run at least as often as the site's maximum acceptable security
update exposure. The command consults enabled repository metadata, which DNF
refreshes according to its normal expiry policy, scans all installed
`kernel-core` packages and installs a missing exact-match `kpatch-patch-*`
family. The RPM scriptlet persists the patch for that base even when another
kernel is running.

After a package family is installed, a newer cumulative build with the same
package name and a higher RPM release is an ordinary DNF upgrade; the site's
normal DNF or `dnf-automatic` policy should apply it. Thus the periodic
`dnf kpatch install` timer bootstraps newly published package families, while
ordinary package updates advance existing families. `dnf kpatch status` is
useful for reporting but does not install anything.

Production node repositories must enable `gpgcheck=1` and trust only the
production signing key. Disabling signature verification is appropriate only
for isolated development testing.

Use Alma's packaged `/usr/sbin/kpatch` and
`/usr/lib/systemd/system/kpatch.service` on client nodes. Do not allow a source
installation beneath `/usr/local` to shadow the service: it lacks the SELinux
execution label needed to load modules from `kpatch_var_lib_t` persistent
storage.
