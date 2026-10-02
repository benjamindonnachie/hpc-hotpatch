# Signed RPM contract

One RPM package family corresponds to one exact bootable base kernel. Its name
matches the convention implemented by AlmaLinux 9's `kpatch-dnf` plugin:

```text
kpatch-patch-<kernel version with underscores>-<release before .el with underscores>
```

For example, base `5.14.0-687.24.1.el9_8.x86_64` is packaged as
`kpatch-patch-5_14_0-687_24_1.x86_64`. Later security targets increment that
package's RPM release and contain a cumulative module for the same base. The
release is deterministic: `<sequence>.<base EL stream>`, for example
`3.el9_8`.

The embedded livepatch module name is an operator-facing cumulative boundary,
for example `klp_687_22_1_el9_8_to_687_23_1`. Content digests remain in the
internal job ID and evidence; they are not the normal name displayed by
`kpatch list`.

Reconciliation runs the selector and validates its evidence before hashing the
aggregate `source.patch`. When a published entry for the same exact base has
the same SHA-256, the newer target is recorded as `covered` with
`effective_no_change: true`; `kpatch-build`, module packaging and a new RPM
release are skipped. The existing cumulative package remains authoritative.
This comparison is deliberately on the validated effective diff, rather than
advisory IDs or source-patch filenames, so a newly selected fix that was
already present in the base can be recognised without masking a real code
change.

Production reconciliation signs every newly built package, independently
verifies it against a public key imported into the builder RPM database, and
also requires a non-empty RSA/DSA/OpenPGP RPM signature header. The header
check is mandatory because `rpmkeys --checksig` returns success for an
unsigned package whose file digests are valid.

### Manual signing hold

Everything up to signing is autonomous by design; signing itself is the one
step intentionally left to an operator (a private signing key has no business
being reachable from an unattended timer). With `require_rpm_signing = true`
and `rpm_sign_command_template` left empty (the shipped default), reconcile
still scans, plans, builds and packages jobs on its own timer, but a
completed build is held with registry status `awaiting-signature` rather than
published. It is skipped when computing which RPMs to pin into a published
version, so an unsigned package can never reach the repository even
transiently.

An operator signs the RPM in place at its registry-recorded (`rpm`) path —
e.g. `rpmsign --addsign <path>` — with no other tooling involved. The next
reconcile run (the existing hourly refresh timer; no separate command or
timer is needed) detects the new signature header, runs the configured
`rpm_verify_command_template` against it, and on success promotes the entry
to `built` so the normal publish path picks it up on that same run. If the
verification command rejects it, the run fails loudly (same as the automatic
signing path) rather than silently leaving it unpublished. If an RPM is
still unsigned, the run simply reports it under `awaiting-signature` and
continues to the next timer tick — this is a routine, expected hold, not an
escalation.

The package exposes the virtual provide and dependency used by native
subscription and kernel-filtering tooling:

```spec
Provides: kpatch-patch = <base uname-r>
Requires: kernel-uname-r = <base uname-r>
```

On installation, `%post` persists the module through
`kpatch install --kernel-version <base>`, so the base does not need to be the
running kernel. It loads the module only if `uname -r` equals the package's
base. Activation restarts the distribution-owned `kpatch.service`, which loads
the persisted `/var/lib/kpatch/<base>/` copy from the SELinux `kpatch_t`
domain. Direct module loading from an RPM scriptlet reaches `insmod` in
`kmod_t`, which Alma denies `module_load` access to both the RPM payload's
`lib_t` label and the persisted module's `kpatch_var_lib_t` label. On upgrade,
restarting the oneshot service is necessary because it remains active after
boot and otherwise would not process the new module. RPM invokes the old
package's `%preun` after installing the
newer package; that scriptlet removes the superseded module from persistent
storage. The already loaded old module is not reversed, and the newer
cumulative module relies on kernel livepatch atomic replacement.

Client nodes must use the distribution-owned `/usr/lib/systemd/system/kpatch.service`
and `/usr/sbin/kpatch`. A source installation under `/usr/local` must not
shadow that service: an unmanaged `/usr/local/sbin/kpatch` has the generic
`bin_t` label and runs as `unconfined_service_t`, which enforcing SELinux
denies permission to load the persisted module.

DNF can report a completed transaction even when an RPM `%post` scriptlet
failed. Acceptance tests must therefore verify the exact new entry under
`/sys/kernel/livepatch/` exists and has `enabled` equal to `1`; package presence
or the `Installed patch modules` section alone is insufficient.

## Client discovery and refresh

Stock `kpatch-dnf` automatic mode is coupled to DNF transactions; it is not a
repository poller. `dnf kpatch auto` installs patches that are already available
for installed kernels, then configures the plugin to add a matching patch when
a future `kernel-core` transaction occurs. It does not by itself discover the
first patch package when that package is published after the kernel was
installed.

Nodes must therefore schedule the following idempotent command with a
persistent systemd timer:

```bash
dnf -y kpatch install
```

This scans all installed kernels for missing exact-match patch packages. Once a
package family has been installed, later cumulative releases retain the same
package name and increase the RPM release, so ordinary DNF or `dnf-automatic`
upgrades them. Production repositories must use `gpgcheck=1` with the
production signing key.

Before enabling publication with a site production key, validate on AlmaLinux:

1. The signer creates a trusted OpenPGP RPM signature and the configured
   verification command rejects unsigned, digest-only packages.
2. DNF with `gpgcheck=1` downloads the package from the promoted repository.
3. DNF/kpatch-dnf resolves the virtual provide for an exact installed kernel.
4. Package installation for a non-running kernel persists but does not load.
5. Package installation for the running kernel loads and completes transition.
6. An RPM upgrade leaves only the new module installed on disk.
7. A reboot into the same base loads only the latest cumulative module.
8. Package erasure prevents future loading without trying to reverse an active
   patch.
