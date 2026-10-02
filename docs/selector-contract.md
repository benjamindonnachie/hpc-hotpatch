# Selector adapter contract

The selector is intentionally outside the provider-neutral orchestration
core. The included EL9 adapter, `python3 -m livepatch_repo.el9_selector`, is
responsible for exact SRPM preparation, spec/changelog mapping, series
expansion, sequential applicability validation and aggregate net-diff
generation.

The configured `selector_command_template` may use:

| Placeholder | Meaning |
|---|---|
| `{base}` | Exact base kernel `uname -r` identity |
| `{target}` | Newest cumulative target kernel identity |
| `{workspace}` | Durable job workspace |
| `{patch}` | Required aggregate patch output |
| `{selection_manifest}` | Required JSON evidence output |
| `{requested_cves}` | Newline-delimited CVEs from the central plan |
| `{advisory_evidence}` | Strict JSON mapping of requested CVEs to canonical advisory ticket IDs |
| `{module_name}` | Requested livepatch module name |

The selector must create a non-empty patch and a manifest of this minimum
shape:

```json
{
  "base": "5.14.0-687.24.1.el9_8.x86_64",
  "target": "5.14.0-687.25.1.el9_8.x86_64",
  "base_source_tree": "/var/lib/livepatch-repo/source-cache/example/BUILD/linux-5.14.0-687.24.1.el9_8",
  "covered_cves": [
    "CVE-2026-12345"
  ]
}
```

The central runner rejects missing required CVEs and also rejects additional
CVEs outside the planned interval. Additional provenance fields are retained
unchanged and included in the RPM evidence file.

Repository collection resolves each CVE's individual vendor rating through
the configured Red Hat Security Data batch endpoint. By default only Critical
and Important decisions are written to `{requested_cves}`. Moderate and Low
CVEs remain in the plan as `below-policy` evidence and are not selector inputs;
an unrecognised or unavailable individual rating fails collection before any
build or publication occurs. DNF's advisory severity is deliberately not used
as a substitute for a per-CVE rating.

DNF advisory detail is collected on the central host with the repository
snapshot. When an advisory names a CVE but the SRPM changelog omits its braced
CVE tag, an exact advisory-description match may carry the advisory's JIRA
number into `{advisory_evidence}`. The EL9 selector canonicalises only the
numeric ticket identifier, requires an exact match to the patch's SRPM
changelog ticket, and records `advisory-ticket(<id>)` provenance. Missing,
ambiguous or out-of-request evidence still fails closed and publishes no RPM.

The retained base source cache is immutable. If the target changelog explicitly
states that an Alma ahead-of-RHEL CVE patch present in the base was dropped or
superseded by a named RHEL series, the EL9 selector copies the base tree into a
private validation workspace, reverses that exact base patch there, and then
applies the target series in spec order. The aggregate input to `kpatch-build`
is the net diff between the untouched retained base and the final validated
tree. The manifest records the reversal in `reversed_superseded_patches`;
ambiguous prose, an absent patch number, a failed reverse, or a failed forward
application stops the central job without publishing.

Some current EL9 source RPMs fold vendor changes directly into the released
source tarball and leave no discrete patch for the selector to map. This is
not permission to select an arbitrary base-to-target source diff. An operator
may explicitly pass `--folded-source-evidence FILE` for an exceptional build.
The versioned JSON must:

- match the exact base and target kernel identities;
- group every requested CVE under a ticket that the target changelog associates
  with that CVE, or that reviewed advisory-ticket evidence associates with the
  CVE when the target changelog contains the same ticket (for example, when a
  CVE is assigned after the fix shipped). A schema version 2 group may instead
  declare a non-empty `tickets` list when independently ticketed fixes share a
  cumulative source file; every CVE must be proved by at least one listed
  ticket;
- list every ticket-scoped source file; and
- pin the SHA-256 of each listed file in both prepared source trees.

Schema version 1 selects the complete base-to-target diff of every declared
file and remains suitable only when all changes in those files belong in the
livepatch. Schema version 2 additionally requires a non-empty `hunks` list for
each file. Each value is the SHA-256 of an exact unified-diff hunk generated
from the two pinned files. The selector regenerates the vendor diff, verifies
every hunk digest, and emits only the reviewed hunks. This prevents a shared
vendor ticket or source file from pulling below-policy or unrelated collateral
into an Important/Critical livepatch.

The selector accepts this fallback only when ordinary selection failed because
one or more requested CVEs had no selectable patch. It verifies exact CVE
coverage, changelog or advisory-ticket provenance, safe regular-file paths and
every file and hunk hash, then emits the reviewed diff. Missing, stale,
over-broad or ambiguous evidence fails closed. Creating the evidence is a
reviewed operator action: the selector cannot reliably infer which changes in
a folded cumulative tree are prerequisites belonging to the same vendor
backport series.

**Hunk pins are not portable across evidence-generation environments.** A
schema-2 `hunks` entry pins the SHA-256 of one exact unified-diff hunk as
produced wherever the evidence was authored. When the upstream/vendor CVE fix
does not apply verbatim to the exact folded base — for example when the fix
was backported with patch fuzz, offset, or hand-adjusted context to land on
this particular base/target pair — the hunk text that was reviewed and pinned
is a product of that reconciliation, not of a plain `git diff --no-index`
between the two pinned files. Regenerating the diff on a different host (a
different git version, or simply re-running the same fuzzy-apply step again)
can legitimately fail to reproduce that exact hunk byte-for-byte even though
both files' whole-file SHA-256 still match. This is the fail-closed design
working as intended, not evidence corruption: a whole-file match proves the
source is authentic, but only an exact hunk match proves the specific reviewed
lines — and nothing else — are what gets emitted. Do not relax hunk
verification to work around this. Instead, re-run whatever reconciliation
(fuzzy patch application, hand narrowing) produced the original hunk, on the
actual base/target trees present on the build host, and re-pin the hashes it
yields; treat the evidence as tied to a specific prepared source tree, not
just to a base/target kernel version pair.

For the EL9 `kpatch-build` backend, `base_source_tree` is also mandatory and
must name an existing absolute directory. The runner passes that prepared
tree, the exact base config and the exact base debuginfo `vmlinux` explicitly
to `kpatch-build`; the builder therefore does not depend on the central host
running the base kernel.

The EL9 adapter deliberately consumes the central plan's newline-delimited CVE
interval and separately captured advisory evidence rather than querying
endpoint advisories again. It carries no node-side provider state, module
loading, reboot, systemd or DNF transaction behaviour. A selection or build
failure remains central: no incomplete RPM is published and no client reboot
is requested.
