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
