# Build isolation and the single-base model

## Operational model

The central builder tracks one architecture and one exact base kernel: the
kernel running on the builder itself. It produces at most one cumulative
livepatch job per reconcile, and successive repository targets are built as
sequential replacements in that single `kpatch-patch-<base>` RPM family. There
is no build concurrency: jobs are executed one at a time and there is no
`max_concurrent_builds` setting to tune.

Parallelism was only ever needed by an earlier design that fanned out builds
across the last N repository kernels. That model has been retired. If separate
stream or architecture profiles are ever scheduled on one host, each runs as an
independent, separately locked reconcile process — not as concurrent build
threads inside a single run.

## Avoiding an unchanged build

Selection and sequential applicability validation are much cheaper than a
kernel build and remain mandatory for every new target. Immediately after that
stage, the runner hashes the confined aggregate `source.patch`. If its SHA-256
matches a published result for the same exact base, the target has made no
effective livepatch change: reconciliation records it as covered by the prior
RPM and stops before the writable source copy, `kpatch-build` and `rpmbuild`.

This is not a comparison of version numbers, CVE sets or vendor patch names.
Those can all change without describing the resulting source accurately. A
digest match proves that the selector produced the same net source change for
the same base; any different aggregate patch proceeds through the full build.
Older published jobs can be migrated by hashing their retained `source.patch`,
while new registry entries store the digest directly.

## Why per-job isolation is still required

Isolation is a correctness requirement for a *single* kpatch-build invocation,
not a concurrency feature. Field inspection of kpatch-build 0.9.11 found that it
derives working paths from `CACHEDIR`, which defaults to `$HOME/.kpatch`:

| Path | Purpose | Consequence of sharing |
|---|---|---|
| `build.log` | kpatch's internal compiler log | A run truncates whatever was there before. |
| `tmp/` | patch, comparison and module intermediates | A run removes `tmp/*` on start. |
| `tmp/kpatch-build.env` | kpatch compiler environment | Overwritten each run. |
| `src/` and `buildroot/` | default source/build cache | Overwritten or cleaned each run. |

The central EL9 invocation supplies `--sourcedir`, so kpatch-build uses the
selector's prepared source tree instead of `$CACHEDIR/src`. That source tree is
still writable and kpatch compiles and temporarily patches it in place.

Therefore every job:

1. **Uses a private kpatch cache.** kpatch-build is launched with
   `CACHEDIR=<job-workspace>/kpatch-cache`; it never touches the service
   account's default `$HOME/.kpatch`.
2. **Treats the prepared source cache as immutable.** A successfully promoted
   exact-NVR source cache is read-only build input.
3. **Builds from a private writable source copy.** Each job materialises its
   own build tree under its workspace with `cp -a --reflink=auto` (with a safe
   copy fallback) and passes that private tree to `--sourcedir`, so an in-place
   patch cannot mutate the shared cache.

All per-job files live below `<work-root>/<job-id>/`: `status.json`,
`build.log`, the private `kpatch-cache`, the writable `build-source`, selected
patch evidence, the module output and the RPM top directory.

## Source preparation and publication safety

Two safeguards remain even though builds are sequential, because they protect
against *separate processes* (a re-run after a crash, or an independently
scheduled profile), not against build threads:

* **Locked source preparation.** Preparing an exact-NVR source cache takes a
  filesystem lock keyed on the NVR, builds in a temporary sibling directory,
  writes the completion stamp last and atomically promotes the result. A failed
  or interrupted preparation never appears complete.
* **Serial signing and atomic publication.** A repository-root signing lock
  serialises RPM finalisation, and publication atomically repoints the
  `current` symlink to an immutable createrepo version directory under its own
  publication lock.

## CPU and memory sizing

kpatch-build 0.9.11 computes its own parallelism from every online CPU and runs
the original and patched kernel builds with `make -j<online-cpus>`, so a single
job already tries to use the whole host. Establish timeouts and resource
expectations from a real build on the dedicated native x86_64 builder; the
x86_64-on-Apple-Silicon UTM/QEMU TCG development environment is suitable for
functional evidence only and must not set native timeout values.

## Acceptance criteria

Automated tests prove:

* each job receives distinct cache, source, log, module and RPM paths keyed by
  job id, so re-running a base cannot disturb another job's tree;
* two cold source preparations for the same exact NVR perform one preparation
  and both consume the atomically promoted result;
* a build failure records the outcome and prevents unintended publication;
* a byte-identical effective patch for the same base reaches
  `effective-no-change` without invoking `kpatch-build` or `rpmbuild`;
* signing remains verifiable and repository promotion remains atomic;
* timeout termination reaps the build's whole process group;
* the full suite remains deterministic.

The remaining field step is an end-to-end real kpatch-build on the dedicated
native x86_64 builder, retaining the per-job log, resource metrics, module
verification, RPM verification and repository evidence.
