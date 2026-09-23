# Requirements: Windows deterministic-build support for AVC

**Status:** Implemented.

- **REQ-01:** The outer Setup build shall remove host paths and VCS-state
  variance with fixed trim/build flags.
- **REQ-02:** `SOURCE_DATE_EPOCH` shall equal the source commit's UTC Unix
  timestamp.
- **REQ-03:** Manifest, payload metadata, and provenance JSON shall use sorted
  keys, two-space indentation, LF endings, and one trailing LF.
- **REQ-04:** The outer Setup dependency graph shall be vendored for offline
  assembly.
- **REQ-05:** The assembly-only Go toolchain shall be pinned out of band in
  `repro-flags.{sh,ps1}` without adding a `toolchain` directive to `go.mod`.
- **REQ-06:** Bash and PowerShell assembly shall produce contract-equivalent
  metadata from equal inputs.
- **REQ-07:** Independent supported build hosts shall produce byte-identical
  unsigned outer Setup bytes for identical inputs.
- **REQ-08:** Assembly shall fail with a named diagnostic when a required
  reproducibility value is absent, malformed, or contradicted.
- **REQ-09:** The CI reproducibility gate shall remain bounded by its workflow
  timeout.
- **REQ-10:** AVC assembly shall not require network access.
- **REQ-11:** The uncompressed build kit shall remain below the enforced size
  ceiling.
