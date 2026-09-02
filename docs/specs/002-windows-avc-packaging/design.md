# Design: AVC-driven Windows enterprise packaging

**Status:** Implemented.

## Summary

The signing boundary is deliberately split. DefenseClaw can access the private
CMID source and prepare an unsigned offline kit, but it does not possess or
consume AVC signing credentials. AVC signs both the inner runtime files and the
outer self-extracting Setup in its controlled pipeline.

## Data flow

```text
DefenseClaw release commit + pinned ai-common/cmid ref
  │
  ├─ make packaging-windows-avc-buildkit
  │    └─ windows-enterprise-buildkit-<version>/
  │         ├─ payload/ (six unsigned inner files)
  │         ├─ source/ + vendor/ (offline outer build)
  │         ├─ assemble.{sh|ps1} + helpers
  │         └─ payload-metadata.json
  │
  └─ AVC pipeline
       1. Authenticode-sign payload/*
       2. assemble.{sh|ps1}
          ├─ verify exact inventory and Cisco signatures
          ├─ emit and embed manifest.json
          └─ build unsigned outer Setup + preliminary provenance
       3. Authenticode-sign outer Setup
       4. finalize.{sh|ps1}
          └─ write signed-outer SHA-256, size, and sidecar
```

The outer Setup embeds the signed inner files, not their unsigned precursors.
This requires inner signing before assembly. The outer signature changes the
outer EXE bytes, so its hash and size can be finalized only after outer signing.

## Components

| Component | Responsibility |
| --- | --- |
| `packaging/scripts/build-managed-windows-bundle.sh` | Apply the CMID overlay in a restorable snapshot, build/stamp the Windows payload, trim and vendor source, and emit the kit metadata/runbook. |
| `packaging/scripts/lib/assemble.{sh,ps1}` | Validate the kit and signed payload, emit the embedded manifest, and reproducibly build the outer Setup. |
| `packaging/scripts/lib/assert-cisco-signature.{sh,ps1}` | Enforce a valid signature and exact Cisco publisher identity. |
| `packaging/scripts/lib/repro-flags.{sh,ps1}` | Pin the assembly toolchain, target, flags, build ID, and source epoch. |
| `cmd/windows-repro-manifest` | Emit byte-stable manifest, payload metadata, and provenance JSON. |
| `packaging/scripts/lib/finalize.{sh,ps1}` | Hash the signed outer Setup and update sidecar/provenance. |
| `cmd/defenseclaw-enterprise-setup` | Validate the embedded six-file manifest and stage the trusted lifecycle payload at runtime. |

## Interfaces

The build-kit producer is:

```bash
make packaging-windows-avc-buildkit VERSION=0.9.0-rc1
```

The local unsigned developer path is:

```bash
make packaging-windows-enterprise-installer VERSION=0.9.0-rc1
```

Assembler defaults are `./payload`, `./source`, and `./out`. Both variants
require a 40-character lowercase source commit and version. Exit-code classes
are `0` success, `2` usage, `3` reproducibility preflight, `4` signature,
`5` build, and `6` I/O or malformed input.

The exact AVC commands and returned artifacts are defined in
`docs/WINDOWS-AVC-PACKAGING-HANDOFF.md` and repeated in the generated kit
`README-AVC.md`.

## Decisions

- **Signing remains outside DefenseClaw.** No signing certificate or secret is
  accepted by the kit producer or public pull-request workflow.
- **The payload inventory is closed.** The runtime, metadata emitter, and both
  assemblers all validate the same six filenames.
- **Outer hash finalization is post-signing.** Preliminary provenance contains
  an empty hash and zero size; the finalizer rewrites only those signed-outer
  facts with the byte-stable serializer shape.
- **The local build is visibly unsigned.** Its directory and distribution
  flavor differ, and runtime scope checks prevent production installation.
- **The legacy gateway ZIP is compatibility output.** The AVC Setup input is
  the build-kit directory, not the ZIP/commit-sidecar pair.

## Risks

| Risk | Control |
| --- | --- |
| AVC signs the outer EXE before embedding signed inner bytes | Fixed four-step ordering and signature checks inside assembly. |
| Bash and PowerShell produce different contracts | `scripts/check-assemble-parity.sh` plus shared manifest emitter and equivalent tests. |
| Ambient runner state changes output | Reproducibility preflight, fixed toolchain/target/build ID, vendored offline build, and cross-runner byte comparison. |
| A payload file is omitted or substituted | Closed filename set, signature validation, metadata binding, embedded SHA-256 manifest, and runtime validation. |
| The signed outer hash describes the unsigned binary | Finalization occurs only after outer signing and release verification recomputes both sidecar and provenance facts. |
| An unsigned developer artifact reaches production | Distinct flavor/output, required explicit switch, exact disposable names/roots, and runtime fail-closed checks. |
