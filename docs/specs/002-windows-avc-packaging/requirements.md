# Requirements: AVC-driven Windows enterprise packaging

**Status:** Implemented.

## Functional requirements

- **REQ-01:** DefenseClaw shall emit one versioned AVC build kit from an exact
  source commit and pinned CMID pseudo-version.
- **REQ-02:** The kit shall contain exactly the six inner payload files named
  in `docs/WINDOWS-AVC-PACKAGING-HANDOFF.md`.
- **REQ-03:** The kit shall include one generated `payload-metadata.json` that
  binds version, source commit, CMID version, and expected filenames.
- **REQ-04:** The kit shall include the complete dependency closure required
  to build the outer Setup and manifest emitter.
- **REQ-05:** The kit shall include a vendored module tree so AVC assembly
  needs no network access.
- **REQ-06:** The trimmed source tree shall preserve the Go module layout,
  embedded payload directory, module files, and non-Go package assets required
  by the compiler.
- **REQ-07:** The kit shall ship the reproducibility, signer-validation, and
  post-signing finalize helpers needed by the selected assembler.
- **REQ-08:** A kit shall expose exactly one root-level assembly entry point,
  selected as bash or PowerShell when DefenseClaw builds the kit.
- **REQ-09:** The bash and PowerShell assemblers shall implement the same
  argument validation, exact inventory, signature, manifest, build, output,
  exit-code, and provenance contract.
- **REQ-10:** Signed assembly shall reject any inner file without a valid
  Authenticode chain whose signer common name is exactly
  `Cisco Systems, Inc.`.
- **REQ-11:** The assembler shall embed and hash the already-signed inner
  payload bytes; no post-manifest payload mutation is allowed.
- **REQ-12:** The outer Setup shall build using the deterministic environment
  and toolchain pin supplied by `repro-flags.{sh,ps1}`.
- **REQ-13:** AVC shall sign in the order inner payload, assemble outer Setup,
  sign outer Setup, then finalize hash and provenance.
- **REQ-14:** A DefenseClaw developer may request an unsigned local build, but
  it shall use a distinct output directory and require the runtime's exact
  disposable certification scope.
- **REQ-15:** Final artifacts shall be the signed Setup EXE, a matching
  sha256sum-format sidecar, and provenance whose outer hash and size match the
  signed EXE.
- **REQ-16:** The manifest and provenance distribution flavor shall be
  `managed-enterprise` for the signed path and
  `managed-enterprise-unsigned` only when the assembler explicitly receives
  `--allow-unsigned`/`-AllowUnsigned`.

## Acceptance criteria

- `scripts/check-assemble-parity.sh` passes for both assemblers.
- The deterministic-build workflow produces identical unsigned outer bytes
  from identical inputs on its independent runners.
- Assembly rejects missing, extra, renamed, unsigned, wrongly signed, or
  post-signing-mutated inner payload files.
- The signed artifact's sidecar and provenance agree with an independent
  SHA-256 and byte-size calculation.
- The local unsigned artifact cannot install into production roots or service
  names.
