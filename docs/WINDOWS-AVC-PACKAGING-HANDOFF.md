# Windows AVC packaging handoff

This is the canonical contract between DefenseClaw release engineering and the
Cisco Secure Client AVC packaging pipeline for the signed Windows
managed-enterprise Setup. DefenseClaw produces an unsigned build kit; AVC owns
both Authenticode signing rounds and returns the finalized release artifacts.

Do not use the retired on-host Windows builder. Use
`make packaging-windows-avc-buildkit VERSION=<version>` for a signed release
handoff, or `make packaging-windows-enterprise-installer VERSION=<version>` only
for a local unsigned disposable-test build.

## What DefenseClaw hands to AVC

The build-kit directory is
`dist/windows-enterprise-buildkit-<version>/` and has this contract:

```text
windows-enterprise-buildkit-<version>/
├── payload/
│   ├── DefenseClawEnterprise.psm1
│   ├── defenseclaw-cmid-broker.exe
│   ├── defenseclaw-gateway.exe
│   ├── defenseclaw-hook.exe
│   ├── defenseclaw.exe
│   └── install-enterprise.ps1
├── source/                         # trimmed, vendored, offline Go build
├── packaging/scripts/lib/
│   ├── assert-cisco-signature.{sh,ps1}
│   ├── finalize.{sh,ps1}
│   └── repro-flags.{sh,ps1}
├── assemble.sh                     # or assemble.ps1, selected at kit build
├── payload-metadata.json
└── README-AVC.md
```

`payload-metadata.json` binds the expected filenames, DefenseClaw version,
source commit, and CMID pseudo-version. The six-file inventory is closed: a
missing, renamed, substituted, or additional embedded payload file is an
assembly failure.

The kit's `source/vendor` tree makes the outer Setup build offline. The pinned
toolchain and reproducibility environment are defined by
`packaging/scripts/lib/repro-flags.{sh,ps1}` rather than inherited from the AVC
runner.

## Required pipeline order

The order is security-critical because the outer Setup embeds the hashes and
bytes of the already-signed inner payload.

### 1. Sign the inner payload

AVC Authenticode-signs all six files under `payload/`. The signing wrapper may
use its standard certificate and timestamp arguments, but every result must
validate to the exact publisher common name `Cisco Systems, Inc.`. EXEs and the
PowerShell script/module are all part of this signed set.

Do not modify any payload byte after this step. The assembler verifies each
signature and emits a SHA-256-bound manifest from these exact bytes.

### 2. Assemble the outer Setup

Derive `SOURCE_DATE_EPOCH` from the UTC Unix timestamp of the exact 40-character
lowercase DefenseClaw source commit recorded in the kit. From the kit root, run
the shipped assembler.

Bash-hosted kit:

```bash
export SOURCE_COMMIT=0123456789abcdef0123456789abcdef01234567
export SOURCE_DATE_EPOCH=1787097600
export RELEASE_VERSION=0.9.0-rc1
export CMID_PSEUDO_VERSION=v0.0.0-20260819000000-0123456789ab
./assemble.sh \
  --source-commit "$SOURCE_COMMIT" \
  --version "$RELEASE_VERSION" \
  --cmid-pseudo-version "$CMID_PSEUDO_VERSION"
```

The values above illustrate the required shapes. The pipeline must substitute
the approved values recorded for the handed-off kit rather than reuse the
examples.

PowerShell-hosted kit:

```powershell
$SourceCommit = '0123456789abcdef0123456789abcdef01234567'
$Version = '0.9.0-rc1'
$CmidPseudoVersion = 'v0.0.0-20260819000000-0123456789ab'
$env:SOURCE_DATE_EPOCH = '1787097600'
pwsh -File .\assemble.ps1 `
  -SourceCommit $SourceCommit `
  -Version $Version `
  -CmidPseudoVersion $CmidPseudoVersion
```

The assembler:

- checks arguments and the fixed reproducibility environment;
- verifies the exact inner payload inventory and Cisco signatures;
- emits the embedded `manifest.json`;
- copies the signed bytes into the Go embed directory;
- builds `out/DefenseClawSetup-Enterprise-x64.exe` with the vendored source;
- emits `out/DefenseClawSetup-Enterprise-x64.exe.provenance.json` with the
  outer hash fields intentionally empty until signing completes.

The assembly host must have the Go toolchain selected by `GOTOOLCHAIN` in the
kit. A bash runner also requires `osslsigncode` and `openssl`; the PowerShell
assembler requires PowerShell 7 and uses Windows Authenticode validation. The
outer build must not access module proxies, GitHub, or the private source
repository.

### 3. Sign the outer Setup

AVC Authenticode-signs:

```text
out/DefenseClawSetup-Enterprise-x64.exe
```

The signed outer EXE is the release artifact. Do not run the assembler again
after outer signing; that would replace it with a new unsigned binary.

### 4. Finalize hash and provenance

After outer signing, run the helper matching the pipeline host, or perform the
exact equivalent inside the AVC signing wrapper.

Bash:

```bash
./packaging/scripts/lib/finalize.sh \
  --setup-exe out/DefenseClawSetup-Enterprise-x64.exe \
  --provenance out/DefenseClawSetup-Enterprise-x64.exe.provenance.json
```

PowerShell:

```powershell
pwsh -File .\packaging\scripts\lib\finalize.ps1 `
  -SetupExe .\out\DefenseClawSetup-Enterprise-x64.exe `
  -Provenance .\out\DefenseClawSetup-Enterprise-x64.exe.provenance.json
```

Finalization computes the SHA-256 and byte size of the **signed** outer EXE,
writes the sha256sum-compatible `.sha256` sidecar, and sets `setup_sha256` and
`setup_size` in provenance with the repository's byte-stable JSON shape.

## Artifacts AVC returns

Return exactly:

```text
DefenseClawSetup-Enterprise-x64.exe
DefenseClawSetup-Enterprise-x64.exe.sha256
DefenseClawSetup-Enterprise-x64.exe.provenance.json
```

Release engineering verifies before publication that:

- the outer Authenticode signature is valid and names the approved Cisco
  publisher;
- the sidecar SHA-256 matches the signed EXE;
- `provenance.setup_sha256` and `setup_size` match the same signed EXE;
- the provenance source commit and version equal the approved release;
- two assemblies of identical signed payload bytes and inputs produce
  byte-identical unsigned outer Setup bytes before the outer signing step.

## Failure and change control

Do not publish partial output. A signature, inventory, reproducibility,
assembly, hash, or provenance mismatch fails the handoff and requires a clean
rerun from the approved kit.

Any change to the six-file payload, kit layout, signer identity, assembly
arguments, toolchain pin, signing order, output names, or provenance fields is
a contract change. Update this document, the generated `README-AVC.md`, both
assembler implementations, their parity checks, and the release verification
before AVC adopts it.
