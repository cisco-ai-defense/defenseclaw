# Design: Windows deterministic-build support for AVC

**Status:** Implemented.

## Components

| Component | Role |
| --- | --- |
| `cmd/windows-repro-manifest` | Emits byte-stable manifest, payload metadata, and provenance JSON. |
| `packaging/scripts/lib/repro-flags.{sh,ps1}` | Pins `GOFLAGS`, `GOTOOLCHAIN`, `CGO_ENABLED`, target OS/architecture, source epoch, and build ID. |
| `scripts/check-repro-flags-parity.sh` | Prevents the shell variants from drifting. |
| `scripts/check-go-mod-no-toolchain.sh` | Keeps the assembly-only toolchain pin out of the OSS module contract. |
| `.github/workflows/windows-deterministic-build.yml` | Builds independent artifacts and compares their SHA-256 values. |
| `internal/build-repro/testdata/` | Contains the non-production fixed payload fixture and regeneration instructions. |

The outer Setup build uses `-mod=vendor -trimpath -buildvcs=false`, a fixed
non-empty linker build ID, `CGO_ENABLED=0`, `GOOS=windows`, `GOARCH=amd64`, and
the assembly-path `GOTOOLCHAIN` pin. `SOURCE_DATE_EPOCH` is a per-build input
derived from the approved commit. Ambient values are overwritten and then
validated immediately before `go build`.

The manifest helper is built for the current assembly host before the scripts
pin `GOOS=windows`. It hashes inputs and serializes JSON identically for both
assembler implementations. The outer Setup itself is then cross-built from the
vendored source tree.

## Tradeoffs

- The toolchain pin lives in the packaging scripts instead of `go.mod`, so
  contributor and OSS builds retain patch-version flexibility while the signed
  managed-enterprise artifact remains reproducible.
- A Go metadata helper is used instead of separate shell serializers, avoiding
  JSON ordering and line-ending differences between bash and PowerShell.
- `CGO_ENABLED=0` removes C-toolchain variance; the outer bootstrap has no cgo
  requirement.

## Risks

| Risk | Control |
| --- | --- |
| Shell implementations drift | Shared emitted JSON plus repro/assembler parity checks. |
| Ambient CI variables alter bytes | Scripts assign exact values and preflight the effective environment. |
| Toolchain patch version changes output | Assembly-only `GOTOOLCHAIN` pin and workflow assertion. |
| Dependency download changes build inputs | Complete vendored source and offline build checks. |
| A fixture includes real production signing material | Fixture documentation and dependency/signer guards require synthetic inputs only. |
