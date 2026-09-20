# Implemented tasks: AVC-driven Windows enterprise packaging

**Status:** Complete.

1. [x] Extend the managed Windows bundler to emit a versioned AVC kit and
   restore the OSS source/module snapshot on every exit.
2. [x] Add bash and PowerShell Cisco-signature validators for the inner
   payload.
3. [x] Emit a closed six-file payload and bind it in
   `payload-metadata.json`.
4. [x] Trim the Setup/emitter import graph and vendor it for offline AVC
   assembly.
5. [x] Ship exactly one selectable root assembler plus shared helpers.
6. [x] Test the complete signed-inner assembly path, signature rejection, and
   cross-shell parity.
7. [x] Emit the manifest before the reproducible outer build and preliminary
   provenance after it.
8. [x] Add post-outer-signing finalize helpers for SHA-256, size, sidecar, and
   provenance.
9. [x] Add the local unsigned build path with a distinct distribution flavor
   and runtime certification restriction.
10. [x] Retire the native-Windows enterprise builder and expose unambiguous
    Make targets for AVC and local unsigned use.
11. [x] Document the handoff, failure boundary, returned artifacts, and release
    verification.

## Verification

```bash
bash -n packaging/scripts/build-managed-windows-bundle.sh
bash -n packaging/scripts/lib/assemble.sh
bash -n packaging/scripts/lib/finalize.sh
scripts/check-assemble-parity.sh
go test ./cmd/defenseclaw-enterprise-setup ./cmd/windows-repro-manifest
```
