# Plan and security boundary: Windows deterministic builds

**Status:** Implemented.

The implementation is limited to build-time tooling: stable metadata emission,
fixed assembly flags and toolchain, vendored offline inputs, parity checks, and
an independent-runner reproducibility gate. It changes no runtime policy or
ordinary OSS build behavior.

## Security boundary

- The manifest helper uses the Go standard library and repository code only.
- The checked-in fixture is synthetic and must never contain a real Cisco
  certificate, key, credential, or production-signed payload.
- Signing remains entirely inside AVC; reproducibility tooling neither accepts
  nor transports signing secrets.
- A reproducible unsigned outer EXE is necessary but not sufficient for
  release: AVC still signs it and release verification binds the final signed
  hash and provenance.
