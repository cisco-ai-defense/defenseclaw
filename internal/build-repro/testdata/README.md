# Reproducibility fixture

This directory holds the fixed signed-payload fixture that the
Workstream E reproducibility gate (`.github/workflows/windows-
deterministic-build.yml`) drives through the assembly step. Two
independent runners must produce byte-identical outer
`DefenseClawSetup-Enterprise-x64.exe` given this fixture as input.

## What's in `signed-payload-fixture.tar.zst`

Five placeholder inner files with fixed contents:

| Name                          | Purpose in the real build |
|-------------------------------|---------------------------|
| `DefenseClawEnterprise.psm1`  | PowerShell module the outer Setup embeds. |
| `defenseclaw-gateway.exe`     | Gateway binary. |
| `defenseclaw-hook.exe`        | Hook binary. |
| `defenseclaw.exe`             | Main CLI. |
| `install-enterprise.ps1`      | Installer script the outer Setup drives. |

Each file is a **short deterministic byte sequence**, not a real
Authenticode-signed PE or PS1. The reproducibility gate exercises the
JSON-emission and `go build` invariants — it does NOT exercise the
signature-verification path (`Assert-CiscoSignature`). AVC-side end-
to-end signing is exercised by Workstream A's downstream CI, not
here.

The fixture is deliberately dummy-unsigned. The Common Name embedded
in any test cert MUST NOT be `Cisco Systems, Inc.` — a lint check
enforces this so a real signed artefact can never be checked in by
accident.

## Regenerating the fixture

```
scripts/generate-repro-fixture.sh
```

The regeneration script:

1. Writes the five files under a temp dir with **byte-identical
   deterministic contents** (short strings, no timestamps, no random).
2. Tars them with `--sort=name --owner=0 --group=0 --numeric-owner
   --mtime=@0` so the archive is byte-reproducible.
3. Compresses with `zstd --no-progress --long=27 -19` for a stable
   compression path.
4. Prints the resulting SHA-256; commit-update requires bumping the
   `FIXTURE_EXPECTED_SHA256` constant in
   `.github/workflows/windows-deterministic-build.yml`.

If a future refresh legitimately changes the fixture (e.g., you add
a sixth expected filename to Workstream A), regenerate and update
the CI expected-SHA in the same PR so the deterministic gate sees
the new baseline.

## Why an inline fixture, not LFS?

Fixture size is under 1 KiB (five tiny text-ish files). LFS overhead
is not justified. If the fixture ever grows past a few MiB (unlikely
for a build-time reproducibility harness), migrate to LFS in a
separate PR.
