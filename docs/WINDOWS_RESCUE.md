# Authenticated Windows Rescue

`defenseclaw-rescue.ps1` is the external recovery entry point for native
Windows x64 systems that need an authenticated fresh installation or
same-version native Setup servicing when the installed DefenseClaw CLI cannot
help. It is intentionally small and version-independent.

## Trust model

Release assets remain immutable. The only mutable object is the
`release-channel` branch pointer, and that pointer selects a commit containing
the stable-channel manifest and its Sigstore bundle.

The rescue script:

1. Resolves `refs/heads/release-channel` to one exact Git commit.
2. Downloads `stable.txt` and `stable.txt.bundle` through URLs containing that
   commit.
3. Uses a SHA-256-pinned Cosign 2.6.3 executable to verify the manifest was
   signed by the exact `release.yaml@refs/heads/main` workflow identity.
4. Parses the manifest as a fixed, canonical schema and requires the Windows
   installer URL to be derived from the immutable target tag.
5. Downloads that release's `install.ps1`, verifies its authenticated SHA-256,
   validates its PowerShell syntax, and executes it in a fresh `-NoProfile`
   PowerShell process.

The Cosign split is intentional. Native Windows and release-candidate jobs use
Cosign 2.6.2 for their legacy bundle contract, while the signed channel and
public rescue paths use the SHA-256-pinned Cosign 2.6.3 verifier. Do not align
those pins without migrating and retesting both contracts.

The channel owns the target version. The rescue path refuses version, local
artifact, alternate verifier, and unverified-mode overrides.

## Use

First obtain `defenseclaw-rescue.ps1` from a trusted DefenseClaw source. For
example, authenticate its digest through the signed release checksums before
running it. Do not pipe a mutable web response directly into PowerShell.

Then run:

```powershell
pwsh -NoLogo -NoProfile -File .\defenseclaw-rescue.ps1 -Yes
```

Installer options such as `-Connector codex`, `-Quickstart`, and
`-QuickstartMode observe` can be appended. There is no `-Version` option: the
authenticated stable channel always selects the Setup servicing or
fresh-install target.

The downloaded `install.ps1` continues to own native Setup authentication,
fresh installation, repair, and same-version servicing behavior. Windows
release acceptance is fresh-install-only through `0.8.8`; this rescue path
does not create or claim a certified native Windows upgrade lane. A
`repair-channel` workflow operation repairs only the signed discovery pointer,
while native Setup repair services an installation already on the selected
version. When Authenticode credentials are unavailable for a release, Setup
may lack Authenticode, but its exact bytes are still authenticated through the
signed release checksums and the signed stable channel.

## Scope

The bootstrap supports native Windows x64 only. Windows ARM64, 32-bit Windows,
and x64 emulation are not supported. macOS and Linux use
`defenseclaw-rescue.sh`.
