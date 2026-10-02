# DefenseClaw Release Runbook

A release is one run of the Release workflow. Installed clients upgrade by
running the latest release's installer, so nothing else has to be updated
between versions. The one exception is a single run after the first 1.x
release, which points 0.8.8–0.8.10 upgrades at it (see "One-time: move
0.8.8–0.8.10 upgrades to 1.x" below).

## Cut a release

1. Merge the changes to `main`. CI's **Install and Upgrade Smoke** jobs build
   release-shaped assets from the commit and run the real installer on Linux
   and Windows.
2. Actions → **Release** → Run workflow on `main` with `version: X.Y.Z` (bare,
   no `v`, newer than the latest release). Or:

   ```bash
   gh workflow run release.yaml --repo cisco-ai-defense/defenseclaw --ref main -f version=X.Y.Z
   ```

3. The workflow builds every asset once, writes and signs `checksums.txt`,
   runs the install lifecycle on Linux x64/arm64, macOS and Windows, and
   publishes the release as **latest**. The lifecycle covers a fresh install
   that verifies the new signature, upgrades from the previous 1.x release,
   0.8.10 and 0.8.4, rollback, the 0.8.x handoff, and failure drills that must
   roll back. See [Testing](TESTING.md#install-and-upgrade-tests).

Releases build for Linux (`amd64`, `arm64`), macOS on Apple Silicon (`arm64`;
Intel Macs are unsupported), and Windows (`amd64`).

The macOS app is signed with Developer ID and notarized when all five Apple
secrets (`MACOS_DEVELOPER_ID_P12_BASE64`, `MACOS_DEVELOPER_ID_P12_PASSWORD`,
`MACOS_NOTARY_KEY_BASE64`, `MACOS_NOTARY_KEY_ID`, `MACOS_NOTARY_ISSUER_ID`) are
set in the `release` environment. Without them the run fails, because
`install.sh` would put an ad-hoc signed app, which runs without administrator
mode, on users' Macs. To publish such an app anyway (a fork, a test), run with
`-f allow_unnotarized_macos_app=true`.

The same run builds the standalone enterprise packages for MDM deployment:
the Windows Setup, the Linux `.deb`, `.rpm` and payload archives, and the
macOS `.pkg`. Unlike the app, they do not need signing secrets. Without them
they ship unsigned, and deployments pin each one by its SHA-256 in the
cosign-signed `checksums.txt`. The release signs them when their secrets
are set: `WINDOWS_AUTHENTICODE_PFX_BASE64` and
`WINDOWS_AUTHENTICODE_PFX_PASSWORD` (Authenticode for the Setup),
`ENTERPRISE_GPG_PRIVATE_KEY` and `ENTERPRISE_GPG_PASSPHRASE` (GPG signatures
for the Linux packages), and `MACOS_INSTALLER_SIGNING_IDENTITY` with
`MACOS_SIGNING_IDENTITY` for the pkg. The pkg reuses the app's Developer ID
certificate and notary key (add `MACOS_INSTALLER_P12_BASE64` and
`MACOS_INSTALLER_P12_PASSWORD` when the Developer ID Installer certificate is
in its own PKCS#12); the app's five secrets alone leave the pkg unsigned. See
`packaging/mdm/signing/README.md` for the trust channels.

To try a release on real machines before users see it, run the workflow with
`draft: true` and download the draft's assets (`gh release download X.Y.Z`).
Use disposable test machines or VMs, not anyone's working install: an
unpublished release has not been through users yet. Check the assets against
the signed checksum list before running anything:

```bash
cosign verify-blob --bundle checksums.txt.bundle \
  --certificate-identity https://github.com/cisco-ai-defense/defenseclaw/.github/workflows/release.yaml@refs/heads/main \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com checksums.txt
sha256sum --check --ignore-missing checksums.txt   # macOS: shasum -a 256 --check --ignore-missing checksums.txt
```

On Windows (PowerShell, with `cosign.exe` on PATH):

```powershell
cosign verify-blob --bundle checksums.txt.bundle `
  --certificate-identity https://github.com/cisco-ai-defense/defenseclaw/.github/workflows/release.yaml@refs/heads/main `
  --certificate-oidc-issuer https://token.actions.githubusercontent.com checksums.txt
Get-Content checksums.txt | ForEach-Object {
  $hash, $name = -split $_
  if ((Test-Path $name) -and (Get-FileHash -Algorithm SHA256 $name).Hash -ne $hash) { throw "$name does not match checksums.txt" }
}
```

Then install them with `install.sh --local DIR` or `install.ps1 -Local DIR`,
and publish:

```bash
gh release edit X.Y.Z --draft=false --latest
```

## When a release is broken

Releases are immutable and a deleted release burns its tag, so never delete
one.

1. Stop new installs from getting it: `gh release edit X.Y.Z --prerelease`, or
   `gh release edit <good version> --latest`.
2. Fix on `main` and cut `X.Y.(Z+1)`. Users who already upgraded get the fix
   with `defenseclaw upgrade`: the fix to any part of the install or upgrade
   process ships in the new release's installer.
3. Anyone whose `defenseclaw` no longer starts runs the install command again,
   or `defenseclaw rollback`, which does not need the broken release to work.

## One-time: move 0.8.8–0.8.10 upgrades to 1.x

`defenseclaw upgrade` on 0.8.8–0.8.10 macOS/Linux follows a signed pointer on
the `release-channel` branch. After the first 1.x release is published and
verified, run the Release workflow once with `operation: legacy-channel` and
`version: <that release>`. It runs the 0.8.10 channel publisher from the
`0.8.10` tag, pointing 0.8.x clients at the release's `defenseclaw-upgrade.sh`,
which hands off to the latest `install.sh`. It does not need to run again.

## Never change

- The asset names `install.sh`, `install.ps1` and `defenseclaw-upgrade.sh`, the
  `releases/latest/download/` and `releases/download/X.Y.Z/` URLs, and bare
  `X.Y.Z` tags. Every installed client downloads these.
- The installer flags `--yes`, `--version`, `--local` and `--rollback`
  (`-Yes`, `-Version`, `-Local`, `-Rollback`). Unknown flags must stay
  warnings, not errors.
- `cli/defenseclaw/upgrade_shim.py` stays standard-library only.
- The install paths: binaries are real files in `~/.local/bin` (hooks record
  those paths) and the Python environment is `~/.defenseclaw/.venv`.
- Releases come only from `release.yaml` on `main`; installers and 0.8.x
  clients check its Sigstore identity.
- `checksums.txt` stays in the flat `<sha256>  <name>` format and lists
  `install.sh`, `install.ps1` and `defenseclaw-upgrade.sh`.
- Never publish `defenseclaw_<v>_<os>_<arch>.*`, `upgrade-manifest.json`,
  `release-provenance.json` or `DefenseClawSetup-x64.exe`: 0.8.x clients stop
  safely only because those names do not exist.
- `defenseclaw-upgrade.sh` keeps its last line
  `# DefenseClaw upgrade resolver complete v1`.

## Changing the config schema

`config.yaml` is validated against the closed schema
`schemas/config/v8/defenseclaw-config.schema.json` (every object sets
`additionalProperties: false`), by both the gateway and the CLI.

- **A new key:** add it to that schema and give it a default in the Python
  (`cli/defenseclaw/config.py`) and Go (`internal/config`) loaders. No
  migration is needed. An older release with the same `config_version`
  rejects the key, so do not write it by default while downgrading to such a
  release must still work.
- **Renaming, removing or re-shaping a key:** prefer adding a new key and
  reading the old one. A `config_version` bump is a larger change: one step in
  `CONFIG_MIGRATIONS` (`cli/defenseclaw/migrations.py`, keyed by the old
  version; the runner writes the new version), `CURRENT_CONFIG_VERSION`
  (`cli/defenseclaw/config.py`), `MaxSupportedConfigVersion`
  (`internal/config/observability_v8_types.go`), the schema's
  `config_version` `const`, and every place that still expects exactly 8
  (`git grep -nE '!= 8|== 8' -- cli/defenseclaw internal`). Do not touch Go's
  `CurrentConfigVersion` (7), the legacy decoder. `defenseclaw migrate --check`
  does not validate these steps, so test that a migrated file loads in both
  loaders.
- **Audit database changes** are forward-only migrations the gateway applies
  at startup (`internal/audit/store.go`, and the judge-body and inventory
  stores); never edit or reorder an existing one.
