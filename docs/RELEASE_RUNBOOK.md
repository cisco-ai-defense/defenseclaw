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
   runs the install lifecycle on Linux x64/arm64, macOS and Windows, upgrades
   the previous release's standalone enterprise packages (see
   [The enterprise upgrade gate](#the-enterprise-upgrade-gate)), and
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

The macOS pkg ships unsigned for now: the `release` environment does not
carry the Developer ID Installer secrets, and their absence does not fail the
run. The pkg is protected by its SHA-256 in the cosign-signed
`checksums.txt`. When a release's pkg is unsigned, the `enterprise-macos` job
summary says so, and the release notes open with a line telling deployments
to verify the pkg through `checksums.txt`. Adding the installer secrets later
turns signing back on with no workflow change.

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

## The enterprise upgrade gate

The `enterprise-upgrade-gate` job upgrades the standalone enterprise package
of the previous 1.x release to the one being released, on a real host of each
kind, and checks that the upgrade kept the administrator's config intent.
`publish` needs it, so a failed lane stops the release. The four lanes are
stable check names (`Enterprise Upgrade (deb)`, `(rpm-el9)`, `(pkg)` and
`(Windows)`), so branch protection can require them:

| Lane | Runner | Package upgraded from, then to | Script |
| --- | --- | --- | --- |
| `deb` | `ubuntu-latest` | `defenseclaw-enterprise-<version>-linux-amd64.deb` | `scripts/test-enterprise-unix-install.sh` |
| `rpm-el9` | `ubuntu-24.04`, in a privileged UBI 9 systemd container pinned by digest | `defenseclaw-enterprise-<version>-linux-amd64.rpm` | `scripts/test-enterprise-linux-container.sh`, which runs the same script in the container |
| `pkg` | `macos-15` | `defenseclaw-enterprise-<version>-darwin-arm64.pkg` | `scripts/test-enterprise-unix-install.sh` |
| `Windows` | `windows-latest` | `DefenseClawSetup-Enterprise-Standalone-x64.exe` | `scripts/test-enterprise-windows-install.ps1 -UpgradeFrom` |

Each lane:

1. Takes the previous release from the `validate` job (the latest published 1.x
   release older than the one being released) and downloads its package with
   `scripts/fetch-previous-enterprise-package.sh --require`. That script checks
   `checksums.txt` against the Release workflow's cosign identity, then the
   package against its SHA-256. A previous release that lacks the package
   fails the lane.
2. Installs the previous package and applies a `config_version: 8`
   administrator config on it, then runs `verify` and `status`.
3. **Linux and macOS only, the rollback drill.** With the root-only lifecycle
   test fault in place (`.test-fault` in the lifecycle directory), installs
   this release's package. The upgrade must fail after the services start,
   report `lifecycle_test_fault` and `rolled_back`, and leave the config and
   the deployment record as the previous release had them. The Windows Setup
   transaction has no test fault, so the Windows lane skips this step.
4. Upgrades to this release (`ensure --from-package`, or the new Setup's
   `/ensure`). It must succeed with `verify` passing and the deployment
   complete, and the result must report the applied policy
   (`policy.applied`) from a config generation above the previous release's.
   `migration-v9.json` must exist, `config.yaml.v8.bak` must equal the
   previous config, and the secrets and the guardian ledger must be
   unchanged.
5. Runs the rest of the install lane on the upgraded deployment: `ensure`
   again is a no-op, `verify` and `status` pass, the MDM detection script
   passes, and uninstall and purge leave nothing behind.
6. Runs `scripts/check_enterprise_upgrade_config.py` on the saved files
   (`config-v8.yaml`, `config-upgraded.yaml`, `migration-v9.json`). It fails
   on any migration conflict, a wrong `source_sha256`, a `config_version`
   other than 9, and any value of the version 8 config that is neither still at
   its path with the same value nor listed in the record as moved or removed.
7. Uploads the lifecycle results as the artifact
   `enterprise-upgrade-results-<lane>` (7 days).

When there is no previous 1.x release (the first 1.x release, or a latest
release that is 0.x), every lane prints the notice "No previous 1.x release, so
there is no enterprise package to upgrade from" and passes without running.
The gate runs in a dry run too, against the real previous release.

To reproduce a lane on a disposable host, download the previous release's
package, verify it as above, and run the lane script with
`--package`, `--version`, `--upgrade-from` and `--previous-version` (see the
header of `scripts/test-enterprise-unix-install.sh`). Run it as root only on a
machine you can throw away: it installs and removes system services.

## Dry run

A dry run exercises the whole workflow, including the enterprise Windows and
macOS jobs, without publishing anything. Use it after changing the workflow
or the packaging scripts. It runs from any branch, and the version may already
be released or be older than the latest release:

```bash
gh workflow run release.yaml --repo cisco-ai-defense/defenseclaw --ref <branch> -f version=X.Y.Z -f dry_run=true
```

With `dry_run: true`:

- `validate` still runs its read-only checks, but notes a non-`main` ref, an
  existing tag, release or draft, a 0.x version or an older version instead of
  failing. It refuses `operation: legacy-channel`.
- `build`, `macos-app`, `enterprise-windows` and `enterprise-macos` run outside
  the `release` environment with every secret blanked. The app is ad-hoc
  signed, and the Setup, pkg and Linux packages are unsigned. Nothing is
  Authenticode-signed, GPG-signed or sent to Apple for notarization.
- `sign` is skipped, because it writes to the public Sigstore log.
  `dry-run-assets` writes an unsigned `checksums.txt` instead.
- `install-gate` runs the full install and upgrade lifecycle on the unsigned
  assets. With no `checksums.txt.bundle`, the installers verify `--local`
  assets against `checksums.txt` only. The upgrade-from-previous lanes run
  only when the latest release is older than the dry-run version.
- `enterprise-upgrade-gate` runs on the unsigned enterprise packages and
  upgrades them from the previous release's signed packages. It runs only when
  the latest release is older than the dry-run version; otherwise each lane
  is a notice.
- `publish` and `legacy-channel` never run. Their release and push steps also
  stop on their own in a dry run.

The assets and `checksums.txt` are the run's `release` artifact, kept for 3
days, and the run summary starts with "dry run: nothing published":

```bash
gh run download <run-id> --repo cisco-ai-defense/defenseclaw -n release -D dry-run-assets
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
  reading the old one. A key a version removes carries
  `x-defenseclaw-removed-in: <version>` in the schema: it is accepted only as
  migration input and rejected in a file of that version or later.
- **A `config_version` bump** is a larger change. The current version is 9
  (`CURRENT_CONFIG_VERSION` in `cli/defenseclaw/config.py`,
  `MaxSupportedConfigVersion` in `internal/config/observability_v8_types.go`;
  the schema accepts 8 and 9). The 8 to 9 migration lives in
  `internal/config/migrate_v9.go`, which `defenseclaw-gateway config migrate`,
  the Python `defenseclaw migrate` and `defenseclaw config migrate` (through the
  gateway binary; `CONFIG_MIGRATIONS` in `cli/defenseclaw/migrations.py` keys
  the step by the old version) and the enterprise lifecycle's `ensure` all
  use. For the next bump add:
  - the migration step and the new version constants above, the schema's
    `config_version` rule, and every place that still expects exactly the old
    version (`git grep -nE '!= 9|== 9' -- cli/defenseclaw internal`);
  - the same migration in the enterprise lifecycle, so an administrator config
    of the previous version still installs: `migrateConfigV9` in
    `internal/enterpriseunix/config.go` (Linux and macOS) and
    `migrateManagedStandaloneConfig` in `internal/cli/config_migrate.go`
    (Windows);
  - the `enterprise-upgrade-gate` assertions
    (`scripts/check_enterprise_upgrade_config.py` checks 8 to 9, and the lane
    scripts install a version 8 config on the previous release).

  `defenseclaw migrate --check` does not validate these steps, so test that a
  migrated file loads in both loaders.
- **Audit database changes** are forward-only migrations the gateway applies
  at startup (`internal/audit/store.go`, and the judge-body and inventory
  stores); never edit or reorder an existing one.
