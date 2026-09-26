# DefenseClaw Release Runbook

A release is one run of the Release workflow. Installed clients upgrade by
running the latest release's installer, so nothing else has to be updated
between versions.

## Cut a release

1. Merge the changes to `main`. CI's **Install and Upgrade Smoke** jobs build
   release-shaped assets from the commit and run the real installer on Linux
   and Windows.
2. Actions → **Release** → Run workflow on `main` with `version: X.Y.Z` (bare,
   no `v`). Or:

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

To try a release on real machines before users see it, run the workflow with
`draft: true`, download the draft's assets (`gh release download X.Y.Z`),
install them with `install.sh --local DIR` or `install.ps1 -Local DIR`, then
publish:

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

A new `config.yaml` key only needs a default in the loaders. Renaming or
removing a key needs one step in `CONFIG_MIGRATIONS`
(`cli/defenseclaw/migrations.py`), a bump of `CURRENT_CONFIG_VERSION`
(`cli/defenseclaw/config.py`) and of `MaxSupportedConfigVersion` in the Go
config package. Audit database changes are forward-only migrations applied by
the gateway at startup.
