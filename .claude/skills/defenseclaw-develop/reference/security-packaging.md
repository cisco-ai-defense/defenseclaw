# Security, packaging, upgrade path, dead code and PR hygiene

Open this when: your change touches secrets, file permissions, fail-closed behavior, dependencies, licensing, release or package formats, the upgrade path, removes or keeps legacy code, or you are about to open a PR.

## Requirements: security

IDs live only in `reference/checklist.md`. These rows add detail and carry no IDs.

| Rule | Why | How to check | Evidence |
|---|---|---|---|
| Hooks and guardrail paths fail closed by default. Fail mode comes from installed policy; the agent environment cannot change it. Authenticated Secure Client legacy delivery is unchanged. A new failure mode resolves through the effective fail mode. | A path that silently opens is a policy bypass. | `go test ./internal/gateway/... -run FailMode` | `docs-site/content/docs/reference/fail-modes.mdx`, `internal/envvars/registry.json` |
| Secrets are held by reference (env var name, credential name) and stored in the owner-private key file (mode 0600, owner DACL on Windows) via the keys registry. | Config, logs and backups must not carry keys. | `pytest cli/tests/test_secure_write_permissions.py` | `internal/safefile`, `docs-site/content/docs/reference/keys.mdx` |
| Privileged code never follows a user-controlled path: use no-follow, regular-file, size-bounded readers and bounded home roots. | A symlink or junction in a home directory becomes a privileged read or write. | `go test ./internal/enterprisehooks -run 'Home\|Bounded'` | `internal/enterprisehooks/home_bounded_unix.go` |
| Identity comes from the kernel or OS, never from headers, payloads or env. | See `reference/identity-policy.md`. | `go test ./internal/gateway -run GuardrailProfile` | `internal/gateway/guardrail_profile.go` |
| Pin GitHub Actions by commit SHA with a version comment, set `persist-credentials: false`, keep workflow permissions read-only at workflow scope, and keep PR-controlled code away from elevated tokens. `actionlint` must pass. | Write-scoped tokens reachable from PR-controlled code let a pull request exfiltrate secrets or publish content. | the Workflow Lint job | `.github/workflows/ci.yml`, `.github/workflows/docs-site.yml`, `.github/actionlint.yaml` |
| Fix dependency advisories by raising the version floor in `pyproject.toml` (dependencies and uv overrides) or `package.json`, never by adding ignores to the audit steps. | The audit jobs fail on advisories. | `uv run pip-audit --vulnerability-service osv`; `npm audit --omit=dev --audit-level=high` in `extensions/defenseclaw` | `pyproject.toml`, `uv.lock`, `extensions/defenseclaw/package-lock.json` |
| Report vulnerabilities through private vulnerability reporting, never public issues. PR text carries no secrets or customer data. | Disclosure before a fix harms users. | read the PR body | `SECURITY.md` |
| New source files carry the repository's Apache-2.0 header with the SPDX line. | Reviewers ask; the macOS app has a header gate. | `make macos-app-license-check`; `head -5` on new files | `scripts/macos_license_headers.py`, `internal/gateway/api.go` |
| When adding a Go module, vendored source or notable dependency, add its license text to `THIRD_PARTY_LICENSES.txt` and keep `NOTICE` current. Never add a `toolchain` directive to `go.mod`. | The file is a scoped attribution artifact; the toolchain pin is out of band. | `make go-mod-no-toolchain` | `THIRD_PARTY_LICENSES.txt`, `NOTICE`, `scripts/check-go-mod-no-toolchain.sh` |

## Requirements: packaging and upgrade path

IDs live only in `reference/checklist.md`. These rows add detail and carry no IDs.

| Rule | Why | How to check | Evidence |
|---|---|---|---|
| Change versions only with `make set-version VERSION=X.Y.Z`. Do not hand-bump version sources. | `make check-version-sync` fails if any source disagrees. | `make check-version-sync` | `Makefile`, `scripts/stamp-version.sh` |
| Publish releases only through the Release workflow on a reviewed main commit. Changes to `release.yaml` need a dry run. | Packages are signed and gated there; a mistake affects every operator. | dry-run dispatch | `.github/workflows/release.yaml`, `docs/RELEASE_RUNBOOK.md` |
| Do not break the upgrade path: `defenseclaw upgrade` runs the latest installer, builds beside the running install, keeps the previous install, runs `defenseclaw migrate` and rolls back on failure. Keep the 0.8.x handoff working. | The install-lifecycle scenarios gate the release. | `scripts/test-install-lifecycle.sh` with `fresh upgrade-previous upgrade-0.8.10 handoff drills` | `docs-site/content/docs/get-started/upgrade.mdx`, `scripts/defenseclaw-upgrade.sh`, `scripts/install.sh`, `cli/defenseclaw/migrations.py` |
| A packaging change (deb, rpm, pkg, Setup, launchd or systemd units) is exercised by the enterprise install and upgrade jobs, and the upgrade must keep the administrator's config intent. | Packages install services as root. | the CI enterprise install and upgrade jobs (`Enterprise Required`) | `.goreleaser.yaml`, `packaging/linux`, `packaging/windows`, `packaging/macos` |
| Keep cross-shell parity: edits to `packaging/scripts/lib/repro-flags.*` and `assemble.*` are mirrored in both shells. | Byte-identical Windows builds depend on it. | `make lint` | `scripts/check-repro-flags-parity.sh`, `scripts/check-assemble-parity.sh` |
| Source-checkout installs are for development only. Do not run `make all` or direct install targets on a host with a managed install, or from a sudo-owned checkout. | They activate the checkout and are not an operator upgrade path. | read `Makefile` preflight | `Makefile` (`_source-install-preflight`), `scripts/refuse-sudo-user-checkout.sh` |
| Every installed file and binary is added to each packaging channel (see `reference/deployment-modes.md`, M-DEP-7 in `reference/checklist.md`). | One channel missing a file fails on that OS. | `make packaging-linux-enterprise`, `make lint` | `Makefile` (`_bundle-data`) |
| State in the PR body how long any retained compatibility shim is needed and which upgrade it serves. | Shims without an end date never leave. | read the PR body | `.github/pull_request_template.md` |

## Requirements: dead and legacy code

IDs live only in `reference/checklist.md`. These rows add detail and carry no IDs.

| Rule | Why | How to check | Evidence |
|---|---|---|---|
| Every change removes the dead and legacy code it touches or finds: unreachable code, unused keys and env vars, stale shims, retired-feature paths. Keep only code that serves a supported upgrade path, and give the reason in the PR body. | Stale paths are where silent fallbacks hide. | grep the touched names across `cli/`, `internal/`, `docs-site/`, `scripts/`, `packaging/` | `internal/legacyconnector/legacyconnector.go`, `internal/config/legacy_connector.go` |
| Retired connector names appear only in the legacy migration modules, `CHANGELOG.md`, the upgrade guide and the manual test plan; build them from fragments in tests. | A scan test fails on any other use. | `pytest cli/tests/test_retired_connector_names.py` | `cli/tests/test_retired_connector_names.py` |

## Requirements: pull request hygiene

IDs live only in `reference/checklist.md`. These rows add detail and carry no IDs.

| Rule | Why | How to check | Evidence |
|---|---|---|---|
| Fill every section of the PR template: Problem, Current Situation, Solution, Architecture Diagram (or N/A), What Changed, Breaking Changes, Open Issues, Test Plan with exact commands and observed results. | The template makes this a hard rule. | compare headings | `.github/pull_request_template.md` |
| Every follow-up in the PR body links a real GitHub issue; write None if there are none. | No action item without an issue. | read Open Issues | `CONTRIBUTING.md` |
| Stage explicit paths. Do not commit credentials, customer data, build outputs, local runtime state or scratch files from the repository root. | `git add -A` picks up stray files. | `git status --short` before staging | `CONTRIBUTING.md` |
| Add the skill-maintenance line to the PR checklist (see `reference/maintenance.md`). | Keeps this guidance current. | read the PR body | `reference/maintenance.md` |
| Keep PRs focused; split unrelated changes. State which reference files in this skill apply. | Reviewers check by area. | n/a | `CONTRIBUTING.md` |
| Include an architecture diagram when behavior spans components. | Easier review. | n/a | `.github/pull_request_template.md` |

## Where it lives

`SECURITY.md`, `CONTRIBUTING.md`, `.github/`, `.goreleaser.yaml`, `packaging/`, `scripts/install.sh`, `scripts/install.ps1`, `scripts/defenseclaw-upgrade.sh`, `internal/safefile/`, `THIRD_PARTY_LICENSES.txt`.

## How to verify

`make lint check`, the install-lifecycle scenarios for upgrade work, the audit commands in the security rows above, and a read of the PR body against the template.

## Common mistakes

- Removing a bridge for 0.8.x before the supported upgrade window ends.
- Silencing an audit finding instead of raising the floor.
- Adding a toolchain directive to `go.mod`.
- Leaving a dead key because "it is harmless".
- Hand-bumping a version string in one file.
- Publishing assets by hand.
