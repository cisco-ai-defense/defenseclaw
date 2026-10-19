# Spec 008: Managed path manifest and managed-mode CI gating

Status: Phases 1 to 3 implemented. Phase 0 (ruleset, reviewers team) is open.
Investigated against `origin/main` at `314616938` (2026-10-19).

## Goal

1. Record every managed (enterprise) path in this repository in one checked-in
   manifest.
2. Any pull request that touches a manifest path runs the managed-mode CI.
3. A red managed lane blocks the merge, so OSS work cannot break managed mode.

## Verdict

| Goal | Possible? | How |
| --- | --- | --- |
| Managed CI runs on every PR that touches managed code | **Yes** | `.github/managed-paths.txt` drives `scripts/ci_changes.py` |
| A red managed lane blocks merge | **Yes**, but it needs a ruleset change by a repo admin (D1) | Require the three aggregate checks |

## Non-goal: moving managed code

The code stays where it is. CI selects suites from the changed paths, so a
complete manifest gives the same gating as a dedicated folder. A move is also
not practical:

- **Imports run both ways.** `internal/managed` has 30+ OSS importers, and the
  enterprise packages import OSS `config`, `connector`, `audit` and `guardrail`.
- **Several paths are pinned outside this repository:**
  - the CMID overlay replaces `internal/managed/cloudreg/provider_cisco.go`
    in place;
  - the AVC handoff kit records `packaging/scripts/**` and
    `cmd/defenseclaw-enterprise-setup`;
  - public docs and `release.yaml` reference `packaging/mdm/**`.
- **About 290 enterprise files share package `cli`** with OSS code. They use
  its unexported helpers in both directions.
- **Mixed files would still need listing.** Many shared files carry managed
  branches inside them, so a manifest would be needed even after a move.

## What we found

### The managed surface is large and spread out

| Area | Pure managed | Mixed (shared code with managed branches) |
| --- | --- | --- |
| Go packages | ~700 files / ~193K LOC in `internal/{managed,enterprisebundle,enterprisehooks,enterprisepolicy,enterprisestatus,enterpriseunix,unixidentity,setuppayload,winsession}`, `cmd/{defenseclaw-enterprise-setup,defenseclaw-cmid-broker,windows-avc-assembler,windows-repro-manifest,defenseclaw-scanners}` | n/a |
| Go files inside shared packages | ~395 files / ~150K LOC; `internal/cli` alone has ~290 `enterprise_*`/`windows_enterprise_*`/`managed_*` files | ~140 files with ~430 managed branches; `internal/gateway` and `internal/gateway/connector` hold ~70% |
| Python CLI | Tests only (31 files in `cli/tests`) | ~25 modules: `config_writer.py`, `config.py`, `envvars.py`, `upgrade_shim.py` plus their callers |
| Packaging | `packaging/{mdm,windows,launchd,launchd-standalone,systemd,selinux,linux,macos,scripts,identity}` (~190 files) | `Makefile`, `.goreleaser.yaml`, the config schema |
| Scripts, docs | 17 enterprise scripts in `scripts/`; 21 docs in `docs/`, 35 pages in `docs-site/content/docs/enterprise/` | ~70 other docs-site pages |

The managed files already use consistent name prefixes (`enterprise_*`,
`windows_enterprise_*`, `managed_*`), so the manifest uses directory prefixes
plus a few filename globs.

### CI gaps found

The managed lanes already existed and run on GitHub-hosted runners without
secrets, so they are fork-safe. The gaps were in the wiring:

| # | Gap | Status |
| --- | --- | --- |
| 1 | **No managed check is a required status check.** The live ruleset requires only the 11 `ci.yml` checks and `Contract codex / macos-latest`. The `ci.yml` comment claimed it required `Enterprise Required`. | Open: D1 |
| 2 | Python changes never set `enterprise`, including `uv.lock` and `pyproject.toml`, which the enterprise Setup embeds. | Fixed: manifest |
| 3 | Go-only managed changes skipped the Windows enterprise PowerShell smokes (`windows_python` did not include `go`). | Fixed: manifest |
| 4 | Workflow edits never ran the lanes they change. | Fixed: the managed workflows are in the manifest |
| 5 | Managed `*.md` files never set `enterprise` (the `*.md` rule won first). | Fixed: the manifest applies on top of the first-match rule |
| 6 | `macos-enterprise-packaging` was not in `Enterprise Required`. | Fixed |
| 7 | The public enterprise Setup contracts and the spec-004 `-tags ga` IPC gate ran only on PRs to `windows-avc-machine-installer`. | Fixed: `enterprise-setup-contracts` job in `ci.yml` |
| 8 | No PR job parsed `packaging/**/*.ps1` or any `*.psm1`. | Fixed: `powershell-static` parses `scripts` and `packaging` |
| 9 | `windows-deterministic-build.yml` used native `paths:` filters, so it could not be a required check. | Fixed: `changes` job and `Windows Deterministic Build Required` |
| 10 | The Secure Client invariance check runs by hand outside the repo. | Not done: stop-and-ask item |

Corrections to the first draft of this spec:
- **Install smoke lanes.** `install-smoke` and `install-smoke-windows` are not
  in `Enterprise Required`. They test the per-user installer and are gated on
  `install`, not `enterprise`, so the aggregator would have reported a
  false failure whenever `enterprise` was on and `install` was off.
- **Deterministic-build paths.** That gate builds from a fixture whose eight
  payload files are placeholders, so the real `install-enterprise.ps1` and
  psm1 do not affect it. Its path list is unchanged. It now lives in
  `REPRO_PATHS` in `scripts/ci_changes.py`, and a test keeps it equal to the
  workflow's `push` paths.

## Design

### The manifest: `.github/managed-paths.txt`

The manifest is a plain section-and-lines file, because the `changes` jobs run
the runner's system `python3` with no PyYAML, and Python 3.10 (still
supported) has no `tomllib`. Patterns use the `RULES` syntax of
`scripts/ci_changes.py`: a trailing `/` is a directory prefix; anything else
is an fnmatch glob over the whole path, where `*` also crosses `/`.

| Section | Holds | Effect |
| --- | --- | --- |
| `[managed]` | Code that exists only for managed mode, the managed tests and this manifest | Sets `managed` |
| `[managed_impacting]` | Shared files with managed branches, the inputs the enterprise packages embed (`uv.lock`, `pyproject.toml`, `.goreleaser.yaml`) and the workflows that define the managed lanes | Sets `managed` |
| `[excluded]` | Paths that look managed but do not change managed behavior (docs, `enterprise-data.yaml` rule packs) | Only silences the drift check |

### Classifier: `scripts/ci_changes.py`

- **Manifest match.** A changed path that matches `[managed]` or
  `[managed_impacting]` sets the `managed` flag. This is in addition to the
  path's first-match rule. The hard-coded enterprise rule this replaces is
  removed.
- **Lanes turned on.** `managed` forces on `enterprise` (`Enterprise
  Required`), `windows_go`, `windows_python` and `pwsh` (`Windows Native
  Required`).
- **Bad manifest.** A missing or malformed manifest raises and the classifier
  runs everything, so it fails safe.
- **Deterministic build.** The `repro` output gates
  `windows-deterministic-build.yml`. It is true for every event other than
  `pull_request` and for any PR touching `REPRO_PATHS`.

### Drift check: `scripts/check_managed_paths.py` (`make check-managed-paths`, part of `make check`)

The check fails when:
- a manifest pattern matches no tracked file;
- a tracked path that looks managed (`enterprise`, `managed`,
  `secure_client`, `standalone`, `mdm`, `cmid`) is in no section;
- a path is in `[excluded]` and also in a managed section.

It cannot see a new managed branch inside a shared file. Reviewers apply
`M-TST-12` in the develop skill for that.

### Aggregates

| Check | Workflow | Accepts a skip only when |
| --- | --- | --- |
| `Enterprise Required` | `ci.yml` | `enterprise == false` |
| `Windows Native Required` | `windows-native.yml` | the Windows outputs are false |
| `Windows Deterministic Build Required` | `windows-deterministic-build.yml` | `repro == false` |

`windows-enterprise-setup.yml` stays for pull requests to the
`windows-avc-machine-installer` branch. `cmd/defenseclaw-enterprise-setup`'s
build contract test pins both copies of the Setup checks.

## Runner cost

The classifier was replayed over the 59 most recent merged PRs to `main`
whose full file list `gh` returns (21 PRs with 100 or more files were left
out; most of them run everything anyway):

| Output | PRs before | PRs after |
| --- | --- | --- |
| `enterprise` | 45 | 48 |
| `windows_go` | 45 | 48 |
| `windows_python` | 38 | 43 |
| `pwsh` | 53 | 53 |
| `repro` (deterministic build) | path filter | 3 |

Go changes already ran the enterprise lanes, so the manifest adds little
runner time. Most of it is the Windows Python shards on Go-only managed PRs.

## Phase 0: open decisions (maintainers and a repo admin)

- **D1.** Require `Enterprise Required`, `Windows Native Required` and
  `Windows Deterministic Build Required` on `main`, and add them to
  `REQUIRED_CHECKS` in `cli/tests/test_ci_changes.py` in the same change.
  **Until then a red managed lane still does not block a merge.**
  - Before turning `Enterprise Required` on, fix its current failure on
    `main`: at `314616938`, `TestManagedHookFailModeIsTheRenderedValue` fails
    in Unix Standalone Lifecycle on Ubuntu and macOS.
- **D2.** Create a managed reviewers team (or name an existing one). A
  CODEOWNERS block generated from the manifest then routes managed paths to
  it. Not built until the team exists.
- **D3.** Decide whether to bring the Secure Client invariance check into the
  repo, keyed on a new manifest section. This is on the stop-and-ask list.
