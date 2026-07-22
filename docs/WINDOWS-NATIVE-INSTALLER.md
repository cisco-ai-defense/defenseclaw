# Native Windows Installer Architecture

> **Implementation reference:** This file documents installer architecture and
> release engineering. End users should follow the
> [Native Windows guide](https://cisco-ai-defense.github.io/defenseclaw/docs/get-started/windows/)
> for the certified support matrix, installation lifecycle, connector scope,
> security boundaries, and troubleshooting. The guide is authoritative for
> user-facing support classifications.

## Existing release inputs

The installer composes the established release outputs instead of creating a
parallel DefenseClaw distribution:

- GoReleaser produces `defenseclaw_<version>_windows_amd64.zip` with the native
  `defenseclaw.exe` gateway and `defenseclaw-hook.exe` hook entry point.
- The Python CLI/TUI is `defenseclaw-<version>-py3-none-any.whl`.
- `upgrade-manifest.json`, `checksums.txt`, signatures, SBOMs, and provenance are
  produced by the existing atomic release pipeline.
- `scripts/install.ps1` is a compatibility bootstrap only. On Windows it
  authenticates the signed release checksum manifest and offline Sigstore
  proof, verifies the schema-1 provenance binding for the exact Setup SHA-256
  and Cisco Authenticode publisher, and delegates to
  `DefenseClawSetup-x64.exe`. It never resolves or installs Python, `uv`,
  wheels, or individual gateway artifacts.
- `scripts/windows-native-ci.ps1` remains the native Windows package and
  lifecycle acceptance harness. Required lifecycle and connector contracts
  install the exact native Setup artifact; a separate no-network test proves
  local bootstrap delegation and legacy argument mapping.

## Delivery decision

`DefenseClawSetup-x64.exe` is a native Go `windowsgui` executable. Its Win32
wizard and silent command-line surface are two modes of the same executable.
The executable embeds every install payload and does not download at install
time.

The installed product is intentionally mixed-runtime:

- `bin\defenseclaw.exe` and the scanner launchers are small native Go launchers.
- `bin\defenseclaw-gateway.exe` and `bin\defenseclaw-hook.exe` remain the
  existing native Go programs.
- `bin\defenseclaw-startup.exe` is a console-free native logon helper. It
  launches the adjacent gateway hidden and pins its data home to the current
  Windows user's `.defenseclaw` directory instead of trusting inherited
  process environment.
- The existing Python CLI/TUI runs from an embedded, managed CPython runtime
  under `runtime\python`. The installer does not claim to turn the CLI/TUI into
  a native GUI application.

WiX/Burn was evaluated. A custom native setup is smaller for the current
per-user-only product because it reuses the repository's existing Go process
identity checks, Python package, and upgrade transaction without privileged MSI
custom actions. The tradeoff is explicit: this implementation does not produce
an MSI or support `INSTALLSCOPE=machine`. A future enterprise MSI must consume
the same versioned payload and state contract; it must not add a second product
layout or compete with the self-updater.

## Offline payload and provenance

`scripts/build-windows-installer.ps1` accepts only exact, version-matched input
names. It also verifies wheel metadata and required gateway archive members.
It builds `site-packages.zip` from `uv.lock` with hash enforcement and
binary-only Windows wheels. The sole source-build exception is the locked,
pure-Python `win-unicode-console==0.5`, which publishes no wheel; all other
packages remain wheel-only. Its source ZIP is pinned to SHA-256
`d4142d4d56d46f449d6f00536a73625a871cba040f0bc1a2e305a04578f07d1e`.
Its verified package directory and metadata are copied directly without
dependency resolution; the legacy archive's `setup.py` is never executed. The
builder then embeds:

- the GoReleaser Windows archive;
- the DefenseClaw wheel used for provenance;
- CPython 3.13.14 embeddable x64, pinned by URL and SHA-256
  `90b4e5b9898b72d744650524bff92377c367f44bd5fbd09e3148656c080ad907`;
- cosign 2.6.2 for offline availability of release-manifest verification,
  pinned to the official Windows x64 release SHA-256
  `dd6c61e510da627bcaed4cd9db844ec11cacd09826d814d89f7f68d40feb07be`;
- the locked installed Python dependency tree;
- the signed release `upgrade-manifest.json`; and
- the native managed-command launcher.

The release also publishes `checksums.txt.bundle` beside the detached
signature and certificate. The compatibility bootstrap passes that bundled
transparency-log proof to pinned Cosign with `--offline`. The authenticated
checksum root must contain exactly one entry each for Setup, its provenance,
and the upgrade manifest. The provenance must describe an internally consistent
signed schema-1 OSS artifact and repeat Setup's exact authenticated SHA-256.
Local mode requires
the complete release bundle plus the pinned Cosign executable and performs no
network access.

An internal manifest hashes every embedded file with SHA-256. Setup validates
that manifest before staging, bounds ZIP entry count and expanded size, rejects
absolute/traversal paths and reparse points, and publishes from a same-volume
staging directory. The manifest, external provenance record, and installed
state also carry the exact 40-character Git source commit and distribution
flavor, so an installer cannot silently lose its build identity between the
release inputs and the installed product.

Every generated ZIP is ordered by its UTF-8 archive path and uses the source
commit timestamp, normalized permissions, and a fixed compression level. The
builder creates each archive twice and requires byte-for-byte equality. Native
Go launchers and Setup use `-trimpath`, disable ambient VCS stamping, pin a
component- and commit-specific Go build ID, and are also built twice before
signing. The unsigned provenance
timestamp is the source commit timestamp, so local unsigned outputs do not gain
a wall-clock difference. Before archiving Python, the builder removes optional
bytecode caches, local `file://` installation origins, and uv's wall-clock cache
metadata, then repairs the affected wheel `RECORD` files. Release CI pins Go
through `go.mod`, pins `uv`, and executes ZIP generation with the pinned
embedded CPython runtime.

The Setup SBOM is one merged SPDX 2.3 JSON document generated after the
Authenticode decision. It describes the exact outer checksum and exact embedded payload
archive, records every payload digest, and expands the CPython standard
library, complete `site-packages.zip`, project and YARA compatibility wheels,
and gateway archive. Python distribution metadata, dependencies,
licenses, and every embedded file are included alongside the gateway, hook,
launchers, and pinned Cosign verifier. Go build information is read from the
exact Setup, gateway, hook, launchers, and Cosign bytes; their runtime
and transitive modules are emitted with purls and Go module sums. Generation
fails closed if the staged payload differs from its manifest, an expected
component is absent, a Python distribution lacks metadata, a Go binary digest
does not match its component, or any relationship/digest is missing from the
SPDX inventory.

The public Windows build is explicitly the `oss` distribution flavor. Passing
`-DistributionFlavor managed-enterprise` fails before artifact processing or
dependency downloads. A managed-enterprise Windows artifact requires a private
CMID provider overlay, a pinned private module version, and authorized private
dependency credentials. The repository currently implements that overlay
contract only for the macOS bundle pipeline; compiling the public
`provider_cisco.go` stub with the `cmid` tag would still fail closed and is not
treated as a managed release. An OSS Windows install configured as
`managed_enterprise` therefore fails closed when managed cloud credentials are
requested instead of silently degrading to an unusable provider.

Local and pull-request builds are unsigned and are labeled as such in Installed
Apps. Release signing follows the same all-or-none policy as macOS credentials:
when any Authenticode secret is absent the workflow fails, when exactly one is
present the release fails, and when both are present signing is mandatory and any
certificate, password, SignTool,
timestamp, or publisher failure aborts instead of falling back to unsigned.
For the signed path, before the payload manifest is hashed, the builder signs
the native CLI launcher, console-free startup helper, gateway, and hook entry
point; the installed scanner launchers are byte-identical copies of that signed
CLI launcher. It then signs the outer setup executable. The build imports the
PFX temporarily into the current-user certificate store, invokes SignTool by
certificate thumbprint, uses an allowlisted HTTPS timestamp endpoint, verifies
the exact publisher `Cisco Systems, Inc.` on every signed executable, and
removes the certificate and private build directory in a `finally` path. No
development certificate or fabricated Cisco signature is generated.

### Native executable resources

Every project-built Windows executable is resource-complete before signing:
the gateway, agent hook, CLI/scanner launcher, logon startup helper, and setup
bootstrapper. Their PE resource directories contain the project-owned
DefenseClaw shield icon, an exact `Cisco Systems, Inc.` / `Cisco DefenseClaw`
`VERSIONINFO` record for the release version, and a component-specific
application manifest. The manifest declares an `amd64` assembly identity,
`asInvoker` with `uiAccess=false`, Windows 10/11 compatibility, Per-Monitor-v2
DPI awareness with a Per-Monitor fallback, and `longPathAware=true`. Setup also
activates Common Controls v6 because its Win32 wizard uses those controls.

The installed `skill-scanner.exe`, `mcp-scanner.exe`, and
`defenseclaw-observability.exe` commands are byte-identical aliases of the
generic signed command launcher and therefore carry the same resource set.
Bundled CPython and cosign are upstream-built dependencies and retain their
upstream PE identity rather than being relabeled as Cisco-built executables.

`internal/windowsresources` constructs resources without timestamps, replaces
the complete PE resource directory, recomputes the PE checksum, and parses the
result back before the artifact can reach signing. Verification requires an
exact byte match for the manifest, all five icon sizes, and version data; it
also rejects a non-amd64 PE or any attempt to patch an already signed file.
GoReleaser applies the same contract to the standalone Windows ZIP, so the
archive and native setup do not diverge.

The builder also inventories every PE that Setup installs, including native
Python extensions and the explicitly unsigned pinned Cosign binary. The
schema-2 payload manifest and external provenance bind each installed path to
its exact SHA-256, expected trust policy, observed signer/certificate/timestamp
evidence, and SPDX file identity. The merged SBOM carries the same canonical
evidence on the corresponding file records and fails if any evidence digest or
file identity does not match.

## Install and maintenance layout

Setup resolves Windows Known Folders rather than trusting profile environment
variables:

- application: `FOLDERID_UserProgramFiles\DefenseClaw` (normally
  `%LOCALAPPDATA%\Programs\DefenseClaw`, including Known Folder redirection);
- maintenance setup cache:
  `%LOCALAPPDATA%\DefenseClaw\InstallerCache\DefenseClawSetup-x64.exe`;
- durable setup transaction state:
  `%LOCALAPPDATA%\DefenseClaw\InstallerState`;
- crash-cleaned payload extraction:
  `%LOCALAPPDATA%\DefenseClaw\InstallerTemp`;
- operator state: `%USERPROFILE%\.defenseclaw`.

The application tree is transactionally replaced. The maintenance cache is a
separate transaction so repair and uninstall never execute from the tree they
must replace. Installed Apps points to that cache. Uninstall removes the cache,
registration, and only a PATH entry originally added by setup. User data is
preserved unless `DELETEUSERDATA=1` is explicit.

Setup does not create a Start-menu batch wrapper. DefenseClaw is a command and
TUI product; the wizard's finish page can open a terminal after updating the
current process PATH. Avoiding a generated command script also removes an
unnecessary quoting and command-injection boundary.

## Lifecycle and rollback

Setup serializes install, repair, upgrade, and uninstall with a per-user global
Windows mutex. A concurrent invocation exits with code 1618 before reading or
mutating product state, including when the same user has sessions on multiple
desktops.

Immediately before an install or uninstall mutation, setup recovers any prior
interrupted transaction while it still owns that mutex. A private, current-user
owned Windows-DACL journal advances atomically and with write-through ordering
through `intent`, `committed`, `converged`, and `complete`. The journal contains
a random operation identity; every destructive application/cache path is
derived from Windows Known Folders. It also records the explicitly selected
Codex and Claude configuration homes and the observed user PATH. Recovery
rejects an altered destructive path, an unrelated install-state identity, an
untrusted journal ACL, or a reparse point in a transaction-owned root. Agent
configuration symlinks remain supported by the connector's target-aware writer.
A durable `complete` tombstone is atomically replaced by the next operation;
markers are not unlinked in an order that could resurrect a stale intent after
power loss.

Before `committed`, setup mutates only transaction-owned application and
maintenance-cache paths and may stop owned services. An interrupted install can
therefore restore the exact old trees and services without overwriting a PATH,
Run-key, or Apps-registration edit made by another process. An interrupted
uninstall restores its exact transaction-ID-bearing trash tree. Setup never
treats a state-less directory at the fixed install path as transaction-owned.

The forward-commit boundary is crossed before packaged migrations, connector
configuration, PATH, Apps registration, gateway auto-start, or hook teardown.
Those changes are replayed idempotently toward the requested target after a
crash; old binaries are never restored against already-migrated configuration.
The journal records the source/target versions and effective `CODEX_HOME` and
`CLAUDE_CONFIG_DIR`, and convergence reruns migrations/configuration, validates
the installed and maintenance executables, requires atomic durable connector
writes, flushes mutated Registry keys, and verifies selected services before
advancing to `converged`. Backup,
trash, user-data, and installer-cache cleanup happens only afterwards. When an
uninstaller is running from its own cache, it leaves the `converged` tombstone
until a later setup verifies that asynchronous self-deletion succeeded. Unsafe
or incomplete recovery keeps the journal and returns 1603 for a bounded retry.

Before mutation, setup validates gateway and watchdog PID records against the
live executable path and process creation identity. It asks the gateway through
its authenticated loopback API to drain and close audit, telemetry, stores, and
sidecars, and signals the watchdog through its user-private named event. It
waits on the exact process handles and uses bounded force termination only as a
legacy/unhealthy fallback. Stop and status never report success while either
owned process remains live. The transaction-owned whole-tree rename is the
authoritative file-lock check; a sharing violation returns fatal-install code
1603 and rolls back without publishing a partial tree.

The new tree is validated with both CLI and gateway version commands. Repair
and upgrade preserve connector/mode state, then idempotently reconcile the
recorded connector so interrupted or drifted setup can converge without adding
duplicate registrations. A fresh explicit connector selection initializes the
chosen integration during the same committed transaction.

Before the private staging tree can be published, Setup requires an exact
one-to-one match between its Authenticode inventory and every extracted PE,
checks each file digest, and enforces the recorded Windows trust policy. Signed
DefenseClaw executables must retain the Cisco publisher, signer identity, and
RFC 3161 timestamp; release validation rejects unsigned Setup artifacts before
publication. Local and pull-request unsigned builds remain labeled as unsigned
and are not sealed for release. Setup repeats inventory verification after
publication and verifies the maintenance and stable-hook copies so extraction or
copy-time tampering cannot silently cross the install boundary.

On upgrade, the CLI uses the installer-owned cosign binary (never an
environment-selected verifier) to verify the signed checksums and the upgrade
manifest covered by them. It then requires the exact Authenticode publisher,
creates the normal state backup, and copies setup to the trusted maintenance
cache. Setup waits for the calling Python process to exit before replacing
files. The new embedded runtime applies the packaged release migrations and
checks every required migration in the trusted manifest before owned services
restart. Downgrades are rejected by both the CLI and setup.

Machine-scope state and the HKLM policy
`SOFTWARE\Policies\Cisco\DefenseClaw\DisableSelfUpdate=1` disable self-update.
Those installations must be serviced by the enterprise deployment channel.

## Release and certification gate

Starting with 0.8.6, the release workflow builds Setup on `windows-latest` and
runs the full native install/repair/connector/uninstall acceptance suite against
the exact EXE. The Authenticode branch is selected before the build and bound to
the resulting provenance. With complete credentials, the workflow passes the
immutable staging artifact to a separate non-advisory real-client job. That job
verifies the Cisco signature plus installer sidecar/provenance digests, requires
provenance and installed payload state to match the exact workflow `GITHUB_SHA`,
and installs that same EXE. The signed gate installs exact official
Codex CLI `0.144.3` and Claude Code `2.1.208` packages, requires both provider credentials,
verifies automatic Codex hook trust without a manual
`/hooks` approval, and
requires lifecycle, tool allow/block, gateway JSONL, SQLite audit correlation,
and connector-tagged OTLP evidence from both clients. It then runs repair and
same-version upgrade with the same Setup bytes and requires uninstall itself to
remove both connectors, user data, Installed Apps, and the user PATH entry while
preserving a seeded unrelated `~/.codex/hooks.json` handler byte-for-byte.

Missing signing credentials, partial signing credentials, invalid signing
material, a bad publisher or timestamp, and any signed-branch certification
failure abort before publication. The workflow emits SHA-256, merged SPDX SBOM,
provenance, and `DefenseClawSetup-x64.exe.certification.json`, then adds every
artifact to the final checksum manifest before the immutable release is created.
macOS and Linux artifacts continue through their existing build path.

The Windows chain transfers each intermediate by immutable GitHub Actions
artifact ID and digest; assembly rejects a missing or malformed custody artifact
digest before processing its exact-ID download. The signed path emits exactly
five release assets:
`DefenseClawSetup-x64.exe`, its `.sha256`, `.provenance.json`, `.sbom.json`, and
`.certification.json` sidecars. Assembly consumes that directory explicitly via
`--windows-dir`, seals all five bytes into the candidate, and signs
`checksums.txt` with an offline-verifiable `checksums.txt.bundle` under the
exact `release.yaml@refs/heads/main` Sigstore identity. The protected
`publish-release` job is the only job granted `contents: write`.

The sealed Setup must pass the standard-user `windows-fresh-install` gate.
The separate historical Windows upgrade matrix remains skipped for 0.8.6
because 0.8.5 did not publish a native Setup baseline; the fresh gate still
exercises install, repair, same-version servicing, and uninstall. Both publish
selection and post-publish custody verification retain
`--omit-windows-binaries` to exclude legacy raw Windows archives only. They do
not exclude Setup or its four custody sidecars. Unsigned Setup builds are limited
to local and pull-request validation. The authenticated PowerShell bootstrap and
automatic upgrade path deliberately continue to reject unsigned Setup targets
rather than silently weakening an existing installation's trust policy.

Pull-request CI builds an unsigned setup and runs setup acceptance only on the
disposable GitHub Actions user. Local setup acceptance refuses to mutate the
current user unless an explicit override is supplied. A release artifact is
not certified until it is rebuilt from the final integrated source head and
passes clean-user native Windows acceptance; an artifact built from an earlier
integration base is evidence only.
