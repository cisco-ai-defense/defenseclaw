# Native Windows Installer Architecture

## Existing release inputs

The installer composes the established release outputs instead of creating a
parallel DefenseClaw distribution:

- GoReleaser produces `defenseclaw_<version>_windows_amd64.zip` with the native
  `defenseclaw.exe` gateway and `defenseclaw-hook.exe` hook entry point.
- The Python CLI/TUI is `defenseclaw-<version>-py3-none-any.whl`.
- `upgrade-manifest.json`, `checksums.txt`, signatures, SBOMs, and provenance are
  produced by the existing atomic release pipeline.
- `scripts/install.ps1` remains the legacy release-asset installer. Its
  per-user state, connector, repair, rollback, and lifecycle behavior is the
  compatibility reference for native setup.
- `scripts/windows-native-ci.ps1` remains the native Windows package and
  lifecycle acceptance harness. Setup acceptance extends that harness instead
  of cloning the whole suite.

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
- CPython 3.12.10 embeddable x64, pinned by URL and SHA-256
  `4acbed6dd1c744b0376e3b1cf57ce906f9dc9e95e68824584c8099a63025a3c3`;
- cosign 2.6.2 for offline availability of release-manifest verification,
  pinned to the official Windows x64 release SHA-256
  `dd6c61e510da627bcaed4cd9db844ec11cacd09826d814d89f7f68d40feb07be`;
- the locked installed Python dependency tree;
- the signed release `upgrade-manifest.json`; and
- the native managed-command launcher.

An internal manifest hashes every embedded file with SHA-256. Setup validates
that manifest before staging, bounds ZIP entry count and expanded size, rejects
absolute/traversal paths and reparse points, and publishes from a same-volume
staging directory. The manifest, external provenance record, and installed
state also carry the exact 40-character Git source commit and distribution
flavor, so an installer cannot silently lose its build identity between the
release inputs and the installed product.

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
Apps. Release builds require real Authenticode credentials. Before the payload
manifest is hashed, the builder signs the native CLI launcher, console-free
startup helper, gateway, and hook entry point; the installed scanner launchers
are byte-identical copies of that signed CLI launcher. It then signs the outer
setup executable. The build imports
the PFX temporarily into the current-user certificate store, invokes SignTool
by certificate thumbprint, uses an allowlisted HTTPS timestamp endpoint,
verifies the exact publisher `Cisco Systems, Inc.` on every signed executable,
and removes the certificate and private build directory in a `finally` path. No
development certificate or fabricated Cisco signature is generated.

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

The release workflow builds setup on `windows-latest`, requires real signing
credentials, emits SHA-256, SBOM, and provenance outputs, and adds the signed
EXE to the final checksum manifest before the immutable release is created.
Running the full native install/repair/connector/uninstall acceptance suite
against that exact signed EXE (including installed-publisher validation) remains
a required certification follow-up; it is not yet an active release-workflow
gate.
macOS and Linux artifacts continue through their existing build path.

Pull-request CI builds an unsigned setup and runs setup acceptance only on the
disposable GitHub Actions user. Local setup acceptance refuses to mutate the
current user unless an explicit override is supplied. A release artifact is
not certified until it is rebuilt from the final integrated source head and
passes clean-user native Windows acceptance; an artifact built from an earlier
integration base is evidence only.
