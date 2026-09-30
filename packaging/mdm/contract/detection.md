# Detecting the standalone deployment

MDMs ask two different questions. Use the mechanism that fits each.

1. **Is the version I assigned installed?** Installation and supersedence
   rules need a cheap, stable answer. Use the registry marker (Windows), the
   package database (Linux) or the pkg receipt (macOS).
2. **Is it healthy and enforcing?** Compliance and Remediations need the
   lifecycle's own verdict. Use `detect.ps1 -RequireHealthy` /
   `detect.sh --require-healthy`, or the `verify` action.

The markers only answer inventory questions. The Windows marker is written
only after a successful lifecycle run. The Linux package database records the
package even when its post-install `ensure` failed, so use `detect.sh` or
`verify` for the real state. Ordinary users cannot write any of them. Only
`verify` proves that the services, protected files, hooks and
machine-policy entries are intact.

## Windows

| Mechanism | Value |
| --- | --- |
| Registry marker (64-bit view) | `HKLM\SOFTWARE\Cisco\DefenseClaw\Enterprise`, written after every successful install, upgrade, repair or ensure; removed after a successful uninstall. Values: `ProductVersion` (string, e.g. `1.4.0`), `Profile` (`standalone`), `InstallRoot` (`C:\Program Files\Cisco\DefenseClaw`), `StateRoot` (`C:\ProgramData\Cisco\DefenseClaw`), `TrustMode` (`authenticode` or `hash_pinned`), `UpdatedAt` (RFC 3339 UTC), `DisableSelfUpdate` (DWORD). |
| Add/Remove Programs | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\CiscoDefenseClawEnterprise`: `DisplayName` "Cisco DefenseClaw Enterprise", `DisplayVersion`, `Publisher`, `UninstallString`, `QuietUninstallString`. |
| Intune registry rule | Key `HKEY_LOCAL_MACHINE\SOFTWARE\Cisco\DefenseClaw\Enterprise`, value `ProductVersion`, **Version comparison**, *Greater than or equal to* the app version, *Associated with a 32-bit app on 64-bit clients*: **No**. |
| Script | `windows/detect.ps1 [-MinimumVersion X.Y.Z] [-RequireHealthy]`. Detected means exit 0 with a line on STDOUT (`DefenseClaw Enterprise <version>`) and nothing on STDERR, which are Intune's custom-detection semantics. Not detected means exit 1 with the reason on STDERR. Works in 32-bit Windows PowerShell 5.1. MDMs that run detection scripts without arguments need `-MinimumVersion` set as the parameter's default in their copy. |
| Health | `detect.ps1 -RequireHealthy`, or the installed CLI's `enterprise windows verify --profile standalone --json` exits 0. |
| Event log | `DefenseClaw` log, source "DefenseClaw Lifecycle", which only SYSTEM and Administrators can write: 100 installed, 101 upgraded, 102 repaired, 110 uninstalled (Application log only: uninstall unregisters the `DefenseClaw` log), 111 ensure no-op, 112 ensure applied, 120 unhealthy, 130 failed, 140 busy, 150 refused. A legacy copy of each event goes to the Application log, source "DefenseClaw Enterprise", which any account can write; do not detect from it. |
| Lifecycle log | `%WINDIR%\Logs\DefenseClaw\enterprise-lifecycle.log` (one JSON result per line, 5 × 5 MiB generations) and `last-result.json`. The wrappers append to `mdm-wrapper.log` in the same folder. Users can read these logs; only SYSTEM and Administrators can write them. |

The marker records the installed version, not the config. An MDM that detects
by version does not re-run the deployment for a config-only change; see the
Intune guide (`intune/windows.md`) for a detection script that also checks
the installed config's SHA-256.

## Linux

| Mechanism | Value |
| --- | --- |
| Package database | `dpkg-query -W -f='${Status} ${Version}' defenseclaw-enterprise` or `rpm -q defenseclaw-enterprise`. This works only for the deb/rpm channel. |
| Script | `linux/detect.sh [--min-version X.Y.Z] [--require-healthy] [--format exit\|value\|jamf]`. It asks the installed gateway (`/opt/defenseclaw/bin/defenseclaw-gateway`, which must be root-owned) for `enterprise linux status --json`, so it also covers the payload channel. Run it as root; otherwise it reports `not-installed`. |
| Health | `detect.sh --require-healthy`, or `defenseclaw-enterprise.sh --action verify` exits 0. |
| Last package result | `/var/lib/defenseclaw-enterprise/last-package-result.json`: the result of the package's own `ensure --from-package`. |
| Wrapper log | `/var/log/defenseclaw-enterprise-mdm.log` (root, 0600). |

## macOS

| Mechanism | Value |
| --- | --- |
| pkg receipt | `pkgutil --pkg-info com.cisco.defenseclaw.enterprise` reports `version: X.Y.Z`. The lifecycle forgets the receipt when you uninstall. |
| Script | `macos/detect.sh`, the same options as on Linux. For Intune custom attributes use `--format value` (String), and for Jamf Pro extension attributes use `--format jamf`. |
| Health | `detect.sh --require-healthy`, or `defenseclaw-enterprise.sh --action verify` exits 0. |
| Last package result | `/opt/cisco/defenseclaw/lifecycle/last-package-result.json`. |
| Wrapper log | `/Library/Logs/Cisco/DefenseClaw/mdm-wrapper.log` (root, 0600). |

## detect.sh output formats

| Format | Exit | Output |
| --- | --- | --- |
| `exit` (default) | 0 detected, 1 not | `DefenseClaw Enterprise <version>` on STDOUT, or the reason on STDERR |
| `value` | always 0 | The installed version, or `not-installed`, `outdated` (with `--min-version`) or `unhealthy` (with `--require-healthy`) |
| `jamf` | always 0 | The same values inside `<result>...</result>` |

In every format, an unknown argument or a bad `--format` exits 2 and prints
nothing on STDOUT.

Script-only MDMs set `DC_MIN_VERSION`, `DC_REQUIRE_HEALTHY` and `DC_FORMAT`
in the settings block instead of flags.

## Versions

Versions are dotted releases (`1.4.0`). A leading `v` and build metadata
(`+...`) are ignored, and a prerelease sorts before its release
(`1.4.0-rc1` < `1.4.0`).

## Upgrades and rollback

`ensure` upgrades in place, and the markers report the new version after it
succeeds, so a "greater than or equal to" rule detects the upgrade.

`ensure` refuses to downgrade on Windows (`downgrade_refused`), and `rpm -U`
refuses older packages on RHEL. To go back a version, follow the rollback
procedure in the enterprise documentation. After a successful rollback the
markers report the older version. Change the version your MDM assigns (and
its detection rule) in the same change; otherwise the MDM finds the newer
version missing and installs it again.
