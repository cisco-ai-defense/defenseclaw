# Intune on Windows: Win32 app and Remediations

## 1. Prerequisite: PowerShell 7 as a dependency

The standalone lifecycle runs on PowerShell 7 and refuses without it. The
engine must be a stable (not preview) x64 MSI install, which registers under
`HKLM\SOFTWARE\Microsoft\PowerShellCore\InstalledVersions` and installs to
`C:\Program Files\PowerShell\7`. The kit's PowerShell 7 scripts need 7.4 or
later. Add it as its own Win32 app:

| Field | Value |
| --- | --- |
| Content | `PowerShell-7.x.y-win-x64.msi` (from Microsoft, hash-checked) |
| Install command | `msiexec /i PowerShell-7.x.y-win-x64.msi /qn ADD_PATH=1 USE_MU=1 ENABLE_MU=1` |
| Uninstall command | `msiexec /x {product-code} /qn` |
| Install behavior | **System** |
| Detection | File: `C:\Program Files\PowerShell\7`, `pwsh.exe`, **String (version)** ≥ `7.4.0`, 32-bit app on 64-bit clients: **No** |

In the DefenseClaw app's **Dependencies** step, add this app with
**Automatically install** set to **Yes**.

## 2. Build the Win32 app content

On an administrator workstation with PowerShell 7.4 or later:

```powershell
./New-DefenseClawIntunePackage.ps1 `
  -SetupPath .\DefenseClawSetup-Enterprise-Standalone-x64.exe `
  -Sha256 <SHA-256 from the cosign-verified checksums.txt> `
  -ConfigPath .\config.yaml `
  -OutputDirectory .\intune-defenseclaw-1.4.0 `
  -IntuneWinAppUtil C:\Tools\IntuneWinAppUtil.exe `
  -ProductVersion 1.4.0
```

The script:

1. Verifies the Setup.
2. Refuses a config that contains an inline `api_key`.
3. Writes `content\` containing the Setup, `config.yaml`,
   `Install-DefenseClawIntune.ps1` and `intune-package.json`, which holds the
   SHA-256 pins the launcher re-checks on the device (`setup_sha256`,
   `config_sha256`), the trust mode and the allowed signers.
4. Wraps the folder into a `.intunewin` when `-IntuneWinAppUtil` is given.
5. Prints the values for the admin center.

Always pass `-ConfigPath`: the first install refuses to run without a config
(exit 1639).

For Authenticode trust, add:

```powershell
-TrustMode Authenticode -AllowedSigners <SHA-256 thumbprint of the signer certificate>
```

## 3. Create the Win32 app

| Step | Setting |
| --- | --- |
| Program: installer type | **Command line** |
| Program: install command | `%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\Install-DefenseClawIntune.ps1` |
| Program: uninstall command | `DefenseClawSetup-Enterprise-Standalone-x64.exe /uninstall JSON=1` (Intune does not expand environment variables in uninstall commands). It always removes the config, credentials and machine state; add `PURGE=1` to also remove each enrolled account's DefenseClaw data and per-user binaries. |
| Install behavior | **System** |
| Device restart behavior | **Determine behavior based on return codes** |
| Return codes | Keep the defaults: `0` Success, `1707` Success, `3010` Soft reboot, `1641` Hard reboot, `1618` Retry. The lifecycle's `1603` and `1639` then report as Failed. |
| Requirements | Operating system architecture **x64** only (the lifecycle refuses ARM64 and 32-bit). DefenseClaw does not check the Windows version: it needs x64 and PowerShell 7. For Intune's required **Minimum operating system**, choose the oldest release your fleet runs; the packaging script prints Windows 10 22H2 as a starting point. |
| Detection rule | Registry. Key `HKEY_LOCAL_MACHINE\SOFTWARE\Cisco\DefenseClaw\Enterprise`, value `ProductVersion`, **Version comparison**, **Greater than or equal to** `1.4.0`, *Associated with a 32-bit app on 64-bit clients*: **No**. Instead, you can use `packaging/mdm/windows/detect.ps1` as a custom detection script; Intune runs it without arguments, so set the default of `$MinimumVersion` in your copy to the app's version. |
| Dependencies | The PowerShell 7 app, **Automatically install: Yes** |
| Supersedence | New versions supersede the previous app with **Uninstall previous version: No**, because `/ensure` upgrades in place and keeps state. |
| Assignment | **Required** for device groups |

Why a launcher instead of calling the Setup directly:

- Setup refuses relative and environment-expanded paths.
- Intune's content folder path is not known in advance.

The launcher re-checks the pins, builds the absolute `CONFIG=` path, and
starts the native Setup with `/ensure JSON=1` (and `ALLOWEDSIGNERS=` for
Authenticode trust). If the host is already installed and you only upgrade
the binaries, `DefenseClawSetup-Enterprise-Standalone-x64.exe /ensure JSON=1`
also works as the install command, because it reuses the installed config.

The first install needs a config: `/ensure` refuses to install without one
(exit 1639).

## 4. Remediations (optional, recommended)

Create a script package in **Devices > Manage devices > Scripts and
remediations > Create script package** with `Remediate-Detect.ps1`
(detection) and `Remediate-Fix.ps1` (remediation):

| Setting | Value |
| --- | --- |
| Run this script using the logged-on credentials | **No** (runs as SYSTEM) |
| Enforce script signature check | **No**, or **Yes** after you sign the scripts with a certificate in the devices' Trusted Publishers store; the scripts then run under the device's execution policy (`Restricted` by default on clients) and must be UTF-8 without a BOM |
| Run script in 64-bit PowerShell | **No** (the default). The scripts read the 64-bit registry view and launch the native x64 CLI either way. |
| Schedule | **Daily**, or **Hourly** every 4–8 hours |

The detection script:

- runs `defenseclaw.exe enterprise windows verify --profile standalone --json`;
- reports compliant (exit 0) on a healthy host or on a host without the
  deployment (the Win32 app handles installation);
- reports exit 1 otherwise.

The remediation script runs `enterprise windows ensure --profile
standalone --json`, which repairs from the installed payload. On unsigned
(hash-pinned) releases it keeps the marker's `hash_pinned` trust mode, so the
kit scripts keep accepting the unsigned CLI. Both scripts print a single
short line, because Intune keeps 2,048 characters of output.

Remediations cannot install, upgrade or change the config: the installed CLI
has no payload to install from, so its `ensure --config` exits 1639. The
Win32 app does those.

## 5. The Cisco AI Defense key

Do not put the key in the Win32 app, in `config.yaml` or in a script. Enable
it in the config (`enterprise.inspection.ai_defense.enabled: true` and the
credential name), install, then store the key once from an elevated
PowerShell 7 session on the device (for example through your remote-support
tool). The key goes from the prompt to standard input and never touches the
disk or a command line:

```powershell
$cli = 'C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw.exe'
$key = Read-Host -AsSecureString -Prompt 'Cisco AI Defense API key'
ConvertFrom-SecureString -SecureString $key -AsPlainText | & $cli enterprise secret set --name ai-defense-api-key --from-stdin
& $cli enterprise secret status
```

For automation, have your secrets-management agent write the key to a file
that only SYSTEM and Administrators can change (on a local NTFS drive), run
`& $cli enterprise secret set --name ai-defense-api-key --from-file <file>`
as SYSTEM or an elevated administrator, then delete the file.
`Invoke-DefenseClawEnterprise.ps1 -SecretName ai-defense-api-key
-SecretPath <file>` (or `-SecretFromStdin`) does the same from tools that run
PowerShell 7.

`enterprise secret set` runs only elevated and only on a host with the
standalone deployment installed (otherwise exit 1603), refuses a file that a
non-administrator can change or an invalid name or value (exit 1639), writes
`C:\ProgramData\Cisco\DefenseClaw\secrets\<name>` (SYSTEM and Administrators
full control, the gateway service read-only), and restarts the gateway.
`enterprise secret status` shows presence, modification time and a digest
prefix, never the value.

## 6. Config changes, upgrades and rollback

- **Upgrade**: build a package from the new Setup, create a new Win32 app with
  the new version in its detection rule, and supersede the old app with
  **Uninstall previous version: No**.
- **Config change**: Setup applies a new config when `/ensure` runs with a
  config that differs from the installed one. The registry rule detects by
  version only, so Intune does not re-run the app for a config-only change.
  Build a package from the same Setup and the new config, supersede the old
  app with **Uninstall previous version: No**, and give the new app a custom
  detection script that also checks the installed config (Windows
  PowerShell 5.1, 32- or 64-bit):

  ```powershell
  $minimum = [version]'1.4.0'
  $configSha256 = 'replace-with-config_sha256-from-intune-package.json'
  $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
  $key = $base.OpenSubKey('SOFTWARE\Cisco\DefenseClaw\Enterprise')
  if ($null -eq $key) { exit 1 }
  $version = [string]$key.GetValue('ProductVersion')
  $stateRoot = [string]$key.GetValue('StateRoot')
  $key.Dispose()
  $base.Dispose()
  $core = ($version -split '[-+]')[0]
  if (-not $core -or [version]$core -lt $minimum) { exit 1 }
  $config = Join-Path $stateRoot 'etc\config.yaml'
  if (-not (Test-Path -LiteralPath $config -PathType Leaf)) { exit 1 }
  $actual = (Get-FileHash -LiteralPath $config -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($actual -ne $configSha256.ToLowerInvariant()) { exit 1 }
  Write-Output "DefenseClaw Enterprise $version"
  exit 0
  ```

- **Rollback**: `/ensure` refuses a Setup older than the installed version
  (`downgrade_refused`, 1603). Follow the rollback procedure in the
  enterprise documentation, and change the assigned app and its detection
  rule in the same change (see `../contract/detection.md`).

## 7. Troubleshooting

| Where | What |
| --- | --- |
| `%WINDIR%\Logs\DefenseClaw\enterprise-lifecycle.log` | Every lifecycle result (JSON, one line per run) |
| `DefenseClaw` event log, source "DefenseClaw Lifecycle" (legacy copy: Application log, source "DefenseClaw Enterprise") | Installed, upgraded, repaired, failed, busy and refused events |
| `C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\AppWorkload.log` | Intune's view of the Win32 install and detection |
| `C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\HealthScripts.log` | Remediations runs |
| `defenseclaw.exe enterprise windows status --profile standalone --json` | Current state; run it elevated |
