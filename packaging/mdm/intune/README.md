# Deploying DefenseClaw managed enterprise with Microsoft Intune

This folder holds the Intune-specific scripts. The step-by-step guides are published with
the docs, the single source for them (this folder used to carry copies that drifted, so they
were removed):

| Guide | Published page |
| --- | --- |
| Prepare the tenant: licences, enrollment, groups, identity | <https://cisco-ai-defense.github.io/defenseclaw/docs/enterprise/mdm/intune/tenant/> |
| Windows: Win32 app and Remediations | <https://cisco-ai-defense.github.io/defenseclaw/docs/enterprise/mdm/intune/windows/> |
| macOS: shell script, or PKG app | <https://cisco-ai-defense.github.io/defenseclaw/docs/enterprise/mdm/intune/macos/> |
| Linux: platform script | <https://cisco-ai-defense.github.io/defenseclaw/docs/enterprise/mdm/intune/linux/> |

| Folder | Content |
| --- | --- |
| `windows/` | `New-DefenseClawIntunePackage.ps1` (builds the Win32 app content), `Install-DefenseClawIntune.ps1` (the launcher), `Remediate-Detect.ps1` and `Remediate-Fix.ps1`, and the reference rule-pack app `Install-DefenseClawRulePack.ps1` with `Detect-DefenseClawRulePack.ps1` |
| `tenant/` | `intune_tenant.py`, a Microsoft Graph helper: check the tenant, create device groups, assign the app, create the Remediations package or a macOS shell script, report compliance. Previews by default. See its README |

Validation status: a live test tenant delivered a rule-pack app and the Windows
base and signed bundle Win32 apps, checked bundle detection and hook
enforcement, and ran uninstall. That run's own lab rule-pack app did not let
the gateway service read the pack folder, so Setup refused the base app with
`1639` until the folder permissions were fixed by hand. With the pack installed
first and the base config naming the bundle's pack, no test call the bundle
blocks was allowed between hook start and bundle confirmation. Intune retried a
bundle app that met a busy lifecycle (`1618`) by itself. The reference
rule-pack scripts here are newer than that run and have not yet run in a
tenant. Tenant setup and Windows/Linux enrollment and compliance were also
tested. Pilot other channels and upgrades before fleet assignment.

| Platform | Install | Detect | Keep healthy | Remove |
| --- | --- | --- | --- | --- |
| Windows 10/11 x64 | Base Win32 app with config; one dependent Win32 app per signed bundle version | Registry rule for base; generated `detect-bundle.ps1` for bundles | Remediations pair (`Remediate-Detect.ps1`, `Remediate-Fix.ps1`); in bundle mode compliant only while the gateway enforces the confirmed bundle, and the fix re-applies it from the bundle store | Base app uninstall; bundle app no-op uninstall |
| macOS 13+ (Apple silicon) | Shell script (recommended) or unmanaged PKG app | `detect.sh` custom attribute; pkg receipt | Script frequency | `uninstall.sh` shell script |
| Ubuntu, RHEL (the releases Intune supports) | Linux platform script | `detect.sh` as a second platform script; package database | Script frequency (default every 15 minutes) | `uninstall.sh` platform script |

## Signed policy bundles on Windows

Deliver three apps, in this order: the rule-pack app, the base app, the
bundle app. Each later app depends on the one before it.

1. **Rule-pack app.** `Install-DefenseClawRulePack.ps1` copies the pack folder
   from its content to `C:\ProgramData\DefenseClaw-RulePacks\<pack>`, gives
   that folder and the pack SYSTEM and Administrators Full control and
   `NT SERVICE\DefenseClawGateway` Read & execute, removes `Users`, verifies the
   copy and the permissions, and changes nothing when run again. Run it with
   `-PlanOnly` on the workstation to print the pack's tree SHA-256 and the
   commands it runs; set that SHA-256 and the pack name in your copy of
   `Detect-DefenseClawRulePack.ps1`, the app's detection script. The script
   sets the parent folder with `Set-Acl`, by SID: this app runs before the base
   app creates the gateway service, and `icacls` cannot grant the service SID
   until the service exists (it fails with `1332`). `-PacksRoot` must be empty,
   or a folder the script set up (it writes `.defenseclaw-rule-packs` there) or
   that already has its permissions. Without the pack, or when the gateway
   cannot read the pack or its parent folder, Setup refuses the base config
   with `1639` and prints an `icacls` fix that works only once the service
   exists. On a new device run the rule-pack app's install command again, or
   set the parent from an elevated prompt:
   `$a = Get-Acl -LiteralPath 'C:\ProgramData\DefenseClaw-RulePacks'; $a.SetSecurityDescriptorSddlForm('O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;S-1-5-80-1858176940-1394861675-2895326486-505287571-2610476274)', 'Owner, Access'); Set-Acl -LiteralPath 'C:\ProgramData\DefenseClaw-RulePacks' -AclObject $a`.
2. **Base app**, built with `-ConfigPath`. Its guardrail block must select the
   same custom rule pack, digest, threshold and rules as the signed bundle,
   with the pack's installed absolute path. Make the rule-pack app its
   dependency. The packaging script prints a `Prerequisite` line for every
   pack the config names outside the DefenseClaw install folders. Setup cannot
   apply a bundle on the first install.
3. **Bundle app.** After the base app is installed, build one Win32 app per
   signed bundle version:

```powershell
./packaging/mdm/intune/windows/New-DefenseClawIntunePackage.ps1 `
  -SetupPath .\DefenseClawSetup-Enterprise-Standalone-x64.exe `
  -Sha256 '<setup sha256>' -BundlePath .\policy.dcbundle `
  -TrustAnchorPath .\bundle-anchors.json -RequireBundle 7 `
  -BaseConfigPath .\config.yaml `
  -ProductVersion 9.9.9 -OutputDirectory .\bundle-app
```

Verify the bundle offline with `defenseclaw-gateway enterprise bundle verify
--anchors .\bundle-anchors.json --platform windows` before packaging, with the
release the devices run: a device on the signer's product version refuses a
bundle whose signed Windows digest it computes differently (`digest_mismatch`)
on any signing OS. The packager pins the copied bundle and anchors and writes `detect-bundle.ps1`
beside `content`; upload that file as the bundle app's custom detection script.
It reads the bundle's manifest-pinned config and refuses a base config with a
different guardrail policy; only the installed pack path may differ. Use the
same `config.yaml` to build the base app and this bundle app. A base-only device
is installed but has no confirmed signed bundle; until the bundle applies, the
base config's pack, which the packager requires to match the bundle's, enforces
the bundle's rules.
Use a numeric `-RequireBundle` version so a later bundle remains detected.
Set the base app as a dependency with **Automatically install: Yes**. Each new
bundle app supersedes the previous bundle app with **Uninstall previous
version: No**. The bundle app's uninstall command is a no-op; remove the
product through the base app.

Build upgrade packages without `-ConfigPath` after a device enters bundle
mode; Setup otherwise refuses `bundle_required`. A bundle package must carry
the Setup for the release installed on the device: an older Setup is refused
as `downgrade_refused`. Bundles are limited to 4 MiB and anchors to 64 KiB.
Setup installs anchors only from an administrator-only path and verifies the
bundle signature on its own copy. The base app's uninstall command,
`Install-DefenseClawIntune.ps1 -Uninstall`, runs plain standalone
`/uninstall JSON=1`, which removes machine state, including anchors and
bundles; `-Purge` (Setup `PURGE=1`) also removes enrolled accounts'
per-user DefenseClaw data and binaries. When Setup refuses with
`uninstall_in_use` (a program runs from the install folder or, with
`-Purge`, has a file in `C:\ProgramData\Cisco\DefenseClaw` open, such as a
SIEM forwarder reading `runtime\audit.db`), the launcher runs it again up to 6
times and then exits `1618`, which Intune retries, instead of `1603`.

Intune's execution contexts shape the design:

- **Windows.** Install commands that call `powershell.exe` start Windows
  PowerShell 5.1, and the 32-bit engine unless the command uses `Sysnative`.
  Remediations scripts run in Windows PowerShell 5.1, in 32-bit unless you
  choose 64-bit; Win32 app detection scripts run in 64-bit unless you choose
  32-bit. So every Intune-facing Windows script here is 5.1-compatible, works
  in either bitness, and does only two things:
  - reads the enterprise marker through the 64-bit registry view;
  - launches the native x64 `DefenseClawSetup-Enterprise-Standalone-x64.exe`
    or `defenseclaw.exe`.

  The native binaries run the lifecycle, which re-verifies and launches its
  own trusted PowerShell 7 engine. Lifecycle logic never runs inside the
  Intune host.
- **macOS.** Shell scripts run as root unless you choose the signed-in user.
  In one tenant on 2026-10-14, Graph accepted scripts through 1,100,000 bytes
  and the Intune Mac agent executed the 1,100,000-byte probe. The maximum size
  was not measured. Scripts are stopped after 60 minutes. Intune
  does not support running them through a proxy. Intune passes them no
  arguments, so the wrapper's settings block carries every value. Use inline
  config without a bundle, or a signed bundle with an empty config block.
  A bundle can use trust anchors already installed on the device, an anchor
  file path, or inline anchors.
- **Linux.** Platform scripts run as the signed-in user unless you choose
  **Root**. The first root run can ask the user for consent. Custom
  compliance discovery scripts always run in the user's context, so they
  cannot read DefenseClaw's root-only status.
- **Everywhere.** Microsoft states that scripts and custom settings are not
  secret storage. Never embed the Cisco AI Defense key in an Intune script,
  a Win32 app or a config file. Deliver it as described on each platform
  page, after DefenseClaw is installed.

Real-tenant caveats:

- Intune cannot enroll Windows Server, so test Windows on Windows 10/11.
- Remediations need Windows Enterprise E3/E5, Education A3/A5, or Windows
  VDA per-user licenses.
- Detection by version does not notice a config-only change on Windows; see the
  Windows page, section 6.
