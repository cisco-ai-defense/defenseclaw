# Deploying DefenseClaw managed enterprise with Microsoft Intune

This folder holds the Intune-specific scripts. The step-by-step guides are published with
the docs, the single source for them (this folder used to carry copies that drifted, so they
were removed):

| Guide | Published page |
| --- | --- |
| Prepare the tenant: licences, enrollment, groups, identity | <https://cisco-ai-defense.github.io/defenseclaw/docs/enterprise/mdm/intune-tenant/> |
| Windows: Win32 app and Remediations | <https://cisco-ai-defense.github.io/defenseclaw/docs/enterprise/mdm/intune-windows/> |
| macOS: shell script, or PKG app | <https://cisco-ai-defense.github.io/defenseclaw/docs/enterprise/mdm/intune-macos/> |
| Linux: platform script | <https://cisco-ai-defense.github.io/defenseclaw/docs/enterprise/mdm/intune-linux/> |

| Folder | Content |
| --- | --- |
| `windows/` | `New-DefenseClawIntunePackage.ps1` (builds the Win32 app content), `Install-DefenseClawIntune.ps1` (the launcher), `Remediate-Detect.ps1` and `Remediate-Fix.ps1` |
| `tenant/` | `intune_tenant.py`, a Microsoft Graph helper: check the tenant, create device groups, assign the app, create the Remediations package or a macOS shell script, report compliance. Previews by default. See its README |

Validation status: the tenant setup, Windows and Linux enrollment and compliance, and the
read-only and preview modes of `tenant/intune_tenant.py` were run on a test tenant. Delivering
DefenseClaw through Intune (the Win32 app, Remediations, the macOS shell script, the Linux
platform script) has not been run against a live tenant yet, so run a pilot group first.

| Platform | Install | Detect | Keep healthy | Remove |
| --- | --- | --- | --- | --- |
| Windows 10/11 x64 | Win32 app | Registry rule on the marker version (`ProductVersion` >= the app version) | Remediations pair (`Remediate-Detect.ps1`, `Remediate-Fix.ps1`) | Win32 uninstall command |
| macOS 13+ (Apple silicon) | Shell script (recommended) or unmanaged PKG app | `detect.sh` custom attribute; pkg receipt | Script frequency | `uninstall.sh` shell script |
| Ubuntu, RHEL (the releases Intune supports) | Linux platform script | `detect.sh` as a second platform script; package database | Script frequency (default every 15 minutes) | `uninstall.sh` platform script |

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
  They must be smaller than 1 MB and are stopped after 60 minutes. Intune
  does not support running them through a proxy. Intune passes them no
  arguments, so the wrapper's settings block carries every value.
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
