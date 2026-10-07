# Microsoft Entra ID starter kit

Scripts and example configs for using Microsoft Entra ID users with DefenseClaw
identity-based guardrail profiles. The guide that goes with them is published at
<https://cisco-ai-defense.github.io/defenseclaw/docs/enterprise/identity-entra-id/>.

DefenseClaw never calls Entra ID or Microsoft Graph. It reads who a user is from the
operating system: the SID and sign-in token on Windows, NSS on Linux, Open Directory on
macOS. These scripts are for the administrator who prepares the tenant and the computers.

**Entra groups per platform.** A `groups` assignment can name an Entra group only where the
operating system knows the membership:

| Platform | How the Entra group reaches the OS | Scripts here |
| --- | --- | --- |
| Entra-joined Windows | A built-in local group lists the Entra group's SID | `Add-EntraGroupToLocalGroup.ps1` |
| Linux with the Azure `aad` module | It does not: the module gives no Entra groups | `setup-entra-ssh-linux.sh` (use `users`) |
| Linux with Himmelblau | Himmelblau names the user's Entra groups in `id` and initgroups | `setup-himmelblau.sh` |
| Linux joined to Microsoft Entra Domain Services | SSSD reads the synced groups as Active Directory groups | `join-entra-domain-services.sh` |
| macOS with Platform SSO | It does not; a local group has to carry the membership | `macos-entra-group-bridge.sh`, `macos-platform-sso.settings-catalog.example.json` |

**Where it applies.** Guardrail profiles (`guardrail.profiles`, `profile_assignments`,
`default_profile`) apply to per-user installs and to the standalone enterprise profile.
The Secure Client profile rejects them and keeps its behavior as it was, so none of this
applies to a Secure Client computer.

## Files

| File | Runs on | Changes anything? | Use |
| --- | --- | --- | --- |
| `entra_setup.py` | any computer with Python 3.9 or later | `apply` with `--apply` only | Microsoft Graph helper: `check`, `sids`, `sid-from-object-id`, `apply` |
| `setup-entra-ssh-linux.sh` | any computer with the Azure CLI | with `--apply` only | Enable Entra SSH sign-in on an Azure Linux VM and grant the sign-in role |
| `Add-EntraGroupToLocalGroup.ps1` | Entra-joined Windows, elevated | yes; `-WhatIf` previews | Put an Entra group's SID into a built-in local group so it appears in sign-in tokens |
| `Get-DefenseClawEntraIdentity.ps1` | Windows | no | Show the join state, Entra accounts, token groups and what DefenseClaw answers |
| `setup-himmelblau.sh` | Ubuntu 24.04, as root | with `--apply` only | Install Himmelblau, write `himmelblau.conf` (UPN account names, allowed groups), restart it safely, `check` |
| `join-entra-domain-services.sh` | RHEL 9, as root | with `--apply` only | Join an Entra Domain Services managed domain with realmd and SSSD, switch short or qualified names, flush the SSSD cache, `check` |
| `macos-entra-group-bridge.sh` | macOS, as root (an Intune shell script) | with `--apply` (or `APPLY=yes`) only | Add the signed-in user to, or remove them from, the local group that stands for an Entra group |
| `macos-platform-sso.settings-catalog.example.json` | | | The Intune settings catalog body (Graph `POST /beta/deviceManagement/configurationPolicies`) for Platform SSO with Company Portal |
| `tenant.example.json` | | | Input for `entra_setup.py apply` |
| `admin-config.windows.example.yaml` | | | Standalone enterprise config with profiles by Entra group SID and by user |
| `per-user-profiles.example.yaml` | | | Profiles for a per-user install, by user |

Rules every script follows: `--help` or `Get-Help`; credentials from the environment, never
from arguments; nothing changes until you say so (`--apply` for the Python and Azure
scripts, which change a tenant or a subscription, and the normal `-WhatIf` for the
PowerShell script, which changes one computer); safe to run twice; a clear error and a
non-zero exit code when something is wrong.

## Quick start

Prepare the tenant and read a group's SID. Use an app registration with the application
permissions `Group.ReadWrite.All` and `User.ReadWrite.All` (`Organization.Read.All` and `Policy.Read.All` for `check`;
`Group.Read.All` and `User.Read.All` for `sids`), admin-consented:

```sh
export AZURE_TENANT_ID=...; export AZURE_CLIENT_ID=...
read -rs AZURE_CLIENT_SECRET && export AZURE_CLIENT_SECRET      # or export GRAPH_ACCESS_TOKEN=...

python3 entra_setup.py check
cp tenant.example.json tenant.json                              # edit it
python3 entra_setup.py apply --config tenant.json               # preview
python3 entra_setup.py apply --config tenant.json --apply --password-file users.txt
python3 entra_setup.py sids --group defenseclaw-ml-team
python3 entra_setup.py sid-from-object-id <object id>           # offline
```

Entra-joined Windows (elevated PowerShell): unblock downloaded scripts with
`Unblock-File .\Get-DefenseClawEntraIdentity.ps1` and
`Unblock-File .\Add-EntraGroupToLocalGroup.ps1`, or use
`powershell.exe -ExecutionPolicy Bypass -File .\Get-DefenseClawEntraIdentity.ps1`.
An unattended Internet-zone script can wait at a security prompt. For Intune
platform scripts, which receive no arguments, use an Account protection policy.

```powershell
.\Get-DefenseClawEntraIdentity.ps1 -GroupSid S-1-12-1-...        # as the user; again as SYSTEM for the identity store
.\Add-EntraGroupToLocalGroup.ps1 -GroupSid S-1-12-1-... -WhatIf
.\Add-EntraGroupToLocalGroup.ps1 -GroupSid S-1-12-1-...
```

Then the user signs out and in, and `Get-DefenseClawEntraIdentity.ps1 -GroupSid` reports whether
the group is in the token. For a fleet, use an Intune policy instead (see the guide).

Azure Linux VM with Entra SSH sign-in:

```sh
./setup-entra-ssh-linux.sh -g my-rg -n my-vm --user alice@contoso.onmicrosoft.com        # plan
./setup-entra-ssh-linux.sh -g my-rg -n my-vm --user alice@contoso.onmicrosoft.com --apply
az extension add --name ssh && az ssh vm -g my-rg -n my-vm
```

Linux with Himmelblau (Ubuntu 24.04, as root). Each user first registers an MFA method in
Entra; the first sign-in then asks for the password, a code and a new Windows Hello PIN:

```sh
sudo ./setup-himmelblau.sh install --domain contoso.onmicrosoft.com --allow-group <group object id>          # plan
sudo ./setup-himmelblau.sh install --domain contoso.onmicrosoft.com --allow-group <group object id> --apply
./setup-himmelblau.sh check --user alice@contoso.onmicrosoft.com
```

Linux joined to Microsoft Entra Domain Services (RHEL 9, as root; the managed domain and the
VNet DNS are set up first, see the guide):

```sh
sudo ./join-entra-domain-services.sh join --domain contoso.onmicrosoft.com --admin dsadmin@contoso.onmicrosoft.com --short-names
sudo ./join-entra-domain-services.sh join --domain contoso.onmicrosoft.com --admin dsadmin@contoso.onmicrosoft.com --short-names --apply
./join-entra-domain-services.sh check --user alice --group ml-team
sudo ./join-entra-domain-services.sh flush --apply        # see a group change before SSSD's cache expires
```

macOS with Platform SSO (as root, or as an Intune shell script with the settings block filled in):

```sh
sudo ./macos-entra-group-bridge.sh add --group ml-team --user alice            # plan
sudo ./macos-entra-group-bridge.sh add --group ml-team --user alice --apply
./macos-entra-group-bridge.sh check --group ml-team --user alice
```

Then install DefenseClaw as that user and copy keys from `per-user-profiles.example.yaml`
into `~/.defenseclaw/config.yaml`. The config files use `config_version: 8`; validate them
with `defenseclaw config validate`.

## What was tested

Run on a live Entra tenant and on test hosts; the scripts themselves are listed with what
ran:

| Item | Result |
| --- | --- |
| `entra_setup.py check`, `sids` (two groups, one missing, JSON), `GRAPH_ACCESS_TOKEN` | Ran against a live tenant. The SID Graph reports for two groups and a user equals the value `sid-from-object-id` computes, and the SIDs of that user and of her group matched her Windows sign-in token |
| `entra_setup.py apply` | Preview and `--apply` ran against a live tenant with throwaway objects: it created a group and a user, put the user in the group and wrote the password file; a second `--apply` changed nothing |
| `setup-entra-ssh-linux.sh` | Plan mode ran against an Ubuntu 22.04 VM that already had the identity, the extension and a role, and against a Windows VM (refused). `--apply` granted the sign-in role to a new user and a new group on that VM, and a second run found both; the identity and extension steps were not needed there, so they ran only as checks |
| `Add-EntraGroupToLocalGroup.ps1` | Ran on Windows Server 2025 in Windows PowerShell 5.1 and PowerShell 7 with a throwaway local group: `-WhatIf`, add, add again, remove, remove again, bad SID, missing group. The same API put a real Entra group into the token of an Entra-joined Windows 11 user |
| `Get-DefenseClawEntraIdentity.ps1` | Ran on Windows Server 2025 (not Entra-joined) in both engines, as administrator and as SYSTEM, with a saved `dsregcmd` output. Not yet run on an Entra-joined computer |
| The example configs | Accepted by the gateway's `config-v8 validate`; a bad profile name is rejected |
| Per-user installs with profiles on Entra-joined Windows 11 and Ubuntu 22.04 (Entra SSH) | Ran live; see the guide |
| Standalone enterprise profile on Entra-joined Windows | Ran live: a `groups` assignment by Entra group SID selected its profile while Users listed the group |
| Himmelblau 5.0.0 nightly on Ubuntu 24.04 | Ran live, per-user and standalone: Entra groups in `id`, a group assignment matched |
| `setup-himmelblau.sh` | `check`, `configure --apply` (with and without `--allow-group`, UPN names) and `restart --apply` ran on that VM; `install` in plan mode only (its steps are the ones run by hand) |
| Entra Domain Services with realmd and SSSD on RHEL 9.8 | Ran live, per-user and standalone: a group assignment matched, with qualified and short names |
| `join-entra-domain-services.sh` | `check` and `names qualified|short --apply` ran on that VM; `join` and `flush` in plan mode only (the join was typed by hand with the same `realm join` command) |
| macOS 15.8 with Platform SSO (Company Portal) | Ran live: no Entra group reaches the Mac; a local group membership matched, per-user and standalone |
| `macos-entra-group-bridge.sh` | `check`, `add` and `remove` (plan and `--apply`) ran as root on that Mac, and a copy with the settings block filled in ran with no console user (no-op). Intune delivery not tested |
| `macos-platform-sso.settings-catalog.example.json` | The body of the policy created through Graph and delivered by Intune in the live test (names replaced) |
| Intune delivery of the local group (Windows) or of the bridge script (macOS), hybrid join, Entra Kerberos | Not tested |

Lint: `ruff` (line length 120), `shellcheck` and PSScriptAnalyzer (including the
`PSUseCompatibleSyntax` rule for Windows PowerShell 5.1) report nothing.

## Limits

- Windows puts an Entra group's SID in a sign-in token only when a built-in local group lists
  it (Administrators, Users, Guests, Power Users, Remote Desktop Users, Remote Management
  Users). A per-user Windows install has no group list at all; use `users` assignments there.
- The Linux `aad` module gives no Entra groups; use `users` assignments, or Himmelblau or
  Entra Domain Services.
- Himmelblau finds an Entra group by gid or object id, not by name: `getent group ml-team`
  answers nothing while `id` names the group.
- SSSD after `realm join` names groups `ml-team@DOMAIN`; write that in the assignment, or switch
  to short names.
- macOS Platform SSO gives no Entra groups; a local group has to carry the membership.
- On Windows, `guardrail profile explain --user` takes a SID, `AzureAD\Name`, the bare name or the UPN.
- `entra_setup.py` uses the commercial Microsoft cloud (`graph.microsoft.com`).

To remove Himmelblau from a host, see the guide's **Remove Himmelblau** section:
purge all five packages (including `himmelblau-apparmor`), remove its apt
repository and key, its configuration and state, and the Entra device object.
Keep user homes until their owners have copied needed data.
