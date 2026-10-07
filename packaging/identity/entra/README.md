# Microsoft Entra ID starter kit

Scripts and example configs for using Microsoft Entra ID users with DefenseClaw
identity-based guardrail profiles. The guide that goes with them is published at
<https://cisco-ai-defense.github.io/defenseclaw/docs/enterprise/identity-entra-id/>.

DefenseClaw never calls Entra ID or Microsoft Graph. It reads who a user is from the
operating system: the SID and sign-in token on Windows, NSS on Linux. These scripts
are for the administrator who prepares the tenant and the computers.

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
permissions `Group.ReadWrite.All` and `User.ReadWrite.All` (`Group.Read.All` and
`User.Read.All` to only read), admin-consented:

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

Entra-joined Windows (elevated PowerShell):

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

Then install DefenseClaw as that user and copy keys from `per-user-profiles.example.yaml`
into `~/.defenseclaw/config.yaml`. The config files use `config_version: 8`; validate them
with `defenseclaw config validate`.

## What was tested

Run on a live Entra tenant and on test hosts; the scripts themselves are listed with what
ran:

| Item | Result |
| --- | --- |
| `entra_setup.py check`, `sids` (two groups, one missing, JSON), `GRAPH_ACCESS_TOKEN` | Ran against a live tenant. The SID Graph reports for two groups and a user equals the value `sid-from-object-id` computes, and the SIDs of that user and of her group matched her Windows sign-in token |
| `entra_setup.py apply` | Preview ran against a live tenant with existing and new objects. `--apply` not run |
| `setup-entra-ssh-linux.sh` | Plan mode ran against an Ubuntu 22.04 VM that already had the identity, the extension and a role, and against a Windows VM (refused). `--apply` not run |
| `Add-EntraGroupToLocalGroup.ps1` | Ran on Windows Server 2025 in Windows PowerShell 5.1 and PowerShell 7 with a throwaway local group: `-WhatIf`, add, add again, remove, remove again, bad SID, missing group. The same API put a real Entra group into the token of an Entra-joined Windows 11 user |
| `Get-DefenseClawEntraIdentity.ps1` | Ran on Windows Server 2025 (not Entra-joined) in both engines, as administrator and as SYSTEM, with a saved `dsregcmd` output. Not yet run on an Entra-joined computer |
| The example configs | Accepted by the gateway's `config-v8 validate`; a bad profile name is rejected |
| Per-user installs with profiles on Entra-joined Windows 11 and Ubuntu 22.04 (Entra SSH) | Ran live; see the guide |
| Standalone enterprise profile on Entra-joined Windows | One live run did not complete; see Known issues in the guide |
| Intune delivery of the local group, hybrid join, Entra Kerberos, himmelblau | Not tested |

Lint: `ruff` (line length 120), `shellcheck` and PSScriptAnalyzer (including the
`PSUseCompatibleSyntax` rule for Windows PowerShell 5.1) report nothing.

## Limits

- Windows puts an Entra group's SID in a sign-in token only when a built-in local group lists
  it (Administrators, Users, Guests, Power Users, Remote Desktop Users, Remote Management
  Users). A per-user Windows install has no group list at all; use `users` assignments there.
- The Linux `aad` module gives no Entra groups; use `users` assignments.
- On Windows, `guardrail profile explain --user` takes a SID or `AzureAD\Name`, not a UPN.
- `entra_setup.py` uses the commercial Microsoft cloud (`graph.microsoft.com`).
