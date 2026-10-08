# Intune tenant helper

`intune_tenant.py` prepares and watches a Microsoft Intune tenant for the DefenseClaw MDM kit
with Microsoft Graph. It is the tenant-side companion to `../windows` (the Win32 app packager,
launcher and Remediations scripts) and to the macOS and Linux wrappers in `../../macos` and
`../../linux`. It talks to Graph only, never to a device, and DefenseClaw never calls Graph.

The guide that goes with it is published at
<https://cisco-ai-defense.github.io/defenseclaw/docs/enterprise/mdm/intune-tenant/>. It covers the
licences, the admin center settings that need a person, device enrollment, groups and identity.

Guardrail profiles in the config you deliver apply to the standalone profile. The Secure Client
profile rejects them and keeps its behavior as it was.

## Validation status

- **Run on a test tenant:** `check` and `devices`, read-only; the preview mode of every command;
  and, with throwaway objects that were removed afterwards, every `--apply` path: `groups`
  (create two groups, add an enrolled device, run again), `remediation` (create the package from
  the kit scripts, assign it with a daily schedule, update and reassign it), `macos-script`
  (create, assign, update) and `assign-app` (an app assigned as required to a group, run again).
  `status` read the install report of an app and the run states of a Remediations package, both
  with no device yet. The tenant (licences, users, groups, automatic enrollment, the Apple push
  certificate) was prepared for this and a Windows 11 and an Ubuntu 24.04 Desktop device were
  enrolled and compliant.
- **Not run yet:** delivering DefenseClaw to a device through Intune, and `status` with devices
  reporting. The MDM certification round does that for the first time.

## Use

```sh
export AZURE_TENANT_ID=...; export AZURE_CLIENT_ID=...
read -rs AZURE_CLIENT_SECRET && export AZURE_CLIENT_SECRET     # or export GRAPH_ACCESS_TOKEN=...

python3 intune_tenant.py check --group defenseclaw-windows --group defenseclaw-macos
python3 intune_tenant.py devices --noncompliant
python3 intune_tenant.py groups --name defenseclaw-windows                     # preview
python3 intune_tenant.py groups --name defenseclaw-windows --apply
python3 intune_tenant.py groups --add-device PC-0042:defenseclaw-windows --apply
python3 intune_tenant.py assign-app --app "DefenseClaw Enterprise" --group defenseclaw-windows
python3 intune_tenant.py remediation --group defenseclaw-windows --daily-at 02:00
python3 intune_tenant.py macos-script --name "DefenseClaw Enterprise" --file ./defenseclaw-enterprise.sh --group defenseclaw-macos
python3 intune_tenant.py status --app "DefenseClaw Enterprise" --remediation "DefenseClaw Enterprise health"
```

Run `python3 intune_tenant.py COMMAND --help` for the options. Python 3.9 or later; no packages.

| Command | Changes the tenant | What it does |
| --- | --- | --- |
| `check` | no | Licences (Intune, Entra ID P1 or P2, Windows Enterprise), MDM authority, MDM user scope (when the token can read it), Windows Hello default, Apple push certificate, groups, device counts. Exits 1 when a check fails |
| `devices` | no | Managed devices with compliance, management state and last sync. Filters: `--os`, `--group`, `--noncompliant` |
| `status` | no | Install state per device of an app, run state per device of a Remediations package |
| `groups` | with `--apply` | Create static security groups; add an Entra device to a group by name |
| `assign-app` | with `--apply` | Add an app assignment; changing its intent updates the existing assignment, which the preview names |
| `remove-assignment` | with `--apply` | Remove an included group assignment before an uninstall rollout; exclusions are preserved |
| `remediation` | with `--apply` | Create or update a Remediations package from `../windows/Remediate-*.ps1` (run as SYSTEM) and assign it on a daily schedule |
| `macos-script` | with `--apply` | Create or update a macOS shell script from a file (run as root) and assign it |

Rules: credentials only from the environment; every command that changes the tenant prints a
plan until you pass `--apply` (and `--dry-run` is accepted); objects are found by exact display
name, created when missing and updated when present, so a second run changes nothing; a Graph
error is printed with its status and code and the exit code is 1.

## Credentials and permissions

Either an app registration (`AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`) with these
application permissions, admin-consented, or a token in `GRAPH_ACCESS_TOKEN`:

| Permission | For |
| --- | --- |
| `Organization.Read.All` | `check` |
| `Group.ReadWrite.All` (`Group.Read.All` to only read), `Device.Read.All` | `check`, `devices`, `groups`, every `--group` |
| `DeviceManagementServiceConfig.Read.All` | `check` (enrollment configurations, Apple push certificate) |
| `DeviceManagementManagedDevices.Read.All` | `check`, `devices` |
| `DeviceManagementApps.ReadWrite.All` | `assign-app`, `status` |
| `DeviceManagementScripts.ReadWrite.All` | `remediation`, `macos-script`, `status` |

A token from `az account get-access-token --resource-type ms-graph` carries the directory
permissions of the signed-in account; the Intune calls need an app registration or a delegated
token that carries the Intune permissions.

## Not possible with Graph here

- The automatic enrollment MDM user scope, the Windows Hello for Business default and the Apple
  push certificate upload are admin center steps. Graph refused an app-only token for the first
  two on the test tenant (`Unsupported app-only call`, and 403 `Tenant is not Global Admin or
  Intune Service Admin`); a Graph upload of the push certificate was not tested. `check` reads
  what it can and says so for the rest.
- Uploading a Win32 app is an admin center step (see `../windows`); `assign-app` assigns it afterwards.
- A Linux platform script is created in the admin center; there is no Linux command here.
- The tenant helper does not assign licences or create users; `../../identity/entra/entra_setup.py`
  creates groups and users in Entra ID.

Microsoft Graph can take up to about 45 seconds to list a newly created group.
The helper waits before creating a missing name, remembers the ID returned by
create, and retries a member add while Graph propagates it. Rerun `groups`
after a failed request; it refuses ambiguous duplicate display names.
