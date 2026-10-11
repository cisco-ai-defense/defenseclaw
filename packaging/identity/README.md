# Identity starter kits

Scripts and example configs for deploying DefenseClaw identity-based guardrail
profiles (`guardrail.profiles`, `profile_assignments`, `default_profile`) with a
specific identity provider. DefenseClaw never calls the provider: it reads who a
user is from the operating system. These kits are for the administrator who
prepares the provider and the hosts.

| Folder | Provider | Hosts | Guide |
| --- | --- | --- | --- |
| [`okta/`](okta/README.md) | Okta LDAP Interface, read by SSSD | Linux (tested on RHEL 9.8) | [Okta on Linux](https://cisco-ai-defense.github.io/defenseclaw/docs/enterprise/identity-okta/) |
| [`entra/`](entra/README.md) | Microsoft Entra ID | Entra-joined Windows, Linux with Entra ID SSH sign-in | [Deploy with Microsoft Entra ID](https://cisco-ai-defense.github.io/defenseclaw/docs/enterprise/identity-entra-id/) |

The Intune tenant helper is in [`../mdm/intune/tenant/`](../mdm/intune/tenant/README.md).

Where this applies: OSS per-user installs and the standalone enterprise profile.
The Secure Client integration rejects guardrail profiles and keeps its behavior as
it was, so none of these kits apply to it.

Rules every script follows:

- `--help` (or `Get-Help`) explains it. Credentials come from the environment or a
  prompt, never from arguments.
- Nothing changes until you say so: `--apply` for a script that changes a tenant,
  `--dry-run` or `-WhatIf` to preview a change to a host.
- A script can be run again and changes only what differs.
- Files are ASCII with Unix line endings (`cli/tests/test_identity_kit.py` checks
  this).
- Each README says what was tested and what was not.
