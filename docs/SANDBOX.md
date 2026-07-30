# OpenShell sandbox implementation

Setup, operation, monitoring, debugging, and teardown are documented in the
[published sandbox guide](https://cisco-ai-defense.github.io/defenseclaw/docs/setup/sandbox/).

The implemented sandbox surface is **experimental**, **Linux-only**, and
**OpenClaw-only**. The init/setup entry points reject non-Linux hosts and fail
closed unless OpenClaw is the active connector. Do not describe it as a general
sandbox for every connector.

## Code ownership

| Concern | Source |
| --- | --- |
| CLI command group and platform status | [`cli/defenseclaw/commands/cmd_sandbox.py`](../cli/defenseclaw/commands/cmd_sandbox.py) |
| Initial user, home, policy, and OpenShell preparation | [`cli/defenseclaw/commands/cmd_init_sandbox.py`](../cli/defenseclaw/commands/cmd_init_sandbox.py) |
| Configuration, systemd units, networking, pairing, and disable flow | [`cli/defenseclaw/commands/cmd_setup_sandbox.py`](../cli/defenseclaw/commands/cmd_setup_sandbox.py) |
| OpenShell binary installation and checksum verification | [`scripts/install-openshell-sandbox.sh`](../scripts/install-openshell-sandbox.sh) |
| Go-side OpenShell configuration, policy, and endpoint handling | [`internal/sandbox/`](../internal/sandbox/) |
| Bundled policy inputs | [`policies/openshell/`](../policies/openshell/) |
| Focused lifecycle and protection tests | [`scripts/test-e2e-sandbox.sh`](../scripts/test-e2e-sandbox.sh), [`scripts/test-e2e-sandbox-protection.sh`](../scripts/test-e2e-sandbox-protection.sh), and [`scripts/test-e2e-sandbox-policy-diff.sh`](../scripts/test-e2e-sandbox-policy-diff.sh) |

OpenShell itself owns its kernel-containment and proxy implementation.
DefenseClaw owns only the orchestration, configuration, policies, integration,
and verification represented by the sources above.
