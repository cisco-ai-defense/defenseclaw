# OpenShell sandbox events

The supported DefenseClaw sandbox behavior, verification, and troubleshooting
surface is documented in the
[published sandbox guide](https://cisco-ai-defense.github.io/defenseclaw/docs/setup/sandbox/).

DefenseClaw does not implement OpenShell's Landlock, seccomp, network proxy,
event schema, or upstream logging guarantees. Treat claims about those
internals as properties of the pinned upstream OpenShell binary, not as a
DefenseClaw event contract.

DefenseClaw-owned evidence lives in:

- [`cli/defenseclaw/commands/cmd_init_sandbox.py`](../cli/defenseclaw/commands/cmd_init_sandbox.py)
  and [`cmd_setup_sandbox.py`](../cli/defenseclaw/commands/cmd_setup_sandbox.py)
  for orchestration and generated service/network configuration;
- [`internal/sandbox/`](../internal/sandbox/) for Go-side configuration,
  policy, endpoint, and installation validation;
- [`policies/openshell/`](../policies/openshell/) for bundled policy inputs;
  and
- [`scripts/test-e2e-sandbox-protection.sh`](../scripts/test-e2e-sandbox-protection.sh)
  and related sandbox tests for assertions DefenseClaw actually verifies.

See [SANDBOX.md](SANDBOX.md) for the full code ownership map.
