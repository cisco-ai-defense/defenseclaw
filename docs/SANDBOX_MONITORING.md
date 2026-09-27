# Sandbox monitoring

NVIDIA OpenShell 0.1 sandbox support is being rebuilt and is not available to
operators yet. The telemetry it will emit is described in
[OPENSHELL_SANDBOX_EVENTS.md](OPENSHELL_SANDBOX_EVENTS.md), and its
architecture in [SANDBOX.md](SANDBOX.md).

The legacy standalone sandbox (`openshell-sandbox` 0.0.x) was removed. On a
host that still has it, `/health` reports the `sandbox` subsystem as
`degraded` and `defenseclaw doctor` warns until cleanup runs; follow the
[published legacy sandbox cleanup guide](https://cisco-ai-defense.github.io/defenseclaw/docs/setup/sandbox/).

This compatibility file remains so existing repository links do not break.
