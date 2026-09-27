# Sandbox debugging

There is no sandbox to debug yet. NVIDIA OpenShell 0.1 sandbox support is
being rebuilt and is not available to operators. Its architecture, including
the OpenShell behaviours the code is built around, is in
[SANDBOX.md](SANDBOX.md), and the telemetry it will emit is described in
[OPENSHELL_SANDBOX_EVENTS.md](OPENSHELL_SANDBOX_EVENTS.md).

The legacy standalone sandbox (`openshell-sandbox` 0.0.x) was removed. On a
host that still has it, `/health` reports the `sandbox` subsystem as
`degraded` and `defenseclaw doctor` warns until cleanup runs. See
[hosts that still have the legacy install](SANDBOX.md#hosts-that-still-have-the-legacy-install)
and the
[published legacy sandbox cleanup guide](https://cisco-ai-defense.github.io/defenseclaw/docs/setup/sandbox/).

This compatibility file remains so existing repository links do not break.
