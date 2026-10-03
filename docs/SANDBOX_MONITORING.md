# Sandbox monitoring

Watch NVIDIA OpenShell 0.1 sandboxes with `defenseclaw sandbox activity -f`,
the TUI Sandboxes panel (key 7), or the macOS app; the
[published sandbox guide](https://cisco-ai-defense.github.io/defenseclaw/docs/sandboxes/guide/#during-the-session) describes the activity
feed. The telemetry sandboxes emit is in
[OPENSHELL_SANDBOX_EVENTS.md](OPENSHELL_SANDBOX_EVENTS.md), and the
architecture in [SANDBOX.md](SANDBOX.md).

The legacy standalone sandbox (`openshell-sandbox` 0.0.x) was removed. On a
host that still has it, `/health` reports the `sandbox` subsystem as
`degraded` and `defenseclaw doctor` warns until cleanup runs. See
[hosts that still have the legacy install](SANDBOX.md#hosts-that-still-have-the-legacy-install)
and the guide's
[legacy sandbox cleanup](https://cisco-ai-defense.github.io/defenseclaw/docs/sandboxes/guide/#legacy-sandbox-cleanup) section.

This compatibility file remains so existing repository links do not break.
