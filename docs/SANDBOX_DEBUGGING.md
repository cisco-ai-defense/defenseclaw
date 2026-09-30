# Sandbox debugging

Start with `defenseclaw sandbox doctor`: every failed check names its fix, and
`--fix` applies the ones that need only your user. The
[troubleshooting](https://cisco-ai-defense.github.io/defenseclaw/docs/setup/sandbox/#troubleshooting) section of the published sandbox
guide (`docs-site/content/docs/setup/sandbox.mdx`) lists the common messages.
The architecture, including the OpenShell behaviours the code is built
around, is in [SANDBOX.md](SANDBOX.md), and the telemetry sandboxes emit is
in [OPENSHELL_SANDBOX_EVENTS.md](OPENSHELL_SANDBOX_EVENTS.md).

The legacy standalone sandbox (`openshell-sandbox` 0.0.x) was removed. On a
host that still has it, `/health` reports the `sandbox` subsystem as
`degraded` and `defenseclaw doctor` warns until cleanup runs. See
[hosts that still have the legacy install](SANDBOX.md#hosts-that-still-have-the-legacy-install)
and the guide's
[legacy sandbox cleanup](https://cisco-ai-defense.github.io/defenseclaw/docs/setup/sandbox/#legacy-sandbox-cleanup) section.

This compatibility file remains so existing repository links do not break.
