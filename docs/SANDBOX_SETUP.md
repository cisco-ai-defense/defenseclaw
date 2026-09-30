# Sandbox setup

`defenseclaw sandbox setup` prepares a Linux machine or an Apple-silicon Mac
for NVIDIA OpenShell 0.1 sandboxes. On a Mac it switches the gateway to
OpenShell's MicroVM driver, since Docker Desktop's Linux VM kernel has no
Landlock (see [compute drivers](SANDBOX.md#compute-drivers)). Its requirements, questions and flags are in the
[one-time setup](https://cisco-ai-defense.github.io/defenseclaw/docs/setup/sandbox/#one-time-setup) section of the published sandbox
guide (`docs-site/content/docs/setup/sandbox.mdx`). The architecture and
supported platforms are in [SANDBOX.md](SANDBOX.md), and the telemetry
sandboxes emit is in [OPENSHELL_SANDBOX_EVENTS.md](OPENSHELL_SANDBOX_EVENTS.md).

The legacy standalone sandbox (`openshell-sandbox` 0.0.x) was removed. To
remove it from a Linux host that still has it, see
[hosts that still have the legacy install](SANDBOX.md#hosts-that-still-have-the-legacy-install)
and the guide's
[legacy sandbox cleanup](https://cisco-ai-defense.github.io/defenseclaw/docs/setup/sandbox/#legacy-sandbox-cleanup) section.

This compatibility file remains so existing repository links do not break.
