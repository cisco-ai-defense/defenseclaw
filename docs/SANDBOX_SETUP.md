# Sandbox setup

`defenseclaw sandbox setup` prepares a Linux machine for NVIDIA OpenShell 0.1
sandboxes. On macOS it runs, but no sandbox can start yet: Docker Desktop's
Linux VM kernel has no Landlock (see
[macOS and Docker Desktop](SANDBOX.md#macos-and-docker-desktop)). Its requirements, questions and flags are in the
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
