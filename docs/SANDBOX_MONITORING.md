# Sandbox monitoring

There is no sandbox to monitor in this release. The legacy standalone sandbox
(`openshell-sandbox` 0.0.x) was removed. On a host that still has it, `/health`
reports the `sandbox` subsystem as `degraded` and `defenseclaw doctor` warns
until cleanup runs; follow the
[published legacy sandbox cleanup guide](https://cisco-ai-defense.github.io/defenseclaw/docs/setup/sandbox/).
See [SANDBOX.md](SANDBOX.md) for a summary. Support for NVIDIA OpenShell 0.1 is
coming in a future release.

This compatibility file remains so existing repository links do not break.
