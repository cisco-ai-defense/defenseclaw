# OpenShell sandbox quickstart

The quickstart for NVIDIA OpenShell 0.1 sandboxes is the
[published sandbox guide](https://cisco-ai-defense.github.io/defenseclaw/docs/sandboxes/guide/)
(`docs-site/content/docs/sandboxes/guide.mdx`). In short, on Linux or an
Apple-silicon Mac (where sandboxes are OpenShell MicroVMs; see
[compute drivers](SANDBOX.md#compute-drivers)):

```bash
defenseclaw sandbox setup
cd ~/code/myapp && defenseclaw sandbox run claude
```

The architecture is in [SANDBOX.md](SANDBOX.md), and the telemetry sandboxes
emit is in [OPENSHELL_SANDBOX_EVENTS.md](OPENSHELL_SANDBOX_EVENTS.md).

The legacy standalone sandbox (`openshell-sandbox` 0.0.x) was removed. To
remove it from a Linux host that still has it, see
[hosts that still have the legacy install](SANDBOX.md#hosts-that-still-have-the-legacy-install)
and the guide's
[legacy sandbox cleanup](https://cisco-ai-defense.github.io/defenseclaw/docs/sandboxes/guide/#legacy-sandbox-cleanup) section.

This compatibility file remains so existing repository links do not break.
