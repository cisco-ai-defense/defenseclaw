# OpenShell sandbox

The legacy standalone sandbox integration was removed. It targeted the
standalone `openshell-sandbox` 0.0.x binary on Linux, for OpenClaw only, and
its generated sandbox policy was never enforced. The `sandbox init` and
`sandbox setup` commands and the gateway's `sandbox` subcommands no longer
exist. OpenClaw and ZeptoClaw use the `shims` subprocess policy on every
platform.

Support for NVIDIA OpenShell 0.1 is being rebuilt and is coming in a future
release.

## Hosts that still have the legacy install

Review the plan, then run the cleanup:

```bash
defenseclaw sandbox legacy-cleanup --dry-run
defenseclaw sandbox legacy-cleanup
```

Cleanup stops the systemd units itself but changes nothing else while any part
of the legacy sandbox still runs. Stop the non-systemd launcher first with
`sudo <data_dir>/scripts/run-sandbox.sh stop`.

The [published legacy sandbox cleanup guide](https://cisco-ai-defense.github.io/defenseclaw/docs/setup/sandbox/)
lists every step, the opt-in `--remove-user` and `--remove-binary` removals,
and the follow-up commands.

Until cleanup runs, a config that still says `openshell.mode: standalone` with
a non-localhost `guardrail.host` keeps the gateway API bound to that host
(an explicit `gateway.api_bind` still wins). While `openshell.mode: standalone`
remains, `/health` reports the `sandbox` subsystem as `degraded`, and
`defenseclaw doctor` and `defenseclaw status` point at
`defenseclaw sandbox legacy-cleanup`.

## Code ownership

| Concern | Source |
| --- | --- |
| `sandbox` command group | [`cli/defenseclaw/commands/cmd_sandbox.py`](../cli/defenseclaw/commands/cmd_sandbox.py) |
| Legacy detection, plan, apply, and receipt | [`cli/defenseclaw/sandbox_legacy.py`](../cli/defenseclaw/sandbox_legacy.py) |
| Legacy bind shim (Go, and its Python twin `legacy_standalone_api_host`) | [`internal/config/legacy_openshell.go`](../internal/config/legacy_openshell.go), [`cli/defenseclaw/config.py`](../cli/defenseclaw/config.py) |
