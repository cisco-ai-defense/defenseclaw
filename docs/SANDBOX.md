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

## OpenShell 0.1.1 spike findings

These are the platform facts the OpenShell 0.1 rebuild is designed around. They
were measured on one Linux arm64 host running OpenShell 0.1.1 (the upstream
installer, the Docker driver, and the `openshell-gateway` user service) in
September 2026.

### Bake-off status

The plan called for a bake-off of OpenShell 0.1.1 against Qpoint qcontrol on
the same scenario matrix. Only the OpenShell half was run: qcontrol was never
installed or measured. So the choice of OpenShell is not backed by a
side-by-side comparison. It rests on how qcontrol works (it hooks functions
inside the agent process, which gives observability and soft control but not
an isolation boundary) and on the OpenShell measurements below. The decision
should be reopened if a qcontrol run shows something OpenShell cannot do.
qcontrol may still be added later as an optional event source.

### Scenario matrix

| Scenario | OpenShell 0.1.1 | qcontrol |
| --- | --- | --- |
| Read host secrets (`~/.ssh`, `~/.aws`) | Host `/home` is not readable inside the sandbox; only explicit bind mounts are visible | Not measured |
| Write outside the project | Only bind mounts are visible; a read-only over-mount refuses writes ("Read-only file system") | Not measured |
| `rm -rf` in `$HOME` | Not run. `$HOME` inside the sandbox is `/sandbox`, which is sandbox-local | Not measured |
| Egress to an arbitrary host | Denied (`policy_dns_ineligible`, then `transparent_tcp_policy_denied`), and a draft policy proposal is filed | Not measured |
| Egress to the metadata IP `169.254.169.254` | Denied | Not measured |
| Egress to the host | Only through `host.openshell.internal`, relayed to host `127.0.0.1` | Not measured |
| DNS exfiltration | Not measured | Not measured |
| `env -i` children | Not measured | Not measured |
| Static busybox and raw-syscall variants of the above | Not run separately | Not measured |

### Networking

- `host.openshell.internal` resolves inside the sandbox to a synthetic address
  (`198.18.0.2`) that the supervisor relays to host `127.0.0.1`; the host
  service sees the client as `127.0.0.1`.
- A `protocol: tcp` rule alone for a CONNECT proxy on `host.openshell.internal`
  is refused by the HTTP parser. `protocol: tcp` with `tls: skip` is a raw
  relay, and HTTPS through a CONNECT proxy on the host then works end to end.
  The DefenseClaw egress proxy is reached through that rule.
- A binary glob of `/**` is accepted. A catch-all host `**.*.*` is accepted
  but only covers hosts with three or more labels.
- Through the relay, `HTTPS_PROXY` is honored by curl, node `fetch` (with
  `NODE_USE_ENV_PROXY=1`), npm, pip, uv, git over HTTPS, and Python urllib.
- Any network policy update, even an unrelated rule, closes in-flight
  connections. They are also closed about 10 to 12 seconds after every sandbox
  start (the first settings poll) and on every global profile import. So the
  design keeps egress decisions in the DefenseClaw proxy, batches OpenShell
  policy updates, imports profiles once at setup, and starts a harness only
  after the first settings poll (about 15 seconds).
- The relay occasionally drops a request (about 0.3 to 0.7 percent under
  concurrency), so hooks need a short timeout and one retry with an
  idempotency key before they fail closed, and the ingress must deduplicate
  by that key.

### Credentials

- A credential placeholder in the sandbox environment is opaque and scoped to
  a policy revision (`openshell:resolve:env:v<revision>_<KEY>`). It is
  substituted in any header and in the query string on bound endpoints,
  including plain-HTTP `protocol: rest` endpoints, but not in bodies. An
  unversioned placeholder gets HTTP 500 (fail closed). Hooks and OTEL
  exporters therefore read the variable at run time; placeholders cannot be
  baked into static config.
- Provider profiles are imported one file at a time with
  `openshell profile import -f <file> --global`; their rules show up as
  `_provider_<name>`.

### Images and mounts

- `--from <local tag>` uses the local image. Image `ENV` is not propagated;
  `sandbox create --env` is.
- Bind mounts need `allow_driver_config` and `enable_bind_mounts` for the
  Docker driver, and Docker resource admission turned off, in the gateway's
  `gateway.toml`, followed by a restart of the gateway service. A read-only
  over-mount (for example of `.git/hooks`) refuses writes, a bind-mounted file
  is effectively read-only, and an empty-file mask over `.env` reads as empty.
- `process.run_as_user` sets the process uid; files written to a bind mount
  are owned on the host by that uid.
- Image content under `/sandbox` is owned by uid 998, so an overlay must chown
  `/sandbox` to the run-as uid. Otherwise writes to `~/.claude` fail and
  Claude Code's `SessionStart` hook silently does not run.
- Landlock hides `/dev` entries that are not listed. PTY tools need
  `/dev/ptmx`, `/dev/pts`, and `/dev/tty` in `read_write`.

### Streams and the CLI

- `WatchSandbox` log lines arrive at level `OCSF` with structured `fields`
  unset, so the shorthand message text is parsed. The cursor format is
  `v1:<uuid>:<20-digit sequence>`. A gateway restart drops the in-memory log
  buffer.
- `openshell sandbox exec` occasionally produces no output on the first call
  after create, so execs use a timeout and a retry and wait for the `Ready`
  and `ConfigurationReady` conditions. `sandbox exec` and `sandbox upload`
  hang while stdin is an open non-TTY pipe, so stdin is always `/dev/null`.

### Harnesses

- **Claude Code 2.1.156.** Managed settings come from
  `/etc/claude-code/managed-settings.json` and the sorted, deep-merged
  `managed-settings.d/*.json`. A drop-in with one schema-invalid field is
  dropped whole and silently, so image builds probe that hooks fire.
  `SessionStart`, `UserPromptSubmit`, `PreToolUse`, `PostToolUse`, `Stop`, and
  `SessionEnd` fire; a deny works through `permissionDecision: "deny"` or exit
  code 2, and an unreachable ingress denies the tool within about a second.
  With `allowManagedHooksOnly: true`, user, project, and command-line settings
  cannot turn managed hooks off. The one gap is Claude's simple/bare mode,
  which disables all hooks. A managed `env` of `CLAUDE_CODE_SIMPLE=0` restores
  every hook except `SessionStart`; the planned mitigation pairs it with a
  DefenseClaw rule that flags bare invocations. Startup variables such as
  `DISABLE_AUTOUPDATER=1` must be passed with `sandbox create --env`, because
  managed `env` applies too late.
- **Codex 0.146.0.** `/etc/codex/requirements.toml` needs
  `allow_managed_hooks_only = true` and `[features] hooks = true` (without the
  feature flag a user setting can turn hooks off). `/etc/codex/managed_config.toml`
  takes precedence on Linux. Codex's own sandbox cannot run inside OpenShell,
  so Codex runs with `--dangerously-bypass-approvals-and-sandbox`. `exec` mode
  authenticates with `CODEX_API_KEY`.

## Code ownership

| Concern | Source |
| --- | --- |
| `sandbox` command group | [`cli/defenseclaw/commands/cmd_sandbox.py`](../cli/defenseclaw/commands/cmd_sandbox.py) |
| Legacy detection, plan, apply, and receipt | [`cli/defenseclaw/sandbox_legacy.py`](../cli/defenseclaw/sandbox_legacy.py) |
| Legacy bind shim (Go, and its Python twin `legacy_standalone_api_host`) | [`internal/config/legacy_openshell.go`](../internal/config/legacy_openshell.go), [`cli/defenseclaw/config.py`](../cli/defenseclaw/config.py) |
