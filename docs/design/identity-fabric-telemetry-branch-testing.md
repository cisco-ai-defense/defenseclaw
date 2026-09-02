# Identity Fabric telemetry: branch testing notes

Branch: `feature/identity-fabric-telemetry` (not for merge)

AI Defense has no ingest endpoint for these records yet, so this branch writes
each record to disk exactly as it would have been sent. The purpose of the
branch is to inspect that output on macOS and Windows before any transport is
built.

## What gets captured

Two Astrix-shaped models, defined in `internal/idfabric/schema.go`:

| Model | Written on | Filename prefix |
|---|---|---|
| `DefenseClawAgentEvent` (`session_start`) | agent session start | `agentevent-<connector>-session_start-` |
| `DefenseClawAgentEvent` (`pre_tool_use`) | every tool call | `agentevent-<connector>-pre_tool_use-` |
| `DefenseClawAgent` (inventory) | agent session start | `agent-<connector>-inventory-` |

The inventory record reuses the same discovery pass as its `session_start`
sibling rather than reading the config tree twice.

Connectors in scope: `codex`, `claudecode`, `cursor`. Any other connector, and
any event other than the two above, is skipped silently.

## Where capture runs, and why it matters

Capture runs **in the hook process**, from `internal/cli/hook.go`, not in the
sidecar. Only the hook has the real user's token, home directory, and the
agent's workspace. In managed enterprise the sidecar runs as LocalSystem, so
collecting there would report the service account as the user and would look
for MCP config in the wrong home.

The consequence to keep in mind while testing: `user.sid` / `user.uid` describe
whoever ran the agent, which is the intended join key.

## Enabling it

Capture is a managed-enterprise feature and is off by default. It turns on when
any of these hold:

- the hook was invoked with `--enterprise-managed`
- `deployment_mode` is `managed_enterprise`
- `DEFENSECLAW_DEPLOYMENT_MODE=managed_enterprise`
- `DEFENSECLAW_IDFABRIC_SPOOL=1` — test-only override, not a supported
  configuration surface

While disabled the code path costs one environment lookup and does not touch
stdin, so a non-enterprise endpoint behaves exactly as it does on `main`.

## Output location

`$DEFENSECLAW_HOME/aid-spool/` (default `~/.defenseclaw/aid-spool/`), or
`DEFENSECLAW_IDFABRIC_SPOOL_DIR` when set. Files are mode 0600, owner-only
directory, written through an atomic replace so a partial JSON document is
never observable. The spool stops writing at 5000 files rather than evicting
evidence.

Filenames are `<model>-<connector>-<event>-<UTC timestamp>-<nonce>.json`. The
connector and event components are sanitized to `[a-z0-9_-]`: the event name
can originate in agent-controlled hook JSON, so it is never trusted as a path
component.

## macOS smoke test

```bash
go build -o /tmp/defenseclaw ./cmd/defenseclaw
export DEFENSECLAW_HOME=/tmp/dc-idfabric && mkdir -p "$DEFENSECLAW_HOME"
export DEFENSECLAW_IDFABRIC_SPOOL=1

echo '{"session_id":"smoke-1","model":"gpt-5-codex","cwd":"'"$PWD"'"}' \
  | /tmp/defenseclaw hook --connector codex --event session_start --api-addr 127.0.0.1:1

echo '{"session_id":"smoke-1","tool_name":"mcp__github__create_issue","tool_input":{"title":"x"}}' \
  | /tmp/defenseclaw hook --connector codex --event pre_tool_use --api-addr 127.0.0.1:1

ls -l "$DEFENSECLAW_HOME/aid-spool"
```

An unreachable `--api-addr` is intentional: capture happens before the gateway
request, so records are written even when the guardrail fails open. Expect
`user.uid` to be your effective UID and `user.sid` to be absent.

## Windows check

Run the same events through the installed enterprise hook as `dcstd`, then read
`C:\Users\dcstd\.defenseclaw\aid-spool\`. Expect `user.sid` to be that
account's SID and `user.uid` to be absent. The SID comes from the thread token
first, so a hook impersonating a manifest-pinned SID reports the impersonated
user rather than the process owner.

## What to check in the output

- `user.sid` on Windows / `user.uid` elsewhere, never both
- `authenticated_user_email` present only when the connector's own account file
  supplies it. Claude Code reads `oauthAccount.emailAddress`; Codex reads the
  `email` claim from the ID token in `auth.json`; Cursor reads `user_email` from
  its payload. It is absent when Codex keeps credentials only in the OS
  credential store. This is attribution evidence, not identity attestation.
- `device.id` is the existing Ed25519 fingerprint. The hook never mints one, so
  an endpoint with no `device.key` reports an empty id rather than a second,
  competing identity.
- `mcp_discovery_status` — `complete` only when every config layer was read or
  authoritatively absent. An unreadable layer yields `partial`/`error` so an
  incomplete scan is never mistaken for an empty inventory.
- `mcp_servers[].url` is reduced to `scheme://host[:port]`. Paths, queries, and
  user-info are dropped. A credential in the URL still shows up as
  `auth_method: basic` or `unknown` rather than `none`.
- Absent by design: prompt text, tool inputs, `cwd`, `env`, header values,
  OAuth blobs, and transcript paths. The workspace directory is used to locate
  MCP config and is never emitted.

Servers the agent has disabled are omitted and counted separately, because the
`mcp_server` shape has no disabled field and emitting them would overstate the
active surface.

## Known gaps

- No transport. Records only land on disk; wiring them to AI Defense is
  follow-up work.
- The `DefenseClawAgent` record is emitted on session start rather than on a
  periodic timer, so `first_seen`/`last_seen` aggregation is not exercised.
- Capture happens before the gateway request, so an event the guardrail later
  refuses (for example a hook missing its installer-bound contract) is still
  recorded.
