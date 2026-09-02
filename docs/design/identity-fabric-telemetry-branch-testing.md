# Identity Fabric telemetry: branch testing plan

Branch: `feature/identity-fabric-telemetry` (not for merge)
Base: `origin/main` at `74fddaee`

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

Nine reference records — every connector and event, both models — are committed
under `internal/idfabric/testdata/samples/`. Read those first; they are what a
correct run looks like, with host-specific values replaced by placeholders.

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

Only the first of those reaches an installed hook today: managed hooks are
registered with `--enterprise-managed`, while the deployment mode is pinned
into the *service* environment that an agent-spawned hook does not inherit.

Two different code paths deliver that flag, because the two platforms invoke
hooks differently:

| Platform | Hook invocation | Where capture happens |
| --- | --- | --- |
| Windows | native `<exe> hook --connector <name>` | inline, in the hook process |
| macOS / Linux | bundled `.sh` script that `curl`s the gateway | `defenseclaw idfabric capture`, backgrounded by the script |

The Unix path needs the separate subcommand because the shell hooks never run
the native `hook` command, and capture cannot move to the gateway: the gateway
is a LaunchDaemon running as root with its own home, so it would attribute
every session on the machine to that one identity.

While disabled the code path costs one environment lookup and does not touch
stdin, so a non-enterprise endpoint behaves exactly as it does on `main`.

## Output location

Per-user state, following each platform's convention, or
`DEFENSECLAW_IDFABRIC_SPOOL_DIR` when set:

| Platform | Directory |
| --- | --- |
| macOS | `~/Library/Application Support/DefenseClaw/aid-spool/` |
| Windows | `%LOCALAPPDATA%\DefenseClaw\aid-spool\` |
| Linux | `${XDG_STATE_HOME:-~/.local/state}/DefenseClaw/aid-spool/` |

This is deliberately **not** derived from the DefenseClaw home. In managed
enterprise mode the home is the machine state root under `ProgramData`, whose
DACL grants SYSTEM, Administrators, and the gateway service account only —
nothing to `Users`, with inheritance protected. A hook running as the
interactive user cannot create a directory there, so a home-derived spool
failed in exactly the mode capture is gated to. Per-user state is also where
per-user records belong, and it stays collectable per profile.

It is not `~/.defenseclaw`: the Unix hook scripts read that path's existence as
"an unmanaged install is present", so creating it on a managed endpoint would
change how a stray unmanaged hook behaves.

The tradeoff is that a user can delete their own pending records. That is
acceptable for a pre-ingest staging buffer that disappears once AI Defense
ingest exists; tamper-evident retention belongs to the audit store.

Files are mode 0600, owner-only
directory, written through an atomic replace so a partial JSON document is
never observable. The spool stops writing at 5000 files rather than evicting
evidence.

Filenames are `<model>-<connector>-<event>-<UTC timestamp>-<nonce>.json`. The
connector and event components are sanitized to `[a-z0-9_-]`: the event name
can originate in agent-controlled hook JSON, so it is never trusted as a path
component.

---

# Part 1 — macOS

Already exercised on macOS; these steps reproduce it.

```bash
git fetch origin
git checkout feature/identity-fabric-telemetry

go test ./internal/idfabric/ ./internal/cli/ -run 'TestCapture|TestDiscover|TestValidateEmail|TestSpool'
go build -o /tmp/defenseclaw ./cmd/defenseclaw

export DEFENSECLAW_IDFABRIC_SPOOL=1
export DEFENSECLAW_IDFABRIC_SPOOL_DIR=/tmp/dc-idfabric-spool

echo '{"session_id":"smoke-1","model":"gpt-5-codex","cwd":"'"$PWD"'"}' \
  | /tmp/defenseclaw hook --connector codex --event session_start --api-addr 127.0.0.1:1

echo '{"session_id":"smoke-1","tool_name":"mcp__github__create_issue","tool_input":{"title":"x"}}' \
  | /tmp/defenseclaw hook --connector codex --event pre_tool_use --api-addr 127.0.0.1:1

ls -l "$DEFENSECLAW_IDFABRIC_SPOOL_DIR"
```

An unreachable `--api-addr` is intentional: capture happens before the gateway
request, so records are written even when the guardrail fails open. Expect
`user.uid` to be your effective UID and `user.sid` to be absent.

Leaving `DEFENSECLAW_IDFABRIC_SPOOL_DIR` unset writes to the real per-user
location in the table above instead, which is what an installed hook uses.

Two things to know before reading the output. This run discovers MCP servers
from *your* real `~/.codex`, `~/.claude.json`, and `~/.cursor`, so the
`mcp_servers` list is a live inventory rather than a fixture — useful for
checking sanitization against genuine config. And `--connector` selects which
config layers are consulted, so the same command run for `codex`, `claudecode`,
and `cursor` should produce three different inventories.

To exercise a real agent session rather than synthetic payloads, the install
must be managed: the capture call is rendered into the `.sh` hooks only under
`{{if .Managed}}`, so an unmanaged macOS install captures nothing regardless of
`DEFENSECLAW_IDFABRIC_SPOOL`. For an unmanaged endpoint, drive the subcommand
directly as shown under "Verifying the macOS capture path".

---

# Part 2 — Windows

The Windows SID path is the only surface with no runtime coverage. It compiles
and is vet-clean for `windows/amd64`, but `OSIdentity()`'s thread-token lookup
has never executed. That is the main thing this run proves.

## Step 1 — Get the branch onto the VM

Connect over the Bastion tunnel, then in the repo clone:

```powershell
git fetch origin
git checkout feature/identity-fabric-telemetry
git log --oneline -1   # expect e6ad81c4
```

If the VM has no clone yet:

```powershell
git clone https://github.com/cisco-ai-defense/defenseclaw.git
cd defenseclaw
git checkout feature/identity-fabric-telemetry
```

## Step 2 — Confirm the platform code runs at all

This is the cheapest possible signal that the SID path works, and it needs no
installer:

```powershell
go test ./internal/idfabric/ -run TestOSIdentityUsesPlatformJoinKey -v
```

The test asserts a non-empty `S-1-` prefixed SID and an absent UID. A failure
here means the token lookup is wrong and nothing else is worth running.

Then the rest of the suite plus the reference samples:

```powershell
go test ./internal/idfabric/ ./internal/cli/
$env:IDFABRIC_WRITE_SAMPLES = "1"
go test ./internal/idfabric/ -run TestCaptureHookEventSamples
git diff --stat internal/idfabric/testdata/samples
```

That diff is the useful artifact: it shows exactly how Windows records differ
from the committed macOS ones. Expect `sid` to replace `uid` and
`operating_system` to become `windows`; anything else differing is worth a
look. Discard the diff afterwards with
`git checkout -- internal/idfabric/testdata/samples`.

## Step 3 — Standalone hook run as `dcstd`

Build once as the admin account, then run the hook as the standard user so the
SID belongs to a non-admin:

```powershell
go build -o C:\Temp\defenseclaw.exe .\cmd\defenseclaw
```

As `dcstd`:

```powershell
$env:DEFENSECLAW_HOME = "$env:USERPROFILE\.defenseclaw"
New-Item -ItemType Directory -Force -Path $env:DEFENSECLAW_HOME | Out-Null
$env:DEFENSECLAW_IDFABRIC_SPOOL = "1"

'{"session_id":"win-1","model":"gpt-5-codex","cwd":"C:\\Users\\dcstd\\proj"}' |
  C:\Temp\defenseclaw.exe hook --connector codex --event session_start --api-addr 127.0.0.1:1

'{"hook_event_name":"PreToolUse","session_id":"win-1","tool_name":"mcp__github__create_issue"}' |
  C:\Temp\defenseclaw.exe hook --connector claudecode --api-addr 127.0.0.1:1

Get-ChildItem "$env:DEFENSECLAW_HOME\aid-spool"
Get-Content "$env:DEFENSECLAW_HOME\aid-spool\*session_start*.json"
```

Confirm `user.sid` matches `dcstd`:

```powershell
[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
```

## Step 4 — Enterprise-managed run

This is the only path that exercises the real gate rather than the env
override, and the only one where `is_policy_enforceable` should be `true`.

Install per the enterprise flow (`packaging/windows/install-enterprise.ps1`),
then drive real agent sessions as `dcstd` with the installed hooks and **no**
`DEFENSECLAW_IDFABRIC_SPOOL` set. Records land in
`C:\Users\dcstd\AppData\Local\DefenseClaw\aid-spool\`.

Check specifically that:

- capture happens with no env override, proving the managed gate works alone
- `is_policy_enforceable` is `true` (it is `false` under the env override,
  because an ordinary user-scope hook can be removed by the user)
- the spool is under the invoking user's `LOCALAPPDATA`, not under
  `ProgramData` and not under the service account's profile
- `device.id` is **expected to be absent**. The device key lives under the
  DefenseClaw home, which in managed mode is the machine state root the user
  cannot even traverse. Same root cause as the spool relocation, but this half
  cannot be fixed from the hook side — it needs either an ACL that lets users
  read the key, or the gateway supplying the fingerprint.

If capture produces nothing, collect `icacls "%LOCALAPPDATA%\DefenseClaw"` and
the stderr line `defenseclaw: identity fabric capture skipped (...)`, whose
reason names the stage that failed.

## Step 5 — Cursor on Windows

Cursor's Windows transport uses the generated PowerShell adapter and
`--input-file` rather than native stdin, which is a different code path through
capture. Run a real Cursor session and confirm records still appear.

## What to check in every record

- `user.sid` on Windows / `user.uid` elsewhere, never both
- `authenticated_user_email` present only when the connector's own account file
  supplies it. Claude Code reads `oauthAccount.emailAddress`; Codex reads the
  `email` claim from the ID token in `auth.json`; Cursor reads `user_email`
  from its payload. It is absent when Codex keeps credentials only in the OS
  credential store. This is attribution evidence, not identity attestation.
- `device.id` is the existing Ed25519 fingerprint. The hook never mints one, so
  an endpoint with no `device.key` omits the field rather than publishing a
  second, competing identity.
- `mcp_discovery_status` — `complete` only when every config layer was read or
  authoritatively absent. An unreadable layer yields `partial`/`error` so an
  incomplete scan is never mistaken for an empty inventory.
- `mcp_servers[].url` is reduced to `scheme://host[:port]`. Paths, queries, and
  user-info are dropped. A credential in the URL still shows up as
  `auth_method: basic` or `unknown` rather than `none`.
- `auth_method: unknown` is expected for servers read from Claude Code's
  `.claude.json` and from Codex `config.toml`: those parsers drop `headers` and
  `authProviderType`, so no auth evidence exists either way and claiming `none`
  would assert something never observed.
- Absent by design: prompt text, tool inputs, `cwd`, `env`, header values,
  OAuth blobs, and transcript paths. The workspace directory is used to locate
  MCP config and is never emitted.

Servers the agent has disabled are omitted and counted separately, because the
`mcp_server` shape has no disabled field and emitting them would overstate the
active surface.

## Open question to settle during the Cursor run

Cursor registers `preToolUse` **and** granular pre-action events
(`beforeShellExecution`, `beforeMCPExecution`, `beforeReadFile`). Capture maps
only `preToolUse`, on the assumption that both fire for the same call and
mapping the granular ones too would double-count every tool use.

If a real Cursor session produces `session_start` records but no
`pre_tool_use` records, that assumption is wrong and the granular events need
mapping in `eventKind`. Watch for this specifically.

## Known gaps

- The device fingerprint is unreadable in managed mode on Windows. `device.key`
  sits under the machine state root, which grants `Users` no traverse right, so
  managed Windows records omit `device.id`. Unlike the spool location, the hook
  cannot fix this from its own side. macOS records carry `device.id` because the
  key is in the user's own `~/.defenseclaw`.
- One short-lived process per hook event on macOS and Linux. The capture child
  is detached with its streams closed, so it adds no latency to the tool call
  and cannot hold the hook's stdout open, but it is a real process and shows up
  in process accounting.
- Records accumulate until something drains them. The spool caps its own total
  size, but nothing consumes these files yet — that is the transport this branch
  exists to specify.

## Verifying the macOS capture path

The Unix path has an interaction worth re-checking after any change to
`_hardening.sh`: `defenseclaw_harden_env` repoints `HOME` at an empty per-hook
sandbox and deletes it on exit. Capture reads the user's connector config,
account email, and device key out of the real profile, so it is invoked with
`HOME` restored. Getting this wrong does not fail loudly — it spools a
well-formed record claiming the user has no MCP servers and no email.

`TestIdentityFabricCaptureRunsWithTheUsersRealHome` pins it by running the real
helper against a stub CLI and asserting which `HOME` arrived. To confirm the
whole chain against your own config:

```bash
go build -o /tmp/defenseclaw ./cmd/defenseclaw
mkdir -p /tmp/idfabric-e2e/spool
cp internal/gateway/connector/hooks/_hardening.sh /tmp/idfabric-e2e/

cat > /tmp/idfabric-e2e/driver.sh <<'SCRIPT'
#!/bin/bash
set -euo pipefail
. /tmp/idfabric-e2e/_hardening.sh
defenseclaw_harden_env
PAYLOAD="{\"hook_event_name\":\"sessionStart\",\"cursor_version\":\"3.10.17\",\"session_id\":\"e2e-1\",\"cwd\":\"$REPO\"}"
defenseclaw_capture_identity_fabric /tmp/defenseclaw cursor sessionStart "$PAYLOAD"
wait
SCRIPT
chmod +x /tmp/idfabric-e2e/driver.sh

REPO="$PWD" DEFENSECLAW_IDFABRIC_SPOOL=1 \
  DEFENSECLAW_IDFABRIC_SPOOL_DIR=/tmp/idfabric-e2e/spool \
  /tmp/idfabric-e2e/driver.sh

ls /tmp/idfabric-e2e/spool
```

A record with a populated `mcp_servers` list, a `uid`, and a `device.id` means
the real home reached the capture child. An empty `mcp_servers` list on a
machine that has MCP servers configured means it did not.
- No transport. Records only land on disk; wiring them to AI Defense is
  follow-up work.
- The `DefenseClawAgent` record is emitted on session start rather than on a
  periodic timer, so `first_seen`/`last_seen` aggregation is not exercised.
  Per the proposal those fields, along with `created_at`, `updated_at`,
  `presence_status`, `agent.id`, and `models`, are AI Defense's to compute and
  are deliberately not sent.
- `is_policy_enforceable` cannot see whether the active policy mode permits
  intervention, so a managed hook in observe-only mode still reports `true`.
  Deciding that accurately needs the sidecar's policy view.
- Capture happens before the gateway request, so an event the guardrail later
  refuses (for example a hook missing its installer-bound contract) is still
  recorded.
