# internal/gateway — Specification

The gateway package implements a persistent sidecar process that connects
DefenseClaw to the OpenClaw gateway over WebSocket. It provides real-time
event monitoring, exec approval enforcement, skill lifecycle control, and a
local REST API for CLI and plugin integration.

## Architecture Overview

```
                ┌──────────────────────────────────────────────────┐
                │                    Sidecar                       │
                │                                                  │
 OpenClaw GW    │  ┌────────┐   ┌─────────────┐   ┌───────────┐  │   CLI / Plugins
 (WebSocket) ◄──┼─►│ Client │──►│ EventRouter │──►│ AuditStore │  │
                │  └────────┘   └──────┬──────┘   └───────────┘  │
                │       │              │                          │
                │       │       ┌──────┴──────┐                   │
                │       │       │ PolicyEngine│                   │
                │       │       └─────────────┘                   │
                │       │                                         │
                │  ┌────┴───────┐  ┌────────────┐                 │
                │  │ APIServer  │  │  Watcher   │                 │
                │  │ (REST API) │  │ (fsnotify) │                 │
                │  └────────────┘  └────────────┘                 │
 localhost:     │       ▲                │                         │
 api_port   ◄──┼───────┘                │ handleAdmissionResult   │
                │                        ▼                         │
                │               client.DisableSkill()             │
                └──────────────────────────────────────────────────┘
```

The Sidecar runs three independent subsystems as goroutines:

1. **Gateway connection loop** — maintains the WebSocket link with automatic
   reconnection and exponential backoff.
2. **Skill/MCP watcher** — monitors filesystem directories for new skill
   installs and runs the admission gate. Opt-in via config.
3. **REST API server** — exposes `/health`, `/status`, and skill/config
   mutation endpoints on localhost.

Each subsystem is fault-isolated: a gateway disconnect does not stop the
watcher or API server. Shutdown is coordinated via context cancellation.

## Files

| File | Purpose |
|------|---------|
| `sidecar.go` | Top-level orchestrator. Creates client, router, watcher; runs all three subsystems; handles watcher verdicts. |
| `client.go` | WebSocket client. Protocol v3 handshake, read loop, request/response multiplexing, reconnection with backoff. |
| `device.go` | Ed25519 device identity. Key generation, PEM persistence, challenge-response signing. |
| `frames.go` | Wire format types. Request, response, event frames and all payload structs. |
| `router.go` | Event dispatcher. Routes gateway events to handlers; dangerous command detection; exec approval gate. |
| `rpc.go` | High-level RPC methods. `DisableSkill`, `EnableSkill`, `GetConfig`, `PatchConfig`, `GetStatus`, `GetToolsCatalog`, `ResolveApproval`. |
| `api.go` | Local REST API server. Health, status, skill enable/disable, config patch endpoints. |
| `health.go` | Subsystem health tracker. Thread-safe state machine with snapshots for the API. |

## WebSocket Protocol (v3)

### Connection Handshake

```
Client                              Gateway
  │                                    │
  │──── WebSocket dial ───────────────►│
  │◄─── HTTP 101 Upgrade ─────────────│
  │                                    │
  │◄─── event: connect.challenge ──────│  { nonce, ts }
  │                                    │
  │──── req: connect ─────────────────►│  { protocol, client, role,
  │     (signed device identity)       │    scopes, auth, device }
  │                                    │
  │◄─── res: hello-ok ────────────────│  { protocol, features,
  │                                    │    auth, policy }
  │                                    │
  │     [read loop active]             │
```

1. Client dials `ws://host:port`.
2. Gateway sends a `connect.challenge` event containing a random `nonce`.
3. Client builds a connect request with protocol version, role, scopes,
   auth token, and a device identity block containing the Ed25519 public
   key and a signature over a deterministic v3 payload (see below).
4. Gateway verifies the signature, returns `hello-ok` with negotiated
   features, auth confirmation, and policy (e.g. tick interval).
5. Read loop starts dispatching events.

### Device Authentication

Each sidecar instance has a persistent Ed25519 keypair stored as PEM at
the path configured by `gateway.device_key_file`. On first run, a new
keypair is generated automatically.

The challenge-response signature is computed over a pipe-delimited string:

```
v3|{deviceID}|{clientID}|{clientMode}|{role}|{scopes}|{signedAtMs}|{token}|{nonce}|{platform}|{deviceFamily}
```

The `DeviceID` is the hex-encoded SHA-256 fingerprint of the raw public key.
The signature is base64url-encoded (no padding).

### Frame Types

All frames are JSON objects with a `type` discriminator:

| Type | Direction | Purpose |
|------|-----------|---------|
| `req` | client → gateway | RPC request (`id`, `method`, `params`) |
| `res` | gateway → client | RPC response (`id`, `ok`, `payload` or `error`) |
| `event` | gateway → client | Broadcast event (`event`, `payload`, optional `seq`) |

Request/response pairs are correlated by UUID `id`. The client maintains a
`pending` map of in-flight request channels; the read loop delivers responses
by matching IDs. Context cancellation cleans up pending entries.

Events carry an optional monotonic `seq` number. The client tracks `lastSeq`
and logs gaps for observability.

### RPC Methods

| Method | Params | Description |
|--------|--------|-------------|
| `connect` | protocol, client, role, scopes, auth, device | Initial handshake |
| `skills.update` | `{ skillKey, enabled }` | Enable or disable a skill at the gateway |
| `config.get` | *(none)* | Fetch current gateway configuration |
| `config.patch` | `{ path, value }` | Apply a partial config update |
| `status` | *(none)* | Fetch gateway runtime status |
| `tools.catalog` | *(none)* | Fetch the runtime tool catalog with provenance |
| `exec.approval.resolve` | `{ id, approved, reason }` | Approve or reject an exec request |

### Event Types

| Event | Payload | Handler Action |
|-------|---------|----------------|
| `connect.challenge` | `{ nonce, ts }` | Consumed during handshake only |
| `tool_call` | `{ tool, args, status }` | Logged to audit; flagged if tool is `shell`/`exec`/`system.run` with dangerous args |
| `tool_result` | `{ tool, output, exit_code }` | Logged to audit |
| `exec.approval.requested` | `{ id, systemRunPlan }` | Dangerous commands denied; safe commands optionally auto-approved |
| `tick` | *(empty)* | Keepalive, no action |

## Event Router

The `EventRouter` dispatches events received from the gateway read loop.

### Dangerous Command Detection

Tool calls and exec approval requests are scanned for dangerous patterns.
Only tools named `shell`, `system.run`, or `exec` are checked. Detection is
case-insensitive substring matching against a static pattern list:

```
curl, wget, nc , ncat, netcat, /dev/tcp,
base64 -d, base64 --decode, eval , bash -c, sh -c,
python -c, perl -e, ruby -e, rm -rf /, dd if=, mkfs,
chmod 777, > /etc/, >> /etc/, passwd, shadow, sudoers
```

**Tool calls**: flagged events are logged but not blocked (the call has
already been initiated by the agent).

**Exec approvals**: dangerous commands are actively denied via
`exec.approval.resolve` with `approved=false`. Safe commands are
auto-approved when `gateway.auto_approve_safe` is `true`; otherwise the
request is left unresolved (manual approval via the gateway UI).

## Reconnection Strategy

`ConnectWithRetry` implements exponential backoff:

- Initial delay: `gateway.reconnect_ms` (default from config)
- Growth factor: 1.7x per attempt
- Maximum delay: `gateway.max_reconnect_ms`
- Runs indefinitely until context cancellation

The sidecar's gateway loop wraps `ConnectWithRetry` in an outer loop that
also handles post-connection disconnects via the `Disconnected()` channel.
The health tracker transitions through `reconnecting → running → reconnecting`
on each cycle.

## Watcher Integration

When `gateway.watcher.enabled` is `true`, the sidecar starts an
`InstallWatcher` that monitors skill directories via fsnotify. Skill
directories are resolved in order:

1. Explicit `gateway.watcher.skill.dirs` from config
2. Autodiscovered via `config.SkillDirs()` (OpenClaw workspace/global paths)

When the watcher produces an `AdmissionResult` with a `blocked` or
`rejected` verdict for a skill, and `gateway.watcher.skill.take_action` is
`true`, the sidecar calls `client.DisableSkill()` to deactivate the skill
at the gateway level. When `take_action` is `false`, the verdict is logged
but no gateway action is taken.

Non-skill events (e.g. MCP installs) and non-blocking verdicts (clean,
allowed, warning) are ignored by the admission handler.

## REST API

The API server binds to `127.0.0.1:{gateway.api_port}` (localhost only).
All responses are `application/json`.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Subsystem health snapshot (gateway, watcher, API states + uptime) |
| `/status` | GET | Health snapshot + gateway hello payload (if connected) |
| `/skill/disable` | POST | Disable a skill at the gateway. Body: `{ "skillKey": "..." }` |
| `/skill/enable` | POST | Enable a skill at the gateway. Body: `{ "skillKey": "..." }` |
| `/config/patch` | POST | Patch gateway config. Body: `{ "path": "...", "value": ... }` |

Skill and config endpoints proxy RPCs through the connected gateway client.
If the gateway is not connected, they return `503 Service Unavailable`. If
the gateway rejects the RPC, they return `502 Bad Gateway`. All mutations
are logged to the audit store.

## Health Tracking

`SidecarHealth` is a thread-safe (RWMutex) state machine tracking three
subsystems independently:

| Subsystem | States |
|-----------|--------|
| Gateway | starting → reconnecting → running → error → stopped |
| Watcher | starting → running → disabled → error → stopped |
| API | starting → running → error → stopped |

Each state transition records a timestamp (`Since`) and optional error
message / details map. The `Snapshot()` method returns a consistent
point-in-time view including uptime.

## Configuration

All gateway settings live under the `gateway` key in
`~/.defenseclaw/config.yaml`:

```yaml
gateway:
  host: "127.0.0.1"
  port: 18789
  token: ""                    # OpenClaw auth token
  device_key_file: "~/.defenseclaw/device.key"
  auto_approve_safe: false     # auto-approve non-dangerous exec requests
  reconnect_ms: 2000           # initial reconnect delay
  max_reconnect_ms: 30000      # max reconnect delay
  approval_timeout_s: 30       # unused in v1 (reserved)
  api_port: 18790              # local REST API port
  watcher:
    enabled: false
    skill:
      enabled: true
      take_action: false       # disable skills at gateway on block/reject
      dirs: []                 # explicit dirs override autodiscovery
```

## Concurrency Model

- **Read loop**: single goroutine per connection, reads WebSocket frames
  and dispatches to pending channels (responses) or `OnEvent` callback
  (events). Terminates on read error or connection close.
- **Pending requests**: `sync.Mutex`-protected map of `id → chan`. Write
  path registers a channel, sends the frame, and blocks on the channel or
  context cancellation. Read loop delivers by ID lookup.
- **Disconnect signaling**: `sync.Once`-guarded channel close. Both the
  read loop (on error) and `Close()` call `signalDisconnect()`.
- **Health tracker**: `sync.RWMutex` protects all three subsystem states.
  Writers take exclusive lock; `Snapshot()` takes read lock.
- **Sidecar subsystems**: three independent goroutines coordinated by a
  shared context and `sync.WaitGroup`. First error is captured via a
  buffered channel.

## Testing

Tests are split across two files:

- `gateway_test.go` — unit tests for health, frames, device identity,
  dangerous pattern detection, client helpers, and API handler error paths.
  No external dependencies.
- `gateway_ws_test.go` — integration tests using a mock WebSocket server
  (`httptest.Server` + gorilla/websocket upgrader) that simulates the full
  v3 handshake. Covers the connect flow, all RPC methods, approval routing,
  API success paths, and sidecar admission result handling.

Run with: `make gateway-test` or `go test -race ./internal/gateway/`
