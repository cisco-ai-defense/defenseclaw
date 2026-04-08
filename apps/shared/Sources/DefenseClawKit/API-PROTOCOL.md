# DefenseClaw macOS App — API & Protocol Reference

Quick reference for debugging sidecar REST and gateway WebSocket interactions.

---

## Sidecar REST API (port 18970)

The Go sidecar (`internal/gateway/api.go`) serves a local REST API. All endpoints
(except `GET /health`) require `Authorization: Bearer <token>` header.

### Token Resolution Order

1. `~/.defenseclaw/config.yaml` → `gateway.token`
2. `~/.defenseclaw/config.yaml` → `gateway.token_env` (env var name)
3. `~/.openclaw/openclaw.json` → `gateway.auth.token` (fallback)

### Key Endpoints

#### GET /tools/catalog

**Chain**: macOS app → sidecar REST → WS RPC `tools.catalog` → OpenClaw gateway

**Response** (array — raw passthrough from gateway):
```json
[
  {
    "name": "Bash",
    "source": "builtin",
    "description": "Run shell commands",
    "parameters": { "command": { "type": "string" } }
  },
  {
    "name": "Read",
    "source": "builtin",
    "description": "Read files"
  }
]
```

**Swift model** (`ToolEntry`):
- `name: String` — required, also used as `id`
- `source: String?` — "builtin", "skill", or "mcp"
- `description: String?`
- `parameters: [String: AnyCodable]?`
- `blocked: Bool?`
- NO `id` field in JSON — computed from `name`

#### POST /api/v1/inspect/tool

**Request**: `{ "tool": "<tool-name>" }`
**Response**: Free-form JSON with policy verdict, CodeGuard findings, etc.

#### GET /health

No auth required. Returns `HealthSnapshot`.

#### GET /alerts

Returns `[Alert]` — scan findings, enforcement events.

#### GET /skills

Returns `[Skill]` — installed skills with status.

#### GET /mcps

Returns `[MCPServer]` — registered MCP servers.

#### PATCH /v1/guardrail/config

**Request**: `{ "mode": "...", "scanner_mode": "...", "block_message": "..." }`
All fields optional.

---

## Gateway WebSocket (port 18789)

OpenClaw gateway uses a v3 WebSocket protocol with JSON frames.

### Frame Types

| Type    | Direction          | Purpose                                     |
|---------|--------------------|---------------------------------------------|
| `req`   | client → gateway   | RPC request: `{ type, id, method, params }` |
| `res`   | gateway → client   | RPC response: `{ type, id, ok, payload }`   |
| `event` | gateway → client   | Broadcast: `{ type, event, payload }`       |
| `chat`  | client → gateway   | User message (NOT an RPC — raw frame)       |

### Connect Handshake

1. Client dials `ws://127.0.0.1:18789`
2. Gateway sends `event: connect.challenge` with `{ nonce, ts }`
3. Client sends `req: connect` with:

```json
{
  "type": "req",
  "id": "<uuid>",
  "method": "connect",
  "params": {
    "minProtocol": 3,
    "maxProtocol": 3,
    "client": {
      "id": "gateway-client",
      "version": "1.0.0",
      "platform": "darwin",
      "mode": "backend"
    },
    "role": "operator",
    "scopes": ["operator.read", "operator.write", "operator.admin", "operator.approvals"],
    "caps": ["tool-events", "session-events"],
    "auth": { "token": "<gateway-token>" },
    "device": {
      "id": "<sha256-hex-of-pubkey>",
      "publicKey": "<base64url-ed25519-pubkey>",
      "signature": "<base64url-ed25519-sig>",
      "signedAt": 1712108884000,
      "nonce": "<from-challenge>"
    },
    "userAgent": "defenseclaw-macos/1.0.0",
    "locale": "en-US"
  }
}
```

**Critical fields**:
- `client.id` MUST be `"gateway-client"` (not a random UUID)
- `auth` must NOT contain `nonce` (only `token`)
- `scopes` MUST include `operator.admin` for chat to work
- `device` block required — Ed25519 challenge-response

### Signature Payload (v3)

Pipe-delimited string signed with Ed25519 private key:
```
v3|{deviceID}|{clientID}|{clientMode}|{role}|{scopes-comma-joined}|{signedAtMs}|{token}|{nonce}|{platform}|{deviceFamily}
```
- `deviceFamily` is empty string
- Signature is base64url-encoded (no padding, `-` and `_` alphabet)

### Sending Chat Messages

Messages are sent as **raw WebSocket frames**, NOT as RPC calls:

```json
{
  "type": "chat",
  "payload": {
    "role": "user",
    "content": [
      { "type": "text", "id": "<uuid>", "text": "Hello" }
    ],
    "timestamp": "2026-04-02T23:48:44Z"
  }
}
```

**Common mistake**: Using `sendRPCAsync("chat.send", ...)` — this sends
`{ type: "req", method: "chat.send" }` which the gateway rejects as
"unknown method". Messages must be `type: "chat"` frames.

### RPC Methods (operator role)

| Method                         | Params                      | Description                    |
|--------------------------------|-----------------------------|--------------------------------|
| `connect`                      | protocol, client, auth, ... | Initial handshake              |
| `skills.update`                | `{ skillKey, enabled }`     | Enable/disable a skill         |
| `config.get`                   | *(none)*                    | Fetch gateway config           |
| `config.patch`                 | `{ path, value }`           | Partial config update          |
| `status`                       | *(none)*                    | Runtime status                 |
| `tools.catalog`                | *(none)*                    | Tool catalog with provenance   |
| `sessions.list`                | *(none)*                    | Active sessions                |
| `sessions.subscribe`           | `{ sessionId }`             | Subscribe to session events    |
| `sessions.messages.subscribe`  | `{ sessionId }`             | Subscribe to message events    |
| `exec.approval.resolve`        | `{ id, decision }`          | Approve/reject exec request    |

### Event Types

| Event                    | Payload                              | Notes                    |
|--------------------------|--------------------------------------|--------------------------|
| `connect.challenge`      | `{ nonce, ts }`                      | Handshake only           |
| `tool_call`              | `{ tool, args, status }`             | Tool invocation          |
| `tool_result`            | `{ tool, output, exit_code }`        | Tool completion          |
| `exec.approval.requested`| `{ id, systemRunPlan }`              | Needs user decision      |
| `session.message`        | `{ message: { role, content } }`     | Chat message from agent  |
| `session.tool`           | `{ data: { type, name, ... } }`      | Tool stream              |
| `agent`                  | `{ stream: "text"/"tool"/"lifecycle"}`| Streaming events         |
| `chat`                   | `{ state, sessionKey }`              | Chat lifecycle           |
| `sessions.changed`       | `{ sessionKey }`                     | New session appeared     |
| `tick`                   | *(empty)*                            | Keepalive                |

---

## Device Identity

Ed25519 keypair at `~/.defenseclaw/device.key` (or `gateway.device_key_file` in config).

- PEM format: `-----BEGIN ED25519 PRIVATE KEY-----` wrapping 32-byte seed
- Device ID: SHA-256 hex of raw public key (64 hex chars)
- Public key transmitted as base64url (no padding)
- Auto-generated on first run if missing

---

## Debugging Checklist

1. **401 on sidecar**: Check token resolution — is `~/.openclaw/openclaw.json` present?
2. **Connect handshake fails**: Check `client.id` is `"gateway-client"`, no `nonce` in `auth`
3. **"missing scope"**: Ensure `operator.admin` is in scopes
4. **"unknown method"**: Chat messages must be `type: "chat"` frames, not RPC
5. **Tools decode error**: Log raw response — check if JSON fields match `ToolEntry` model
6. **"device identity required"**: Check `~/.defenseclaw/device.key` exists and is valid PEM
