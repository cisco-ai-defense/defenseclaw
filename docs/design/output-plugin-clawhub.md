# Tech Spec: DefenseClaw Output Plugin for ClawHub

**Date:** 2026-04-28
**Status:** Proposed
**Author:** nghodki

---

## 1. Problem Statement

Today, wiring DefenseClaw security into an OpenClaw instance requires DefenseClaw to deploy its embedded plugin (`extensions/defenseclaw/`). This means the DefenseClaw operator must have access to the OpenClaw instance's filesystem to install the extension.

OpenClaw supports a marketplace model (ClawHub) where users can discover and install plugins independently. We need a **standalone, ClawHub-publishable plugin** that any OpenClaw administrator can install from ClawHub — without requiring DefenseClaw to push files onto their machine.

## 2. Goals

1. **Self-contained**: The plugin installs via ClawHub with zero DefenseClaw-side deployment.
2. **Full feature parity**: Fetch interceptor (15 LLM providers), tool inspection hooks, health monitoring, egress telemetry, scan/block/allow commands — everything the embedded version does.
3. **Remote sidecar support**: The embedded plugin assumes `localhost:18970`. The standalone plugin must support connecting to a DefenseClaw gateway running on a different host (e.g., a shared security gateway for a team).
4. **No collision with embedded**: If both the embedded and standalone plugins are present, they must not conflict. Slash commands are prefixed (`/dc-scan`, `/dc-block`, `/dc-allow`), and the plugin id is `defenseclaw-plugin`.
5. **ClawHub-ready packaging**: `package.json`, `openclaw.plugin.json`, and build artifacts follow ClawHub's publish requirements.

## 3. Non-Goals

- Replacing the embedded `extensions/defenseclaw/` plugin (it remains the primary mechanism for DefenseClaw-managed deployments).
- Building a ClawHub backend or registry service.
- Automated sidecar provisioning — the user is responsible for running a DefenseClaw gateway that is reachable from their OpenClaw instance.

## 4. Architecture

### 4.1 Directory Layout

```
defenseclaw/
  output-plugin/                          ← NEW top-level directory
    package.json                          ← npm package: @defenseclaw/openclaw-plugin
    openclaw.plugin.json                  ← OpenClaw manifest (id: defenseclaw-plugin)
    tsconfig.json                         ← TypeScript config (ES2022, ESM)
    CLAWHUB.md                            ← Step-by-step upload instructions
    README.md                             ← User-facing install & config guide
    src/
      index.ts                            ← Plugin entry point
      fetch-interceptor.ts                ← globalThis.fetch + https.request patching
      client.ts                           ← DaemonClient for sidecar REST API
      types.ts                            ← Shared TypeScript types
      correlation-headers.ts              ← X-DefenseClaw-* header constants & builders
      agent_identity.ts                   ← Stable agent id persistence
      sidecar-config.ts                   ← Config resolution (plugin config → env → file)
      health-monitor.ts                   ← Sidecar health polling
      egress-telemetry.ts                 ← Layer 3 egress event reporting
      aws-sdk-http1-for-guardrail.ts      ← Bedrock HTTP/1 shim
      bedrock-config-detect.ts            ← Bedrock usage detection
      providers.json                      ← Canonical LLM provider domains (copied from Go)
      policy/
        enforcer.ts                       ← PolicyEnforcer + scan runners
      scanners/
        mcp-scanner.ts                    ← In-process MCP config scanner
```

### 4.2 Relationship to Embedded Plugin

```
extensions/defenseclaw/          (EXISTING — deployed by DefenseClaw operator)
  ├── Assumes localhost sidecar
  ├── plugin id: "defenseclaw"
  ├── Slash commands: /scan, /block, /allow
  └── Config reads ~/.defenseclaw/config.yaml primarily

output-plugin/                   (NEW — installed by OpenClaw user from ClawHub)
  ├── Supports remote sidecar host
  ├── plugin id: "defenseclaw-plugin"
  ├── Slash commands: /dc-scan, /dc-block, /dc-allow
  └── Config comes from plugin configSchema (ClawHub settings UI)
```

Both can coexist. The output-plugin uses a distinct plugin id and command prefix. If both are active, they share the same sidecar — the gateway is stateless and handles concurrent plugin connections.

### 4.3 Data Flow

```
OpenClaw Agent (with output-plugin installed)
  │
  ├─── before_tool_call hook ──────────► DefenseClaw Gateway
  │    POST /api/v1/inspect/tool          (remote or local)
  │    X-DefenseClaw-* correlation         │
  │    ◄── { action, severity, reason } ───┘
  │
  ├─── globalThis.fetch patch ──────────► Guardrail Proxy (port 4000)
  │    Redirects LLM API calls             │
  │    X-DC-Target-URL: original host      ├─► Rule pack matching
  │    X-AI-Auth: provider key             ├─► LLM judge (optional)
  │    X-DefenseClaw-* correlation         ├─► Cisco AI Defense
  │    ◄── Response (+ x-defenseclaw-     ─┘
  │        blocked header if rejected)
  │
  ├─── health-monitor ─────────────────► GET /status (every 60s)
  │    Warns user if gateway is down
  │
  └─── egress-telemetry ──────────────► POST /v1/events/egress
       Reports passthrough/shape/known     (best-effort, non-blocking)
```

## 5. Detailed Changes

### 5.1 `openclaw.plugin.json` (Manifest)

```json
{
  "id": "defenseclaw-plugin",
  "name": "DefenseClaw Security (ClawHub)",
  "version": "0.1.0",
  "description": "Wire DefenseClaw security governance into any OpenClaw instance. Installs fetch interception, tool inspection hooks, and security scanning — no DefenseClaw-side deployment required.",
  "enabledByDefault": true,
  "configSchema": {
    "type": "object",
    "additionalProperties": false,
    "properties": {
      "agent": {
        "type": "object",
        "additionalProperties": false,
        "description": "Logical agent identity for sidecar correlation",
        "properties": {
          "id":       { "type": "string", "description": "Stable logical agent id" },
          "name":     { "type": "string", "description": "Display name" },
          "policyId": { "type": "string", "description": "Policy id" }
        }
      },
      "sidecarHost": {
        "type": "string",
        "default": "127.0.0.1",
        "description": "Hostname or IP of the DefenseClaw gateway"
      },
      "sidecarPort": {
        "type": "integer",
        "default": 18970,
        "description": "Port for the DefenseClaw Go sidecar REST API"
      },
      "guardrailPort": {
        "type": "integer",
        "default": 4000,
        "description": "Port for the DefenseClaw guardrail proxy"
      },
      "mode": {
        "type": "string",
        "enum": ["observe", "action"],
        "default": "observe",
        "description": "observe = log only; action = block threats"
      },
      "awsHttp1Shim": {
        "type": "string",
        "enum": ["auto", "on", "off"],
        "default": "auto",
        "description": "Force Bedrock SDK to HTTP/1 for guardrail interception"
      }
    }
  }
}
```

**Key differences from embedded manifest:**
- `id`: `"defenseclaw-plugin"` (avoids collision)
- `name`: includes `"(ClawHub)"` suffix for UI distinction
- `version`: starts at `0.1.0`
- `sidecarHost`: new field (default `"127.0.0.1"`)
- `guardrailPort`: new field (default `4000`) — the embedded version reads this from `~/.defenseclaw/config.yaml`; the standalone version takes it from plugin config

### 5.2 `package.json`

```json
{
  "name": "@defenseclaw/openclaw-plugin",
  "version": "0.1.0",
  "description": "ClawHub plugin — wires DefenseClaw security into any OpenClaw instance",
  "type": "module",
  "main": "dist/index.js",
  "types": "dist/index.d.ts",
  "openclaw": {
    "extensions": ["./dist/index.js"],
    "pluginManifest": "./openclaw.plugin.json",
    "compat": {
      "pluginApi": ">=1.0.0"
    },
    "build": {
      "openclawVersion": ">=1.0.0"
    }
  },
  "scripts": {
    "build": "tsc",
    "dev": "tsc --watch",
    "test": "vitest run",
    "test:watch": "vitest",
    "prepublish": "npm run build"
  },
  "dependencies": {
    "js-yaml": "^4.1.0"
  },
  "peerDependencies": {
    "@openclaw/plugin-sdk": ">=1.0.0"
  },
  "peerDependenciesMeta": {
    "@openclaw/plugin-sdk": { "optional": true }
  },
  "devDependencies": {
    "@types/js-yaml": "^4.0.9",
    "@types/node": "^25.5.0",
    "typescript": "^5.4.0",
    "vitest": "^3.0.0"
  },
  "license": "Apache-2.0",
  "permissions": [
    "net:connect"
  ]
}
```

**Key differences from embedded `package.json`:**
- `openclaw.compat.pluginApi`: `">=1.0.0"` — required by ClawHub for compatibility validation
- `openclaw.build.openclawVersion`: `">=1.0.0"` — required by ClawHub for build metadata
- `name`: scoped `@defenseclaw/openclaw-plugin`
- `permissions`: `"net:connect"` (not just `localhost` — needs remote sidecar)
- `prepublish` script for ClawHub build

### 5.3 `sidecar-config.ts` — Config Resolution Changes

The embedded version reads `~/.defenseclaw/config.yaml` and falls back to defaults. The standalone version uses a **3-tier resolution** that prioritizes plugin config (from ClawHub settings UI):

```
1. Plugin config (openclaw.plugin.json configSchema values set by user)
   ↓ fallback
2. Environment variables (DEFENSECLAW_HOST, DEFENSECLAW_PORT, DEFENSECLAW_GUARDRAIL_PORT)
   ↓ fallback
3. ~/.defenseclaw/config.yaml (if present on the OpenClaw host)
   ↓ fallback
4. Hardcoded defaults (127.0.0.1:18970, guardrail 4000)
```

The `loadSidecarConfig()` function gains an optional `overrides` parameter:

```typescript
interface SidecarConfigOverrides {
  host?: string;
  apiPort?: number;
  guardrailPort?: number;
}

function loadSidecarConfig(overrides?: SidecarConfigOverrides): SidecarConfig
```

When called from `index.ts`, the plugin passes the user's `pluginConfig` values as overrides.

### 5.4 `index.ts` — Plugin Entry Point Changes

The entry point is structurally identical to the embedded version, with these differences:

| Aspect | Embedded (`extensions/defenseclaw`) | Standalone (`output-plugin`) |
|--------|-------------------------------------|------------------------------|
| Plugin id | `defenseclaw` | `defenseclaw-plugin` |
| Slash commands | `/scan`, `/block`, `/allow` | `/dc-scan`, `/dc-block`, `/dc-allow` |
| Sidecar config | `loadSidecarConfig()` (file-only) | `loadSidecarConfig(pluginConfig)` (config-first) |
| Console prefix | `[defenseclaw]` | `[defenseclaw-plugin]` |
| Client header | `X-DefenseClaw-Client: openclaw-plugin` | `X-DefenseClaw-Client: openclaw-clawhub-plugin` |

### 5.5 Remaining Source Files (Unchanged Logic)

These files are copied from the embedded plugin with no behavioral changes:

| File | Purpose | Lines |
|------|---------|-------|
| `fetch-interceptor.ts` | `globalThis.fetch` + `https.request` patching, provider domain matching, body shape detection | ~1130 |
| `client.ts` | `DaemonClient` — HTTP client for sidecar REST API with correlation headers | ~390 |
| `types.ts` | Shared TypeScript types (Severity, Finding, ScanResult, CorrelationContext, etc.) | ~230 |
| `correlation-headers.ts` | `X-DefenseClaw-*` header name constants and builder functions | ~113 |
| `agent_identity.ts` | Stable agent id persistence and resolution (env → config → storage) | ~140 |
| `health-monitor.ts` | Periodic sidecar `/status` polling with protection-down warning | ~163 |
| `egress-telemetry.ts` | Best-effort egress event reporting to guardrail proxy | ~213 |
| `aws-sdk-http1-for-guardrail.ts` | Bedrock HTTP/2→HTTP/1 downgrade for guardrail interception | ~304 |
| `bedrock-config-detect.ts` | Detect Bedrock usage in OpenClaw config | ~52 |
| `providers.json` | Canonical LLM provider domains (copied from `internal/configs/providers.json`) | ~96 |
| `policy/enforcer.ts` | PolicyEnforcer + CLI scan wrappers (skill, plugin, code) | ~659 |
| `scanners/mcp-scanner.ts` | In-process MCP configuration security scanner | ~445 |

## 6. ClawHub Publishing Steps

Documented in `CLAWHUB.md` (included in the plugin directory):

```
1. Build:      cd output-plugin && npm install && npm run build
2. Verify:     Ensure dist/ contains index.js, index.d.ts, and all compiled modules
3. Package:    npm pack (creates @defenseclaw-openclaw-plugin-0.1.0.tgz)
4. Upload:     clawhub publish @defenseclaw-openclaw-plugin-0.1.0.tgz
               (or: clawhub publish --directory . if ClawHub supports directory mode)
5. Metadata:   ClawHub reads openclaw.plugin.json for the listing page
6. Install:    Users run: clawhub install @defenseclaw/openclaw-plugin
7. Configure:  Users set sidecarHost/sidecarPort in OpenClaw plugin settings
```

## 7. File Inventory

### New Files (16 files)

| Path | Type | Source |
|------|------|--------|
| `output-plugin/package.json` | Config | New (based on embedded) |
| `output-plugin/openclaw.plugin.json` | Manifest | New (extended config schema) |
| `output-plugin/tsconfig.json` | Config | Copy from embedded |
| `output-plugin/README.md` | Docs | New |
| `output-plugin/CLAWHUB.md` | Docs | New |
| `output-plugin/src/index.ts` | Source | Modified copy (commands, config) |
| `output-plugin/src/sidecar-config.ts` | Source | Modified copy (overrides param) |
| `output-plugin/src/fetch-interceptor.ts` | Source | Copy |
| `output-plugin/src/client.ts` | Source | Modified copy (client header) |
| `output-plugin/src/types.ts` | Source | Copy |
| `output-plugin/src/correlation-headers.ts` | Source | Copy |
| `output-plugin/src/agent_identity.ts` | Source | Copy |
| `output-plugin/src/health-monitor.ts` | Source | Copy |
| `output-plugin/src/egress-telemetry.ts` | Source | Copy |
| `output-plugin/src/aws-sdk-http1-for-guardrail.ts` | Source | Copy |
| `output-plugin/src/bedrock-config-detect.ts` | Source | Copy |
| `output-plugin/src/providers.json` | Data | Copy |
| `output-plugin/src/policy/enforcer.ts` | Source | Copy |
| `output-plugin/src/scanners/mcp-scanner.ts` | Source | Copy |

### Modified Files (0)

No existing files are modified.

## 8. Security Considerations

- **Remote sidecar**: The standalone plugin supports `net:connect` (not just localhost). When `sidecarHost` is set to a remote address, sidecar REST traffic and guardrail proxy traffic traverse the network. The existing `X-DC-Auth` token mechanism provides authentication. Users should use TLS termination (reverse proxy) for production remote deployments.
- **Token resolution**: The plugin respects `OPENCLAW_GATEWAY_TOKEN` env var and `~/.defenseclaw/.env` file, same as the embedded version.
- **No new attack surface**: The plugin uses the same APIs, same correlation headers, same audit trail as the embedded version. The sidecar is the trust boundary.

## 9. Testing Strategy

- **Unit tests**: Not included in initial version — the embedded plugin's test suite (`extensions/defenseclaw/src/__tests__/`) validates the shared logic. Tests will be added in a follow-up.
- **Manual verification**: Install from the built tarball, configure sidecar address, verify fetch interception and tool inspection work against a running DefenseClaw gateway.

## 10. Rollout

1. Merge PR with the `output-plugin/` directory.
2. Build and publish to ClawHub staging.
3. Test with a remote DefenseClaw gateway.
4. Publish to ClawHub production.
