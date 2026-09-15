# Design: Integration Resilience Layer

## Summary

Three new optional connector interfaces (`InterceptionVerifier`,
`CredentialHydrator`, `CompatibilityProbe`) plus a connector metadata API
endpoint, version-aware config profiles, and ZeptoClaw snapshot refresh.
No changes to the existing `Connector` interface or its 18 optional
interfaces. Each connector adopts the new interfaces at its own pace;
none are mandatory.

## Architecture

### Design principles

1. **Additive only.** The `Connector` interface in `connector.go` is
   frozen. New capabilities are optional interfaces, following the
   established pattern (`HookProfileProvider`, `ComponentScanner`,
   `AllowedHostsProvider`, etc.).

2. **Connector owns its implementation.** Each connector decides how to
   probe, hydrate, and verify. The interfaces define _what_ is reported,
   not _how_ it is achieved.

3. **Proxy and hook connectors are peers.** The same interfaces work for
   both transport models, but the semantics differ. A proxy connector
   probes transport layers; a hook connector probes config entries.

4. **Fail-open by default.** Connectors that do not implement the new
   interfaces continue to work exactly as today. The gateway does not
   require any connector to implement them.

### Components

```text
internal/gateway/connector/
  connector.go              (UNCHANGED — existing Connector interface)
  resilience.go             (NEW — InterceptionVerifier, CredentialHydrator, CompatibilityProbe)
  resilience_test.go        (NEW)

internal/gateway/
  token_resolver.go         (UNCHANGED — existing TokenResolverFunc)
  token_hydrator.go         (NEW — CredentialStore + hydration dispatch)
  token_hydrator_test.go    (NEW)
  api_credentials.go        (NEW — GET/PUT /v1/credentials/{provider})
  api_connector_metadata.go (NEW — GET /v1/connectors/{name}/metadata)

internal/gateway/connector/
  openclaw.go               (MODIFIED — implements InterceptionVerifier, CredentialHydrator, CompatibilityProbe)
  zeptoclaw.go              (MODIFIED — implements InterceptionVerifier, CredentialHydrator, CompatibilityProbe + snapshot refresh)
  hook_only.go              (MODIFIED — generic InterceptionVerifier + CompatibilityProbe for hook connectors)
  claudecode.go             (MODIFIED — implements InterceptionVerifier, CompatibilityProbe)
  codex.go                  (MODIFIED — implements InterceptionVerifier, CompatibilityProbe)
  hermes.go (hook_only.go)  (MODIFIED — implements InterceptionVerifier, CompatibilityProbe)
  omnigent.go               (MODIFIED — implements InterceptionVerifier, CompatibilityProbe)

extensions/defenseclaw/src/
  credential-resolver.ts    (NEW — plugin-side credential endpoint client)
  transport-negotiator.ts   (NEW — probe-install-verify per layer)
  fetch-interceptor.ts      (MODIFIED — uses transport-negotiator)

internal/watcher/
  watcher.go                (MODIFIED — register ZeptoClaw config for watch)

cli/defenseclaw/
  connector_metadata.py     (NEW — gateway metadata API client)
  connector_paths.py        (MODIFIED — delegate to metadata API when available)
```

### Interface definitions

All three interfaces live in a single new file `resilience.go` in the
`connector` package, beside the existing optional interfaces.

```go
// File: internal/gateway/connector/resilience.go
package connector

import "context"

// --- Interface 1: InterceptionVerifier ---

// LayerStatus describes the health of a single interception layer.
type LayerStatus struct {
    Name    string // "fetch", "https", "http", "http.get", "undici", "api_base", "hook_config"
    Healthy bool
    Detail  string // human-readable, e.g. "api_base for anthropic still points at proxy"
}

// InterceptionStatus is the aggregate health of all layers.
type InterceptionStatus struct {
    Working      bool          // true when at least one layer is healthy
    Layers       []LayerStatus
    Gaps         []string      // human-readable gap descriptions
    LastVerified time.Time
}

// InterceptionVerifier is implemented by connectors that can verify their
// observe/act pipeline is intact at runtime.
//
// Proxy connectors probe transport patches (fetch, https, undici) or
// config rewrites (api_base). Hook connectors probe hook config entries
// and script/artifact presence.
//
// Optional. Connectors that do not implement this interface are assumed
// healthy (no degradation signal).
type InterceptionVerifier interface {
    VerifyInterception(ctx context.Context, opts SetupOpts) InterceptionStatus
}


// --- Interface 2: CredentialHydrator ---

// CredentialHydrator is implemented by proxy connectors that can receive
// LLM provider API keys from DefenseClaw instead of requiring users to
// configure them in each agent.
//
// Hook-only connectors do not route LLM traffic through the proxy and
// therefore do not implement this interface.
//
// Optional. When not implemented, the gateway uses the existing
// resolution chain (env vars, dotenv, X-AI-Auth header).
type CredentialHydrator interface {
    // HydrateProviderKey pushes a provider API key to wherever the
    // connector expects it.
    //   OpenClaw:   stored in-memory, served via GET /v1/credentials/{provider}
    //   ZeptoClaw:  written to config.json api_key + in-memory snapshot
    HydrateProviderKey(provider string, key string) error

    // RefreshSnapshot reloads credential state from the agent's config.
    // No-op for connectors whose credentials flow through headers.
    RefreshSnapshot() error

    // SupportedProviders returns the provider names this connector can
    // deliver keys to. Empty means "all providers."
    SupportedProviders() []string
}


// --- Interface 3: CompatibilityProbe ---

// ProbeResult reports whether the four stages of the observe/act pipeline
// are working for a specific connector and agent version.
type ProbeResult struct {
    Connector      string
    AgentVersion   string
    Intercepting   bool     // can the system see the agent's traffic/events?
    Authenticating bool     // does the agent present valid credentials?
    Blocking       bool     // does the agent honor block verdicts?
    Reporting      bool     // do telemetry events arrive?
    Failures       []string // human-readable failure descriptions
}

// CompatibilityProbe is implemented by connectors that can self-test
// the full observe-act pipeline with synthetic events.
//
// Proxy connectors send a synthetic HTTP request through the proxy.
// Hook connectors send a synthetic hook payload to their API endpoint.
//
// Optional. Used by `defenseclaw doctor --verify-connector` and by the
// CI certification pipeline to populate validated_versions.json.
type CompatibilityProbe interface {
    ProbeCompatibility(ctx context.Context, opts SetupOpts) ProbeResult
}
```

### Per-connector implementation matrix

| Connector | InterceptionVerifier | CredentialHydrator | CompatibilityProbe | Notes |
|-----------|---------------------|-------------------|-------------------|-------|
| **openclaw** | Yes: probe 5 transport layers via existing self-test | Yes: in-memory store + `/v1/credentials/` endpoint | Yes: synthetic fetch through proxy | Existing self-test in fetch-interceptor.ts is surfaced to Go via `/v1/events/egress` selftest events |
| **zeptoclaw** | Yes: verify api_base values in config.json | Yes: patch config.json api_key + refresh snapshot | Yes: synthetic request to `/c/zeptoclaw` | Also implements config file watcher for snapshot refresh |
| **claudecode** | Yes: verify hooks in `~/.claude/settings.json` + script existence | No: hook-only, no LLM traffic | Yes: synthetic hook POST to `/api/v1/claudecode/hook` | 28 events; probe tests pre_tool_use block shape |
| **codex** | Yes: verify hooks in `~/.codex/config.toml` + script existence | No: hook-only | Yes: synthetic hook POST to `/api/v1/codex/hook` | 5 contract versions; probe tests against active band |
| **hermes** | Yes: verify hooks in `config.yaml` + allowlist + script | No: hook-only | Yes: synthetic hook POST to `/api/v1/hermes/hook` | 23 events; probe tests pre_tool_call block shape `{"decision":"block"}` |
| **cursor** | Yes: verify hooks in `~/.cursor/hooks.json` + script | No: hook-only | Yes: synthetic hook POST | 21 events; probe tests pre-action block shape |
| **devin** | Yes: verify hooks in config + script | No: hook-only | Yes: synthetic hook POST | 8 events |
| **geminicli** | No: deprecated | No | No: deprecated | Deprecated; replaced by antigravity |
| **copilot** | Yes: verify hooks in `~/.copilot/hooks/defenseclaw.json` | No: hook-only | Yes: synthetic hook POST | 14 events; workspace-scoped hooks also checked |
| **openhands** | Yes: verify hooks in `~/.openhands/hooks.json` + script | No: hook-only | Yes: synthetic hook POST | Darwin-only NativeOTLP also verified |
| **antigravity** | Yes: verify hooks in `~/.gemini/config/hooks.json` | No: hook-only | Yes: synthetic hook POST | 5 events; pre-execution inspection only |
| **opencode** | Yes: verify plugin artifact in `~/.config/opencode/plugins/` | No: hook-only | Yes: synthetic hook POST | Plugin artifact instead of shell script |
| **amp** | Yes: verify plugin artifact in `~/.config/amp/plugins/` | No: hook-only | Yes: synthetic hook POST | Strict bearer auth; no loopback bypass |
| **omnigent** | Yes: verify Python policy bridge + `.pth` file + config.yaml | No: hook-only | Yes: synthetic hook POST | Python policy bridge, unique among connectors |

### Data flow: Interception verification

```text
┌───────────────────────┐
│  Gateway boot / timer │
│  (every 60s default)  │
└──────────┬────────────┘
           │
           ▼
┌──────────────────────────────────────────┐
│  connector.(InterceptionVerifier)        │
│  .VerifyInterception(ctx, opts)          │
└──────────┬───────────────────────────────┘
           │
    ┌──────┴──────┐
    │             │
    ▼             ▼
 Proxy          Hook-only
    │             │
    │  ┌──────────┴──────────────┐
    │  │ For each hook entry:    │
    │  │  - config file exists?  │
    │  │  - entry present?       │
    │  │  - script executable?   │
    │  │  - plugin artifact OK?  │
    │  └──────────┬──────────────┘
    │             │
    │  ┌──────────┴──────────────┐       ┌──────────────────────────────┐
    │  │ OpenClaw:               │       │ ZeptoClaw:                   │
    │  │  Read self-test results │       │  Read config.json            │
    │  │  from /v1/events/egress │       │  Check each provider.api_base│
    │  │  selftest branch        │       │  points at proxy addr        │
    │  └──────────┬──────────────┘       └──────────┬───────────────────┘
    │             │                                  │
    └──────┬──────┘──────────────────────────────────┘
           │
           ▼
┌─────────────────────────────────┐
│  InterceptionStatus             │
│  {Working, Layers[], Gaps[]}    │
├─────────────────────────────────┤
│  If !Working:                   │
│    → audit event (interception- │
│      gap)                       │
│    → telemetry severity=critical│
│  If gaps but working:           │
│    → audit event (interception- │
│      gap, severity=warning)     │
└─────────────────────────────────┘
```

### Data flow: Credential hydration

```text
                  ┌──────────────────────────────┐
                  │ External source               │
                  │ (enterprise cloud, operator   │
                  │  API, or future vault plugin) │
                  └──────────────┬───────────────┘
                                 │
                                 ▼
                  ┌──────────────────────────────┐
                  │ PUT /v1/credentials/{provider}│
                  │ Body: {"key": "sk-..."}       │
                  │ Auth: X-DC-Auth or master key │
                  └──────────────┬───────────────┘
                                 │
                                 ▼
                  ┌──────────────────────────────┐
                  │ CredentialStore (in-memory)   │
                  │ map[provider]→{key, updated}  │
                  └──────┬───────────────┬───────┘
                         │               │
                ┌────────┘               └────────┐
                ▼                                  ▼
   ┌────────────────────────┐        ┌────────────────────────┐
   │ OpenClaw connector     │        │ ZeptoClaw connector    │
   │ .HydrateProviderKey()  │        │ .HydrateProviderKey()  │
   │                        │        │                        │
   │ Stores in CredentialStore│       │ 1. Update snapshot     │
   │ Served at GET /v1/creds │        │ 2. Patch config.json   │
   │ Plugin reads at intercept│       │    api_key field       │
   └────────────────────────┘        └────────────────────────┘
                                              │
                                              ▼
                                 ┌────────────────────────┐
                                 │ File watcher detects   │
                                 │ external key change    │
                                 │ → RefreshSnapshot()    │
                                 │ → re-verify api_base   │
                                 └────────────────────────┘

   Hook-only connectors: NOT involved.
   They do not route LLM traffic and do not hold provider keys.
```

### Data flow: Compatibility probing

```text
┌──────────────────────────────────┐
│ defenseclaw doctor --verify-conn │
│ or CI make connector-certify     │
└──────────────┬───────────────────┘
               │
               ▼
┌──────────────────────────────────────────┐
│  connector.(CompatibilityProbe)          │
│  .ProbeCompatibility(ctx, opts)          │
└──────────────┬───────────────────────────┘
               │
       ┌───────┴───────┐
       │               │
       ▼               ▼
    Proxy            Hook-only
       │               │
       │  ┌────────────┴─────────────────────┐
       │  │ 1. Build synthetic hook payload   │
       │  │    (pre_tool_call / PreToolUse)   │
       │  │ 2. POST to /api/v1/{conn}/hook    │
       │  │    with scoped token              │
       │  │ 3. Check response shape matches   │
       │  │    HookProfile.Respond output     │
       │  │ 4. Check telemetry event arrived  │
       │  └────────────┬─────────────────────┘
       │               │
  ┌────┴────────────┐  │
  │ 1. Send probe   │  │
  │    request to   │  │
  │    proxy with   │  │
  │    X-DC-Probe:1 │  │
  │ 2. Verify proxy │  │
  │    received it  │  │
  │ 3. Verify auth  │  │
  │ 4. Verify audit │  │
  │    event emitted│  │
  └────┬────────────┘  │
       │               │
       └───────┬───────┘
               │
               ▼
┌──────────────────────────────────────────┐
│  ProbeResult                             │
│  {Intercepting, Authenticating,          │
│   Blocking, Reporting, Failures[]}       │
├──────────────────────────────────────────┤
│  If all true:                            │
│    → write validated_versions.json entry │
│    → doctor prints ✅ pass               │
│  If any false:                           │
│    → doctor prints ❌ with Failures[]    │
│    → no version certification            │
└──────────────────────────────────────────┘
```

### Data flow: Connector metadata API

```text
┌──────────────────────────┐
│ Python CLI / macOS app   │
│ needs connector paths    │
└────────────┬─────────────┘
             │
             ▼
┌──────────────────────────────────────┐
│ GET /v1/connectors/{name}/metadata   │
│ Auth: X-DC-Auth                      │
└────────────┬─────────────────────────┘
             │
             ▼
┌──────────────────────────────────────┐
│ Gateway resolves:                    │
│  conn = registry.Get(name)           │
│  caps = conn.(ConnectorCapability    │
│          Provider).Capabilities(opts)│
│  paths = conn.(AgentPathProvider)    │
│          .AgentPaths(opts)           │
│  locs = conn's ConnectorLocations    │
│                                      │
│ Returns JSON:                        │
│  {capabilities, paths, locations,    │
│   interception_status (if verifier), │
│   version_bands}                     │
└──────────────────────────────────────┘
             │
             ▼
┌──────────────────────────────────────┐
│ Python CLI connector_metadata.py     │
│  - caches response for session       │
│  - falls back to hardcoded paths     │
│    if gateway unreachable            │
└──────────────────────────────────────┘
```

## Interfaces

### New Gateway API Endpoints

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| GET | `/v1/connectors/{name}/metadata` | X-DC-Auth | Connector capabilities, paths, locations, interception status |
| GET | `/v1/credentials/{provider}` | X-DC-Auth | Read hydrated provider key (OpenClaw plugin use) |
| PUT | `/v1/credentials/{provider}` | X-DC-Auth or master key | Push a provider key to the credential store |
| DELETE | `/v1/credentials/{provider}` | X-DC-Auth or master key | Revoke a hydrated provider key |

### Modified CLI Commands

| Command | Change |
|---------|--------|
| `defenseclaw doctor --verify-connector` | New flag; invokes CompatibilityProbe |
| `defenseclaw doctor` (existing checks) | Adds InterceptionVerifier results to output |
| `defenseclaw status` | Shows interception layer health when verifier is available |

## Data Model

### CredentialStore (in-memory)

```go
type CredentialStore struct {
    mu    sync.RWMutex
    keys  map[string]StoredCredential // provider name → credential
}

type StoredCredential struct {
    Key       string
    Source    string    // "hydrated", "env", "dotenv", "header"
    UpdatedAt time.Time
}
```

No on-disk persistence. Credentials live only in memory. On restart, the
external source (enterprise cloud, operator script) re-pushes keys.

### validated_versions.json (on-disk, ~/.defenseclaw/)

```json
{
  "schema_version": 1,
  "entries": {
    "openclaw": {
      "last_validated_version": "2026.8.15",
      "defenseclaw_version": "0.8.10",
      "validated_at": "2026-09-14T10:30:00Z",
      "probe_result": {
        "intercepting": true,
        "authenticating": true,
        "blocking": true,
        "reporting": true
      }
    },
    "hermes": {
      "last_validated_version": "0.20.0",
      "defenseclaw_version": "0.8.10",
      "validated_at": "2026-09-14T10:30:00Z",
      "probe_result": {
        "intercepting": true,
        "authenticating": true,
        "blocking": true,
        "reporting": true
      }
    }
  }
}
```

## Integration Points

### With existing connector infrastructure

- `InterceptionVerifier` is checked by the sidecar boot
  (`sidecar.go`), the periodic health timer, and `api.go` for the
  metadata endpoint.
- `CredentialHydrator` is called by the new `CredentialStore` which is
  wired into the existing `TokenResolverFunc` path in `proxy.go`.
- `CompatibilityProbe` is called by the CLI `doctor` command and the
  new `make connector-certify` target.

### With existing telemetry

- Interception gap events use the existing audit store
  (`internal/audit/`) and telemetry pipeline
  (`internal/observability/`).
- No new telemetry families are introduced; events use existing
  `connector_health` family with new reason codes.

### With existing watcher

- ZeptoClaw config watch registers with the existing file watcher in
  `internal/watcher/`. The watcher already monitors connector config
  files for inventory events; this adds a callback for snapshot refresh.

## Tradeoffs

1. **Optional interfaces vs. required methods.** We chose optional
   interfaces because forcing all 14 connectors to implement three new
   methods in one change would be impractical and against the
   established pattern. The cost is that some connectors may never
   implement them.

2. **In-memory credential store vs. on-disk.** We chose in-memory
   because writing provider API keys to disk creates a new secret
   storage surface. The cost is that credentials are lost on restart and
   must be re-pushed.

3. **Python CLI gateway fallback.** When the gateway is unreachable the
   CLI falls back to hardcoded paths. This preserves existing behavior
   but means the CLI can still drift from the gateway's view. The
   alternative (fail hard when gateway is down) would break offline
   workflows like `defenseclaw scan`.

4. **Self-test reuse for OpenClaw.** The fetch interceptor already runs
   a self-test every 60 seconds. The Go-side `InterceptionVerifier`
   reads self-test results from the existing `/v1/events/egress`
   `selftest` branch rather than implementing a second probe. This
   avoids duplicating logic but couples the verifier to the self-test
   protocol.

## Risks

1. **Synthetic probe detection.** If an upstream agent detects and
   filters synthetic probe events, `CompatibilityProbe` would report
   false positives. Mitigation: probes use the same payload format as
   real events; the only marker is an internal header
   (`X-DC-Probe: 1`) stripped before forwarding.

2. **Credential endpoint abuse.** `GET /v1/credentials/{provider}`
   exposes API keys to any authenticated caller on loopback. Mitigation:
   requires `X-DC-Auth` (gateway token or master key); the endpoint is
   loopback-only; keys are not logged.

3. **Config file race.** `HydrateProviderKey` on ZeptoClaw writes to
   `config.json` while the user or ZeptoClaw itself may also be writing.
   Mitigation: use atomic write (temp file + rename); take the existing
   connector setup lock during writes.
