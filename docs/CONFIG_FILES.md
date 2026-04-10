# Config Files & Environment Variables

How configuration flows between DefenseClaw components. This covers every
file and environment variable the system reads or writes, who creates each
one, and which code path consumes it.

## Visual Overview

```
USER runs: defenseclaw setup guardrail
  │
  ├─ WRITES ──► ~/.defenseclaw/config.yaml         (all settings, including guardrail.*)
  ├─ WRITES ──► ~/.defenseclaw/.env                 (API key values, mode 0600)
  └─ WRITES ──► ~/.defenseclaw/guardrail_runtime.json (initial mode + scanner_mode)


GO SIDECAR boots: reads config.yaml once
  │
  ├─ Builds ConnectorRouter from guardrail.connectors.* config
  │    ├─ OpenClaw connector (if connectors.openclaw.enabled)
  │    ├─ ZeptoClaw connector (if connectors.zeptoclaw.enabled)
  │    └─ Generic connector (always, as fallback)
  │
  ├─ Runs guardrail proxy (goroutine; internal/gateway/sidecar.go):
  │    ├─ Loads guardrail.* and cisco_ai_defense.* from in-memory config
  │    ├─ Receives ConnectorRouter for multi-framework request detection
  │    ├─ Resolves API keys via ~/.defenseclaw/.env (ResolveAPIKey + loadDotEnv)
  │    └─ Listens on guardrail.port for OpenAI-compatible traffic
  │
  └─ API server handles PATCH /api/v1/guardrail/config
       └─ WRITES ──► ~/.defenseclaw/guardrail_runtime.json  (mode + scanner_mode)
          (does NOT update config.yaml)


GUARDRAIL PROXY:
  │
  ├─ Reads config.yaml indirectly (struct from sidecar config load)
  ├─ Reads guardrail_runtime.json with a TTL cache (internal/gateway/proxy.go:550–577) ◄─ hot-reload
  ├─ Resolves upstream API keys (internal/gateway/provider.go:798–809, loadDotEnv in dotenv.go:28)
  ├─ Authenticates clients with deriveMasterKey (internal/gateway/proxy.go:521–535)
  └─ Runs inspection in Go (GuardrailInspector — local patterns, Cisco AI Defense, LLM judge, OPA)
```

> **Note on redundancy:** `mode` and `scanner_mode` live in both `config.yaml`
> and `guardrail_runtime.json`. The PATCH endpoint only updates the runtime JSON
> without writing back to `config.yaml`, so the two can drift after a hot-reload.

---

## Files

### `~/.defenseclaw/config.yaml`

Central config file shared by the Go sidecar and the Python CLI. Stores
scanner settings, gateway connection, watcher config, guardrail settings
(including model routing and `guardrail.port` for the built-in proxy — no
separate proxy YAML file), top-level `cisco_ai_defense` settings, skill actions,
and everything else.

| | |
|---|---|
| **Created by** | `defenseclaw init`, `defenseclaw setup skill-scanner`, `defenseclaw setup mcp-scanner`, `defenseclaw setup gateway`, `defenseclaw setup guardrail`, `defenseclaw setup sandbox` — all via Python `cfg.save()` (`cli/defenseclaw/config.py:290`) |
| **Read by** | **Python CLI** at startup via `config.load()` (`cli/defenseclaw/config.py:426`). **Go sidecar** at startup via `config.Load()` (`internal/config/config.go:262`, Viper). |
| **NOT read by** | Standalone Python guardrail code paths (none in the default stack); the Go sidecar loads YAML via Viper and passes structs into the proxy. |

---

### `~/.defenseclaw/.env`

Persists API key **values** for daemon contexts where the user's shell
environment isn't inherited. Written with `mode 0600`.

Example contents:

```
ANTHROPIC_API_KEY=sk-ant-api03-...
```

| | |
|---|---|
| **Created by** | `defenseclaw setup guardrail` via `_write_dotenv()` (`cmd_setup.py:179–184`, called from guardrail setup). |
| **Read by** | **Guardrail proxy** and related gateway code via `ResolveAPIKey()` (`internal/gateway/provider.go:798–809`), which calls `loadDotEnv()` (`internal/gateway/dotenv.go:28`) when the named env var is not already set in the process environment. |
| **Path derivation** | `filepath.Join(dataDir, ".env")` — same as `NewGuardrailProxy` (`internal/gateway/proxy.go:80`). |

---

### `~/.defenseclaw/guardrail_runtime.json`

Small JSON file for hot-reloading guardrail mode and scanner mode without
restarting the guardrail proxy. Contains only two fields.

Example contents:

```json
{"mode": "observe", "scanner_mode": "local"}
```

| | |
|---|---|
| **Created by** | **Go sidecar** API server via `writeGuardrailRuntime()` (`internal/gateway/api.go:1051–1063`), called from the `PATCH /api/v1/guardrail/config` handler (line 1023). |
| **Read by** | **Guardrail proxy** via `reloadRuntimeConfig()` (`internal/gateway/proxy.go:550–577`) with a 5-second TTL cache before handling requests. |
| **Path derivation (writer)** | `filepath.Join(a.scannerCfg.DataDir, "guardrail_runtime.json")` — uses `DataDir` from Go config. |
| **Path derivation (reader)** | `filepath.Join(p.dataDir, "guardrail_runtime.json")` — `dataDir` from sidecar config (`internal/gateway/proxy.go:559`). |
| **Caveat** | The PATCH handler updates the in-memory Go config but does **not** call `cfg.Save()`, so `config.yaml` drifts out of sync after a PATCH. |

---

## Connector Configuration

The guardrail proxy uses a connector-based architecture to support multiple
agent frameworks. Connector config is under `guardrail.connectors` in
`config.yaml`.

### `guardrail.connectors.openclaw`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | Enable OpenClaw connector (backward compatible default) |
| `token_env` | string | `OPENCLAW_GATEWAY_TOKEN` | Env var name for the gateway auth token |

### `guardrail.connectors.zeptoclaw`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Enable ZeptoClaw connector (must be explicitly enabled via setup) |
| `token_env` | string | `""` | Env var name for the proxy auth token |
| `providers` | map | `{}` | Map of provider name → upstream connection details |

Each entry in `providers` has:

| Field | Type | Description |
|-------|------|-------------|
| `upstream_url` | string | Real upstream URL (e.g. `https://api.openai.com`) |
| `auth_header` | string | Header name for upstream auth (`Authorization`, `x-api-key`, `api-key`) |
| `auth_scheme` | string | Auth prefix (`Bearer` or `""` for bare key) |

Example config:

```yaml
guardrail:
  connectors:
    openclaw:
      enabled: true
      token_env: OPENCLAW_GATEWAY_TOKEN
    zeptoclaw:
      enabled: true
      token_env: ""
      providers:
        openai:
          upstream_url: https://api.openai.com
          auth_header: Authorization
          auth_scheme: Bearer
        anthropic:
          upstream_url: https://api.anthropic.com
          auth_header: x-api-key
          auth_scheme: ""
        openrouter:
          upstream_url: https://openrouter.ai/api/v1
          auth_header: Authorization
          auth_scheme: Bearer
```

| | |
|---|---|
| **Created by** | `defenseclaw setup guardrail --claw zeptoclaw` populates ZeptoClaw providers from `~/.zeptoclaw/config.json`. OpenClaw defaults are set by `DefaultConnectorsConfig()` in `internal/config/connectors.go`. |
| **Read by** | **Go sidecar** `buildConnectorRouter()` (`internal/gateway/sidecar.go`) — builds `ConnectorRouter` from these settings at startup. |
| **Defaults** | OpenClaw enabled with `OPENCLAW_GATEWAY_TOKEN`; ZeptoClaw disabled. If ZeptoClaw is enabled but a provider is missing from the config map, the connector falls back to the embedded default table (`internal/gateway/connector/zeptoclaw_defaults.go` — 19 providers). |

---

## Environment Variables

### Built-in guardrail proxy (Go)

The sidecar **runs the guardrail proxy in-process** (`internal/gateway/sidecar.go:352–375`) and does **not** inject a legacy `DEFENSECLAW_*` subprocess environment for it. Mode, scanner mode, model, port, Cisco AI Defense, and judge settings come from `config.yaml` loaded at startup (`config.Load()` in `internal/config/config.go`), then are passed into `NewGuardrailProxy` (`internal/gateway/proxy.go:70–118`).

| Concern | Where it comes from |
|---|---|
| **`guardrail.mode`**, **`guardrail.scanner_mode`** | YAML at startup; hot-reload from `guardrail_runtime.json` (`reloadRuntimeConfig` / `applyRuntime`, `internal/gateway/proxy.go:550–592`). |
| **Upstream LLM API key** | Env var named by `guardrail.api_key_env`, with values merged from `~/.defenseclaw/.env` via `ResolveAPIKey` (`internal/gateway/provider.go:798–809`) and `loadDotEnv` (`internal/gateway/dotenv.go:28`), first used in `NewGuardrailProxy` (`internal/gateway/proxy.go:80–82`). |
| **Cisco AI Defense** | `cisco_ai_defense` on the loaded `config.Config`; `NewCiscoInspectClient` (`internal/gateway/cisco_inspect.go:53–88`) resolves the API key with the same `dotenvPath` as the proxy. |
| **LLM judge** | `guardrail.judge` + `NewLLMJudge` (`internal/gateway/llm_judge.go`), using the same `filepath.Join(dataDir, ".env")` pattern. |
| **Bearer auth (clients → proxy)** | `deriveMasterKey` from `device.key` (`internal/gateway/proxy.go:521–535`; checked in `authenticateRequest`, `510–518`). |

### API key env vars (e.g., `ANTHROPIC_API_KEY`)

| | |
|---|---|
| **Set by** | User shell or `defenseclaw setup guardrail` writing `~/.defenseclaw/.env`. |
| **Read by** | **The proxy** — `ResolveAPIKey(cfg.APIKeyEnv, dotenvPath)` in `NewGuardrailProxy` (`internal/gateway/proxy.go:80–82`) supplies the key for upstream provider calls (`NewProvider` in `internal/gateway/provider.go`). |

### Legacy `DEFENSECLAW_*` variables

**The built-in Go guardrail proxy does not set or depend on** `DEFENSECLAW_GUARDRAIL_MODE`, `DEFENSECLAW_SCANNER_MODE`, `DEFENSECLAW_API_PORT`, `DEFENSECLAW_DATA_DIR`, or `PYTHONPATH` for inspection. Mode and scanner mode come from `config.yaml` and `guardrail_runtime.json` as described above.

---

## Sandbox-related config fields

These fields are set by `defenseclaw setup sandbox` for openshell-sandbox
standalone mode (Linux supervisor with Landlock, seccomp, network namespace).

### `openshell.mode`

| | |
|---|---|
| **Values** | `""` (default, no sandbox), `"standalone"` |
| **Set by** | `defenseclaw setup sandbox` |
| **Read by** | Go sidecar (`internal/config/config.go: OpenShellConfig.IsStandalone()`). |
| **Effect** | When `"standalone"`, the sidecar knows OpenClaw is running inside a Linux namespace with a veth pair. |

### `openshell.version`

| | |
|---|---|
| **Values** | `"0.6.2"` (default, pinned tested version) |
| **Set by** | `defaults.go`, overridable in config.yaml |
| **Read by** | `defenseclaw init --sandbox` (install prompt), `internal/sandbox/install.go` (version check). |
| **Effect** | Pins the openshell-sandbox binary version for reproducibility. |

### `openshell.sandbox_home`

| | |
|---|---|
| **Values** | `"/home/sandbox"` (default) |
| **Set by** | `defenseclaw setup sandbox --sandbox-home <path>` |
| **Read by** | Setup, init, systemd unit generation — all sandbox paths derive from this. |
| **Effect** | Root directory for the sandbox user's home. All OpenClaw and DefenseClaw sandbox-side files live here. |

### `openshell.auto_pair`

| | |
|---|---|
| **Values** | `true` (default), `false` |
| **Set by** | `defenseclaw setup sandbox --no-auto-pair` |
| **Read by** | `defenseclaw setup sandbox` (device pre-pairing step). |
| **Effect** | When `true`, the sidecar's Ed25519 device key is pre-injected into the sandbox's `devices.json` during setup. The sidecar connects immediately on first start without manual approval. When `false`, the operator must manually approve the pairing request. |

### `gateway.api_bind`

| | |
|---|---|
| **Values** | `""` (default: `127.0.0.1`), or an explicit IP address |
| **Set by** | `defenseclaw setup sandbox` (auto-detected from `guardrail.host` in standalone mode) |
| **Read by** | Go sidecar `runAPI()` — determines which interface the REST API binds to. |
| **Effect** | In standalone mode, defaults to the host veth IP (e.g., `10.200.0.1`) so the sandbox can reach the API. Otherwise defaults to loopback. |

### `guardrail.host`

| | |
|---|---|
| **Values** | `"localhost"` (default), or a bridge IP like `"10.200.0.1"` |
| **Set by** | `defenseclaw setup sandbox --host-ip <ip>` |
| **Read by** | **Python CLI** `patch_openclaw_config()` — sets the `defenseclaw` provider `baseUrl` in `openclaw.json` to `http://{host}:{guardrail.port}`. **Go sidecar** `runAPI()` — in standalone mode, when `api_bind` is unset and host is not `localhost`, uses `guardrail.host` as the REST API bind address. |
| **Effect** | Lets OpenClaw inside the sandbox point at the guardrail proxy and sidecar API on the host veth IP. |
