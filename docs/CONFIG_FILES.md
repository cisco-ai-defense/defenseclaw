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
  ├─ Runs guardrail proxy (goroutine; internal/gateway/sidecar.go:352–375):
  │    ├─ Loads guardrail.* and cisco_ai_defense.* from in-memory config
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
scanner settings, gateway connection, watcher config, webhook notifications,
guardrail settings (including model routing and `guardrail.port` for the
built-in proxy — no separate proxy YAML file), top-level `cisco_ai_defense`
settings, skill actions, and everything else.

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

### `~/.defenseclaw/doctor_cache.json`

Snapshot of the most recent `defenseclaw doctor` run. Used by the Go TUI's
Overview panel to show pass/fail counts and top failures without re-running
the (network-intensive) probes on every redraw.

Example contents:

```json
{
  "captured_at": "2026-04-17T18:21:09Z",
  "passed": 12,
  "failed": 0,
  "warned": 1,
  "skipped": 2,
  "checks": [
    {"status": "warn", "label": "Splunk HEC", "detail": "queue depth 4200/5000"}
  ]
}
```

| | |
|---|---|
| **Created by** | Python CLI at the end of every `defenseclaw doctor` (and `setup --verify`) run via `_write_doctor_cache()` (`cli/defenseclaw/commands/cmd_doctor.py`). Atomic write — tempfile + `os.replace` — so concurrent reads never see partial JSON. |
| **Read by** | Go TUI on startup and after every doctor invocation via `LoadDoctorCache()` (`internal/tui/doctor_cache.go`). |
| **Stale threshold** | 15 minutes — older snapshots show a `(stale — [d] to rerun)` notice in the Overview panel. |
| **Failure handling** | Cached even on non-zero exit so the Overview panel reflects current reality, not the last-successful run. Missing file is normal on first launch and is treated as "not yet run". |

See [TUI.md → Cached doctor status](TUI.md#cached-doctor-status-overview-panel)
for the user-facing behavior.

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

---

## Webhook Notification Config

> **Not an audit sink.** `webhooks[]` delivers low-volume, per-event
> chat/incident notifications (Slack, PagerDuty, Webex, HMAC-signed
> generic JSON). High-volume every-event forwarding lives under
> `audit_sinks[]` and is managed with `defenseclaw setup observability`
> — see [docs/OBSERVABILITY.md](OBSERVABILITY.md) §3.4 (`http_jsonl`)
> and §7 (notifier webhooks) for the full split.

The `webhooks` section in `config.yaml` configures outbound HTTP notifications
for enforcement events. Each entry defines a webhook endpoint. Disabled by
default in all policy presets.

### CLI

Use `defenseclaw setup webhook` — do not hand-edit `config.yaml` unless you
have to. The CLI validates URLs (SSRF guard), resolves `secret_env` so you
catch missing env vars at write time, and writes atomically:

```bash
# Add
defenseclaw setup webhook add slack      --url https://hooks.slack.com/services/... --enabled
defenseclaw setup webhook add pagerduty  --url https://events.pagerduty.com/v2/enqueue --secret-env PD_KEY --enabled
defenseclaw setup webhook add webex      --url https://webexapis.com/v1/messages --secret-env WEBEX_TOKEN --room-id ROOM_ID --enabled
defenseclaw setup webhook add generic    --url https://ops.example.com/hooks --secret-env HMAC_SECRET --enabled

# Inspect / manage
defenseclaw setup webhook list
defenseclaw setup webhook show <name>
defenseclaw setup webhook enable  <name>
defenseclaw setup webhook disable <name>
defenseclaw setup webhook remove  <name>

# Smoke-test without touching production (does not write to config.yaml)
defenseclaw setup webhook test slack --url https://hooks.slack.com/services/... --preview-only
```

The same wizard is available in the TUI under Setup → Webhooks; it collects
all inputs and then shells out to the non-interactive CLI to write the YAML.
`defenseclaw doctor` probes every entry (SSRF, required env vars, reachability)
without dispatching a synthetic event.

### YAML

```yaml
webhooks:
  - url: "https://hooks.slack.com/services/T00/B00/xxx"
    type: slack              # slack | pagerduty | webex | generic
    secret_env: ""           # env var NAME holding the auth secret/token
    room_id: ""              # webex only
    min_severity: HIGH       # CRITICAL | HIGH | MEDIUM | LOW | INFO
    events:                  # empty = all event categories
      - block
      - drift
      - guardrail
    timeout_seconds: 10      # per-request HTTP timeout
    cooldown_seconds: 60     # optional; omit/null = use 300s default; 0 = disabled
    enabled: true            # set false to disable without removing the entry
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `url` | string | `""` | Webhook endpoint URL. Required. For Webex bot, use `https://webexapis.com/v1/messages`. For Webex Incoming Webhooks, use the full incoming webhook URL. |
| `type` | string | `"generic"` | Channel type: `slack` (Block Kit), `pagerduty` (Events API v2), `webex` (Webex Messages API or Incoming Webhook), or `generic` (flat JSON). |
| `secret_env` | string | `""` | Name of an environment variable holding the secret. For `pagerduty`, this is the routing key. For `webex` with the Messages API, this is the bot access token (sent as `Authorization: Bearer`). Not needed for Webex Incoming Webhooks. For `generic`, the value is used for HMAC-SHA256 signing (`X-Hub-Signature-256`). Not used for `slack`. |
| `room_id` | string | `""` | Webex room ID to post messages to. Required when `type` is `webex` with the Messages API. Omit for Webex Incoming Webhooks (room is embedded in the URL). |
| `min_severity` | string | `"HIGH"` | Minimum event severity to dispatch. Events below this threshold are silently dropped. |
| `events` | list | `[]` | Event categories to include. Empty means all categories. Valid values: `block`, `drift`, `guardrail`, `scan`, `health`. |
| `timeout_seconds` | int | `10` | HTTP timeout per webhook request. |
| `cooldown_seconds` | int? | *nil* → 300s | Tri-state: omit / null → runtime default (`webhookDefaultCooldown = 300s`); `0` → debounce disabled (dispatch every event); `>0` → explicit minimum seconds between dispatches per (webhook, event-category) pair. |
| `enabled` | bool | `false` | Whether this endpoint is active. |

| | |
|---|---|
| **Set by** | `defenseclaw setup webhook` (preferred) or operator via `config.yaml`. |
| **Read by** | **Go sidecar** at startup via `config.Load()`. **Python CLI** via `config.load()` (round-trips the cooldown tri-state, read-only for display). |
| **Effect** | When enabled, the `WebhookDispatcher` in `internal/gateway/webhook.go` sends structured JSON payloads to each endpoint when enforcement events (block, drift, guardrail-block, …) occur. Retries up to 3 times with exponential backoff on transient failures (5xx, network errors); 4xx are treated as permanent. |
