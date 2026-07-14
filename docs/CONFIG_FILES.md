# Config Files & Environment Variables

How configuration flows between DefenseClaw components. This covers every
file and environment variable the system reads or writes, who creates each
one, and which code path consumes it.

## Visual Overview

```
USER runs: defenseclaw setup guardrail
  │
  ├─ WRITES ──► ~/.defenseclaw/config.yaml         (all settings, including guardrail.*)
  └─ WRITES ──► ~/.defenseclaw/.env                 (API key values, mode 0600)


GO SIDECAR boots: reads config.yaml
  │
  ├─ Starts central config watcher/reconciler
  │    ├─ Watches the active config.yaml path with fsnotify
  │    ├─ Reloads and validates the full YAML on change
  │    └─ Hot-applies safe changes or requests configured restart behavior
  │
  ├─ Runs guardrail proxy (goroutine):
  │    ├─ Loads guardrail.* and cisco_ai_defense.* from in-memory config
  │    ├─ Resolves API keys via ~/.defenseclaw/.env (ResolveAPIKey + loadDotEnv)
  │    └─ Listens on guardrail.port for OpenAI-compatible traffic
  │
  └─ API server handles PATCH /v1/guardrail/config
       └─ PATCHES ─► ~/.defenseclaw/config.yaml  (supported guardrail fields)


GUARDRAIL PROXY:
  │
  ├─ Reads config.yaml indirectly (validated snapshots from the sidecar)
  ├─ Receives hot-applied guardrail updates from the config reconciler
  ├─ Resolves upstream API keys (internal/gateway/provider.go:798–809, loadDotEnv in dotenv.go:28)
  ├─ Authenticates clients with deriveMasterKey (internal/gateway/proxy.go:521–535)
  └─ Runs inspection in Go (GuardrailInspector — local patterns, Cisco AI Defense, LLM judge, OPA)
```

> `config.yaml` is the single source of truth. On upgrade, any legacy
> `guardrail_runtime.json` values are migrated into `config.yaml` once and the
> runtime JSON file is deleted.

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
| **Created by** | `defenseclaw init`, `defenseclaw setup skill-scanner`, `defenseclaw setup mcp-scanner`, `defenseclaw setup gateway`, `defenseclaw setup guardrail`, `defenseclaw sandbox setup` — all via Python `cfg.save()` (`cli/defenseclaw/config.py:290`) |
| **Read by** | **Python CLI** at startup via `config.load()` (`cli/defenseclaw/config.py:426`). **Go sidecar** at startup via `config.Load()` (`internal/config/config.go:262`, Viper). |
| **NOT read by** | Standalone Python guardrail code paths (none in the default stack); the Go sidecar loads YAML via Viper and passes structs into the proxy. |

For guardrail tuning, `guardrail.rule_pack_dir` inside this file selects the
active rule-pack directory. This is separate from `defenseclaw policy activate`
and controls which `judge/*.yaml`, `sensitive_tools.yaml`, and
`suppressions.yaml` files the sidecar loads.

The `registries:` block holds external skill / MCP catalog sources
managed by `defenseclaw registry add` / `edit` / `remove`. Each entry
mirrors `internal/config/registries.go::RegistrySource` and
`cli/defenseclaw/config.py::RegistrySource`. See
[`docs/REGISTRIES.md`](./REGISTRIES.md) for the full pipeline.

```yaml
registries:
  sources:
    - id: corp-skills
      kind: http_yaml         # clawhub | smithery | skills_sh | http_yaml | http_json | git | file
      url: https://catalog.example.com/skills.yaml
      content: skill          # skill | mcp | both
      auth_env: DEFENSECLAW_REGISTRY_TOKEN  # NAME of env var holding the token
      enabled: true
      # auto_sync / sync_interval_hours are RESERVED for v2.
      # No scheduler reads them today — run `defenseclaw registry
      # sync --all` (or wire it into cron / systemd-timer) for now.
      auto_sync: false
      sync_interval_hours: 24
    - id: skills-sh-public
      kind: skills_sh         # https://skills.sh public catalog
      url: ""                 # empty == curated/official view; or 'all-time' / 'trending' / 'hot'
      content: skill
      enabled: true
```

Sync runs persist verdicts to
`~/.defenseclaw/registries/<id>/index.json` and auto-promote clean
entries into `asset_policy.{skill,mcp}.registry` with
`Reason="registry:<id>"` so admission can attribute the rule back to
its source.

> **Note on `auto_sync`** — This field is persisted but **not yet
> honoured at runtime**. There is no in-process scheduler that
> periodically calls `registry sync` today; setting `auto_sync: true`
> only preserves the bit for a future release. Until then, schedule
> `defenseclaw registry sync --all` from cron / a systemd timer / your
> CI loop.

---

### `~/.defenseclaw/registries/<source-id>/`

Per-registry on-disk cache, populated by `defenseclaw registry sync`:

| File | Purpose |
|------|---------|
| `index.json` | Per-entry verdicts (status, severity, approved/rejected). Read by the Python CLI's `registry entries` / `registry show` and by the TUI's Registries panel. |
| `manifest.yaml` | Raw fetched manifest bytes, kept for forensic inspection (diff what the publisher served vs what made it through the validator). |

Both files are written atomically (temp + rename, mode 0o600).

---

### Connector-owned agent config files

DefenseClaw reads and writes some connector-native files when a connector has a
documented local customization surface. For Antigravity, the PR #365 contract is:

| Surface | Paths | DefenseClaw behavior |
| --- | --- | --- |
| Hooks | `~/.gemini/config/hooks.json` | Read/write the global hook file only. Workspace and plugin hook files are discovery-only to avoid duplicate hook firing. |
| MCP | `~/.gemini/config/mcp_config.json`, `<workspace>/.agents/mcp_config.json` | Read/write global and workspace MCP configs. Plugin-contained `<plugin>/mcp_config.json` is discovery-only. |
| Skills | `~/.gemini/config/skills/<skill>/SKILL.md`, `<workspace>/.agents/skills/<skill>/SKILL.md` | Read/write AgentSkills folder form. CLI direct markdown skills under `~/.gemini/antigravity-cli/skills/` are discovery-only. |
| Rules | `~/.gemini/GEMINI.md`, `<workspace>/.agents/rules/`, `<plugin>/rules/*.md` | Discovery-only until activation metadata and naming are documented. |
| Plugins | `~/.gemini/config/plugins/<plugin>/`, `~/.gemini/antigravity-cli/plugins/<plugin>/`, `<workspace>/.agents/plugins/<plugin>/` | Install/list/scan/remove at the documented global or workspace path. The CLI-managed `antigravity-cli/plugins` path is also discovered; runtime disable remains policy/advisory state rather than a native `agy plugin disable` call. |
| Agents | `<plugin>/agents/` | Plugin-contained agents are discovery-only; standalone Antigravity agent paths are not documented. |

The legacy Antigravity marketing-path hook file
`~/.gemini/antigravity-cli/hooks.json` is not a DefenseClaw write target.

---

### `~/.defenseclaw/policies/guardrail/<profile>/`

Guardrail rule-pack directory for one profile such as `default`, `strict`, or
`permissive`. The active profile is whichever directory
`guardrail.rule_pack_dir` points to.

Typical contents:

- `judge/*.yaml` — judge prompts, categories, severity mappings
- `sensitive_tools.yaml` — tool-level sensitivity rules
- `suppressions.yaml` — pre-judge strips, finding suppressions, tool suppressions

| | |
|---|---|
| **Created by** | Usually seeded by `defenseclaw init` under `~/.defenseclaw/policies/guardrail/`. |
| **Read by** | **Go sidecar / guardrail proxy** via `guardrail.LoadRulePack()` (`internal/guardrail/rulepack.go`). |
| **Fallback behavior** | If a file is missing on disk, DefenseClaw falls back to the built-in embedded default for that file. |
| **Common operator edit** | Add a narrow entry to `suppressions.yaml` when a known-safe value such as an app username is being flagged. |

See [Guardrail Rule Packs & Suppressions](GUARDRAIL_RULE_PACKS.md) for the
operator workflow and examples.

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

### Legacy `~/.defenseclaw/guardrail_runtime.json`

Removed in 0.8.0. During gateway startup, DefenseClaw migrates any legacy
runtime values into `config.yaml`, then deletes `guardrail_runtime.json`. If the
migration or deletion fails, startup fails instead of running with split-brain
guardrail config.

Migrated keys:

| Legacy JSON key | New YAML key |
|---|---|
| `mode` | `guardrail.mode` |
| `scanner_mode` | `guardrail.scanner_mode` |
| `block_message` | `guardrail.block_message` |
| `connector` | `guardrail.connector` |
| `hilt_enabled` | `guardrail.hilt.enabled` |
| `hilt_min_severity` | `guardrail.hilt.min_severity` |

---

## Environment Variables

### Built-in guardrail proxy (Go)

The sidecar **runs the guardrail proxy in-process** (`internal/gateway/sidecar.go:352–375`) and does **not** inject a legacy `DEFENSECLAW_*` subprocess environment for it. Mode, scanner mode, model, port, Cisco AI Defense, and judge settings come from `config.yaml` loaded at startup (`config.Load()` in `internal/config/config.go`), then are passed into `NewGuardrailProxy` (`internal/gateway/proxy.go:70–118`).

| Concern | Where it comes from |
|---|---|
| **`guardrail.mode`**, **`guardrail.scanner_mode`** | YAML at startup and config watcher reload; PATCH `/v1/guardrail/config` persists supported runtime changes back into `config.yaml`. |
| **Upstream LLM API key** | Resolved via `Config.ResolveLLM("guardrail").ResolvedAPIKey()` (`internal/config/config.go`). The unified top-level `llm.api_key_env` (default `DEFENSECLAW_LLM_KEY`) is read from `~/.defenseclaw/.env` via `loadDotEnv` (`internal/gateway/dotenv.go:28`) and consumed in `NewGuardrailProxy` (`internal/gateway/proxy.go`). A `guardrail.llm` override block can set a different key/model per component. The legacy `guardrail.api_key_env` field remains as a read-only fallback until operators run `defenseclaw setup migrate-llm`. |
| **Cisco AI Defense** | `cisco_ai_defense` on the loaded `config.Config`; `NewCiscoInspectClient` (`internal/gateway/cisco_inspect.go:53–88`) resolves the API key with the same `dotenvPath` as the proxy. |
| **LLM judge** | `guardrail.judge` (strategy/thresholds) + `Config.ResolveLLM("guardrail.judge")` (model, key, base URL) feed `NewLLMJudge` (`internal/gateway/llm_judge.go`). The judge inherits every field from the top-level `llm:` block unless `guardrail.judge.llm` overrides it. |
| **Bearer auth (clients → proxy)** | `deriveMasterKey` from `device.key` (`internal/gateway/proxy.go:521–535`; checked in `authenticateRequest`, `510–518`). |

### API key env vars (e.g., `ANTHROPIC_API_KEY`)

| | |
|---|---|
| **Set by** | User shell or `defenseclaw setup guardrail` writing `~/.defenseclaw/.env`. |
| **Read by** | **The proxy** — `ResolveAPIKey(cfg.APIKeyEnv, dotenvPath)` in `NewGuardrailProxy` (`internal/gateway/proxy.go:80–82`) supplies the key for upstream provider calls (`NewProvider` in `internal/gateway/provider.go`). |

### Legacy `DEFENSECLAW_*` variables

**The built-in Go guardrail proxy does not set or depend on** `DEFENSECLAW_GUARDRAIL_MODE`, `DEFENSECLAW_SCANNER_MODE`, `DEFENSECLAW_API_PORT`, `DEFENSECLAW_DATA_DIR`, or `PYTHONPATH` for inspection. Mode and scanner mode come from `config.yaml` as described above.

---

## Sandbox-related config fields

These fields are set by `defenseclaw sandbox setup` for openshell-sandbox
standalone mode (Linux supervisor with Landlock, seccomp, network namespace).

### `openshell.mode`

| | |
|---|---|
| **Values** | `""` (default, no sandbox), `"standalone"` |
| **Set by** | `defenseclaw sandbox setup` |
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
| **Set by** | `defenseclaw sandbox setup --sandbox-home <path>` |
| **Read by** | Setup, init, systemd unit generation — all sandbox paths derive from this. |
| **Effect** | Root directory for the sandbox user's home. All OpenClaw and DefenseClaw sandbox-side files live here. |

### `openshell.auto_pair`

| | |
|---|---|
| **Values** | `true` (default), `false` |
| **Set by** | `defenseclaw sandbox setup --no-auto-pair` |
| **Read by** | `defenseclaw sandbox setup` (device pre-pairing step). |
| **Effect** | When `true`, the sidecar's Ed25519 device key is pre-injected into the sandbox's `devices.json` during setup. The sidecar connects immediately on first start without manual approval. When `false`, the operator must manually approve the pairing request. |

### `gateway.api_bind`

| | |
|---|---|
| **Values** | `""` (default: `127.0.0.1`), or an explicit IP address |
| **Set by** | `defenseclaw sandbox setup` (auto-detected from `guardrail.host` in standalone mode) |
| **Read by** | Go sidecar `runAPI()` — determines which interface the REST API binds to. |
| **Effect** | In standalone mode, defaults to the host veth IP (e.g., `10.200.0.1`) so the sandbox can reach the API. Otherwise defaults to loopback. |

### `guardrail.host`

| | |
|---|---|
| **Values** | `"localhost"` (default), or a bridge IP like `"10.200.0.1"` |
| **Set by** | `defenseclaw sandbox setup --host-ip <ip>` |
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
defenseclaw setup webhook show slack-hooks-slack-com
defenseclaw setup webhook enable slack-hooks-slack-com
defenseclaw setup webhook disable slack-hooks-slack-com
defenseclaw setup webhook remove slack-hooks-slack-com

# Preview the payload for an already-configured destination (no delivery)
defenseclaw setup webhook test slack-hooks-slack-com --dry-run
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

## Desktop Notifications Config

> **Local-only.** `notifications.*` fires user-session OS toasts
> (macOS `osascript`, Linux `notify-send`) for blocks and OpenClaw chat
> approvals managed by the gateway. It is **not** an audit sink and **not** a remote
> notification channel — for chat / incident routing use `webhooks[]`
> above, and for downstream forwarding see
> [docs/OBSERVABILITY.md](OBSERVABILITY.md).

The `notifications` block in `config.yaml` controls a single
in-process dispatcher (`internal/gateway/notifier`) that surfaces a
desktop toast whenever:

1. A hook (Claude Code, Codex), the guardrail proxy, or asset policy
   **blocks** a tool call.
2. The same component **would have blocked** the call but is in
   observe / would-block mode.
3. An OpenClaw **Human-in-the-Loop approval** is pending in the chat-origin
   session (informational only — clicking the notification does not approve
   anything; the operator replies in OpenClaw). Native-ask hook connectors
   render their own host prompt and connectors without native ask do not
   create a pending TUI approval.

The dispatcher applies a global token-bucket rate limit, an LRU
dedup window, and a per-category / per-source filter so it can be
dialed down without losing every signal.

### CLI

Use `defenseclaw setup notifications` to flip the master switch.
Defaults are platform-conditional: **on** on darwin (every macOS
user already has Notification Center running) and **off**
elsewhere (Linux operators opt in explicitly so a `notify-send`
that fails on a headless box does not fire on every block):

```bash
# One-shot Y/n onboarding prompt (defaults to Yes):
defenseclaw setup notifications

# Direct toggles
defenseclaw setup notifications on
defenseclaw setup notifications off --yes
defenseclaw setup notifications status

# Apply immediately to the running sidecar (the dispatcher is
# constructed once at boot from notifications.*, so a flip without
# --restart leaves the previous state in effect for the live process).
defenseclaw setup notifications on --restart
```

Per-category and per-source fields are exposed via
`defenseclaw setup notifications-set <slot> <on|off>` so you can
silence one surface (e.g. asset-policy blocks) without flipping the
master switch:

```bash
# Categories
defenseclaw setup notifications-set block_enforced off
defenseclaw setup notifications-set block_would_block on
defenseclaw setup notifications-set hitl_approval on

# Sources (dotted form or short alias)
defenseclaw setup notifications-set sources.hook off
defenseclaw setup notifications-set guardrail off
defenseclaw setup notifications-set asset_policy off
```

Throttle fields (`dedup_window`, `max_per_minute`) remain config-only — flip
them in `config.yaml`; the running gateway reloads the file and reconciles the
notification dispatcher.

### YAML

```yaml
notifications:
  enabled: true              # master switch (default: true on macOS/Windows, false elsewhere)
  block_enforced: true       # action-mode block events
  block_would_block: false   # observe-mode "would have blocked / would have asked" events
                             # (off by default; opt in while tuning policy in observe mode)
  hitl_approval: true        # informational toasts for gateway-brokered OpenClaw approvals
  sources:
    hook: true               # claude_code_hook + codex_hook decisions
    guardrail: true          # GuardrailProxy verdicts
    asset_policy: true       # asset_policy_runtime decisions
  dedup_window: 30s          # default 30s; "" / 0s falls back to default
  max_per_minute: 12         # default 12; 0 falls back to default
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` on darwin, `false` elsewhere | Master switch (see `config.DefaultNotificationsEnabled` / Python `_default_notifications_enabled`). When `false` the dispatcher is short-circuited and no other field has any effect. |
| `block_enforced` | bool | `true` | Surface a toast for action-mode blocks (`action == "block"`). |
| `block_would_block` | bool | `false` | Surface a toast for observe-mode would-block events (verdict was a block but the runtime mode degraded it to alert) AND for "would-ask" events where a `confirm` verdict never reached the chat surface (observe mode, or the connector cannot natively ask — see `BlockEvent.WouldAsk`). Off by default so a fresh install only notifies for things that actually happened. |
| `hitl_approval` | bool | `true` | Surface an **informational** toast at the start of the OpenClaw `HILTApprovalManager.Request` flow. The notification has no buttons; the operator replies in the OpenClaw chat-origin session. |
| `sources.hook` | bool | `true` | Allow notifications from `evaluateClaudeCodeHook` / `evaluateCodexHook`. |
| `sources.guardrail` | bool | `true` | Allow notifications from `GuardrailProxy` block / would-block branches. |
| `sources.asset_policy` | bool | `true` | Allow notifications from `evaluateRuntimeMCPAssetPolicy` / `evaluateRuntimeSkillAssetPolicy`. |
| `dedup_window` | duration | `30s` | LRU dedup window keyed on `sha256(category|source|target|reason)`. Identical events seen inside the window are suppressed. Empty string or `0s` resolves to the default. |
| `max_per_minute` | int | `12` | Global token-bucket cap across **all** categories. When exhausted, the dispatcher emits a single roll-up toast per minute (`"DefenseClaw suppressed N notifications"`) and silently drops the rest until the bucket refills. `0` resolves to the default. |

| | |
|---|---|
| **Set by** | `defenseclaw setup notifications` (preferred) or operator via `config.yaml`. |
| **Read by** | **Go sidecar** at startup via `config.Load()` → `notifier.New(cfg.Notifications)` (wired into hooks, proxy, asset runtime, and `HILTApprovalManager`). **Python CLI** via `config.load()` for round-trip preservation; the Python side does not emit notifications itself. |
| **Effect** | The dispatcher fires `internal/notify.SendNotification` in a goroutine so request latency is unaffected. On macOS this calls `osascript` (`display notification … with title …`); on Linux it calls `notify-send`; on Windows the signed gateway owns an in-process `Shell_NotifyIconW` broker. Native-delivery failures and unsupported platforms fall back to a structured stderr log line. State (dedup LRU + token bucket) is per-process and resets on gateway restart. |
