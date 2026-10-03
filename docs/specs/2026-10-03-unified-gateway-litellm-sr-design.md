# DefenseClaw Unified Gateway — LiteLLM + SR as Managed Subsystems

> DefenseClaw gateway starts, configures, and monitors LiteLLM and SR
> as managed child processes. The user edits only `~/.defenseclaw/config.yaml`.
> The gateway translates that config into LiteLLM model registrations
> (via REST API) and SR routing signals (via config file + container restart).

**Status:** Draft
**Date:** 2026-10-03
**Repo:** cisco-ai-defense/defenseclaw (OSS)

---

## 1. Problem

Today LiteLLM, SR, and the DefenseClaw gateway are three independent
processes with three separate configs. The user must:

- Edit `~/.defenseclaw/config.yaml` for guardrails, hooks, routing models
- Edit `~/.defenseclaw/litellm/config.yaml` for LiteLLM provider mapping
- Edit `~/.defenseclaw/semantic-router/config.yaml` for SR signals
- Start all three manually (or via a script)
- Keep them in sync when models change

This breaks when any process dies, configs drift, or JWT tokens expire.

## 2. Design

### 2.1 Single Config, Single Command

```
~/.defenseclaw/config.yaml (user edits this only)
    │
    ├── llm section → Go gateway generates LiteLLM model registrations
    ├── routing section → Go gateway generates SR config + signals
    └── guardrail section → Go gateway uses directly (unchanged)

defenseclaw-gateway start
    │
    ├── Starts LiteLLM child process (port 4001, minimal bootstrap)
    ├── Waits for LiteLLM healthy
    ├── Pushes models via POST /model/new for each routing.models entry
    ├── Starts SR Docker container (port 8080)
    ├── Waits for SR healthy
    ├── Starts guardrail proxy + hooks (existing behavior)
    └── Monitors both children — restarts on crash
```

### 2.2 Config Translation

The existing `config.yaml` already has all the information:

```yaml
# ~/.defenseclaw/config.yaml (what the user edits)
llm:
  provider: azure
  model: claude-sonnet-4-6
  base_url: https://chat-ai.cisco.com/openai/deployments/claude-sonnet-4-6
  api_key_env: CISCO_AI_JWT
  extra_headers:
    user: '{"appkey":"egai-prd-other-020122827-other-1790804579247"}'

routing:
  enabled: true
  models:
    - name: claude-opus
      model: claude-opus-4-8
      provider: azure
      base_url: https://chat-ai.cisco.com/openai/deployments/claude-opus-4-8
      api_key_env: CISCO_AI_JWT
    - name: gpt-nano
      model: gpt-5-4-nano
      provider: azure
      base_url: https://chat-ai.cisco.com/openai/deployments/gpt-5-4-nano
      api_key_env: CISCO_AI_JWT
  signals:
    keywords:
      coding_intent:
        keywords: [code, implement, debug, refactor, python, function]
      reasoning_intent:
        keywords: [analyze, compare, tradeoffs, architecture, design]
  decisions:
    - name: route_coding
      conditions: [{type: keyword, name: coding_intent}]
      model_refs: [gpt-5-5]
    - name: route_reasoning
      conditions: [{type: keyword, name: reasoning_intent}]
      model_refs: [claude-opus]
```

The gateway translates this at startup:

**For LiteLLM:** Each `routing.models[]` entry becomes a `POST /model/new`:
```json
{
  "model_name": "claude-opus",
  "litellm_params": {
    "model": "deepseek/claude-opus-4-8",
    "api_base": "https://chat-ai.cisco.com/openai/deployments/claude-opus-4-8",
    "api_key": "<resolved from CISCO_AI_JWT>",
    "extra_headers": {"api-key": "<jwt>", "user": "..."}
  }
}
```

The `deepseek/` provider prefix is auto-added for Circuit API models
(detected by `chat-ai.cisco.com` base URL) to enable Responses→Chat
bridging. For Ollama Cloud, `ollama/` prefix. For direct OpenAI,
`openai/` prefix.

**For SR:** The `routing.signals` and `routing.decisions` sections are
written to `~/.defenseclaw/semantic-router/config.yaml` and the SR
container is restarted to reload.

### 2.3 Go Code Changes

**New files:**

| File | Purpose |
|------|---------|
| `internal/gateway/litellm_manager.go` | Starts LiteLLM, pushes model config via REST, monitors health |
| `internal/gateway/sr_manager.go` | Generates SR config, starts Docker container, monitors health |
| `internal/gateway/config_translator.go` | Translates DefenseClaw config → LiteLLM model params + SR config |

**Modified files:**

| File | Change |
|------|--------|
| `internal/gateway/sidecar.go` | Startup sequence calls `litellmManager.Start()` and `srManager.Start()` before guardrail init |
| `internal/gateway/provider.go` | Factory functions return `litellmProvider` (already done) |
| `internal/gateway/proxy.go` | Remove Bifrost import (already done) |

**`litellm_manager.go`** lifecycle:
1. `Start(ctx, cfg)` — writes minimal bootstrap YAML, starts `litellm` process, waits healthy
2. `PushModels(cfg)` — for each model in config, calls `POST /model/new`
3. `UpdateModel(name, params)` — called when config reloads
4. `Health()` — polls `/health/liveliness`
5. `Stop()` — sends SIGTERM, waits, kills

**`config_translator.go`** provider detection:
```go
func litellmProviderPrefix(baseURL string) string {
    switch {
    case strings.Contains(baseURL, "chat-ai.cisco.com"):
        return "deepseek"  // Circuit API: bridges Responses→Chat
    case strings.Contains(baseURL, "api.ollama.com"):
        return "ollama"
    case strings.Contains(baseURL, "api.anthropic.com"):
        return "anthropic"
    default:
        return "openai"
    }
}
```

### 2.4 LiteLLM Bootstrap Config

The gateway writes a minimal YAML for LiteLLM to start with:

```yaml
# Auto-generated by defenseclaw-gateway. Do not edit.
general_settings:
  master_key: "<gateway_token>"
  store_model_in_db: true
  database_url: "sqlite:///Users/<user>/.defenseclaw/litellm/litellm.db"

litellm_settings:
  drop_params: true
  modify_params: true
  callbacks: ["filter_empty.proxy_handler_instance"]
```

Models are added via API after startup, not in the YAML. This means
LiteLLM starts fast (no provider validation at boot) and models can
be updated without restart.

### 2.5 SR Config Generation

The gateway writes `~/.defenseclaw/semantic-router/config.yaml` from
the `routing` section, then starts/restarts the Docker container. The
SR config includes:

- `providers.models[]` from `routing.models[]`
- `signals.keywords` from `routing.signals.keywords`
- `decisions[]` from `routing.decisions[]`
- `global.router.model_selection.enabled: true`

### 2.6 SR Callback in LiteLLM

The `sr_router.py` callback (already written) calls the SR container's
`/api/v1/classify/intent` endpoint before each LLM request. The
callback runs inside LiteLLM and rewrites the `model` field based on
the SR classification.

Since SR requires an embedding model for keyword classification
(known bug in v0.3.0), the config generator either:
- Bundles a small embedding model path in the SR config
- Or upgrades the SR container to a version that handles keyword-only

### 2.7 JWT Auto-Refresh

The gateway already refreshes the Circuit API JWT via OAuth. The
`litellm_manager` updates the model's `api_key` via
`POST /model/update` when the JWT is refreshed — no LiteLLM restart
needed.

### 2.8 Monitoring

The gateway polls both children:
- LiteLLM: `GET /health/liveliness` every 10s
- SR: `GET /health` every 10s

On crash: log, restart child, re-push config.
On gateway shutdown: SIGTERM both children, wait 5s, SIGKILL.

## 3. Config Schema Changes

No new top-level sections. The existing `llm`, `routing`, and
`guardrail` sections already contain all needed information. The only
addition:

```yaml
litellm:
  port: 4001           # default 4001
  callbacks: []         # additional LiteLLM callbacks (optional)
  db_path: ""           # override SQLite path (optional)
```

This is optional — the gateway uses sensible defaults.

## 4. What Gets Removed

- `~/.defenseclaw/litellm/config.yaml` — auto-generated, not user-edited
- `~/.defenseclaw/start-defenseclaw.sh` — replaced by gateway managing both
- Manual LiteLLM and SR process management
- Bifrost Go SDK (`provider_bifrost.go`, `go.mod` dependency)

## 5. Success Criteria

1. `defenseclaw-gateway restart` starts gateway + LiteLLM + SR
2. User edits only `~/.defenseclaw/config.yaml`
3. Models added to config appear in LiteLLM within 5s
4. SR classifies queries and routes to the correct model
5. JWT refresh propagates to LiteLLM without restart
6. LiteLLM crash auto-restarts within 10s
7. `defenseclaw-gateway stop` cleanly stops all three

## 6. Implementation Order

1. Fix config schema mismatch (strip unsupported fields at load time)
2. `config_translator.go` — translate config → LiteLLM params + SR YAML
3. `litellm_manager.go` — process lifecycle + model push via REST API
4. `sr_manager.go` — config write + Docker container lifecycle
5. Wire into `sidecar.go` startup sequence
6. Build, install, test end-to-end
7. Remove `provider_bifrost.go` and Bifrost dependency from `go.mod`
