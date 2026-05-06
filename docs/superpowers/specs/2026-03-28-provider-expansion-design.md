# Provider Expansion: OpenRouter, Azure OpenAI, Google Gemini

> **Status:** PROPOSAL (0% implemented)

**Date:** 2026-03-28
**Status:** Approved
**Scope:** Add 4 new LLM provider backends to the guardrail proxy

## Context

The DefenseClaw guardrail proxy currently supports two upstream LLM providers:
- `openaiProvider` — pass-through to OpenAI API
- `anthropicProvider` — full request/response translation from OpenAI format to Anthropic Messages API

This limits adoption to teams using only OpenAI or Anthropic. This spec adds OpenRouter, Azure OpenAI, and Google Gemini (both native and OpenAI-compatible modes).

## Decision: Approach B — Separate Provider Structs, Shared Helpers

Each new provider is its own struct implementing `LLMProvider`. All OpenAI-compatible variants reuse existing helpers (`patchRawBody`, `readOpenAISSE`, `providerHTTPClient`). The Gemini native provider has full request/response translation, similar in scope to the existing Anthropic provider.

**Rejected alternatives:**
- **Approach A (extend openaiProvider with hooks):** Grows complexity of the core provider; Azure URL construction doesn't fit cleanly.
- **Approach C (functional options factory):** Over-engineered for 3-4 variants; doesn't match codebase style.

## Provider Specifications

### OpenRouter (`openrouterProvider`)

- **Struct:** `openrouterProvider{model, apiKey, baseURL string}`
- **Default base URL:** `https://openrouter.ai/api`
- **Auth:** `Authorization: Bearer <key>`
- **Extra headers:** `HTTP-Referer: https://github.com/defenseclaw/defenseclaw`, `X-Title: defenseclaw`
- **URL path:** `/v1/chat/completions`
- **Request/response format:** OpenAI pass-through via `patchRawBody()` + `readOpenAISSE()`
- **Config example:** `model: openrouter/anthropic/claude-opus-4-5`

### Azure OpenAI (`azureOpenAIProvider`)

- **Struct:** `azureOpenAIProvider{model, apiKey, baseURL string}`
- **Base URL:** required from user (e.g., `https://myresource.openai.azure.com/openai/deployments/gpt4o`)
- **Auth:** `api-key: <key>` header (NOT Bearer token)
- **URL path:** `{baseURL}/chat/completions?api-version=2024-12-01-preview` appended to base URL
- **Request/response format:** OpenAI pass-through via `patchRawBody()` + `readOpenAISSE()`
- **Config example:** `model: azure/gpt-4o` with `api_base: https://myresource.openai.azure.com/openai/deployments/gpt4o`

### Gemini OpenAI-Compatible (`geminiCompatProvider`)

- **Struct:** `geminiCompatProvider{model, apiKey, baseURL string}`
- **Default base URL:** `https://generativelanguage.googleapis.com/v1beta/openai`
- **Auth:** `Authorization: Bearer <key>`
- **URL path:** `/chat/completions`
- **Request/response format:** OpenAI pass-through via `patchRawBody()` + `readOpenAISSE()`
- **Config example:** `model: gemini-openai/gemini-2.0-flash`

### Gemini Native (`geminiNativeProvider`)

- **Struct:** `geminiNativeProvider{model, apiKey, baseURL string}`
- **Default base URL:** `https://generativelanguage.googleapis.com/v1beta`
- **Auth:** `?key=<apiKey>` query parameter
- **URL paths:**
  - Non-streaming: `/models/{model}:generateContent`
  - Streaming: `/models/{model}:streamGenerateContent?alt=sse`
- **Full translation required:**
  - `translateRequest()`: OpenAI messages to Gemini `contents[]` with `parts[]`
  - `translateResponse()`: Gemini `candidates[].content.parts[]` to OpenAI choices
  - `readGeminiSSE()`: Gemini SSE stream to `StreamChunk` callbacks
- **Config example:** `model: gemini/gemini-2.0-flash`

#### Gemini Message Format Mapping

| OpenAI | Gemini Native |
|--------|--------------|
| `role: "system"` | `systemInstruction.parts[].text` |
| `role: "user"` | `role: "user", parts[].text` |
| `role: "assistant"` | `role: "model", parts[].text` |
| `role: "tool"` | `role: "function", parts[].functionResponse` |
| `tool_calls` | `parts[].functionCall` |
| `finish_reason: "stop"` | `finishReason: "STOP"` |
| `finish_reason: "length"` | `finishReason: "MAX_TOKENS"` |
| `finish_reason: "tool_calls"` | `finishReason: "STOP"` (with functionCall present) |

## Routing

### Model prefix format: `provider/model-name`

| Prefix | Provider | Example |
|--------|----------|---------|
| `openai/` | openaiProvider | `openai/gpt-4o` |
| `anthropic/` | anthropicProvider | `anthropic/claude-opus-4-5` |
| `openrouter/` | openrouterProvider | `openrouter/anthropic/claude-opus-4-5` |
| `azure/` | azureOpenAIProvider | `azure/gpt-4o` |
| `gemini/` | geminiNativeProvider | `gemini/gemini-2.0-flash` |
| `gemini-openai/` | geminiCompatProvider | `gemini-openai/gemini-2.0-flash` |

### `splitModel()` fix

OpenRouter model names contain slashes (e.g., `openrouter/anthropic/claude-opus-4-5`). The current `splitModel()` splits on the first `/`. Updated to use a known-prefix list:

```go
func splitModel(model string) (provider, modelID string) {
    i := strings.IndexByte(model, '/')
    if i < 0 {
        return "", model
    }
    prefix := model[:i]
    switch prefix {
    case "openai", "anthropic", "openrouter", "azure", "gemini", "gemini-openai":
        return prefix, model[i+1:]
    }
    return "", model
}
```

### `inferProvider()` additions

```go
if strings.HasPrefix(model, "gemini") { return "gemini" }
if strings.HasPrefix(apiKey, "AIza") { return "gemini" }
```

## Config Changes

### `GuardrailConfig` — one new field

```yaml
guardrail:
  model: "azure/gpt-4o"
  api_key_env: "UPSTREAM_API_KEY"
  api_base: "https://myresource.openai.azure.com/openai/deployments/gpt4o"  # NEW
```

The `api_base` field is optional. It mirrors the existing `JudgeConfig.APIBase`. Used by Azure (required) and as an override for any other provider's default base URL.

### Proxy constructor change

```go
// Before:
provider, err := NewProvider(cfg.Model, apiKey)
// After:
provider := NewProviderWithBase(cfg.Model, apiKey, cfg.APIBase)
```

## File Organization

Split the 811-line `provider.go` into focused files:

| File | Contents | Lines (est.) |
|------|----------|-------------|
| `provider.go` | Types, interface, routing, shared helpers | ~350 |
| `provider_openai.go` | `openaiProvider` (extracted) | ~110 |
| `provider_anthropic.go` | `anthropicProvider` + Anthropic types/translation (extracted) | ~350 |
| `provider_openrouter.go` | `openrouterProvider` | ~80 |
| `provider_azure.go` | `azureOpenAIProvider` | ~90 |
| `provider_gemini_compat.go` | `geminiCompatProvider` | ~80 |
| `provider_gemini.go` | `geminiNativeProvider` + Gemini types/translation | ~250 |

## Testing

One test file per new provider using `httptest.NewServer`:

| File | Verifies |
|------|----------|
| `provider_openrouter_test.go` | Extra headers sent, base URL override, streaming |
| `provider_azure_test.go` | `api-key` header (not Bearer), URL with api-version query param, base URL required |
| `provider_gemini_compat_test.go` | Default base URL, Bearer auth, streaming |
| `provider_gemini_test.go` | Request translation (messages, system, tools), response translation, finish reason mapping, SSE parsing, streaming tool call assembly |

Each test verifies: correct URL path, correct auth header, request body translation (Gemini native), response translation back to OpenAI format, SSE streaming end-to-end.

## OpenClaw Config Patching — Multi-Provider Coverage

### Problem

The current `patch_openclaw_config()` only intercepts the single `agents.defaults.model.primary`
model. But openclaw.json can have **multiple providers** configured under `models.providers`,
and OpenClaw may route requests to any of them (agent-level overrides, fallback chains).
Traffic to unpatched providers bypasses the guardrail.

Additionally, provider-specific config (especially `baseUrl` for Azure deployments) is never
extracted from the original openclaw.json, so the Go proxy doesn't know where to forward.

### Solution: Patch ALL configured providers

**`patch_openclaw_config()`** changes:

1. **Read all providers** from `cfg["models"]["providers"]` before patching.
2. **For each provider** that DefenseClaw supports (`anthropic`, `openai`, `azure`, `openrouter`,
   `gemini`, `gemini-openai`):
   - Save the original provider entry to `cfg["_defenseclaw_original_providers"][name]`
     (for restore on disable).
   - Extract `baseUrl` and `apiKey` from the provider entry.
   - Replace the provider entry's `baseUrl` with `http://localhost:{port}` and `apiKey`
     with the master key, keeping the `models` list intact so OpenClaw still sees the
     same model IDs.
3. **For each UNSUPPORTED provider** (any provider not in the known list):
   - Still patch `baseUrl` → `http://localhost:{port}` and `apiKey` → master key.
   - Save original to `_defenseclaw_original_providers` (for restore).
   - Mark as `"supported": false` in `guardrail_providers.json`.
   - The Go proxy will **block all traffic** to unsupported providers by default,
     returning an error: `"provider {name} is not supported by DefenseClaw guardrail — traffic blocked"`.
   - This ensures zero LLM traffic bypasses the guardrail, even for unknown providers.
   - The interactive wizard shows a warning: "Provider '{name}' is not supported by DefenseClaw.
     Traffic to this provider will be blocked while guardrail is enabled."
4. **Add the `defenseclaw` provider** as before (for the primary model alias).
5. **Save extracted provider configs** to a new `guardrail_providers.json` file in
   `~/.defenseclaw/` so the Go proxy knows the real upstream endpoints:

```json
{
  "anthropic": {"base_url": "", "api_key_env": "ANTHROPIC_API_KEY"},
  "azure": {"base_url": "https://myresource.openai.azure.com/openai/deployments/gpt4o", "api_key_env": "AZURE_OPENAI_API_KEY"},
  "openrouter": {"base_url": "", "api_key_env": "OPENROUTER_API_KEY"}
}
```

The API keys themselves are saved to `.env` (mode 0600) — the JSON file only stores env var
names, never raw secrets.

**`restore_openclaw_config()`** changes:

- Read `cfg["_defenseclaw_original_providers"]` and restore each provider entry.
- Remove the `_defenseclaw_original_providers` key.
- Existing restore logic (remove `defenseclaw` provider, restore primary model) unchanged.

**`detect_current_model()`** → renamed/extended to **`detect_provider_configs()`**:

Returns a dict of all configured providers with their base URLs and model lists, not just
the primary model. The interactive wizard uses this to show which providers will be intercepted.

### Go Proxy: Multi-Provider Routing

Currently the proxy has a single `LLMProvider` for all upstream requests. With multi-provider
patching, the proxy needs to route to the correct upstream based on the **original** provider
prefix in the model name.

**New field in `GuardrailProxy`:**

```go
type GuardrailProxy struct {
    // ... existing fields ...
    providers map[string]LLMProvider  // keyed by provider prefix
    primary   LLMProvider             // default/primary provider (backward compat)
}
```

**Routing in `handleChatCompletion()`:**

After parsing the request, extract the provider prefix from the model name and look up the
correct provider:

```go
provider, _ := splitModel(req.Model)
upstream, ok := p.providers[provider]
if !ok {
    // Check if this is a known-but-unsupported provider (patched with supported=false)
    if _, blocked := p.blockedProviders[provider]; blocked {
        msg := fmt.Sprintf("provider %q is not supported by DefenseClaw guardrail — traffic blocked", provider)
        writeOpenAIError(w, http.StatusForbidden, msg)
        return
    }
    // Unknown provider with no prefix — use primary (backward compat)
    upstream = p.primary
}
resp, err := upstream.ChatCompletion(r.Context(), req)
```

**New field:**

```go
type GuardrailProxy struct {
    // ... existing fields ...
    providers        map[string]LLMProvider  // supported providers, keyed by prefix
    blockedProviders map[string]bool         // unsupported providers — block all traffic
    primary          LLMProvider             // default/primary provider (backward compat)
}
```

**Provider map construction** at startup:

Read `guardrail_providers.json` + `.env` and construct one `LLMProvider` per entry.
Falls back to the single-provider behavior if the file doesn't exist (backward compat).

### Interactive Wizard Changes

The wizard prompt flow changes to:

1. Detect **all** providers in openclaw.json (not just the primary model).
2. Show: "Found N providers configured in OpenClaw: anthropic, azure, openrouter"
3. Ask: "Route all providers through the guardrail? (Y/n)"
   - If yes: patch all, prompt for API key env vars for each.
   - If no: ask which providers to intercept.
4. For `azure` providers specifically: the `baseUrl` is extracted automatically from
   `models.providers.azure.baseUrl` — no manual prompt needed.
5. For each intercepted provider: confirm the API key env var name (auto-detected), prompt
   for the actual key value if not in env or .env.

## Python CLI Changes

The setup wizard and guardrail helpers must recognize the new providers so that
`defenseclaw setup guardrail` (interactive and non-interactive) works end-to-end.

### `cli/defenseclaw/guardrail.py`

| Function | Current | Change |
|----------|---------|--------|
| `KNOWN_PROVIDERS` | `["anthropic", "openai"]` | Add `"openrouter"`, `"azure"`, `"gemini"`, `"gemini-openai"` |
| `guess_provider(model)` | Handles claude→anthropic, gpt/o1/o3/o4→openai, gemini→google | Add: bare model heuristics are unchanged; the provider prefix in `model` is the primary mechanism. `gemini→"gemini"` (not "google") to match Go routing. |
| `detect_api_key_env(model)` | anthropic/claude→`ANTHROPIC_API_KEY`, openai/gpt→`OPENAI_API_KEY`, gemini/google→`GOOGLE_API_KEY` | Add: `"azure"` or `"deployment"` → `AZURE_OPENAI_API_KEY`, `"openrouter"` → `OPENROUTER_API_KEY` |
| `model_to_proxy_name(model)` | Strips `anthropic-`, `openai-`, `google-` prefixes | Add `azure-`, `openrouter-`, `gemini-`, `gemini-openai-` prefix stripping. Also handle multi-slash models (OpenRouter): use last segment. |

### `cli/defenseclaw/config.py`

| Location | Change |
|----------|--------|
| `GuardrailConfig` dataclass (line 428) | Add `api_base: str = ""` field |
| `_merge_guardrail()` (line 713) | Read `api_base` from raw dict |
| `Config.save()` / `_serialize_guardrail()` | Write `api_base` to YAML |

### `cli/defenseclaw/commands/cmd_setup.py`

**`_interactive_guardrail_setup()`:**
- After provider is detected/chosen, if provider is `"azure"`:
  - Prompt for `api_base` (required): "Azure deployment URL (e.g. https://myresource.openai.azure.com/openai/deployments/gpt4o)"
  - Store in `gc.api_base`
- For other providers, optionally prompt for `api_base` override if the user wants a custom endpoint

**`execute_guardrail_setup()`:**
- No changes needed — it already passes `gc` to config save and `patch_openclaw_config`. The `api_base` flows through the saved config.yaml to the Go binary.

**Summary row in setup output (line ~707):**
- Add `("guardrail.api_base", gc.api_base)` when non-empty

### Go `internal/config/config.go`

| Location | Change |
|----------|--------|
| `GuardrailConfig` struct (line 254) | Add `APIBase string \`mapstructure:"api_base" yaml:"api_base"\`` |

### Go `internal/config/defaults.go`

No changes — `APIBase` defaults to empty string (zero value), which is correct.

## Out of Scope (Follow-ups)

- **AWS Bedrock** — requires SigV4 signing, different auth model.
- **Auto-patch new providers** — if a user adds a provider to openclaw.json after DefenseClaw setup, it currently bypasses the guardrail. Fix: extend the 5-second hot-reload loop to reconcile openclaw.json, auto-patching any unpatched providers (supported → route through proxy, unsupported → block). Reuses existing `guardrail_runtime.json` polling pattern.
- **TypeScript plugin changes** — plugin talks to the sidecar, not the LLM. No changes needed.

## Estimated Size

- ~80 lines each: OpenRouter, Azure, Gemini-compat providers (Go)
- ~250 lines: Gemini native provider (Go)
- ~100 lines: Go multi-provider routing + config changes
- ~120 lines: Python CLI changes (guardrail.py, config.py, cmd_setup.py — multi-provider patching)
- ~80 lines: Python restore/detect changes
- ~500 lines: tests (Go provider tests + Python patching tests)
- **Total: ~1290 new lines**
