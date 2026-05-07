# LLM Provider Support

DefenseClaw's guardrail proxy supports multiple LLM providers, routing requests through content inspection before forwarding to the upstream API.

## Supported Providers

| Provider | Protocol | Auth Method | Base URL |
|----------|----------|-------------|----------|
| OpenAI | OpenAI Chat API | Bearer token | `https://api.openai.com/v1` |
| Anthropic | Anthropic Messages API | x-api-key header | `https://api.anthropic.com/v1` |
| AWS Bedrock | Bedrock Runtime | AWS SigV4 | Region-specific |
| Google Gemini | Gemini API | Bearer token / API key | `https://generativelanguage.googleapis.com` |
| Ollama | OpenAI-compatible | None (local) | `http://localhost:11434/v1` |

## Configuration

### Unified LLM Config (v5)

```yaml
# ~/.defenseclaw/config.yaml
llm:
  model: claude-sonnet-4-20250514
  api_key_env: ANTHROPIC_API_KEY
  base_url: ""  # empty = auto-detect from model name
  timeout: 30
  max_retries: 2
```

### Per-Component Overrides

```yaml
guardrail:
  model: claude-sonnet-4-20250514
  judge:
    model: claude-opus-4-20250514
    api_key_env: ANTHROPIC_API_KEY
```

### Provider Detection

The proxy auto-detects the provider from the request shape:
- **OpenAI**: POST to `/v1/chat/completions` with `messages` array
- **Anthropic**: POST to `/v1/messages` with `x-api-key` header
- **Bedrock**: AWS SigV4 signed request to `bedrock-runtime` endpoint
- **Gemini**: Request to `generativelanguage.googleapis.com`
- **Ollama**: Request to localhost:11434

### Custom Provider Configuration

```bash
defenseclaw setup provider
```

Creates a `custom-providers.json` overlay for endpoints not auto-detected.

## Proxy Routing

All LLM traffic flows through the guardrail proxy:

```
Agent → Guardrail Proxy (port 4000) → Inspection Pipeline → Upstream Provider
```

The proxy:
1. Identifies the provider from request shape/headers
2. Runs the 4-stage inspection pipeline (regex → Cisco → LLM judge → OPA)
3. Forwards allowed requests to the original upstream
4. Streams responses back through response inspection

## API Key Resolution

For each LLM call, the proxy resolves the API key via:
1. `Config.ResolveLLM("guardrail").ResolvedAPIKey()`
2. Falls back to `~/.defenseclaw/.env` via `loadDotEnv()`
3. Falls back to shell environment
