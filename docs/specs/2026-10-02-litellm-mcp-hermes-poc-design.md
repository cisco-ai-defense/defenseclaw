# DefenseClaw LiteLLM + MCP Gateway + Hermes Agent — POC Design

> Replace the Go gateway + Bifrost with LiteLLM embedded in DefenseClaw,
> use LiteLLM's MCP gateway for tool access, and connect a Hermes agent
> running in a Docker sandbox. Single-user local install — no CP, no DP,
> no tenants, no admin.

**Status:** Draft
**Date:** 2026-10-02
**Repo:** cisco-ai-defense/defenseclaw (OSS)
**Target:** Local docker-compose on an end-user's machine

---

## 1. Problem Statement

DefenseClaw Enterprise runs 23+ services across a control plane and data
plane. This POC proves a radically simpler architecture — LiteLLM
embedded inside DefenseClaw as one service, plus Hermes as the sandboxed
agent — can deliver the same core capabilities on a single machine:

- LLM routing with cost optimization
- MCP tool access (Outlook, Webex, search, etc.)
- Agent execution in complete isolation (no host access)
- Guardrails (prompt injection, PII)
- Zero infrastructure beyond Docker

The user runs `docker-compose up` and gets a working AI agent with
protected LLM access and authenticated MCP tools.

## 2. Architecture

```
docker-compose up
  │
  ├── defenseclaw        (Python: LiteLLM + DefenseClaw callbacks)
  │     port 4000          LLM proxy + MCP gateway
  │
  ├── redis               (caching, rate limiting)
  │     port 6379
  │
  └── hermes              (Hermes agent in Docker sandbox)
        connects to defenseclaw:4000
```

No Postgres — the user's API key is in `.env`, LiteLLM runs in
key-less mode with a single master key for local auth. Spend tracking
uses LiteLLM's in-memory or Redis-backed counters. No database needed.

### 2.1 What Each Component Replaces

| POC Component | Replaces (from Enterprise) |
|---------------|---------------------------|
| `defenseclaw` (LiteLLM) | api-gateway, auth-manager, Bifrost, MCP proxy, MCP registry, secret sidecar, policy-manager, config-manager, settings-manager, AWM, posture-manager, tenant-manager, db-manager, cp-secret-manager |
| `redis` | New (caching, rate limits) |
| `hermes` | PulseClaw agent, OpenClaw runtime, sandbox pod, warm pool, ASP, sandbox router, orchestrator |

### 2.2 Request Flows

**LLM call:**
```
Hermes → POST defenseclaw:4000/v1/chat/completions
  → master key auth (single shared key from .env)
  → pre-call callback: guardrail check (replaces shield)
  → router: SR classifier picks model tier
    → Circuit API (cheap model)
    → fallback: Circuit API (quality model)
    → fallback: direct OpenAI/Anthropic
  → post-call callback: response guardrail
  → response to Hermes
```

**MCP tool call:**
```
Hermes → POST defenseclaw:4000/v1/chat/completions
           (message contains MCP tool_use)
  → master key auth
  → LiteLLM MCP gateway resolves tool → MCP server
  → credentials injected from env-based secrets
  → proxy to MCP server (Outlook, Webex, etc.)
  → result returned as tool_result in chat response
  → Hermes processes result
```

No provisioning flow — the user configures everything in `.env` and
`config/litellm_config.yaml` before running `docker-compose up`.

## 3. DefenseClaw Service (Python)

### 3.1 Entry Point

A Python application that starts LiteLLM with custom callbacks. Not a
fork of LiteLLM — a thin wrapper that adds DefenseClaw-specific logic.

```python
# defenseclaw/main.py
import litellm
from litellm.proxy.proxy_server import app as litellm_app
from fastapi import FastAPI

app = FastAPI(title="DefenseClaw")

# LiteLLM serves all /v1/* routes (chat, models, MCP)
app.mount("/v1", litellm_app)

# Health check
@app.get("/healthz")
def healthz():
    return {"status": "ok"}
```

### 3.2 LiteLLM Configuration

```yaml
# config/litellm_config.yaml
model_list:
  # Primary: Circuit API (cheap tier)
  - model_name: "defenseclaw-default"
    litellm_params:
      model: "openai/gpt-4o-mini"
      api_base: "os.environ/CIRCUIT_API_BASE"
      api_key: "os.environ/CIRCUIT_API_KEY"

  # Quality tier
  - model_name: "defenseclaw-quality"
    litellm_params:
      model: "openai/gpt-4o"
      api_base: "os.environ/CIRCUIT_API_BASE"
      api_key: "os.environ/CIRCUIT_API_KEY"

  # Fallback: Direct provider
  - model_name: "defenseclaw-fallback"
    litellm_params:
      model: "anthropic/claude-sonnet-4-20250514"
      api_key: "os.environ/ANTHROPIC_API_KEY"

router_settings:
  routing_strategy: "cost-based-routing"
  redis_host: "redis"
  redis_port: 6379

general_settings:
  master_key: "os.environ/DEFENSECLAW_MASTER_KEY"

litellm_settings:
  cache: true
  cache_params:
    type: "redis"
    host: "redis"
    port: 6379
    ttl: 3600
```

### 3.3 Custom Callbacks

**Smart Router (cost optimization):**
```python
# defenseclaw/callbacks/circuit_router.py
from litellm.integrations.custom_logger import CustomLogger

class CircuitSmartRouter(CustomLogger):
    """Classifies query complexity and selects model tier."""

    async def async_pre_call_hook(self, user_api_key_dict, cache, data, call_type):
        query = data.get("messages", [{}])[-1].get("content", "")
        if self._is_simple(query):
            data["model"] = "defenseclaw-default"
        else:
            data["model"] = "defenseclaw-quality"
        return data

    def _is_simple(self, query: str) -> bool:
        # Heuristic: short questions go to cheap model
        return len(query) < 200 and "?" in query
```

**Guardrail (replaces Go shield):**
```python
# defenseclaw/callbacks/guardrails.py
import litellm
from litellm.integrations.custom_logger import CustomLogger

class DefenseClawGuardrail(CustomLogger):
    """Pre/post-call content safety checks."""

    async def async_pre_call_hook(self, user_api_key_dict, cache, data, call_type):
        messages = data.get("messages", [])
        for msg in messages:
            content = msg.get("content", "")
            if self._detect_injection(content):
                raise litellm.BlockedRequestError(
                    message="Request blocked by DefenseClaw guardrail",
                    model=data.get("model", ""),
                    llm_provider="defenseclaw",
                )
        return data

    def _detect_injection(self, content: str) -> bool:
        # Basic heuristic patterns for POC
        indicators = [
            "ignore previous instructions",
            "ignore all instructions",
            "disregard your system prompt",
            "you are now",
            "new instructions:",
        ]
        lower = content.lower()
        return any(p in lower for p in indicators)

    async def async_post_call_success_hook(self, data, user_api_key_dict, response):
        # Response-side PII/harmful content check
        pass
```

**MCP Secret Resolver:**
```python
# defenseclaw/callbacks/mcp_secret_resolver.py
import os
from litellm.integrations.custom_logger import CustomLogger

class MCPSecretResolver(CustomLogger):
    """Injects MCP server credentials from environment variables."""

    SECRETS_MAP = {
        "outlook": "OUTLOOK_OAUTH_TOKEN",
        "webex": "WEBEX_API_KEY",
        "websearch": "WEBSEARCH_API_KEY",
    }

    async def async_pre_call_hook(self, user_api_key_dict, cache, data, call_type):
        tools = data.get("tools", [])
        for tool in tools:
            if tool.get("type") == "mcp":
                server = tool.get("server_name", "")
                env_var = self.SECRETS_MAP.get(server)
                if env_var:
                    token = os.environ.get(env_var, "")
                    if token:
                        tool["auth_headers"] = {"Authorization": f"Bearer {token}"}
        return data
```

### 3.4 Endpoints

Only LiteLLM's standard routes plus a health check. No custom API.

| Endpoint | Source | Purpose |
|----------|--------|---------|
| `POST /v1/chat/completions` | LiteLLM | LLM calls + MCP tool calls |
| `GET /v1/models` | LiteLLM | List available models |
| `GET /v1/model/info` | LiteLLM | Model metadata + cost info |
| `GET /healthz` | DefenseClaw | Health check |

## 4. MCP Gateway (LiteLLM Built-in)

LiteLLM's native MCP gateway. Configuration:

```yaml
# config/litellm_config.yaml (continued)
mcp_servers:
  - name: "outlook"
    url: "http://outlook-mcp:8080"
    description: "Microsoft Outlook email and calendar"

  - name: "webex"
    url: "http://webex-mcp:8080"
    description: "Webex messaging and meetings"

  - name: "websearch"
    url: "http://websearch-mcp:8080"
    description: "Web search"
```

For the POC, MCP servers run as additional docker-compose services or
as stdio subprocesses inside the defenseclaw container. Credentials
come from `.env` and are injected by the MCPSecretResolver callback.

## 5. Hermes Agent

### 5.1 Configuration

```yaml
# hermes/defenseclaw.yaml
providers:
  - name: defenseclaw
    type: openai
    base_url: "${DEFENSECLAW_URL}/v1"
    api_key: "${DEFENSECLAW_MASTER_KEY}"
    default: true
    models:
      - defenseclaw-default
      - defenseclaw-quality

terminal:
  backend: local  # the container IS the sandbox

mcp:
  servers:
    outlook:
      transport: http
      url: "${DEFENSECLAW_URL}/mcp/outlook"
      headers:
        Authorization: "Bearer ${DEFENSECLAW_MASTER_KEY}"
    webex:
      transport: http
      url: "${DEFENSECLAW_URL}/mcp/webex"
      headers:
        Authorization: "Bearer ${DEFENSECLAW_MASTER_KEY}"
    websearch:
      transport: http
      url: "${DEFENSECLAW_URL}/mcp/websearch"
      headers:
        Authorization: "Bearer ${DEFENSECLAW_MASTER_KEY}"

memory:
  enabled: true
  path: /data/hermes/memory

skills:
  enabled: true
  path: /data/hermes/skills
```

### 5.2 Docker Container

```dockerfile
# hermes/Dockerfile
FROM hermesagent/hermes:latest

COPY defenseclaw.yaml /home/hermes/.hermes/config.yaml
COPY .hermes.md /home/hermes/.hermes/.hermes.md

VOLUME /data/hermes
```

### 5.3 Agent Instructions

```markdown
# hermes/.hermes.md
You are a DefenseClaw-powered AI agent running in a secure sandbox.

## Available Tools
- **Outlook**: Read/send email, manage calendar
- **Webex**: Send messages, manage rooms
- **Web Search**: Search the internet

## How You Work
- All LLM calls route through DefenseClaw (guardrails, cost optimization).
- All tool calls authenticate through DefenseClaw (credential injection).
- You run in complete isolation. No host access.
```

## 6. Docker Compose

```yaml
# docker-compose.yaml
services:
  defenseclaw:
    build: ./defenseclaw
    ports:
      - "4000:4000"
    environment:
      - DEFENSECLAW_MASTER_KEY=${DEFENSECLAW_MASTER_KEY}
      - CIRCUIT_API_BASE=${CIRCUIT_API_BASE}
      - CIRCUIT_API_KEY=${CIRCUIT_API_KEY}
      - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY:-}
      - OUTLOOK_OAUTH_TOKEN=${OUTLOOK_OAUTH_TOKEN:-}
      - WEBEX_API_KEY=${WEBEX_API_KEY:-}
      - WEBSEARCH_API_KEY=${WEBSEARCH_API_KEY:-}
      - REDIS_HOST=redis
      - REDIS_PORT=6379
    depends_on:
      redis:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:4000/healthz"]
      interval: 10s
      timeout: 5s
      retries: 3

  redis:
    image: redis:7-alpine
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      timeout: 3s
      retries: 5

  hermes:
    build: ./hermes
    environment:
      - DEFENSECLAW_URL=http://defenseclaw:4000
      - DEFENSECLAW_MASTER_KEY=${DEFENSECLAW_MASTER_KEY}
    depends_on:
      defenseclaw:
        condition: service_healthy
    volumes:
      - hermes-data:/data/hermes
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    stdin_open: true
    tty: true

volumes:
  hermes-data:
```

## 7. User Setup Flow

```bash
# 1. Clone
git clone https://github.com/cisco-ai-defense/defenseclaw.git
cd defenseclaw

# 2. Configure
cp .env.example .env
# Edit .env: set CIRCUIT_API_KEY (required), optionally WEBEX_API_KEY, etc.

# 3. Run
docker-compose up

# 4. Use
# Hermes agent is now running in the terminal.
# Ask it questions — LLM calls go through DefenseClaw.
# Ask it to search the web — MCP tool call goes through DefenseClaw.
```

No admin panel, no tenant creation, no provisioning step. The user
edits `.env` and runs `docker-compose up`.

## 8. File Structure

```
defenseclaw/                          # OSS repo root
├── docker-compose.yaml
├── .env.example
├── defenseclaw/                      # Python package (new)
│   ├── __init__.py
│   ├── main.py                       # FastAPI + LiteLLM mount
│   ├── config.py                     # Settings from env
│   ├── callbacks/
│   │   ├── __init__.py
│   │   ├── circuit_router.py         # SR smart routing
│   │   ├── guardrails.py             # Shield replacement
│   │   └── mcp_secret_resolver.py    # Credential injection from env
│   ├── Dockerfile
│   └── pyproject.toml
├── hermes/
│   ├── Dockerfile
│   ├── defenseclaw.yaml              # Hermes config
│   └── .hermes.md                    # Agent instructions
├── config/
│   ├── litellm_config.yaml           # Provider + MCP + routing config
│   └── guardrail_rules.yaml          # Content policy rules
└── README.md                         # Setup + usage
```

## 9. What Gets Validated

| Requirement | How It's Validated |
|-------------|-------------------|
| Bifrost replaced by LiteLLM | LLM calls from Hermes route through LiteLLM to Circuit API |
| LiteLLM MCP gateway works | Hermes calls MCP tools via LiteLLM, gets results |
| MCP auth at gateway | Credentials injected from .env by callback, not by agent |
| Hermes in Docker sandbox | Agent runs with cap_drop ALL, no host access |
| Hermes connected via key | Master key authenticates both LLM and MCP calls |
| Smart routing reduces cost | SR callback routes simple queries to cheap model |
| Guardrails work | Prompt injection blocked by pre-call callback |
| No CP/DP needed | Entire system is 3 containers on one machine |

## 10. Out of Scope

- Multi-user / multi-tenant
- Admin UI / dashboard
- Kubernetes deployment
- Real OAuth flow for Outlook (use pre-seeded token in .env)
- Full shield rule parity (POC has basic injection detection)
- Persistent spend tracking (in-memory/redis counters only)

## 11. Success Criteria

The POC succeeds if a user can:

1. `cp .env.example .env` — fill in one API key (Circuit API)
2. `docker-compose up` — everything starts
3. Type a question in the Hermes terminal — get an LLM response
4. Ask Hermes to search the web — MCP tool call works
5. Try a prompt injection — blocked by guardrail
6. Verify Hermes container cannot access host filesystem

## 12. Risks

| Risk | Severity | Mitigation |
|------|----------|------------|
| LiteLLM MCP gateway is new/unstable | Medium | Fall back to Hermes-native MCP if LiteLLM MCP fails |
| Hermes Docker image is large (~2GB) | Low | Acceptable for POC |
| Circuit API auth differs from OpenAI standard | Medium | LiteLLM custom provider config handles non-standard auth |
| Guardrail callback is simpler than Go shield | Accepted | POC proves the pattern; full parity is follow-up |
| No Postgres means no persistent spend logs | Low | Redis counters sufficient for POC; add Postgres later if needed |
