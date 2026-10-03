# DefenseClaw POC — LiteLLM + Hermes Agent

Proves the entire CP/DP architecture can be replaced by two components:
**DefenseClaw** (LiteLLM-powered LLM proxy + MCP gateway) and a
**sandboxed agent** (Hermes-compatible, running in Docker with zero
host access).

## Quick Start

```bash
cd poc/defenseclaw-hermes

# 1. Configure
cp .env.example .env
# Edit .env — set LLM_API_KEY to your OpenAI key (or any OpenAI-compatible)

# 2. Run
docker compose up --build

# The test-agent container runs automated validation tests.
# Look for "ALL TESTS PASSED" in the output.
```

## What Gets Tested

| Test | What It Proves |
|------|---------------|
| LLM call | Hermes → DefenseClaw → LLM provider works end-to-end |
| Guardrail | Prompt injection blocked by DefenseClaw pre-call callback |
| Smart routing | Query complexity classifier selects model tier |
| Sandbox isolation | Agent container has no host access, runs non-root, no privilege escalation |

## Architecture

```
docker compose up
  ├── defenseclaw    (LiteLLM proxy, port 4000)
  ├── redis          (caching)
  └── test-agent     (sandboxed, cap_drop ALL, read-only rootfs)
```

## Design Spec

See [docs/specs/2026-10-02-litellm-mcp-hermes-poc-design.md](../../docs/specs/2026-10-02-litellm-mcp-hermes-poc-design.md).
