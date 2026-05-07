# Credentials Management

DefenseClaw uses a declarative credential registry to manage API keys and tokens required by various subsystems.

## Credential Storage

Credentials are stored in `~/.defenseclaw/.env` (mode 0600, dotenv format):

```
ANTHROPIC_API_KEY=sk-ant-api03-...
DEFENSECLAW_GATEWAY_TOKEN=abc123...
CISCO_AI_DEFENSE_API_KEY=...
SPLUNK_HEC_TOKEN=...
```

## CLI Commands

### List credentials

```bash
# Show all credentials with status
defenseclaw keys list

# Machine-readable output
defenseclaw keys list --json

# Show only missing required keys
defenseclaw keys list --missing-only

# Show masked value previews
defenseclaw keys list --show-values
```

### Set a credential

```bash
# Interactive (prompts for value)
defenseclaw keys set ANTHROPIC_API_KEY

# Non-interactive
defenseclaw keys set ANTHROPIC_API_KEY --value sk-ant-api03-...
```

### Check required credentials

```bash
# Exit 0 if all required keys are set
defenseclaw keys check

# Fill all missing required credentials interactively
defenseclaw keys fill-missing
```

## Credential Registry

The credential registry classifies keys by requirement level:

| Level | Meaning |
|-------|---------|
| REQUIRED | Must be set for core functionality |
| OPTIONAL | Enhances functionality but not mandatory |
| CONDITIONAL | Required only when a feature is enabled |

### Common Credentials

| Env Var | Purpose | Level |
|---------|---------|-------|
| `DEFENSECLAW_GATEWAY_TOKEN` | Sidecar authentication | REQUIRED |
| `ANTHROPIC_API_KEY` | LLM judge / guardrail (Anthropic) | CONDITIONAL (guardrail enabled) |
| `OPENAI_API_KEY` | LLM judge / guardrail (OpenAI) | CONDITIONAL (guardrail enabled) |
| `CISCO_AI_DEFENSE_API_KEY` | Cisco AI Defense scanner | CONDITIONAL (remote scanner) |
| `SPLUNK_HEC_TOKEN` | Splunk HEC audit sink | CONDITIONAL (Splunk configured) |
| `VIRUSTOTAL_API_KEY` | VirusTotal binary analysis | OPTIONAL |

## Resolution Order

When resolving a credential, DefenseClaw checks in order:
1. Shell environment variable
2. `~/.defenseclaw/.env` file
3. Config YAML field (deprecated — triggers warning)

## Security

- `.env` file is created with mode 0600 (owner read/write only)
- `defenseclaw config show` masks all secret values by default
- Use `--reveal` flag to show masked previews (first/last 4 chars)
- Fields ending in `_api_key`, `_token`, `_secret`, `_password` are auto-detected as sensitive
