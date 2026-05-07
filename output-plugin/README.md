# DefenseClaw Security Plugin for OpenClaw (ClawHub)

Standalone OpenClaw plugin that wires DefenseClaw security governance into any OpenClaw instance. Install from ClawHub — no DefenseClaw-side deployment required.

## What It Does

- **Fetch interception**: Patches `globalThis.fetch` and `https.request` to route all LLM API calls (15+ providers) through the DefenseClaw guardrail proxy for real-time inspection
- **Tool inspection**: `before_tool_call` hook sends every tool invocation to the DefenseClaw sidecar for 6-category threat analysis (secrets, dangerous commands, sensitive paths, C2 patterns, cognitive file tampering, trust exploitation)
- **Health monitoring**: Polls the DefenseClaw gateway every 60s and warns when protection is down
- **Egress telemetry**: Reports intercepted/bypassed LLM calls for observability
- **Slash commands**: `/dc-scan`, `/dc-block`, `/dc-allow` for on-demand security scanning and policy enforcement
- **Bedrock HTTP/1 shim**: Automatically downgrades AWS Bedrock SDK from HTTP/2 to HTTP/1 so traffic hits the guardrail proxy

## Prerequisites

A running DefenseClaw gateway accessible from the OpenClaw instance. The gateway can be:
- **Local**: Running on the same machine (default `127.0.0.1:18970`)
- **Remote**: Running on a shared security server (configure `sidecarHost` and `sidecarPort`)

## Install

```bash
clawhub install @defenseclaw/openclaw-plugin
```

## Configure

After installation, configure the plugin in OpenClaw's plugin settings:

| Setting | Default | Description |
|---------|---------|-------------|
| `sidecarHost` | `127.0.0.1` | DefenseClaw gateway hostname or IP |
| `sidecarPort` | `18970` | DefenseClaw gateway REST API port |
| `guardrailPort` | `4000` | DefenseClaw guardrail proxy port |
| `mode` | `observe` | `observe` = log only, `action` = block threats |
| `agent.id` | *(auto-generated)* | Stable agent identity for audit correlation |
| `agent.name` | *(none)* | Display name in audit logs |
| `agent.policyId` | *(none)* | Policy id for capability-based access control |
| `awsHttp1Shim` | `auto` | Force Bedrock to HTTP/1: `auto`, `on`, or `off` |

### Environment Variables

These override `~/.defenseclaw/config.yaml` but are overridden by plugin config:

| Variable | Description |
|----------|-------------|
| `DEFENSECLAW_HOST` | Gateway hostname |
| `DEFENSECLAW_PORT` | Gateway REST API port |
| `DEFENSECLAW_GUARDRAIL_PORT` | Guardrail proxy port |
| `OPENCLAW_GATEWAY_TOKEN` | Authentication token for the gateway |

## Slash Commands

| Command | Description |
|---------|-------------|
| `/dc-scan <path> [type]` | Scan a skill, plugin, MCP config, or code (`type`: skill, plugin, mcp, code) |
| `/dc-block <type> <name> [reason]` | Block a skill, MCP server, or plugin |
| `/dc-allow <type> <name> [reason]` | Allow-list a skill, MCP server, or plugin |

## Coexistence with Embedded Plugin

This plugin (`defenseclaw-plugin`) can coexist with the embedded DefenseClaw plugin (`defenseclaw`) that ships with DefenseClaw itself. They use different plugin IDs and command prefixes, so there are no conflicts. Both connect to the same DefenseClaw gateway.

## Build from Source

```bash
cd output-plugin
npm install
npm run build
```

## License

Apache-2.0
