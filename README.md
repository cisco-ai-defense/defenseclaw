<div align="center">

<img alt="DefenseClaw logo" src="assets/defenseclaw-logo.png" width="640" />

<h1>DefenseClaw</h1>

<p>
  <strong>Security governance for OpenClaw and agentic AI runtimes.</strong><br />
  Scan capabilities before use, inspect runtime traffic, and export durable audit evidence.
</p>

<p>
  <a href="https://opensource.org/licenses/Apache-2.0"><img alt="License: Apache 2.0" src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" /></a>
  <a href="https://www.python.org/downloads/"><img alt="Python 3.10+" src="https://img.shields.io/badge/python-3.10%2B-blue.svg" /></a>
  <a href="https://go.dev/"><img alt="Go 1.26.2" src="https://img.shields.io/badge/go-1.26.2-00ADD8.svg" /></a>
  <a href="https://github.com/cisco-ai-defense/defenseclaw/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/cisco-ai-defense/defenseclaw/actions/workflows/ci.yml/badge.svg" /></a>
  <a href="https://discord.com/invite/nKWtDcXxtx"><img alt="Discord: Join us" src="https://img.shields.io/badge/Discord-Join%20Us-7289DA?logo=discord&amp;logoColor=white" /></a>
</p>

<p>
  <a href="https://www.cisco.com/site/us/en/products/security/ai-defense/index.html"><img alt="Cisco AI Defense" src="https://img.shields.io/badge/Cisco-AI%20Defense-049fd9?logo=cisco&amp;logoColor=white" /></a>
  <a href="https://learn-cloudsecurity.cisco.com/ai-security-framework"><img alt="AI Security Framework" src="https://img.shields.io/badge/AI%20Security-Framework-orange" /></a>
  <a href="https://deepwiki.com/cisco-ai-defense/defenseclaw"><img alt="Ask DeepWiki" src="https://deepwiki.com/badge.svg" /></a>
</p>

</div>

| Govern | Inspect | Prove |
|--------|---------|-------|
| Skills, MCP servers, plugins, and generated code before they run | Prompts, completions, tool calls, and sandbox activity at runtime | SQLite audit history, JSONL, OTLP, Splunk, webhooks, and TUI views |

DefenseClaw combines a Python operator CLI, a Go gateway sidecar, and an OpenClaw TypeScript plugin. Together they enforce a simple operating rule: untrusted agent capabilities are scanned, governed, logged, and blocked when policy says they are unsafe.

## Highlights

- **Admission control** - scan skills, MCP servers, plugins, and code before they run.
- **Runtime guardrails** - inspect prompts, completions, and tool calls with regex rules, policy, optional LLM judge, and Cisco AI Defense inspection.
- **CodeGuard** - built-in static checks for secrets, dangerous execution, unsafe deserialization, weak crypto, injection patterns, and risky file access.
- **OpenShell sandbox support** - Linux sandbox setup with network, filesystem, syscall, and policy controls.
- **Audit and observability** - SQLite audit store, JSONL gateway logs, OTLP export, Splunk HEC, webhooks, and local Grafana/Splunk bundles.
- **Operator UX** - a CLI and TUI for setup, health checks, alerts, block/allow lists, scanner results, and policy workflows.

---

## Scope and Limitations

DefenseClaw is an enforcement and evidence layer for agentic AI deployments. It improves safety by combining scanner results, runtime inspection, policy decisions, sandbox controls, and audit trails, but it does not prove that an agent, skill, plugin, or model interaction is risk-free.

High-risk deployments should pair DefenseClaw with human review, least-privilege credentials, sandboxing, CI gates, and production monitoring. In observe mode, findings are logged without blocking. In action mode, configured HIGH and CRITICAL findings can block prompts, tool calls, or component admission.

---

## Documentation

| Guide | Description |
|-------|-------------|
| [Quick Start](docs/QUICKSTART.md) | First successful local setup and scan flow |
| [Install](docs/INSTALL.md) | macOS, Linux, DGX Spark, source builds, and release installation |
| [CLI Reference](docs/CLI.md) | Python CLI commands and operator workflows |
| [API Reference](docs/API.md) | Gateway REST API and sidecar endpoints |
| [Architecture](docs/ARCHITECTURE.md) | Component model, data flow, and responsibilities |
| [Guardrail](docs/GUARDRAIL.md) | LLM and tool inspection architecture |
| [Guardrail Rule Packs](docs/GUARDRAIL_RULE_PACKS.md) | Rule packs, suppressions, and tuning |
| [Sandbox](docs/SANDBOX.md) | OpenShell sandbox setup, architecture, monitoring, and debugging |
| [Observability](docs/OBSERVABILITY.md) | Audit sinks, OTLP, Splunk, Grafana, and webhook notifications |
| [Splunk App](docs/SPLUNK_APP.md) | Local Splunk app dashboards and investigation flow |
| [TUI](docs/TUI.md) | Terminal dashboard panels and navigation |
| [Config Files](docs/CONFIG_FILES.md) | Config locations, environment variables, and policy files |
| [Plugin Development](docs/PLUGINS.md) | Custom scanner plugin workflow and example |
| [Testing](docs/TESTING.md) | Python, Go, TypeScript, Rego, docs, and CI checks |
| [Developer Spec](docs/development/DEVELOPER_SPEC.md) | Historical product/developer spec |
| [Gateway Spec](docs/reference/GATEWAY_SPEC.md) | Internal gateway package specification |

Project Markdown documentation is centralized under [docs/](docs/). Package-local READMEs stay beside bundles or examples that need local context.

---

## Installation

### Prerequisites

| Requirement | Version |
|-------------|---------|
| Python | 3.10+ |
| Go | 1.26.2+ |
| Node.js | 18+ for the OpenClaw plugin |
| uv | Recommended for Python installs |
| Docker | Optional, for local observability and Splunk bundles |

### Install from source

```bash
git clone https://github.com/cisco-ai-defense/defenseclaw.git
cd defenseclaw
make all
```

### Install with the release script

```bash
curl -LsSf https://raw.githubusercontent.com/cisco-ai-defense/defenseclaw/main/scripts/install.sh | bash
defenseclaw init --enable-guardrail
```

For platform-specific steps, see [docs/INSTALL.md](docs/INSTALL.md).

---

## Quick Start

```bash
# Check the local install and dependencies
defenseclaw doctor

# Initialize config, scanner defaults, and guardrail plumbing
defenseclaw init --enable-guardrail

# Scan installed agent capabilities
defenseclaw skill scan all
defenseclaw mcp list
defenseclaw plugin scan extensions/defenseclaw

# Start the Go gateway sidecar
defenseclaw-gateway start

# Open the operator dashboard
defenseclaw tui
```

Run the guardrail in observe mode while tuning:

```bash
defenseclaw setup guardrail --mode observe --restart
```

Switch to action mode when the policy is ready to block:

```bash
defenseclaw setup guardrail --mode action --restart
```

See [docs/QUICKSTART.md](docs/QUICKSTART.md) for the full walkthrough.

---

## Architecture

| Component | Runtime | Role |
|-----------|---------|------|
| Python CLI | Python | Operator commands, scanner orchestration, config setup, local bundles |
| Gateway sidecar | Go | REST API, WebSocket bridge, policy engine, guardrail proxy, audit store, telemetry |
| OpenClaw plugin | TypeScript | Fetch interception, tool-call inspection hooks, slash commands, sidecar integration |
| Policies | YAML/Rego | Admission decisions, guardrail actions, sandbox/firewall behavior, scanner profiles |
| Documentation | Markdown/JSON | Centralized docs, package-local READMEs, and DeepWiki configuration |

The gateway exposes local REST APIs for the CLI and plugin, connects to OpenClaw over WebSocket, inspects LLM traffic through a local proxy, and records decisions in a durable audit store.

```text
Agent runtime -> OpenClaw plugin -> DefenseClaw gateway -> policy + scanners + audit
                                    |
                                    +-> guardrail proxy -> LLM provider
                                    +-> OTLP / Splunk / webhooks / JSONL
```

For diagrams and detailed flows, read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## Scanning and Guardrails

DefenseClaw wraps Cisco AI Defense scanners and local policy into a single admission flow:

| Surface | Scanner or control |
|---------|--------------------|
| Skills | `cisco-ai-skill-scanner`, CodeGuard, policy actions |
| MCP servers | `cisco-ai-mcp-scanner`, block/allow policy |
| Plugins | DefenseClaw plugin scanner, install-source checks, optional LLM analysis |
| Source code | CodeGuard via CLI, sidecar API, and plugin write/edit hooks |
| Prompts and completions | Guardrail proxy with rule packs, suppressions, optional LLM judge, Cisco inspection |
| Tool calls | Tool argument inspection, sensitive path checks, command risk checks, policy verdicts |

Scanner policies live in [policies/scanners/](policies/scanners/). Guardrail rule packs live in [policies/guardrail/](policies/guardrail/).

---

## Observability

DefenseClaw records enforcement and runtime evidence across several channels:

| Channel | Use |
|---------|-----|
| SQLite audit store | Local durable event history |
| Gateway JSONL | Correlated structured runtime events |
| OTLP | Metrics, logs, and traces to compatible collectors |
| Splunk HEC | SIEM forwarding and local Splunk app workflows |
| Webhooks | Slack, PagerDuty, Webex, and generic event notifications |
| TUI | Operator-facing alerts, health, scans, tools, policy, and setup |

Start local observability with:

```bash
defenseclaw setup local-observability up
defenseclaw gateway
defenseclaw setup local-observability status
```

See [docs/OBSERVABILITY.md](docs/OBSERVABILITY.md) and [docs/SPLUNK_APP.md](docs/SPLUNK_APP.md).

---

## Development

```bash
# Build all components
make build

# Run primary test suites
make test

# Run lint checks
make lint
```

Focused test and development guidance lives in [docs/TESTING.md](docs/TESTING.md) and [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md).

---

## Contributing

Contributions are welcome. Start with [CONTRIBUTING.md](CONTRIBUTING.md), [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md), and the focused docs for the area you are changing.

## Security

Please report vulnerabilities through the process in [SECURITY.md](SECURITY.md).

## License

Apache 2.0 - see [LICENSE](LICENSE).

Copyright 2026 Cisco Systems, Inc. and its affiliates.
