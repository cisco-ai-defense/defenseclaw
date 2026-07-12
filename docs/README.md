# DefenseClaw Documentation

This directory is the central home for Markdown documentation. Package-local READMEs stay beside the bundles and examples they document.

DefenseClaw is the governance layer for OpenClaw and agentic AI runtimes. It scans agent capabilities before use, inspects runtime traffic, enforces policy, and records audit evidence for operators and security teams.

## Start Here

| Guide | Description |
|-------|-------------|
| [Install](INSTALL.md) | DGX Spark, macOS, Linux, existing OpenClaw installs, and source builds |
| [Quick Start](QUICKSTART.md) | First successful setup, scan, guardrail, and dashboard flow |
| [Architecture](ARCHITECTURE.md) | System diagram, data flow, and component responsibilities |
| [CLI Reference](CLI.md) | Python CLI commands and flags |
| [API Reference](API.md) | Go sidecar REST API endpoints |
| [Config Files](CONFIG_FILES.md) | Config paths, environment variables, policy files, and defaults |

## Runtime Security

| Guide | Description |
|-------|-------------|
| [Guardrail](GUARDRAIL.md) | Guardrail proxy data flow and configuration |
| [Guardrail Quick Start](GUARDRAIL_QUICKSTART.md) | Set up and test the LLM guardrail |
| [Guardrail Rule Packs](GUARDRAIL_RULE_PACKS.md) | Rule packs, suppressions, and tuning |
| [OpenShell Sandbox](SANDBOX.md) | Sandbox overview and operational guide |
| [Sandbox Architecture](SANDBOX_ARCHITECTURE.md) | Isolation model and subsystem details |
| [Sandbox Setup](SANDBOX_SETUP.md) | Linux sandbox installation steps |
| [Sandbox Monitoring](SANDBOX_MONITORING.md) | Health, logs, metrics, and alerts |
| [Sandbox Debugging](SANDBOX_DEBUGGING.md) | Troubleshooting sandbox failures |
| [OpenShell Sandbox Events](OPENSHELL_SANDBOX_EVENTS.md) | Sandbox event contract |

## Observability and Operations

| Guide | Description |
|-------|-------------|
| [Observability v8](OBSERVABILITY.md) | Current bucket, routing, redaction, destination, local-history, dashboard, and runbook guide |
| [Observability v8 design index](design/observability-v8/README.md) | Normative architecture, schema, migration, and acceptance contracts |
| [Splunk App](SPLUNK_APP.md) | Local Splunk app purpose, dashboards, signals, and investigation flow |
| [TUI](TUI.md) | Dashboard usage, keybindings, and navigation |
| [E2E](E2E.md) | End-to-end test harnesses and local validation |

### Historical observability references

These documents describe the retired v7 topology and are retained for migration,
compatibility, and archaeology. They are not configuration or schema authority for
a v8 runtime.

| Historical guide | Use |
|---|---|
| [Observability Contract (v7)](OBSERVABILITY-CONTRACT.md) | Legacy JSONL/audit/OTel envelope and correlation behavior |
| [OpenTelemetry Specification (v7)](OTEL.md) | Legacy direct-provider signals and Splunk mapping |
| [OTEL Implementation Status (v7)](OTEL-IMPLEMENTATION-STATUS.md) | v7 closeout snapshot and known limitations |

## Development

| Guide | Description |
|-------|-------------|
| [Contributing](CONTRIBUTING.md) | Development workflow and contribution notes |
| [Testing](TESTING.md) | Python, Go, TypeScript, Rego, docs, and CI checks |
| [Plugin Development](PLUGINS.md) | Custom scanner plugin workflow and example |
| [Developer Spec](development/DEVELOPER_SPEC.md) | Historical product/developer spec |
| [Gateway Spec](reference/GATEWAY_SPEC.md) | Internal gateway package specification |

## Requirements and Design Notes

| Guide | Description |
|-------|-------------|
| [Free From Day 1 Requirement](requirements/FREE_FROM_DAY1.md) | Local Splunk Free-mode requirement and validation notes |
| [CLI UX Quickstart](design/cli-ux-quickstart.md) | CLI quickstart design notes |
| [OpenShell Standalone Sandbox](design/openshell-standalone-sandbox.md) | Standalone sandbox design notes |
| [Sandbox Productization](design/sandbox-productization.md) | Sandbox packaging and productization notes |
| [Sandbox Scanning](design/sandbox-scanning.md) | Sandbox scanner integration notes |
| [Sandbox Security Analysis](design/sandbox-security-analysis.md) | Security analysis notes |
| [Standalone Sandbox Issues](design/standalone-sandbox-issues.md) | Known issue tracking notes |
| [Observability v8 Specification](design/observability-v8/README.md) | Unified logging, audit, OTel, routing, redaction, migration, rich trace, and dashboard compatibility contracts |
| [Local Observability Stack Moved Notice](archive/LOCAL_OBSERVABILITY_STACK_MOVED.md) | Archived pointer from the old deploy path to the bundled stack |
| [Webhook Notifications PR Description](archive/WEBHOOK_NOTIFICATIONS_PR_DESCRIPTION.md) | Archived PR description retained for implementation context |
