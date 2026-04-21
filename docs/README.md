# DefenseClaw Documentation

DefenseClaw is the enterprise governance layer for [OpenClaw](https://github.com/openclaw/openclaw). It wraps Cisco AI Defense scanners and NVIDIA OpenShell so operators can scan skills, MCP servers, and code before execution, enforce block and allow lists, and review activity from a terminal dashboard with a durable audit trail.

## Table of Contents

- [Installation Guide](INSTALL.md) — DGX Spark + macOS, existing or fresh OpenClaw
- [Quick Start Guide](QUICKSTART.md) — 5-minute walkthrough of all commands
- [Architecture](ARCHITECTURE.md) — system diagram, data flow, component responsibilities
- [CLI Reference](CLI.md) — all Python CLI commands and flags
- [API Reference](API.md) — Go sidecar REST API endpoints
- [LLM Guardrail](GUARDRAIL.md) — guardrail data flow and configuration
- [Guardrail Quick Start](GUARDRAIL_QUICKSTART.md) — set up and test the LLM guardrail
- [OpenShell Sandbox](SANDBOX.md) — sandbox architecture, setup, monitoring, and debugging
- [Splunk App Guide](SPLUNK_APP.md) — local Splunk app purpose, dashboards, signals, and investigation flow
- [TUI Guide](TUI.md) — dashboard usage, keybindings, navigation
- [OpenTelemetry](OTEL.md) — OTEL signal spec, Splunk mapping
- [Config Files](CONFIG_FILES.md) — config files and environment variables
- [Plugin Development](PLUGINS.md) — custom scanner plugin interface
- [Testing](TESTING.md) — multi-language test guide (Python, Go, TypeScript, Rego)
- [Contributing](CONTRIBUTING.md)
