<div align="center">

<pre>
     ____         ____                       ____  _
    / __ \  ___  / __/___   ___   ___  ___  / ___|| | __ _ __      __
   / / / / / _ \/ /_// _ \ / _ \ / __|/ _ \| |    | |/ _` |\ \ /\ / /
  / /_/ / /  __/ __//  __/| | | |\__ \  __/| |___ | | (_| | \ V  V /
 /_____/  \___/_/   \___/ |_| |_||___/\___| \____||_|\__,_|  \_/\_/
</pre>

<h1>DefenseClaw</h1>

<p>
  <strong>Security governance for OpenClaw and agentic AI runtimes.</strong><br />
  Scan capabilities before use, inspect runtime traffic, and export durable audit evidence.
</p>

<p>
  <a href="https://opensource.org/licenses/Apache-2.0"><img alt="License: Apache 2.0" src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" /></a>
  <a href="https://www.python.org/downloads/"><img alt="Python 3.10+" src="https://img.shields.io/badge/python-3.10%2B-blue.svg" /></a>
  <a href="https://go.dev/"><img alt="Go 1.26.4" src="https://img.shields.io/badge/go-1.26.4-00ADD8.svg" /></a>
  <a href="https://github.com/cisco-ai-defense/defenseclaw/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/cisco-ai-defense/defenseclaw/actions/workflows/ci.yml/badge.svg" /></a>
  <a href="https://discord.com/invite/nKWtDcXxtx"><img alt="Discord: Join us" src="https://img.shields.io/badge/Discord-Join%20Us-7289DA?logo=discord&amp;logoColor=white" /></a>
</p>

<p>
  <a href="https://www.cisco.com/site/us/en/products/security/ai-defense/index.html"><img alt="Cisco AI Defense" src="https://img.shields.io/badge/Cisco-AI%20Defense-049fd9?logo=cisco&amp;logoColor=white" /></a>
  <a href="https://learn-cloudsecurity.cisco.com/ai-security-framework"><img alt="AI Security Framework" src="https://img.shields.io/badge/AI%20Security-Framework-orange" /></a>
  <a href="https://deepwiki.com/cisco-ai-defense/defenseclaw"><img alt="Ask DeepWiki" src="https://deepwiki.com/badge.svg" /></a>
</p>

</div>

| Govern | Inspect | Probe |
|--------|---------|-------|
| Skills, MCP servers, plugins, and generated code before they run | Prompts, completions, tool calls, and sandbox activity at runtime | SQLite audit history, JSONL, OTLP, Splunk, webhooks, and TUI views |

DefenseClaw combines a Python operator CLI, a Go gateway sidecar, and an OpenClaw TypeScript plugin. Together they enforce a simple operating rule: untrusted agent capabilities are scanned, governed, logged, and blocked when policy says they are unsafe.

## Highlights

- **Admission control** - scan skills, MCP servers, plugins, and code before they run.
- **Runtime guardrails** - inspect prompts, completions, and tool calls with regex rules, policy, optional LLM judge, and Cisco AI Defense inspection.
- **CodeGuard** - built-in static checks for secrets, dangerous execution, unsafe deserialization, weak crypto, injection patterns, and risky file access.
- **OpenShell sandbox support** - Linux sandbox setup with network, filesystem, syscall, and policy controls.
- **Registries** - ingest external skill / MCP catalogs (corporate HTTPS YAML, [smithery.ai](https://smithery.ai/), [skills.sh](https://skills.sh/), git, ClawHub) with SSRF guards, scanner-driven verdicts, and auto-promotion into asset policy. See [docs/REGISTRIES.md](docs/REGISTRIES.md).
- **Audit and observability** - one config-v8 graph for bucket collection, mandatory SQLite history, centralized redaction, and independent JSONL, OTLP, Prometheus, Splunk HEC, Galileo, HTTP, console, and local Grafana/Splunk destinations.
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
| [Observability](docs/OBSERVABILITY.md) | V8 buckets, local history, redaction, destination fan-out, OTLP, Splunk, and Grafana |
| [Splunk App](docs/SPLUNK_APP.md) | Local Splunk app dashboards and investigation flow |
| [Splunk O11y Dashboards](bundles/splunk_o11y_dashboards/README.md) | Splunk Observability Cloud dashboards and detectors for native OTel metrics |
| [TUI](docs/TUI.md) | Terminal dashboard panels and navigation |
| [Config Files](docs/CONFIG_FILES.md) | Config locations, environment variables, and policy files |
| [Registries](docs/REGISTRIES.md) | External skill / MCP catalog ingestion (clawhub, smithery, skills.sh, http, git, file) |
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
| Go | 1.26.4+ |
| Node.js | 18+ for the OpenClaw plugin |
| uv | Recommended for Python installs |
| Docker | Optional, for local observability and Splunk bundles |

### Build from source (developers only)

```bash
git clone https://github.com/cisco-ai-defense/defenseclaw.git
cd defenseclaw
make all
```

The source targets and `scripts/install-dev.sh` are development tooling, not an
upgrade path. Direct install targets refuse to overwrite a release-managed
installation or one owned by another checkout. `make all` is the explicit
developer-machine reinstall workflow: when the installed CLI already points
exactly into the current checkout, it may reclaim markerless or prior-release
source state and records a strict ownership marker after rebuilding. This can
run the checkout's current migrations against developer state and must not be
used as a release upgrade. Release-managed installations must use the
release-owned `scripts/upgrade.sh` or `scripts/upgrade.ps1` resolver.

### Install with the release script

```bash
VERSION=0.8.4
INSTALL_URL="https://raw.githubusercontent.com/cisco-ai-defense/defenseclaw/${VERSION}/scripts/install.sh"
curl -LsSf "$INSTALL_URL" | VERSION="$VERSION" bash
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
| Optional JSONL | Correlated structured runtime events when a file destination is configured |
| OTLP | Named, independent metrics/logs/traces destinations with native fan-out |
| Splunk HEC | SIEM forwarding and local Splunk app workflows |
| Splunk O11y dashboards | Native Splunk Observability Cloud dashboards and detectors for DefenseClaw metrics |
| Webhooks | Slack, PagerDuty, Webex, and generic event notifications |
| TUI | Operator-facing alerts, health, scans, tools, policy, and setup |

Config v8 keeps the source concise while compiling omissions into a complete
effective plan:

```yaml
config_version: 8
observability: {}
```

That default collects every registered log, trace, and metric and retains every
collected log unredacted in mandatory local SQLite. No remote export occurs until
a destination is added. An enabled destination with no `send` or `routes` receives
every bucket and every signal its kind supports, unredacted: general OTLP gets
logs/traces/metrics, Splunk HEC gets logs, Prometheus gets metrics, and the Galileo
preset gets traces. Multiple destinations receive independent copies.

Review the expanded policy and unredacted legs with:

```bash
defenseclaw config show --effective --section observability
defenseclaw observability plan
```

Use centralized `none`, `sensitive`, `content`, `strict`, or custom field-aware
redaction profiles per bucket or destination. Full-fidelity defaults can include
prompts, outputs, tool arguments/results, evidence, paths, and identifiers, so
configure a redacting profile before exporting across a trust boundary that must
not receive that content.

Edit bucket and redaction policy in the source file, validate it before the
gateway sees it, and inspect the compiled result rather than copying the generated
reference wholesale:

```bash
umask 077
cp "$HOME/.defenseclaw/config.yaml" \
  "$HOME/.defenseclaw/config.yaml.before-observability-edit"
${EDITOR:-vi} "$HOME/.defenseclaw/config.yaml"

defenseclaw config validate && \
defenseclaw config show --effective --section observability && \
defenseclaw observability plan && \
defenseclaw-gateway restart && \
defenseclaw doctor
```

Do not restart after a validation failure. Restore the private backup, correct the
source, and validate again. A global or bucket redaction profile also applies to
the generated local SQLite projection. To keep full-fidelity local history while
redacting only a remote trust boundary, leave the global/bucket profile at `none`
and set `send.redaction_profile` or a route profile on that remote destination.

Start local observability with:

```bash
defenseclaw setup local-observability up
defenseclaw-gateway start
defenseclaw setup local-observability status
```

Dashboard emptiness is not one state: **0** means the instrumented signal had zero
matching events, **No data** means no matching series/log/trace exists for the
selected range and filters, and **Not reported** means the connector/provider did
not supply an optional value such as tokens or cost. Conditional panels such as
HITL, failure-only views, and a trace waterfall before a Trace ID is selected are
expected to show **No data**. A destination test checks connectivity only and does
not create ordinary dashboard traffic; generate a fresh real agent turn, tool
call, scan, or approval to validate the corresponding panels.

Agent360's node graph is a Loki-backed lifecycle DAG: session creation is a
separate anchor, one per-root **Prompt inputs** node counts distinct depth-zero
`model.request` facts in the range, and parent-to-child delegation feeds per-agent
model, tool, approval, update, turn-outcome, and terminal summaries. Prompt inputs
deduplicate by turn, model-request, request, operation, then occurrence ID; the
ordered/raw views retain the individual initial and follow-up records. Session and
spawn anchors may be recovered from the prior 24 hours so boundary windows remain
renderable; a recovered spawn is kept only when that child has graph-eligible
activity in the selected range.
Repeated model calls are grouped by
owning agent, provider, and model. Repeated tool calls are grouped by owning agent
into Bash, MCP, Skills, Collaboration, File edits, Web/browser, Visual, or Task
control; an unrecognized tool keeps its reported name. Exact
`collaboration.send_message` requests are excluded from the generic Collaboration
family so they appear only as message groups; other collaboration tools remain in
that family. Request records are
included even when no terminal counterpart arrived. Their grouped total is a
request count, not a claim that every request is still pending; terminal status
remains available in the linked raw records. Depth `0` is the root and recursive children may be
reported through depth `64`; click detail identifies whether each lineage edge was
reported by the connector or inferred by DefenseClaw. Node clicks expose exact
counts and stable agent/root/parent identity, with filtered links to the raw OTEL
events behind every group. Optional current/root/parent session fields remain on
the lifecycle, session, ordered, and raw surfaces; they are not agent-node grouping
keys, so missing or late session metadata cannot split one agent's total.

Dashboards do not redact, mask, or hide fields again. DefenseClaw applies
centralized v8 redaction before canonical OTEL export; Grafana shows or links every
field actually present in that projection, including content when the producer
exported it. A field removed or transformed before export cannot be recovered by
the local stack. Update edges come only from actual
`collaboration.send_message` tool records. For each sender, `/root` and
`/root/*` targets collapse into one **Messages to root** node whose target agent
ID resolves to the exported root. Exact root task paths and calls remain in the
ordered/raw drill-downs. Non-root targets stay explicitly grouped by exact task
path and are not invented as opaque agent-ID joins when the connector did not
report that mapping. Generic compatibility events are never relabeled as updates.

Optional destinations own independent bounded queues. Defaults are 2,048 records
and 64 MiB per queue; push batches default to 512 records, 8 MiB, and 5 seconds
(1 second for the omitted Galileo preset delay). Queue overflow drops the newest
attempted enqueue without evicting older FIFO work or affecting mandatory SQLite
and sibling destinations. Exact fields, bounds, and adapter differences are in
[docs/OBSERVABILITY.md](docs/OBSERVABILITY.md).

Add Galileo Cloud or self-hosted Galileo without replacing the local route:

```bash
export GALILEO_API_KEY='...'
defenseclaw setup galileo --project defenseclaw --logstream production
defenseclaw setup galileo test
```

See [docs/OBSERVABILITY.md](docs/OBSERVABILITY.md), the
[Galileo guide](docs-site/content/docs/observability/galileo.mdx), and
[schema ownership map](schemas/README.md). Splunk-specific setup is in
[docs/SPLUNK_APP.md](docs/SPLUNK_APP.md).

Every supported existing POSIX installation, including one already on `0.8.4`,
crosses the `0.8.5` hard cut with the authenticated target-release
`defenseclaw-upgrade.sh` asset in latest mode, without a version override. The
immutable `0.8.4` built-in parser cannot accept the truthful target manifest
whose Windows bridge matrix is empty. Do not execute any obsolete raw-network
hint printed by a frozen built-in CLI. The release-owned resolver performs
`source → 0.8.4 bridge → fresh 0.8.4 controller → 0.8.5 hard cut` as one
transaction. The migration
backs up and atomically converts configuration, preserves narrower
routing/redaction behavior and root/subagent Agent360 compatibility, refreshes
owned local dashboards without resetting volumes, and never requires a separate
apply command. See [CLI Reference — upgrade](docs/CLI.md#upgrade) for the
authenticated resolver bootstrap.

For Splunk Observability Cloud, use the dashboard bundle at
[bundles/splunk_o11y_dashboards/README.md](bundles/splunk_o11y_dashboards/README.md):

```bash
defenseclaw setup splunk dashboards apply \
  --api-url <api-endpoint> \
  --o11y-api-token <api-access-token> \
  --with-detectors \
  --enable-detectors \
  --yes
```

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
