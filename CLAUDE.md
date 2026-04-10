# DefenseClaw

Enterprise governance layer for OpenClaw. Wraps Cisco AI Defense scanners and NVIDIA OpenShell into a CLI + TUI that secures agentic AI deployments. See `defenseclaw-spec.md` for the full product spec.

## Commands

| Command | Description |
|---------|-------------|
| `make build` | Build all components (Python CLI + Go gateway + TS plugin) |
| `make install` | Build and install all components |
| `make pycli` | Build Python CLI into .venv |
| `make gateway` | Build Go gateway binary |
| `make gateway-cross GOOS=linux GOARCH=amd64` | Cross-compile gateway for target platform |
| `make plugin` | Build the OpenClaw TypeScript plugin |
| `make gateway-install` | Build + install gateway to ~/.local/bin |
| `make plugin-install` | Build + install plugin to ~/.openclaw/extensions/ |
| `make dev-install` | Full dev setup via install-dev.sh |
| `make test` | Run all tests (Python + Go) |
| `make cli-test-cov` | Run Python tests with coverage report |
| `make go-test-cov` | Run Go tests with coverage report |
| `make ts-test` | Run TypeScript plugin tests |
| `make rego-test` | Run Rego policy tests |
| `make lint` | Run Python linter (ruff + py_compile) |
| `make py-lint` | Run ruff check on Python CLI |
| `make go-lint` | Run golangci-lint on Go code |
| `go run ./cmd/defenseclaw` | Run gateway from source |

## Tech Stack (locked)

- **Go 1.25+** — single binary, cross-compile to linux/amd64, linux/arm64, darwin/arm64, darwin/amd64
- **Cobra + Viper** — CLI framework + config
- **Bubbletea + Lipgloss + Bubbles** — TUI (charmbracelet stack)
- **SQLite** (`modernc.org/sqlite`) — audit log, scan results, block/allow lists (no external DB)
- **YAML** — config at `~/.defenseclaw/config.yaml`, OpenShell policies
- **goreleaser** — cross-platform builds + homebrew tap

## Architecture

```
cmd/defenseclaw/        Entry point
internal/
  cli/                  Cobra command definitions (one file per command)
  scanner/              Scanner interface + wrappers (shell out to Python CLIs)
  enforce/              Block/allow engine, quarantine, OpenShell policy sync
  tui/                  Bubbletea TUI (four panels: Alerts, Skills, MCP, Status)
  audit/                SQLite audit store + event logger + export + Splunk HEC
  config/               Viper config loader + defaults + environment detection + claw mode + connectors
  inventory/            AIBOM integration
  sandbox/              OpenShell CLI wrapper + policy generation
  gateway/
    connector/          Connector interface, router, and per-framework connectors
                        (OpenClaw, ZeptoClaw, Generic fallback)
plugins/                Plugin interface, registry, examples
policies/               Default/strict/permissive YAML policy templates
schemas/                JSON schemas for audit events and scan results
test/                   E2E tests, unit tests, fixtures
```

## Key Files

- `cmd/defenseclaw/main.go` — entrypoint
- `defenseclaw-spec.md` — product spec (source of truth, read-only)
- `internal/scanner/scanner.go` — Scanner interface all scanners implement
- `internal/scanner/result.go` — ScanResult + Finding types (unified output)
- `internal/audit/store.go` — SQLite schema and operations
- `internal/enforce/policy.go` — Admission gate (block -> allow -> scan)
- `internal/config/claw.go` — Claw mode resolver (skill dirs, MCP dirs per framework)
- `internal/config/connectors.go` — Connector config types (OpenClaw, ZeptoClaw)
- `internal/gateway/connector/connector.go` — Connector interface + RoutingDecision
- `internal/gateway/connector/router.go` — ConnectorRouter (ordered detection)
- `internal/gateway/connector/openclaw.go` — OpenClaw connector (X-DC-Target-URL headers)
- `internal/gateway/connector/zeptoclaw.go` — ZeptoClaw connector (model prefix inference)
- `internal/gateway/connector/generic.go` — Generic fallback connector
- `internal/gateway/connector/helpers.go` — Shared utilities (SSRF check, provider inference)
- `internal/gateway/connector/zeptoclaw_defaults.go` — Embedded provider URL table (19 providers)
- `internal/tui/app.go` — TUI root model

## Claw Mode

DefenseClaw supports multiple agent frameworks via `claw.mode` in config.
Currently: `openclaw`. Future: `nemoclaw`, `opencode`, `claudecode`.

All skill/MCP directory resolution derives from the active mode
(`internal/config/claw.go`). OpenClaw skill resolution order:

1. `~/.openclaw/workspace/skills/` — workspace/project skills
2. Custom `skills_dir` from `~/.openclaw/openclaw.json` — user-configured path
3. `~/.openclaw/skills/` — global user skills

## Connector Architecture (LLM Guardrail)

The guardrail proxy uses a connector-based architecture to support multiple
agent frameworks on the same proxy port. Each framework has a dedicated
Connector that translates its request format into a canonical `RoutingDecision`.

**Detection order**: OpenClaw → ZeptoClaw → Generic (fallback).

- **OpenClaw Connector** — detects `X-DC-Target-URL` header from fetch interceptor
- **ZeptoClaw Connector** — detects `X-ZC-Provider` header or standard auth without DC headers; resolves upstream URL from config/defaults
- **Generic Connector** — fallback for curl, future frameworks; infers provider from model name

Config: `guardrail.connectors.openclaw` (enabled by default), `guardrail.connectors.zeptoclaw` (disabled by default). See `docs/GUARDRAIL.md` for full data flow.

## Conventions

- `internal/` for all packages — nothing exported outside the binary
- Errors: `fmt.Errorf("package: context: %w", err)` — prefix with package name
- Context: every public function takes `ctx context.Context` as first arg
- No global state — pass deps via struct constructors
- Table-driven tests — `t.Run` subtests, one `TestXxx` per exported function
- CLI commands return `error` — Cobra handles exit codes, never call `os.Exit`
- Scanner wrappers shell out to Python CLIs — never rewrite them in Go
- OpenShell orchestrated, not replaced — write its policy YAML, don't fork it

## Admission Gate

```
Block list? -> YES -> reject, log, alert
             NO -> Allow list? -> YES -> skip scan, install, log
                                NO -> Scan
                                      CLEAN -> install, log
                                      HIGH/CRITICAL -> reject, log, alert
                                      MEDIUM/LOW -> install with warning, log, alert
```

All six paths must be tested.

## Build Iterations

1. ~~Skeleton + Scan + AIBOM~~ — repo structure, init, scan commands, SQLite audit ✓
2. ~~Block/Allow + Enforcement~~ — block/allow lists, quarantine, OpenShell policy sync ✓
3. ~~TUI~~ — four-panel bubbletea dashboard (Alerts, Skills, MCP Servers + status bar) ✓
4. ~~Deploy + CodeGuard + Full Flow~~ — orchestrated deploy, CodeGuard, status/stop ✓
5. Docs + Plugins + OSS Polish — plugin system, installer, goreleaser, CI

## Gotchas

- Python scanners (`skill-scanner`, `mcp-scanner`, `aibom`) are external deps — pip install, don't vendor
- `modernc.org/sqlite` is pure Go (no CGo) — required for easy cross-compilation
- Block must take effect in under 2 seconds, no restart — event-driven enforcement, not polling
- Allow-listed items skip scan gate but are still logged and inventoried
- TUI refreshes within 5 seconds — subscribe to audit store changes
- macOS has no OpenShell — degrade gracefully: scan + lists + audit work, sandbox enforcement skipped

## Boundaries

- `defenseclaw-spec.md` — read-only, do not modify
- Splunk SIEM adapter available (HEC-based, batch + real-time). No approval queues or IAM integration in v1
- Never store secrets in code or config — use OS keychain or env vars
- No `os.Exit()` outside `main()` — return errors up the stack
- Never rewrite Python scanners in Go — wrap them
- Never replace OpenShell — orchestrate it
- Never require root — everything runs in userspace
- Single binary — no Docker dependency for DefenseClaw itself
