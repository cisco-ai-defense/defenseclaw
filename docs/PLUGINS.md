# Plugin Development

DefenseClaw governs OpenClaw plugins with the same scan, verdict, block, allow, and audit flow used for skills and MCP servers. The plugin scanner checks plugin directories for risky install behavior, permissions, credential access, obfuscation, and supply-chain signals.

## Commands

```bash
# Scan a plugin directory
defenseclaw plugin scan extensions/defenseclaw

# Emit machine-readable findings
defenseclaw plugin scan extensions/defenseclaw --json

# Use stricter policy and optional LLM analysis
defenseclaw plugin scan /path/to/plugin --policy strict --use-llm

# Install a plugin and apply configured plugin action policy
defenseclaw plugin install /path/to/plugin --action
```

Plugin scan policy files live under `policies/scanners/plugin-scanner/`.

## Example

A minimal custom scanner example lives in `plugins/examples/custom-scanner/`.

```bash
go run ./plugins/examples/custom-scanner
```

Use it as a scaffold for repository layout and wiring, then connect the real scanner behavior through the DefenseClaw plugin scan command or the Go scanner wrapper in `internal/scanner/plugin.go`.

## Implementation Notes

| Area | Source |
|------|--------|
| Python CLI command | `cli/defenseclaw/commands/cmd_plugin.py` |
| Python scanner wrapper | `cli/defenseclaw/scanner/plugin.py` |
| Go scanner wrapper | `internal/scanner/plugin.go` |
| Example plugin scanner | `plugins/examples/custom-scanner/` |
| Scanner policies | `policies/scanners/plugin-scanner/` |

The Go gateway invokes plugin scans through `defenseclaw plugin scan --json` unless a standalone plugin-scanner binary is configured. JSON output is normalized into the shared `ScanResult` and `Finding` types so policy decisions, audit events, telemetry, and UI rendering behave consistently across scanner types.
