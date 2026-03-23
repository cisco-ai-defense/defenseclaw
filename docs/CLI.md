# CLI Reference

All subcommands are registered on `defenseclaw`. Use `defenseclaw help <command>` for flags and examples.

## Commands

| Command | Description | Iteration |
|--------|-------------|-----------|
| `init` | Create `~/.defenseclaw` config and SQLite audit database | 1 |
| `scan skill <path>` | Run skill-scanner on a skill directory | 1 |
| `scan mcp <path-or-url>` | Run mcp-scanner on MCP manifest or endpoint | 1 |
| `scan aibom <path>` | Run aibom inventory on a project path | 1 |
| `scan code <path>` | Run CodeGuard security rules on code files | 4 |
| `scan [path]` | Run all scanners against a target (scans all claw skill dirs when no path given) | 1 |
| `skill install <name>` | Scan → enforce block/allow list → install if clean | 2 |
| `skill scan <path>` | Run all scanners against a skill and report verdict | 2 |
| `skill disable <key>` | Disable a skill via gateway RPC and add to block list | 4 |
| `skill enable <key>` | Re-enable a previously disabled skill | 4 |
| `deploy [path]` | Full orchestrated deploy: init → scan → block → policy → sandbox | 4 |
| `block skill <id>` | Add a skill to the block list | 2 |
| `block mcp <id>` | Add an MCP server to the block list | 2 |
| `allow skill <id>` | Add a skill to the allow list | 2 |
| `allow mcp <id>` | Add an MCP server to the allow list | 2 |
| `list blocked` | List blocked skills and MCP servers | 2 |
| `list allowed` | List allowed skills and MCP servers | 2 |
| `quarantine <skill>` | Immediately block + quarantine a skill | 2 |
| `rescan` | Re-scan all known targets, auto-block/unblock by results | 4 |
| `alerts` | Show recent security alerts | 4 |
| `status` | Show environment, sandbox health, and counts | 4 |
| `stop` | Stop the OpenShell sandbox | 4 |
| `tui` | Launch the interactive terminal dashboard | 3 |
| `audit` | View audit log events | 1 |
| `audit export` | Export audit events (JSON, CSV, Splunk HEC) | 5 |

## deploy

```
defenseclaw deploy [path] [flags]
```

Full orchestrated deployment:
1. Initialize if needed
2. Run all scanners (skills + MCP + AIBOM + CodeGuard)
3. Auto-block anything HIGH/CRITICAL
4. Generate OpenShell sandbox policy
5. Start OpenClaw in sandbox
6. Print summary

**Flags:**
- `--skip-init` — skip initialization step

## scan code

```
defenseclaw scan code <path>
```

Scans code files using built-in CodeGuard security rules. Detects:
- Hardcoded credentials (API keys, AWS keys, private keys)
- Unsafe command execution (`eval`, `exec`, `system`, `subprocess`)
- SQL injection (string formatting in queries)
- Unsafe deserialization (`pickle`, `yaml.load`)
- Weak cryptography (MD5, SHA1)
- Path traversal
- Outbound HTTP to variable URLs

## status

```
defenseclaw status
```

Shows environment, data directory, sandbox state, scanner availability,
enforcement counts, and activity summary.

## rescan

```
defenseclaw rescan
```

Re-scans all items on block and allow lists. Targets with HIGH/CRITICAL
findings are auto-blocked. Previously blocked items that are now clean
are moved to the allow list.

## stop

```
defenseclaw stop
```

Gracefully stops the OpenShell sandbox process started by `defenseclaw deploy`.

## alerts

```
defenseclaw alerts [-n limit]
```

Displays recent security alerts (events with severity CRITICAL, HIGH, MEDIUM, or LOW).

**Flags:**
- `-n, --limit` — number of alerts to show (default: 25)

## audit

```
defenseclaw audit [-n limit]
```

Displays recent audit events from the SQLite event store.

**Flags:**
- `-n, --limit` — number of events to show (default: 25)

## audit export

```
defenseclaw audit export [flags]
```

Exports audit events in multiple formats for SIEM/SOAR integration.

**Formats:**
- `json` — JSON array (default)
- `csv` — CSV with headers
- `splunk` — Send directly to Splunk via HTTP Event Collector (HEC)

**Flags:**
- `-f, --format` — export format: `json`, `csv`, `splunk` (default: `json`)
- `-n, --limit` — number of events to export (default: 100)
- `-o, --output` — output file path, or `-` for stdout (default: `-`, ignored for splunk)

**Examples:**

```bash
# Export last 100 events as JSON to stdout
defenseclaw audit export

# Export to a file
defenseclaw audit export -o audit-events.json

# Export as CSV
defenseclaw audit export -f csv -o events.csv

# Send events to Splunk (requires splunk config in config.yaml or env var)
DEFENSECLAW_SPLUNK_HEC_TOKEN=<token> defenseclaw audit export -f splunk -n 500
```

### Splunk Configuration

Add to `~/.defenseclaw/config.yaml`:

```yaml
splunk:
  hec_endpoint: https://your-splunk:8088/services/collector/event
  hec_token: ""           # or set DEFENSECLAW_SPLUNK_HEC_TOKEN env var
  index: defenseclaw
  source: defenseclaw
  sourcetype: _json
  verify_tls: false       # set true for production
  enabled: false          # set true for real-time forwarding
  batch_size: 50
  flush_interval_s: 5
```

When `splunk.enabled: true`, every audit event (scans, blocks, allows, deploys) is
forwarded to Splunk in real-time via HEC as it happens. The `audit export -f splunk`
command is for bulk/batch export of historical events.
