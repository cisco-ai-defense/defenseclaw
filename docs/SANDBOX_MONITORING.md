# Sandbox Monitoring

## Logs

### Sandbox service

```bash
journalctl -u openshell-sandbox -f
```

Logs from the sandbox process itself: namespace creation, policy evaluation
results, network proxy events.

### Gateway sidecar

```bash
journalctl -u defenseclaw-gateway -f
# or
tail -f ~/.defenseclaw/gateway.log
```

Logs from the sidecar: WebSocket connection state, skill/plugin watcher
events, admission gate decisions, guardrail verdicts.

### Key log patterns

| Pattern | Meaning |
|---|---|
| `CONNECT` | Outbound TCP connection from sandbox |
| `CONNECT_L7` | L7-inspected HTTP connection |
| `FORWARD` | Proxied connection |
| `L7_REQUEST` | HTTP request inspected at application layer |
| `BYPASS_DETECT` | Direct connection attempt bypassing the proxy |

## Health Check

```bash
# From the host
curl http://10.200.0.1:18970/health

# Or via CLI
defenseclaw status
```

The sidecar tracks subsystem health independently:

| Subsystem | Healthy states |
|---|---|
| Gateway (WebSocket) | `running` |
| Watcher (fsnotify) | `running` or `disabled` |
| API (REST) | `running` |
| Guardrail (proxy) | `running` or `disabled` |
| Sandbox | `running` |

## Service Status

```bash
systemctl status openshell-sandbox.service
systemctl status defenseclaw-sandbox.target
```

## Network Verification

```bash
# Check veth pair exists
ip link show | grep veth-h

# Check sandbox namespace
ip netns list | grep -i sandbox

# Check iptables rules
sudo iptables -t nat -L -n | grep 10.200.0
```

## Audit Trail

All scan results, admission decisions, and enforcement actions are logged to
the SQLite database at `~/.defenseclaw/defenseclaw.db`.

```bash
# Recent events
defenseclaw audit list --limit 20

# Export
defenseclaw audit export --format json
```

Optional Splunk HEC forwarding can be configured for real-time SIEM
integration. See [SPLUNK_APP.md](SPLUNK_APP.md).
