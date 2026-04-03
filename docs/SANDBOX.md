# OpenShell Sandbox

DefenseClaw can run OpenClaw inside an NVIDIA OpenShell sandbox with full governance enabled. The sandbox provides OS-level isolation while DefenseClaw adds scanning, policy enforcement, and audit logging on top.

---

## Architecture

### What It Is

Standalone sandbox mode runs OpenClaw inside an NVIDIA OpenShell sandbox with DefenseClaw governance. The sandbox provides OS-level isolation (Linux namespaces, Landlock, seccomp) while DefenseClaw adds scanning, policy enforcement, and audit logging on top.

### Components

```
systemd
  └── defenseclaw-sandbox.target       ← start/stop the sandbox
        └── openshell-sandbox.service  ← runs as root, drops to sandbox user
              └── start-sandbox.sh
                    └── openshell-sandbox    ← NVIDIA binary, creates namespaces
                          └── openclaw       ← agent runtime (inside sandbox)

defenseclaw-gateway start                ← separate process (not systemd)
  └── defenseclaw-gateway run            ← Go binary, runs as user
        ├── WebSocket → connects to sandbox OpenClaw
        ├── fsnotify → watches skill/plugin dirs
        ├── REST API → :18970
        └── Guardrail proxy → :4000 (optional)
```

The **DefenseClaw gateway sidecar** runs independently as a regular user process. It is **not** part of the systemd target. Start it with `defenseclaw-gateway start` after starting the sandbox.

### How They Talk

```
┌─────────────────────────┐          ┌─────────────────────────┐
│   Sandbox (10.200.0.2)  │  veth    │     Host (10.200.0.1)   │
│                         │◄────────►│                         │
│  OpenClaw :18789 (WS)   │          │  Sidecar REST :18970    │
│  DefenseClaw plugin     │          │  Guardrail proxy :4000  │
│  CodeGuard skill        │          │  SQLite audit DB        │
└─────────────────────────┘          └─────────────────────────┘
```

- **WebSocket (port 18789):** Sidecar connects to OpenClaw's gateway inside the sandbox. Authenticated via Ed25519 device key, pre-paired during setup.
- **REST API (port 18970):** CLI commands (`defenseclaw skill list`, `status`, etc.) hit the sidecar's API on the host side.
- **Guardrail proxy (port 4000):** All LLM traffic from inside the sandbox routes through this proxy for inspection before reaching the provider.

### Network Isolation

The sandbox runs in its own network namespace with a veth pair:

| Address | Side |
|---|---|
| `10.200.0.1` | Host |
| `10.200.0.2` | Sandbox |

Outbound traffic from the sandbox is forced through OpenShell's HTTP CONNECT proxy at `10.200.0.1:3128`. DNS is restricted to configured nameservers (default: `8.8.8.8`, `1.1.1.1`) via iptables rules injected by `post-sandbox.sh`.

### DNS

The sandbox network namespace has no DNS resolver by default. OpenShell blocks all traffic except connections through its proxy, which means UDP port 53 queries to external resolvers are silently dropped. This breaks any application that resolves hostnames before connecting (e.g., Node.js uses `getaddrinfo()` rather than delegating DNS to the proxy).

To fix this without running a DNS forwarder process:

1. **Custom resolv.conf** — `defenseclaw setup sandbox` generates `sandbox-resolv.conf` with the configured nameservers (default: `8.8.8.8`, `1.1.1.1`). On each start, `start-sandbox.sh` uses `unshare --mount` to bind-mount this file over `/etc/resolv.conf` inside the sandbox. The host's resolv.conf is never modified.

2. **iptables allow rules** — `post-sandbox.sh` injects UDP 53 allow rules scoped to only those specific nameservers (not a blanket UDP 53 allow). This limits DNS exfiltration to abusing the configured resolvers.

Nameservers are configurable: `--dns 10.0.0.2,10.0.0.3` for internal resolvers, or `--dns host` to mirror the host's `/etc/resolv.conf`.

### Host-Side iptables Rules

In addition to the in-namespace DNS rules, `post-sandbox.sh` injects rules on the host side when host networking is enabled:

| Rule | Purpose |
|---|---|
| `MASQUERADE` on `10.200.0.0/24` UDP 53 | Routes DNS responses back to the sandbox IP. Without this, replies from external nameservers have no return path into the namespace. |
| `route_localnet=1` | Allows DNAT from localhost to non-loopback addresses, required for UI forwarding. |
| `DNAT` localhost:18789 → 10.200.0.2:18789 | Forwards the OpenClaw UI port so it's accessible from `localhost` on the host without SSH tunneling. |
| `MASQUERADE` on 10.200.0.2:18789 | Ensures return traffic from the DNAT'd UI connection routes correctly. |

When guardrail is enabled, additional rules allow the sandbox to reach the sidecar API (port 18970) and guardrail proxy (port 4000) on the host IP.

All these rules are cleaned up by `cleanup-sandbox.sh` on service stop and re-injected on every start. Use `--no-host-networking` to skip them entirely (OpenShell manages networking internally in that case).

### Security Layers

| Layer | Provides |
|---|---|
| Linux namespaces | Process, network, mount isolation |
| Landlock LSM | Filesystem access control |
| seccomp-BPF | System call filtering |
| OpenShell OPA policy | Per-connection network policy (destination, binary, L7) |
| DefenseClaw guardrail | LLM request/response inspection |
| DefenseClaw admission gate | Skill/plugin scanning before installation |
| CodeGuard skill | Runtime code execution monitoring |

### What Each Component Does

**OpenShell sandbox** — Kernel-level containment. Creates namespaces, applies Landlock/seccomp profiles, evaluates OPA policy on every outbound connection.

**DefenseClaw sidecar** — Governance. Watches skill/plugin directories, runs the admission gate (block → allow → scan), disables risky skills/plugins, logs everything to SQLite, optionally forwards to Splunk.

**DefenseClaw plugin** — Runs inside the sandbox as an OpenClaw extension. Intercepts `before_tool_call` events, provides `/scan`, `/block`, `/allow` slash commands, routes LLM traffic through the guardrail proxy.

**CodeGuard skill** — Installed as a skill inside the sandbox. Monitors code execution patterns at runtime.

---

## Setup

### Prerequisites

- Linux with systemd (no macOS/Windows support for sandbox mode)
- OpenClaw installed (`~/.openclaw/` exists with a valid `openclaw.json`)
- Root access (sandbox creation requires `CAP_SYS_ADMIN`)
- `openshell-sandbox` binary (auto-installed if missing)

### Step 1: Initialize

```bash
sudo defenseclaw sandbox init
```

What happens:

1. Checks that `openshell-sandbox` is installed; downloads from NVIDIA if missing
2. Installs `iptables` if missing (needed for DNS and guardrail forwarding)
3. Creates the `sandbox` system user and group with home at `/home/sandbox`
4. Moves the existing OpenClaw home (`~/.openclaw/`) under sandbox ownership:
   - Backs up original ownership to `openclaw-ownership-backup.json`
   - `chown -R sandbox:sandbox` on the OpenClaw directory
   - Creates a symlink from `/home/sandbox/.openclaw` to the original path
   - Sets POSIX ACLs so the sandbox user has full access
5. Creates `/home/sandbox/.defenseclaw/`
6. Installs the DefenseClaw plugin into `~/.openclaw/extensions/defenseclaw/`
7. Copies default OpenShell policies (Rego + YAML)
8. Automatically runs `defenseclaw sandbox setup` (Step 2)

### Step 2: Configure

```bash
sudo defenseclaw sandbox setup [OPTIONS]
```

Options (all have sensible defaults):

| Flag | Default | Purpose |
|---|---|---|
| `--sandbox-ip` | `10.200.0.2` | IP inside sandbox namespace |
| `--host-ip` | `10.200.0.1` | Host-side veth IP |
| `--sandbox-home` | `/home/sandbox` | Sandbox user's home |
| `--openclaw-port` | `18789` | OpenClaw gateway port |
| `--policy` | `permissive` | Policy template (permissive/default/strict) |
| `--dns` | `8.8.8.8,1.1.1.1` | DNS servers for the sandbox |

What happens:

1. Validates the `sandbox` user and home directory exist
2. Writes DefenseClaw config (`~/.defenseclaw/config.yaml`):
   - `openshell.mode = "standalone"`
   - Gateway, guardrail, and watcher settings
3. Installs the selected policy template
4. Generates `sandbox-resolv.conf` with the configured DNS servers
5. Patches the sandbox-side `openclaw.json`:
   - Sets gateway port, bind mode, and guardrail baseUrl to point at the host IP
6. Generates systemd unit files → `<data_dir>/systemd/`
7. Generates launcher scripts → `<data_dir>/scripts/`
8. Pre-pairs the sidecar's Ed25519 device key into the sandbox's `paired.json`
9. Detects and stores the gateway auth token
10. Installs the CodeGuard skill into the sandbox
11. Installs/updates the DefenseClaw plugin and registers it in `openclaw.json`
12. Fixes file ownership and directory ACLs
13. Copies units to `/etc/systemd/system/` and scripts to `/usr/local/lib/defenseclaw/`
14. Runs `systemctl daemon-reload`
15. Generates `run-sandbox.sh` for non-systemd environments

### Step 3: Start

#### Start the sandbox

```bash
sudo systemctl start defenseclaw-sandbox.target
```

Or without systemd:

```bash
sudo /path/to/data_dir/scripts/run-sandbox.sh
```

This starts the sandbox service, which:
1. Runs `pre-sandbox.sh` — cleans orphan namespaces, fixes ACLs
2. Runs `start-sandbox.sh` — bind-mounts resolv.conf, launches `openshell-sandbox`
3. Runs `post-sandbox.sh` — waits for veth pair, injects iptables rules for DNS, sidecar API, and guardrail forwarding

#### Start the gateway sidecar

In a separate terminal (or use `tmux`/`screen`):

```bash
defenseclaw-gateway start
```

Or run in the background:

```bash
defenseclaw-gateway start &
```

The gateway connects to the sandbox over WebSocket, watches for skill/plugin changes, and serves the REST API at `http://10.200.0.1:18970`.

### Step 4: Enable on Boot (optional)

```bash
sudo systemctl enable defenseclaw-sandbox.target
```

### Restart Behavior

The sandbox service uses `Restart=always` with a 30-second delay (`RestartSec=30`) capped at 2 minutes (`RestartMaxDelaySec=120`). It restarts on any exit — crash or clean shutdown. Only `systemctl stop` prevents restart.

---

## Monitoring

### Logs

#### Sandbox service

```bash
journalctl -u openshell-sandbox -f
```

Logs from the sandbox process itself: namespace creation, policy evaluation results, network proxy events.

#### Gateway sidecar

```bash
tail -f ~/.defenseclaw/gateway.log
```

Logs from the sidecar: WebSocket connection state, skill/plugin watcher events, admission gate decisions, guardrail verdicts.

**Note:** The gateway runs as a regular process (not a systemd service), started via `defenseclaw-gateway start`.

#### Key log patterns

| Pattern | Meaning |
|---|---|
| `CONNECT` | Outbound TCP connection from sandbox |
| `CONNECT_L7` | L7-inspected HTTP connection |
| `FORWARD` | Proxied connection |
| `L7_REQUEST` | HTTP request inspected at application layer |
| `BYPASS_DETECT` | Direct connection attempt bypassing the proxy |

### Health Check

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

### Service Status

```bash
systemctl status openshell-sandbox.service
systemctl status defenseclaw-sandbox.target
```

### Network Verification

```bash
# Check veth pair exists
ip link show | grep veth-h
```

Expected output (the suffix after `veth-h-` will be different each time):
```
7: veth-h-0305ec0c@if6: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default qlen 1000
```

What this tells you:
- **veth pair exists and is UP** — `veth-h-<random-id>` is the host side of the virtual Ethernet pair (ID varies per sandbox instance)
- **Link is active** — `BROADCAST,MULTICAST,UP,LOWER_UP` means the interface is functioning
- **Paired with sandbox interface** — `@if6` indicates it's connected to interface 6 inside the sandbox namespace
- **State UP** — the link is operational

To see both sides with their IPs:

```bash
# Host side (should show 10.200.0.1)
ip addr show $(ip link show | grep veth-h | awk '{print $2}' | cut -d@ -f1)

# Sandbox side (should show 10.200.0.2)
SANDBOX_PID=$(pgrep -f openshell-sandbox)
sudo nsenter -t $SANDBOX_PID -n -- ip addr show
```

Other checks:

```bash
# Check sandbox namespace
ip netns list | grep -i sandbox

# Check iptables rules
sudo iptables -t nat -L -n | grep 10.200.0
```

### Audit Trail

All scan results, admission decisions, and enforcement actions are logged to the SQLite database at `~/.defenseclaw/defenseclaw.db`.

```bash
# Recent events
defenseclaw audit list --limit 20

# Export
defenseclaw audit export --format json
```

Optional Splunk HEC forwarding can be configured for real-time SIEM integration. See [SPLUNK_APP.md](SPLUNK_APP.md).

---

## Debugging

### Important: Process Model and File Ownership

OpenClaw runs as a **child process** of `openshell-sandbox`. The sandbox binary starts as root, creates the namespace, then drops privileges and launches OpenClaw as the `sandbox` user.

During `defenseclaw sandbox init`, ownership of all OpenClaw files and directories (`~/.openclaw/`) is changed to the `sandbox` user. This means any manual edits to `openclaw.json`, skill files, or plugin configs must be done as the `sandbox` user:

```bash
sudo -u sandbox vi /home/sandbox/.openclaw/openclaw.json
# or
sudo -u sandbox nano /home/sandbox/.openclaw/openclaw.json
```

Editing as root or another user will create files owned by the wrong user, causing permission errors when OpenClaw tries to read or write them.

### Sandbox Won't Start

```bash
# Check service status and recent logs
systemctl status openshell-sandbox.service
journalctl -u openshell-sandbox --no-pager -n 50
```

**Common causes:**

| Symptom | Fix |
|---|---|
| `pre-sandbox.sh` fails | Orphan namespace or stale PID/lock file. Run `pre-sandbox.sh` manually to see the error. |
| `start-sandbox.sh` permission denied | Scripts not executable. `sudo chmod 755 /usr/local/lib/defenseclaw/*.sh` |
| `openshell-sandbox` not found | Binary missing. Re-run `defenseclaw sandbox init` to auto-install. |
| Namespace creation fails | Kernel doesn't support user namespaces or Landlock. Check `cat /proc/sys/kernel/unprivileged_userns_clone`. |

### Sidecar Can't Connect to Sandbox

```bash
# Test WebSocket connectivity from the host
curl -v http://10.200.0.2:18789
```

**Common causes:**

| Symptom | Fix |
|---|---|
| Connection refused | OpenClaw not running inside sandbox. Check sandbox logs. |
| Auth failure / handshake rejected | Device key not paired. Re-run `defenseclaw sandbox setup` to re-pair. |
| Timeout | veth pair not up. Check `ip link show \| grep veth-h`. |

### Network Issues Inside Sandbox

```bash
# Enter the sandbox namespace (find the PID first)
SANDBOX_PID=$(pgrep -f openshell-sandbox)
sudo nsenter -t $SANDBOX_PID -n -- bash

# Inside the namespace:
ip addr show           # should show 10.200.0.2
ping -c1 10.200.0.1    # host should be reachable
curl http://10.200.0.1:18970/health   # sidecar API
```

**DNS not working:**
```bash
# Check resolv.conf was bind-mounted
sudo nsenter -t $SANDBOX_PID -n -m -- cat /etc/resolv.conf

# Check iptables DNS rules
sudo nsenter -t $SANDBOX_PID -n -- iptables -L -n | grep 53
```

**Outbound blocked unexpectedly:**
Check the OpenShell policy files:
```bash
cat ~/.defenseclaw/openshell-policy.rego
cat ~/.defenseclaw/openshell-policy.yaml
```

The Rego policy controls which destinations each binary can reach. Connection denials are logged to journald with a `CONNECT` event containing `action=deny`.

**Note:** Changes to OpenShell network policy files (`openshell-policy.rego`, `openshell-policy.yaml`) only take effect after restarting the sandbox service:

```bash
sudo systemctl restart openshell-sandbox.service
```

### Skills/Plugins Not Loading

```bash
# Check watcher is running
curl http://10.200.0.1:18970/health | jq .watcher

# List skills the sidecar sees
defenseclaw skill list

# Check plugin registration
cat /home/sandbox/.openclaw/openclaw.json | jq .plugins
```

**Common causes:**

| Symptom | Fix |
|---|---|
| Watcher shows `error` | ACL issue. Run `sudo scripts/fix-sandbox-acls.sh`. |
| Skill blocked | Check block list: `defenseclaw block list`. Remove if false positive: `defenseclaw block remove <key>`. |
| Plugin not in list | Not registered in `openclaw.json`. Re-run `defenseclaw sandbox setup`. |

### Guardrail Proxy Issues

```bash
# Check guardrail is running
curl http://10.200.0.1:18970/health | jq .guardrail

# Test the proxy directly
curl -x http://10.200.0.1:4000 https://api.openai.com/v1/models
```

If LLM calls from inside the sandbox fail, verify the plugin's `baseUrl` points to the host IP:
```bash
cat /home/sandbox/.openclaw/openclaw.json | jq '.plugins'
```

### Restart Loop

If the service keeps restarting (30s cycle):

```bash
# See why it's exiting
journalctl -u openshell-sandbox --no-pager -n 100

# Temporarily stop to investigate
sudo systemctl stop defenseclaw-sandbox.target
```

Check for resource issues (`dmesg | grep -i oom`), filesystem permission problems, or invalid policy files.

### Ownership / Permission Errors

```bash
# Re-fix ownership
sudo chown -R sandbox:sandbox /home/sandbox/.openclaw

# Re-fix ACLs
sudo setfacl -R -m u:sandbox:rwX /home/sandbox/.openclaw

# Or use the bundled script
sudo scripts/fix-sandbox-acls.sh
```

### Collecting a Debug Bundle

```bash
# Gather everything in one shot
systemctl status openshell-sandbox.service > /tmp/dclaw-debug.txt
journalctl -u openshell-sandbox --no-pager -n 200 >> /tmp/dclaw-debug.txt
defenseclaw status >> /tmp/dclaw-debug.txt 2>&1
ip link show >> /tmp/dclaw-debug.txt
sudo iptables -t nat -L -n >> /tmp/dclaw-debug.txt
```
