# OpenShell Sandbox — Quick Start & Testing

Set up the OpenShell sandbox and verify it works end-to-end.

## Prerequisites

- Linux with systemd (Ubuntu 20.04+, RHEL 8+, or similar)
- Root access (`sudo` privileges)
- DefenseClaw CLI installed (`defenseclaw --help` works)
- DefenseClaw Gateway built (`make gateway` produces `defenseclaw-gateway`)
- OpenClaw installed (`~/.openclaw/` exists with valid `openclaw.json`)
- `openshell-sandbox` binary (auto-installed if missing)

**Note:** Sandbox mode is **not available** on macOS or Windows. Linux with systemd is required.

**About Expected Outputs:** The example outputs in this guide are based on a real DefenseClaw sandbox deployment. Your actual output may differ depending on:
- Which skills/MCPs are installed in your OpenClaw instance
- Your OpenClaw configuration and model provider
- Network conditions and DNS resolution
- The policy template you select

The examples provide a reference for what successful operation looks like — adapt them to your specific environment.

## 1. Initialize the Sandbox

```bash
sudo defenseclaw sandbox init
```

This command:
- Downloads `openshell-sandbox` from NVIDIA if not installed
- Installs `iptables` if missing
- Creates the `sandbox` system user and group
- Moves OpenClaw files to sandbox ownership
- Creates symlinks and sets ACLs
- Installs the DefenseClaw plugin
- Copies default OpenShell policies
- Automatically runs `defenseclaw sandbox setup`

**Expected output:**
```
DefenseClaw Sandbox Init
========================

✓ openshell-sandbox binary found at /usr/local/bin/openshell-sandbox
✓ iptables installed
✓ Created sandbox user and group
✓ Moved OpenClaw to sandbox ownership
✓ Installed DefenseClaw plugin
✓ Copied default OpenShell policies

Running sandbox setup...
```

## 2. Configure the Sandbox

If you need to customize settings, re-run setup with options:

```bash
sudo defenseclaw sandbox setup \
  --sandbox-ip 10.200.0.2 \
  --host-ip 10.200.0.1 \
  --openclaw-port 18789 \
  --policy permissive \
  --dns 8.8.8.8,1.1.1.1
```

**Policy options:**
- `permissive` — development mode (allows sidecar, channels, npm, LLM providers, openclaw.ai) — **default**
- `default` — balanced security (allows sidecar, channels, npm, openclaw.ai; LLM traffic via guardrail only)
- `strict` — high security (only sidecar connectivity, no external network)

**DNS options:**
- Comma-separated IPs: `--dns 8.8.8.8,1.1.1.1`
- Use host's resolv.conf: `--dns host`
- Internal resolvers: `--dns 10.0.0.2,10.0.0.3`

**Expected output:**
```
✓ Sandbox user validated
✓ Config written to ~/.defenseclaw/config.yaml
✓ Policy template installed: default
✓ Generated sandbox-resolv.conf
✓ Patched openclaw.json for sandbox
✓ Generated systemd units
✓ Generated launcher scripts
✓ Pre-paired device key
✓ Detected gateway auth token
✓ Installed CodeGuard skill
✓ Installed DefenseClaw plugin
✓ Fixed file ownership
✓ Copied units to /etc/systemd/system/
✓ Ran systemctl daemon-reload

Next steps:
  1. Start the sandbox:
     sudo systemctl start defenseclaw-sandbox.target

  2. (Re)start the gateway:
     defenseclaw-gateway start
```

## 3. Start Services

**IMPORTANT: Startup Order** — The sandbox must start first to create the veth network pair. The gateway needs this network interface to bind its API server. Always follow this sequence:

1. Start sandbox first
2. Wait 10-15 seconds for network setup
3. Restart gateway

### Step 1: Start the sandbox

```bash
sudo systemctl start defenseclaw-sandbox.target
```

Wait 10-15 seconds for the sandbox to complete network setup. Verify it started:

```bash
systemctl status openshell-sandbox.service
```

**Expected output:**
```
● openshell-sandbox.service - OpenShell Sandbox (DefenseClaw-managed)
     Loaded: loaded (/etc/systemd/system/openshell-sandbox.service; disabled)
     Active: active (running) since Mon 2026-03-30 11:33:53 PDT; 5s ago
   Main PID: 749 (openshell-sandb)
      Tasks: 41
     Memory: 563.9M
     CGroup: /system.slice/openshell-sandbox.service
             ├─749 openshell-sandbox --policy-rules ...
             ├─838 openclaw
             └─880 openclaw-gateway
```

Verify the veth pair was created:

```bash
ip link show | grep veth-h
```

**Expected output (ID will vary):**
```
7: veth-h-a1b2c3d4@if6: <BROADCAST,MULTICAST,UP,LOWER_UP> ...
```

### Step 2: Restart the gateway

```bash
defenseclaw-gateway restart
```

**Expected output:**
```
Stopping gateway sidecar (PID 350)... OK
Starting gateway sidecar daemon... OK (PID 1912)

Use 'defenseclaw-gateway status' to check health
```

This ensures the gateway binds to the correct network interface after the veth pair is created.

### Step 3: Verify gateway is running

```bash
defenseclaw-gateway status
```

**Expected output:**
```
DefenseClaw Sidecar Health
══════════════════════════
  Started:  2026-03-30T12:44:28-07:00
  Uptime:   25s

  Gateway:   RUNNING (since 2026-03-30T12:44:28-07:00)
             protocol: 3

  Watcher:   RUNNING (since 2026-03-30T12:44:28-07:00)

  API:       RUNNING (since 2026-03-30T12:44:28-07:00)
             addr: 10.200.0.1:18970

  Guardrail: RUNNING (since 2026-03-30T12:44:28-07:00)
             addr: 10.200.0.1:4000
             mode: action

  Sandbox:   RUNNING (since 2026-03-30T12:44:28-07:00)
             sandbox_ip: 10.200.0.2
             openclaw_port: 18789
```

All subsystems should show `RUNNING`. The key indicators:
- **API addr: 10.200.0.1:18970** (not 127.0.0.1)
- **Gateway: RUNNING**
- **Sandbox: RUNNING**

## 4. Verify the Sandbox is Running

### Check sandbox service

```bash
defenseclaw-gateway sandbox status
```

**Expected output:**
```
● openshell-sandbox.service - OpenShell Sandbox (DefenseClaw-managed)
     Active: active (running) ...
```

### Check veth pair

```bash
ip link show | grep veth-h
```

**Expected output (ID will vary):**
```
7: veth-h-a1b2c3d4@if6: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default qlen 1000
```

This confirms the network bridge between host and sandbox is active.

### Check IP addresses

```bash
# Host side (should show 10.200.0.1)
ip addr show $(ip link show | grep veth-h | awk '{print $2}' | cut -d@ -f1)
```

**Expected:**
```
inet 10.200.0.1/24 scope global veth-h-a1b2c3d4
```

### Access the OpenClaw UI

Open your browser to:
```
http://localhost:18789
```

This is forwarded from the sandbox automatically via iptables DNAT rules. You should see the OpenClaw web interface.

## 5. Test Network Isolation

### Test DNS resolution inside sandbox

```bash
defenseclaw-gateway sandbox exec -- ping -c 1 8.8.8.8
```

**Expected output:**
```
PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.
64 bytes from 8.8.8.8: icmp_seq=1 ttl=115 time=7.51 ms

--- 8.8.8.8 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
```

### Test outbound HTTPS

All outbound connections must go through the OpenShell proxy:

```bash
defenseclaw-gateway sandbox exec -- curl -sI https://google.com
```

**Expected output:**
```
HTTP/2 301
location: https://www.google.com/
content-type: text/html; charset=UTF-8
...
```

### Verify proxy enforcement

Check the sandbox logs to confirm the connection was proxied:

```bash
journalctl -u openshell-sandbox --no-pager --since "1 minute ago" | grep CONNECT | tail -5
```

**Expected output:**
```
Mar 30 12:22:33 hostname openshell-sandbox[749]: INFO openshell_sandbox::proxy: CONNECT src_addr=10.200.0.2 dst_host=google.com dst_port=443 action="allow" engine="opa" policy=allow_channels
```

Key fields:
- `src_addr=10.200.0.2` — request from sandbox
- `action="allow"` — permitted by policy
- `engine="opa"` — Open Policy Agent evaluated the request
- `policy=allow_channels` — matched policy rule

### Test blocked destination (strict policy only)

If using `strict` policy, external connections should be blocked:

```bash
defenseclaw-gateway sandbox exec -- curl -m 5 http://example.com
```

**Expected (strict policy):**
```
curl: (28) Connection timed out after 5001 milliseconds
```

Check logs for denial:

```bash
journalctl -u openshell-sandbox --no-pager --since "1 minute ago" | grep "action=\"deny\""
```

## 6. Test Skill Scanning

### List installed skills

```bash
defenseclaw skill list
```

**Expected output:**
```
                              Skills (4/51 ready)
┏━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━┳━━━━━━━━━━━━┓
┃ S… ┃ Skill         ┃ Description                ┃ Source     ┃  ┃ Actions    ┃
┡━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━╇━━━━━━━━━━━━┩
│ ✓… │ ▫️ healthcheck │ Host security hardening a… │ openclaw-… │  │ -          │
│ ✓… │ ▫️ node-conne… │ Diagnose OpenClaw node co… │ openclaw-… │  │ -          │
│ ✓… │ ▫️ skill-crea… │ Create, edit, improve, or… │ openclaw-… │  │ -          │
│ ✓… │ ▫️ codeguard   │ Security-aware code gener… │ openclaw-… │  │ -          │
│ ✗… │ 👀 peekaboo   │ Capture and automate macO… │ openclaw-… │  │ blocked    │
│ ✗… │ ☔ weather    │ Get current weather and f… │ openclaw-… │  │ blocked    │
│ ✗… │ 🐦 xurl       │ A CLI tool for making aut… │ openclaw-… │  │ blocked    │
└────┴───────────────┴────────────────────────────┴────────────┴──┴────────────┘
```

The `✓` means the skill is ready, `✗` means not installed or blocked. Check the "Actions" column for blocked skills.

### Scan a specific skill

```bash
defenseclaw skill scan healthcheck
```

**Expected output:**
```
Scanning skill: healthcheck
===========================

Running skill-scanner...
✓ No malicious patterns detected
✓ No hardcoded credentials
✓ No dangerous execution

Running aibom...
✓ Generated AIBOM

Result: CLEAN
  Severity: NONE
  Findings: 0

Admission gate: ALLOWED
```

### Watch automatic scanning

When a new skill is installed via the OpenClaw UI, the gateway watcher automatically scans it. Monitor the logs:

```bash
tail -f ~/.defenseclaw/gateway.log
```

Install a skill in the UI, and you should see:

```
[watcher] new skill detected: calculator
[watcher] running admission gate for skill: calculator
[scanner] scan result: CLEAN (severity=NONE, findings=0)
[watcher] admission gate: ALLOWED (skill: calculator)
```

## 7. Test Skill Blocking

### Block a skill

```bash
defenseclaw skill block peekaboo --reason "screen capture not allowed"
```

**Expected output:**
```
✓ Blocked skill: peekaboo
  Reason: screen capture not allowed
  Path: ~/.openclaw/skills/peekaboo/
```

### Verify the block

```bash
defenseclaw skill list | grep peekaboo
```

**Expected output:**
```
│ ✗… │ 👀 peekaboo   │ Capture and automate macO… │ openclaw-… │  │ blocked    │
```

### Unblock a skill

```bash
defenseclaw skill allow peekaboo
```

## 8. Monitor the Sandbox

### View sandbox logs (live)

```bash
journalctl -u openshell-sandbox -f
```

Key patterns to watch for:

| Pattern | Meaning |
|---------|---------|
| `CONNECT` | Outbound TCP connection attempt |
| `action="allow"` | Connection permitted |
| `action="deny"` | Connection blocked |
| `engine="opa"` | Policy decision by Open Policy Agent |
| `policy=allow_channels` | Which policy rule matched |

### View gateway logs (live)

```bash
tail -f ~/.defenseclaw/gateway.log
```

Key patterns:

| Pattern | Meaning |
|---------|---------|
| `[gateway] ← event` | WebSocket event from OpenClaw |
| `[watcher] new skill detected` | Skill installed, triggering scan |
| `[watcher] admission gate: ALLOWED` | Skill passed security scan |
| `[watcher] admission gate: BLOCKED` | Skill failed security scan |
| `PRE-CALL` | LLM prompt inspection (if guardrail enabled) |
| `POST-CALL` | LLM response inspection (if guardrail enabled) |

### Check overall status

```bash
defenseclaw status
```

**Expected output:**
```
DefenseClaw Status
══════════════════
  Environment:  linux
  Data dir:     ~/.defenseclaw
  Config:       ~/.defenseclaw/config.yaml
  Audit DB:     ~/.defenseclaw/audit.db

  Sandbox:      available

  Scanners:
    skill-scanner    not found
    mcp-scanner      not found
    codeguard        built-in

  Enforcement:
    Blocked skills:  3
    Allowed skills:  0
    Blocked MCPs:    0
    Allowed MCPs:    1

  Activity:
    Total scans:     8
    Active alerts:   56

  Splunk:       not configured
```

### View security alerts

```bash
defenseclaw alerts
```

This opens an interactive TUI showing recent security findings. Use arrow keys to navigate, Enter to view details, Q to quit.

## 9. Test Interactive Shell

### Open a shell as sandbox user

```bash
defenseclaw-gateway sandbox shell
```

This drops you into a bash shell as the `sandbox` user. From here you can:

```bash
# Check your identity
whoami
# sandbox

# Check network connectivity
curl -sI https://api.github.com

# List OpenClaw files
ls -la ~/.openclaw/

# Exit the shell
exit
```

## 10. Stop the Sandbox

### Stop the sandbox service

```bash
sudo systemctl stop defenseclaw-sandbox.target
```

This stops the sandbox. The gateway will automatically detect the disconnection.

### Stop the gateway

```bash
# If running in foreground: Ctrl+C

# If running in background:
defenseclaw-gateway stop
```

## 11. Enable on Boot (Optional)

To start the sandbox automatically on system boot:

```bash
sudo systemctl enable defenseclaw-sandbox.target
```

**Note:** The gateway is not managed by systemd and must be started manually or via a user service/shell profile.

## 12. Restart After Changes

If you modify the OpenShell policy files:

```bash
sudo systemctl restart openshell-sandbox.service
```

The gateway will automatically reconnect (no restart needed).

## Security Verification Checklist

After setup, verify these security properties:

- [ ] Sandbox service is running: `systemctl status openshell-sandbox.service`
- [ ] veth pair exists: `ip link show | grep veth-h`
- [ ] Host IP is 10.200.0.1: `ip addr show $(ip link show | grep veth-h | awk '{print $2}' | cut -d@ -f1)`
- [ ] Outbound HTTP works: `defenseclaw-gateway sandbox exec -- curl -sI https://google.com`
- [ ] Connections are proxied: `journalctl -u openshell-sandbox | grep CONNECT | tail -5`
- [ ] OpenClaw UI accessible: open `http://localhost:18789` in browser
- [ ] Skills are scanned: `defenseclaw skill list` shows ready skills
- [ ] Blocked skills are enforced: list shows "blocked" in Actions column
- [ ] Gateway is connected: `tail ~/.defenseclaw/gateway.log` shows event stream

## Troubleshooting

### Sandbox won't start

```bash
systemctl status openshell-sandbox.service
journalctl -u openshell-sandbox -n 50
```

Common causes:
- `openshell-sandbox` binary not found → re-run `sudo defenseclaw sandbox init`
- Permission denied on scripts → `sudo chmod 755 /usr/local/lib/defenseclaw/*.sh`
- Kernel doesn't support namespaces → check `cat /proc/sys/kernel/unprivileged_userns_clone`

### Gateway can't connect to sandbox

Check WebSocket connectivity:

```bash
# From host, test if OpenClaw is listening
curl -v http://10.200.0.2:18789
```

Common causes:
- OpenClaw not running inside sandbox → check `systemctl status openshell-sandbox.service`
- Device key not paired → re-run `sudo defenseclaw sandbox setup`
- veth pair not up → check `ip link show | grep veth-h`

### Network connections blocked unexpectedly

View the active policy:

```bash
cat ~/.defenseclaw/openshell-policy.yaml
```

The YAML file lists allowed destinations. To allow a new destination, edit the file and add:

```yaml
  allow_custom:
    binaries:
    - path: /**
    endpoints:
    - host: "example.com"
      ports: [443]
      tls: skip
```

Then restart:

```bash
sudo systemctl restart openshell-sandbox.service
```

### Skills not being scanned automatically

Check watcher status:

```bash
grep watcher ~/.defenseclaw/gateway.log | tail -10
```

If you see errors about ACLs:

```bash
sudo setfacl -R -m u:sandbox:rwX /home/sandbox/.openclaw
```

### UI not accessible on localhost:18789

Check iptables DNAT rule:

```bash
sudo iptables -t nat -L -n | grep 18789
```

Should show:

```
DNAT       tcp  --  127.0.0.1/32         0.0.0.0/0            tcp dpt:18789 to:10.200.0.2:18789
```

If missing, re-run the post-sandbox script:

```bash
sudo /usr/local/lib/defenseclaw/post-sandbox.sh
```

### Gateway shows connection retries

If you see repeated "connection attempt #N" messages:

```
[gateway] connect failed (attempt #2): dial tcp 10.200.0.2:18789: connection refused (retry in 1.36s)
```

This is normal during sandbox startup. OpenClaw takes 10-15 seconds to initialize. The gateway will keep retrying and connect automatically once OpenClaw is ready.

### Proxy connection errors in sandbox logs

If you see:

```
WARN openshell_sandbox::proxy: Proxy connection error error=Connection refused (os error 111)
```

This can be normal and doesn't necessarily indicate a problem. It happens when processes make rapid connection attempts and the proxy is briefly unavailable. Check if actual HTTP requests (curl, etc.) are succeeding.

## Next Steps

- Read the full documentation: [SANDBOX.md](SANDBOX.md)
- Configure custom policies: [SANDBOX.md § Setup § Configure](SANDBOX.md#step-2-configure)
- Set up SIEM integration: [SPLUNK_APP.md](SPLUNK_APP.md)
- Enable guardrails: [GUARDRAIL_QUICKSTART.md](GUARDRAIL_QUICKSTART.md)
- Explore the CLI: `defenseclaw --help` and `defenseclaw-gateway --help`
