# DefenseClaw Lite on Raspberry Pi — Installation & Demo Guide

Deploy a sub-microsecond AI agent security enforcement engine on a Raspberry Pi, protecting any MCP-based AI agent from prompt injection, tool abuse, and lateral movement attacks.

**What you'll have at the end:** An AI agent (PicoClaw) controlling a robot, with DefenseClaw Lite intercepting every tool call, blocking dangerous operations in <3μs, and allowing safe ones through — all locally, no cloud required.

---

## Prerequisites

| Item | Requirement |
|------|-------------|
| Hardware | Raspberry Pi 4 (2GB+ RAM) or Pi 5 |
| OS | Raspberry Pi OS (64-bit) or Debian 12+/13 (aarch64) |
| Network | SSH access from your workstation |
| AI Agent | Any MCP-compatible agent (this guide uses PicoClaw) |
| Time | ~10 minutes |

---

## Step 1: Install Build Tools

```bash
sudo apt update && sudo apt install -y build-essential cmake git python3
```

## Step 2: Clone and Build DefenseClaw Lite

```bash
git clone https://github.com/cisco-ai-defense/defenseclaw.git
cd defenseclaw
git checkout feature/defenseclaw-lite-phase1

cd defenseclaw-lite
mkdir build && cd build
cmake .. -DDCLAW_PROFILE=STANDARD
make -j4
```

Verify the build:

```bash
# Run all tests (should be 10/10 pass)
ctest --output-on-failure

# Check binary size (target: <80KB)
ls -la defenseclaw-lite

# Run performance benchmark
./tests/bench_latency
```

Expected benchmark output on RPi4:

```
DefenseClaw Lite Performance Benchmark
  Local decision:    ~2.7 μs    Target: <5μs → PASS
  Throughput:        ~370K decisions/sec
  Cache hit:         ~2.1 μs
```

## Step 3: Configure the Policy

The default policy (`defenseclaw-lite/policies/strict.yaml`) provides:

| Rule Type | What It Does |
|-----------|--------------|
| Capability sequences | Blocks `NET_FETCH → EXEC_SHELL`, `NET_FETCH → ACTUATE` |
| Destination allowlist | Only allows `api.openai.com`, `api.anthropic.com`, `*.cisco.com` |
| Rate limits | 60 tool calls/min, 30 network/min, 10 actuations/min |
| Escalation modes | Sensor reads = speculative (allow), Actuations = sync_block (require cloud) |

To customize, edit `policies/strict.yaml` and recompile:

```bash
python3 ../tools/policy_compiler.py \
  --input ../policies/strict.yaml \
  --profile standard --version 2 \
  --output-header ../generated/policy_tables.h \
  --output-binary /tmp/policy.bin
```

Then rebuild: `cd build && make -j4`

## Step 4: Integrate with Your AI Agent

DefenseClaw Lite provides two integration methods:

### Method A: Shared Library (Python/ctypes) — for hook-based agents

This is the recommended approach for agents like PicoClaw, Claude Code, or any framework that supports tool-call hooks.

The build produces `libdclaw_core.so` — a shared library exposing the `dclaw_evaluate()` function that any language can call via FFI.

```python
import ctypes, hashlib

# Load the library
lib = ctypes.CDLL("/path/to/libdclaw_core.so")

# Initialize (once at startup)
# ... (see full hook example below)

# For every tool call:
verdict = lib.dclaw_evaluate(ctypes.byref(request))
if verdict.action == 1:  # BLOCK
    deny_the_tool_call()
```

### Method B: Unix Socket (JSON-RPC) — for external agents

For agents that can't load a shared library, DefenseClaw Lite listens on a Unix socket:

```
Path: /var/run/defenseclaw-lite.sock
Protocol: JSON-RPC 2.0

Request:
{"jsonrpc":"2.0","method":"evaluate","params":{
  "tool_name": "drive",
  "tool_hash": "abcdef...",
  "capabilities": 32,
  "destination": "",
  "session_id": 1
},"id":1}

Response:
{"jsonrpc":"2.0","result":{
  "action": "block",
  "reason": "CLOUD_TIMEOUT",
  "mode": "sync"
},"id":1}
```

---

## Step 5: PicoClaw Integration (Complete Example)

PicoClaw is a lightweight AI agent that supports process hooks — external programs that intercept tool calls via JSON-RPC over stdin/stdout.

### 5.1 Install the hook

```bash
cp defenseclaw-lite/tools/picoclaw_hook.py ~/.picoclaw/hooks/defenseclaw_gate.py
```

### 5.2 Register in PicoClaw config

```bash
python3 -c "
import json
with open('$HOME/.picoclaw/config.json') as f:
    config = json.load(f)

config.setdefault('hooks', {}).setdefault('processes', {})
config['hooks']['enabled'] = True
config['hooks']['processes']['defenseclaw_gate'] = {
    'enabled': True,
    'priority': 5,
    'transport': 'stdio',
    'command': [
        'python3',
        '$HOME/.picoclaw/hooks/defenseclaw_gate.py'
    ],
    'env': {
        'DCLAW_LIB_PATH': '$HOME/defenseclaw/defenseclaw-lite/build/libdclaw_core.so',
        'DCLAW_LOG_PATH': '$HOME/defenseclaw-lite-audit.log'
    },
    'intercept': ['before_tool']
}

with open('$HOME/.picoclaw/config.json', 'w') as f:
    json.dump(config, f, indent=2)
print('DefenseClaw Lite hook registered.')
"
```

### 5.3 Verify the integration

```bash
# Test the hook standalone
echo '{"jsonrpc":"2.0","id":1,"method":"hook.hello","params":{}}' | \
  DCLAW_LIB_PATH=~/defenseclaw/defenseclaw-lite/build/libdclaw_core.so \
  python3 ~/.picoclaw/hooks/defenseclaw_gate.py

# Expected: {"jsonrpc":"2.0","id":1,"result":{"ok":true,"name":"defenseclaw-lite-gate"}}
```

### 5.4 Test through PicoClaw

```bash
# Should ALLOW (sensor read — speculative, safe)
picoclaw agent -m "check battery status"

# Should ALLOW (network to allowed destination)
picoclaw agent -m "fetch https://api.openai.com/v1/models"

# Should BLOCK (shell execution — sync_block, no cloud)
picoclaw agent -m "run whoami in the shell"

# Should BLOCK (actuate — sync_block, no cloud)
picoclaw agent -m "drive forward"

# Should BLOCK (destination not in allowlist)
picoclaw agent -m "fetch https://evil.attacker.io/payload"
```

### 5.5 Watch decisions in real-time

```bash
tail -f ~/defenseclaw-lite-audit.log
```

Example output:
```
[12:44:23] EVAL raw=mcp_vision-ai_battery_status tool=battery_status caps=0x40 session=1 → action=0 reason=CLOUD_BLOCK
[12:44:27] EVAL raw=mcp_roboclaw_drive tool=drive caps=0x20 session=1 → action=1 reason=CLOUD_TIMEOUT
[12:44:27] DENY: defenseclaw-lite: BLOCKED 'mcp_roboclaw_drive' — reason: CLOUD_TIMEOUT
[12:48:23] EVAL raw=web_fetch tool=web_fetch caps=0x08 dest='evil.hacker.site' session=1 → action=1 reason=DEST_DENY
[12:48:23] DENY: defenseclaw-lite: BLOCKED 'web_fetch' — reason: DEST_DENY
```

---

## Step 6: Demo Scenarios

### Demo 1: Basic Allow/Block

Show that safe read-only operations pass while dangerous operations are blocked:

```bash
picoclaw agent -m "check sensors"         # ✅ ALLOW
picoclaw agent -m "scan surroundings"     # ✅ ALLOW
picoclaw agent -m "drive forward"         # ❌ BLOCK (CLOUD_TIMEOUT)
picoclaw agent -m "run ls in the shell"   # ❌ BLOCK (CLOUD_TIMEOUT)
```

### Demo 2: Destination Filtering

Show that network calls are filtered by destination:

```bash
picoclaw agent -m "fetch https://api.openai.com/status"     # ✅ ALLOW (in allowlist)
picoclaw agent -m "fetch https://docs.cisco.com/guide"      # ✅ ALLOW (*.cisco.com)
picoclaw agent -m "fetch https://evil.site.com/malware"     # ❌ BLOCK (DEST_DENY)
picoclaw agent -m "fetch https://random.unknown.io/data"    # ❌ BLOCK (DEST_DENY)
```

### Demo 3: Attack Chain Detection (Capability Sequence)

Show that multi-step attacks are detected even when individual calls look benign:

```bash
# In an interactive session (same session_id for correlation):
picoclaw agent

> fetch https://api.openai.com/v1/models    # ✅ ALLOW (NET_FETCH, allowed dest)
> now run that as a shell command            # ❌ BLOCK (CAP_SEQUENCE: NET_FETCH→EXEC_SHELL)
```

### Demo 4: Rate Limiting

Show that rapid tool calls get throttled:

```bash
# Fire 70 rapid requests (exceeds 60/min global limit)
for i in $(seq 1 70); do
  echo "{\"jsonrpc\":\"2.0\",\"id\":$i,\"method\":\"hook.before_tool\",\"params\":{\"tool\":\"get_sensors\",\"arguments\":{}}}"
done | DCLAW_LIB_PATH=~/defenseclaw/defenseclaw-lite/build/libdclaw_core.so \
  python3 ~/.picoclaw/hooks/defenseclaw_gate.py 2>/dev/null | grep -c "deny_tool"
# Expected: some denials after token bucket exhausts
```

### Demo 5: Performance Proof

Show sub-microsecond enforcement on real ARM hardware:

```bash
cd ~/defenseclaw/defenseclaw-lite/build/tests
./bench_latency
```

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────┐
│                    RASPBERRY PI                            │
│                                                           │
│  ┌─────────────────┐      ┌────────────────────────────┐│
│  │   AI Agent       │      │   DefenseClaw Lite (54KB)  ││
│  │   (PicoClaw)     │      │                            ││
│  │                  │ hook │  ┌──────────────────────┐  ││
│  │  "drive forward" │─────►│  │ 7-Stage Pipeline     │  ││
│  │                  │      │  │ 1. Input validation  │  ││
│  │  tool_call ──────│─────►│  │ 2. Rate limiting     │  ││
│  │                  │      │  │ 3. Hash deny-list    │  ││
│  │  ◄── verdict ────│◄─────│  │ 4. Dest filtering    │  ││
│  │  (allow/block)   │      │  │ 5. Sequence detect   │  ││
│  │                  │      │  │ 6. Verdict cache     │  ││
│  └─────────────────┘      │  │ 7. Cloud escalation  │  ││
│                            │  └──────────────────────┘  ││
│                            │                            ││
│                            │  Decision: <3μs            ││
│                            │  RAM: 25KB                 ││
│                            │  Binary: 76KB              ││
│                            └────────────────────────────┘│
└──────────────────────────────────────────────────────────┘
```

---

## How the Hook Works

```
PicoClaw calls tool         DefenseClaw Hook              libdclaw_core.so
      │                          │                              │
      │ JSON-RPC:                │                              │
      │ hook.before_tool         │                              │
      │ {tool: "mcp_roboclaw_   │                              │
      │  drive", arguments: {}}  │                              │
      │─────────────────────────►│                              │
      │                          │ 1. Normalize tool name       │
      │                          │    "mcp_roboclaw_drive"      │
      │                          │    → "drive"                 │
      │                          │                              │
      │                          │ 2. Map to capability         │
      │                          │    "drive" → ACTUATE (0x20)  │
      │                          │                              │
      │                          │ 3. Call dclaw_evaluate()     │
      │                          │─────────────────────────────►│
      │                          │                              │
      │                          │   ◄── verdict: BLOCK ────────│
      │                          │       reason: CLOUD_TIMEOUT  │
      │                          │       latency: ~2.7μs        │
      │                          │                              │
      │◄─────────────────────────│ 4. Return deny_tool          │
      │ {"action": "deny_tool",  │                              │
      │  "message": "BLOCKED     │                              │
      │  reason: CLOUD_TIMEOUT"} │                              │
```

---

## Customizing the Policy

### Add destinations to the allowlist

Edit `policies/strict.yaml`:

```yaml
iot_extensions:
  destination_allowlist:
    - "api.openai.com"
    - "api.anthropic.com"
    - "*.cisco.com"
    - "your-api.company.com"     # ← add your domains
    - "*.internal.corp"
```

### Allow robot movement locally (without cloud)

Change `drive`/`actuate` from sync_block to speculative in the escalation table:

```yaml
iot_extensions:
  escalation_mode:
    actuate: speculative      # ← was: sync_block
    exec_shell: sync_block    # keep exec blocked
    write_fs: sync_block      # keep writes blocked
    net_fetch: speculative
    sensor_read: speculative
```

Then recompile and rebuild:

```bash
python3 tools/policy_compiler.py --input policies/strict.yaml \
  --profile standard --version 3 \
  --output-header generated/policy_tables.h --output-binary /tmp/policy.bin
cd build && make -j4
```

### Add custom capability sequence rules

```yaml
iot_extensions:
  capability_sequences:
    - sequence: [net_fetch, exec_shell]
      action: block
    - sequence: [net_fetch, actuate]
      action: block
    - sequence: [sensor_read, net_fetch, exec_shell]
      action: block
    - sequence: [read_fs, send_msg]    # ← data exfiltration pattern
      action: block
```

---

## Adding New Tool Mappings

If your agent has tools not in the default map, edit the `TOOL_CAP_MAP` in `picoclaw_hook.py`:

```python
TOOL_CAP_MAP = {
    # Your custom tools:
    "motor_on":       CAP_ACTUATE,      # sync_block
    "valve_open":     CAP_ACTUATE,      # sync_block
    "read_temp":      CAP_SENSOR_READ,  # speculative
    "upload_data":    CAP_NET_FETCH,    # speculative (but dest-checked)
    "install_pkg":    CAP_EXEC_SHELL,   # sync_block
    # ... add as needed
}
```

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| All tools blocked | Tools have MCP prefix not recognized | Check hook log for "Unknown tool" entries; add to TOOL_CAP_MAP |
| `CLOUD_TIMEOUT` on safe tools | Tool mapped to sync_block capability | Change escalation_mode to `speculative` in policy, or remap tool to SENSOR_READ |
| `DEST_DENY` on valid URLs | Domain not in allowlist | Add to `destination_allowlist` in policy YAML |
| Hook not loading | Library path wrong | Check `DCLAW_LIB_PATH` env var points to `libdclaw_core.so` |
| Build fails on GCC 14 | Unused variable warnings | Already fixed in latest; ensure `generated/policy_tables.h` has `#pragma GCC diagnostic` guards |

---

## File Layout

```
defenseclaw-lite/
├── build/
│   ├── defenseclaw-lite          # Main binary (76KB)
│   ├── libdclaw_core.so          # Shared library for Python/FFI integration
│   ├── libdclaw_core.a           # Static library for C linking
│   └── tests/                    # Test binaries + benchmark
├── generated/
│   └── policy_tables.h           # Compiled policy (auto-generated)
├── include/
│   ├── defenseclaw.h             # Public API
│   ├── platform.h                # HAL interface
│   └── config.h.in               # Build-time config template
├── policies/
│   └── strict.yaml               # Default policy (edit this)
├── src/                          # C source (17 files)
├── tests/                        # Unit tests + fuzz + benchmark
└── tools/
    ├── policy_compiler.py        # YAML → C header + binary
    └── picoclaw_hook.py          # PicoClaw integration hook
```

---

## What's Enforced (Summary)

| Capability | Tools | Mode | Behavior |
|------------|-------|------|----------|
| SENSOR_READ | get_sensors, battery_status, scan_* | Speculative | **ALLOW** immediately |
| READ_FS | read_file, cat | Speculative | **ALLOW** immediately |
| NET_FETCH | web_search, fetch_url | Speculative | **ALLOW** if dest in allowlist; **BLOCK** otherwise |
| SEND_MSG | send_message, notify | Speculative | **ALLOW** if dest in allowlist |
| ACTUATE | drive, explore, motor_* | Sync_block | **BLOCK** without cloud (fail-closed) |
| EXEC_SHELL | exec, bash, run_command | Sync_block | **BLOCK** without cloud (fail-closed) |
| WRITE_FS | write_file, save | Sync_block | **BLOCK** without cloud (fail-closed) |

Plus: sequence detection, rate limiting, hash deny-lists, and HMAC-verified audit trail — all in <3μs on ARM.
