# DefenseClaw Edge Connector + Fleet Management — End-to-End Integration Test

**Date:** 2026-10-14
**Branch:** feature/defenseclaw-lite-phase1
**Head:** 73e6de171

## Prerequisites

- macOS or Linux host
- Go 1.26+ (for gateway build)
- CMake 3.16+ and C compiler (for edge-connector build)
- Mosquitto broker (`brew install mosquitto` or `apt install mosquitto`)
- Mosquitto clients (`brew install mosquitto` or `apt install mosquitto-clients`)
- Python 3.10+ with project venv (`.venv/`)

## Step 1: Start MQTT Broker

```bash
# Create config
mkdir -p /tmp/dclaw-e2e/config
cat > /tmp/dclaw-e2e/config/mosquitto.conf << 'EOF'
listener 1883
allow_anonymous true
persistence false
log_dest stderr
EOF

# Start broker
mosquitto -c /tmp/dclaw-e2e/config/mosquitto.conf -d

# Verify
mosquitto_pub -h 127.0.0.1 -p 1883 -t test/ping -m "pong" && echo "Broker: OK"
```

**Expected:** `Broker: OK`

## Step 2: Create DefenseClaw Home Directory

```bash
export DEFENSECLAW_HOME=$HOME/.defenseclaw-e2e-test
rm -rf "$DEFENSECLAW_HOME"
mkdir -p "$DEFENSECLAW_HOME"
chmod 700 "$DEFENSECLAW_HOME"

# Generate cryptographic keys
AUDIT_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
OTA_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
DEVICE_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
FLEET_TOKEN=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")

# Write .env
cat > "$DEFENSECLAW_HOME/.env" << EOF
DCLAW_FLEET_API_TOKEN=$FLEET_TOKEN
DCLAW_AUDIT_KEY=$AUDIT_KEY
DCLAW_OTA_KEY=$OTA_KEY
DCLAW_DEVICE_KEY=$DEVICE_KEY
EOF
chmod 600 "$DEFENSECLAW_HOME/.env"

echo "FLEET_TOKEN=$FLEET_TOKEN"
```

## Step 3: Create Config and Policy Data

```bash
# Create v9 config with fleet enabled
cat > "$DEFENSECLAW_HOME/config.yaml" << EOF
config_version: 9
data_dir: $DEFENSECLAW_HOME
environment: e2e-test
fleet:
  enabled: true
EOF
chmod 600 "$DEFENSECLAW_HOME/config.yaml"

# Copy guardrail rule packs from source tree
mkdir -p "$DEFENSECLAW_HOME/policies/guardrail"
cp -r policies/guardrail/default "$DEFENSECLAW_HOME/policies/guardrail/"
cp -r policies/guardrail/strict "$DEFENSECLAW_HOME/policies/guardrail/"
cp -r policies/guardrail/permissive "$DEFENSECLAW_HOME/policies/guardrail/"
cp policies/guardrail/tool-chains.json "$DEFENSECLAW_HOME/policies/guardrail/" 2>/dev/null
cp -r policies/guardrail-use-cases "$DEFENSECLAW_HOME/policies/" 2>/dev/null
mkdir -p "$DEFENSECLAW_HOME/policies/rego"
cp policies/rego/*.rego "$DEFENSECLAW_HOME/policies/rego/" 2>/dev/null
rm -f "$DEFENSECLAW_HOME/policies/rego/"*_test.rego
cp policies/*.yaml "$DEFENSECLAW_HOME/policies/" 2>/dev/null
mkdir -p "$DEFENSECLAW_HOME/fleet"
chmod 700 "$DEFENSECLAW_HOME/fleet"
```

## Step 4: Build and Start Go Gateway

```bash
# Build
make gateway

# Start with fleet enabled
source "$DEFENSECLAW_HOME/.env"
export DCLAW_FLEET_API_TOKEN DCLAW_AUDIT_KEY DCLAW_OTA_KEY DCLAW_DEVICE_KEY
export DCLAW_MQTT_BROKER_URL=mqtt://127.0.0.1:1883
export DCLAW_FLEET_AUTO_REGISTER=true

./defenseclaw-gateway &>/tmp/gw-e2e.log &
GW_PID=$!
sleep 5

# Verify — note the actual API port from the log
API_PORT=$(grep -oP 'API port:\s+\K\d+' /tmp/gw-e2e.log | head -1)
echo "API port: $API_PORT"
curl -s -H "Authorization: Bearer $DCLAW_FLEET_API_TOKEN" \
     -H "X-Requested-With: defenseclaw-cli" \
     http://127.0.0.1:$API_PORT/api/v1/fleet/health | python3 -m json.tool
```

**Expected:** JSON response with `total_devices: 0`, `online: 0`.

## Step 5: Build and Start C Edge Connector

```bash
cd edge-connector
mkdir -p build-e2e && cd build-e2e
cmake .. -DCMAKE_BUILD_TYPE=Debug -DDCLAW_DEV_MODE=ON -DDCLAW_PROFILE=STANDARD
make -j$(nproc)

# Start with device identity
source "$DEFENSECLAW_HOME/.env"
export DCLAW_TENANT_ID=1
export DCLAW_FLEET_ID=1
export DCLAW_DEVICE_ID=42
export DCLAW_AUDIT_KEY
export DCLAW_DEVICE_KEY  # Will use the fleet-provisioned key after registration
export DCLAW_OTA_KEY
export DCLAW_BROKER_URL=mqtt://127.0.0.1:1883
export DCLAW_IPC_SOCKET_PATH=/tmp/dclaw-e2e.sock
export DCLAW_FLASH_PATH=/tmp/dclaw-e2e-flash
rm -f /tmp/dclaw-e2e.sock /tmp/dclaw-e2e-flash

./edge-connector &>/tmp/edge-e2e.log &
EDGE_PID=$!
sleep 3
```

**Expected log output:**
```
[DCLAW-MQTT] Registration message sent on defenseclaw/1/1/42/register
[DCLAW-MQTT] Connected to 127.0.0.1:1883
edge-connector: running (profile=STANDARD, ipc=/tmp/dclaw-e2e.sock)
```

## Step 6: Test Device Registration

```bash
# Register device via REST API
curl -s -X POST \
  -H "Authorization: Bearer $DCLAW_FLEET_API_TOKEN" \
  -H "Content-Type: application/json" \
  -H "X-Requested-With: defenseclaw-cli" \
  -H "X-DefenseClaw-Client: e2e-test" \
  http://127.0.0.1:$API_PORT/api/v1/fleet/devices \
  -d '{
    "tenant_id": 1, "fleet_id": 1, "device_id": 42,
    "hw_profile": "rpi4-8gb", "fw_version": "1.0.0",
    "policy_version": 0, "capabilities": 127
  }' | python3 -m json.tool
```

**Expected:** HTTP 201 with `device_id`, `device_key`, `status: "online"`.

## Step 7: Test IPC Verdict Flow

```bash
# Helper to compute SHA-256 tool hash
hash() { python3 -c "import hashlib; print(hashlib.sha256(b'$1').hexdigest())"; }

# 7a: Simple ALLOW
printf '{"jsonrpc":"2.0","method":"evaluate","params":{"tool_name":"read_file","tool_hash":"%s","capabilities":1,"session_id":1},"id":1}\n' "$(hash read_file)" \
  | nc -U /tmp/dclaw-e2e.sock
```

**Expected:** `{"jsonrpc":"2.0","result":{"action":"allow",...},"id":1}`

```bash
# 7b: Capability sequence BLOCK (NET_FETCH then EXEC_SHELL)
printf '{"jsonrpc":"2.0","method":"evaluate","params":{"tool_name":"curl","tool_hash":"%s","capabilities":2,"session_id":100,"destination":"api.openai.com"},"id":2}\n' "$(hash curl)" \
  | nc -U /tmp/dclaw-e2e.sock

printf '{"jsonrpc":"2.0","method":"evaluate","params":{"tool_name":"bash","tool_hash":"%s","capabilities":4,"session_id":100},"id":3}\n' "$(hash bash)" \
  | nc -U /tmp/dclaw-e2e.sock
```

**Expected:** First call → `allow`. Second call → `block` with `reason:2` (capability sequence).

## Step 8: Test Content Scanner

```bash
# 8a: AWS secret key detection
printf '{"jsonrpc":"2.0","method":"evaluate","params":{"tool_name":"write_file","tool_hash":"%s","capabilities":8,"session_id":200,"content":"API key: AKIAIOSFODNN7EXAMPLE","direction":0},"id":10}\n' "$(hash write_file)" \
  | nc -U /tmp/dclaw-e2e.sock

# 8b: SSN detection
printf '{"jsonrpc":"2.0","method":"evaluate","params":{"tool_name":"write_file","tool_hash":"%s","capabilities":8,"session_id":201,"content":"SSN: 123-45-6789","direction":0},"id":11}\n' "$(hash write_file)" \
  | nc -U /tmp/dclaw-e2e.sock

# 8c: SQL injection detection
printf '{"jsonrpc":"2.0","method":"evaluate","params":{"tool_name":"write_file","tool_hash":"%s","capabilities":8,"session_id":202,"content":"SELECT * FROM users; DROP TABLE users;--","direction":0},"id":12}\n' "$(hash write_file)" \
  | nc -U /tmp/dclaw-e2e.sock

# 8d: SSRF to localhost
printf '{"jsonrpc":"2.0","method":"evaluate","params":{"tool_name":"curl","tool_hash":"%s","capabilities":2,"session_id":203,"destination":"127.0.0.1"},"id":13}\n' "$(hash curl)" \
  | nc -U /tmp/dclaw-e2e.sock

# 8e: SSRF to cloud metadata
printf '{"jsonrpc":"2.0","method":"evaluate","params":{"tool_name":"curl","tool_hash":"%s","capabilities":2,"session_id":204,"destination":"169.254.169.254"},"id":14}\n' "$(hash curl)" \
  | nc -U /tmp/dclaw-e2e.sock
```

**Expected:** All five → `block`.

## Step 9: Test Fleet Operations

```bash
# 9a: Send device command
FULL_ID=<device_id from registration>
curl -s -X POST \
  -H "Authorization: Bearer $DCLAW_FLEET_API_TOKEN" \
  -H "Content-Type: application/json" \
  -H "X-Requested-With: defenseclaw-cli" \
  -H "X-DefenseClaw-Client: e2e-test" \
  http://127.0.0.1:$API_PORT/api/v1/fleet/devices/$FULL_ID/command \
  -d '{"command":"reboot"}' | python3 -m json.tool

# 9b: Emergency lockdown
curl -s -X POST \
  -H "Authorization: Bearer $DCLAW_FLEET_API_TOKEN" \
  -H "Content-Type: application/json" \
  -H "X-Requested-With: defenseclaw-cli" \
  -H "X-DefenseClaw-Client: e2e-test" \
  http://127.0.0.1:$API_PORT/api/v1/fleet/policy/emergency \
  -d '{"tenant_id":1,"fleet_id":1,"command":"block_all"}' | python3 -m json.tool

# 9c: Decommission
curl -s -X POST \
  -H "Authorization: Bearer $DCLAW_FLEET_API_TOKEN" \
  -H "Content-Type: application/json" \
  -H "X-Requested-With: defenseclaw-cli" \
  -H "X-DefenseClaw-Client: e2e-test" \
  http://127.0.0.1:$API_PORT/api/v1/fleet/devices/decommission-batch \
  -d '{"devices":[{"tenant_id":1,"fleet_id":1,"device_id":99}]}' | python3 -m json.tool
```

**Expected:** Command → `dispatched`. Emergency → `distributed`. Decommission → `completed`.

## Step 10: Test Token Rotation

```bash
curl -s -X POST \
  -H "Authorization: Bearer $DCLAW_FLEET_API_TOKEN" \
  -H "Content-Type: application/json" \
  -H "X-Requested-With: defenseclaw-cli" \
  -H "X-DefenseClaw-Client: e2e-test" \
  http://127.0.0.1:$API_PORT/api/v1/fleet/token/rotate \
  -d '{}' | python3 -m json.tool
```

**Expected:** New token returned; old token returns 401.

## Step 11: Verify Fleet Health

```bash
curl -s -H "Authorization: Bearer $NEW_TOKEN" \
  -H "X-Requested-With: defenseclaw-cli" \
  http://127.0.0.1:$API_PORT/api/v1/fleet/health | python3 -m json.tool
```

**Expected:** `total_devices`, `online`, `cache_size` all reflect the test activity.

## Cleanup

```bash
pkill -f defenseclaw-gateway
pkill -f 'edge-connector$'
pkill -f mosquitto
rm -f /tmp/dclaw-e2e.sock /tmp/dclaw-e2e-flash
rm -rf $HOME/.defenseclaw-e2e-test
```

---

## Test Results (2026-10-14)

| # | Test | Result | Details |
|---|---|---|---|
| 1 | Broker setup | PASS | Mosquitto 2.1.2 on localhost:1883 |
| 2 | Gateway startup + fleet health | PASS | Fleet API returns 200 (auth) / 401 (unauth) |
| 3 | Device registration (×2) | PASS | Devices 42 + 99 registered with unique keys |
| 4 | Heartbeat (C→MQTT→Go) | PASS | Device 42 online, uptime + denied counters updated |
| 5 | Verdict: ALLOW | PASS | `read_file` → allow (speculative) |
| 6 | Verdict: capability sequence BLOCK | PASS | `curl`→`bash` → block (reason 2) |
| 7 | Content scan: AWS key | PASS | AKIAIOSFODNN7EXAMPLE → block |
| 8 | Content scan: SSN | PASS | 123-45-6789 → block |
| 9 | Content scan: SQL injection | PASS | DROP TABLE → block |
| 10 | SSRF: localhost | PASS | 127.0.0.1 → block |
| 11 | SSRF: cloud metadata | PASS | 169.254.169.254 → block |
| 12 | Device command (reboot) | PASS | Dispatched via MQTT |
| 13 | Emergency lockdown | PASS | block_all distributed |
| 14 | Device decommission | PASS | Device 99 removed, fleet count 1 |
| 15 | Token rotation | PASS | New token 200, old token 401 |
| 16 | Verdict cache | PASS | 3 cached entries after IPC evaluations |
