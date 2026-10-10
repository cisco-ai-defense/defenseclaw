# MQTT Broker Security Configuration

DefenseClaw edge devices communicate with the fleet manager through an MQTT broker.
The broker itself is external infrastructure (typically Mosquitto), not embedded in
DefenseClaw code. This guide covers how to configure it securely.

## 1. Authentication (Username/Password)

Both the Go TCP client and the C edge-connector daemon read `DCLAW_MQTT_USER` and
`DCLAW_MQTT_PASS` from the environment and include them in the MQTT CONNECT packet.
The broker must be configured to require authentication so that unauthenticated
clients are rejected (CONNACK return code != 0).

### Mosquitto Configuration

Add to `/etc/mosquitto/mosquitto.conf`:

```
# Require authentication — reject anonymous connections
allow_anonymous false

# Password file (generated below)
password_file /etc/mosquitto/passwd

# ACL file (per-device topic restrictions)
acl_file /etc/mosquitto/acl
```

### Per-Device Credential Generation

Each device should have its own broker credentials. The device username follows
the pattern `dclaw-device-{device_id}`.

```bash
#!/bin/bash
# generate-device-creds.sh — Generate MQTT credentials for a fleet of devices
#
# Usage: ./generate-device-creds.sh <tenant_id> <fleet_id> <device_id_start> <device_id_end>
#
# Outputs:
#   - Appends to /etc/mosquitto/passwd
#   - Prints DCLAW_MQTT_USER and DCLAW_MQTT_PASS env vars for each device

set -euo pipefail

TENANT_ID="${1:?Usage: $0 <tenant_id> <fleet_id> <start_id> <end_id>}"
FLEET_ID="${2:?}"
START_ID="${3:?}"
END_ID="${4:?}"
PASSWD_FILE="${MOSQUITTO_PASSWD_FILE:-/etc/mosquitto/passwd}"

for device_id in $(seq "$START_ID" "$END_ID"); do
    username="dclaw-device-${device_id}"
    password=$(openssl rand -hex 16)

    # Add to Mosquitto password file (hashed)
    mosquitto_passwd -b "$PASSWD_FILE" "$username" "$password"

    echo "Device $device_id:"
    echo "  DCLAW_MQTT_USER=$username"
    echo "  DCLAW_MQTT_PASS=$password"
    echo ""
done

# Also create the fleet manager credential
fm_username="dclaw-fleet-manager"
fm_password=$(openssl rand -hex 32)
mosquitto_passwd -b "$PASSWD_FILE" "$fm_username" "$fm_password"

echo "Fleet Manager:"
echo "  DCLAW_MQTT_USER=$fm_username"
echo "  DCLAW_MQTT_PASS=$fm_password"
echo ""
echo "Reload Mosquitto: sudo systemctl reload mosquitto"
```

## 2. Topic ACL (Per-Device Isolation)

Without ACLs, any authenticated device can publish to or subscribe to any other
device's topics. A compromised device could:
- Impersonate another device by publishing to its heartbeat/register topics
- Eavesdrop on another device's verdict responses
- Inject false verdict responses

### Mosquitto ACL Configuration

Create `/etc/mosquitto/acl`:

```
# Fleet manager has full access to all DefenseClaw topics
user dclaw-fleet-manager
topic readwrite defenseclaw/#

# Per-device rules: each device can only access its own topic subtree.
# Pattern substitution uses %u for the authenticated username.
#
# Device username format: dclaw-device-{device_id}
# Topic format: defenseclaw/{tenant_id}/{fleet_id}/{device_id}/...

# Example for device 42 in tenant 1, fleet 1:
user dclaw-device-42
topic read  defenseclaw/1/1/42/#
topic write defenseclaw/1/1/42/#

# Example for device 100 in tenant 1, fleet 2:
user dclaw-device-100
topic read  defenseclaw/1/2/100/#
topic write defenseclaw/1/2/100/#

# Fleet-wide topics (OTA policy, emergency broadcasts) — read only for devices
# These are published by the fleet manager and consumed by all devices in a fleet.
user dclaw-device-42
topic read defenseclaw/1/1/ota/policy
topic read defenseclaw/1/1/ota/emergency

user dclaw-device-100
topic read defenseclaw/1/2/ota/policy
topic read defenseclaw/1/2/ota/emergency
```

### ACL Generation Script

For fleets with many devices, generate the ACL file programmatically:

```bash
#!/bin/bash
# generate-acl.sh — Generate Mosquitto ACL for a fleet
#
# Usage: ./generate-acl.sh <tenant_id> <fleet_id> <device_id_start> <device_id_end>

set -euo pipefail

TENANT_ID="${1:?Usage: $0 <tenant_id> <fleet_id> <start_id> <end_id>}"
FLEET_ID="${2:?}"
START_ID="${3:?}"
END_ID="${4:?}"
ACL_FILE="${MOSQUITTO_ACL_FILE:-/etc/mosquitto/acl}"

cat >> "$ACL_FILE" <<EOF

# Fleet manager — full access
user dclaw-fleet-manager
topic readwrite defenseclaw/#

EOF

for device_id in $(seq "$START_ID" "$END_ID"); do
    cat >> "$ACL_FILE" <<EOF

# Device $device_id (tenant=$TENANT_ID, fleet=$FLEET_ID)
user dclaw-device-${device_id}
topic read  defenseclaw/${TENANT_ID}/${FLEET_ID}/${device_id}/#
topic write defenseclaw/${TENANT_ID}/${FLEET_ID}/${device_id}/#
topic read  defenseclaw/${TENANT_ID}/${FLEET_ID}/ota/policy
topic read  defenseclaw/${TENANT_ID}/${FLEET_ID}/ota/emergency
EOF
done

echo "ACL written to $ACL_FILE"
echo "Reload Mosquitto: sudo systemctl reload mosquitto"
```

## 3. TLS / mTLS (Phase 2 -- Not Yet Implemented)

> **Status:** TLS transport is not yet implemented in the Edge Connector.
> The `tls_engine.c` file contains only stubs. Use plaintext MQTT on a trusted
> network for now and rely on authentication + ACLs (sections 1-2 above) for
> access control. mTLS support is planned for a future release.

## 4. Security Hardening Checklist

### Broker Configuration
- [ ] `allow_anonymous false` is set
- [ ] Password file uses hashed passwords (generated with `mosquitto_passwd -b`)
- [ ] ACL file restricts each device to its own topic subtree
- [ ] Fleet manager credential uses a strong random password (32+ bytes)
- [ ] Broker logs are monitored for authentication failures
- [ ] (Phase 2) TLS listener (port 8883) enabled with `require_certificate true`
- [ ] (Phase 2) Plaintext listener (port 1883) disabled in production

### Network
- [ ] MQTT port is not exposed to the public internet
- [ ] Firewall rules restrict MQTT access to known device IP ranges
- [ ] VPN or private network used for device-to-broker communication
- [ ] Rate limiting on broker connections to prevent DoS

### Credential Management
- [ ] Per-device credentials (not fleet-wide shared passwords)
- [ ] Credentials rotated on a regular schedule
- [ ] Compromised device credentials can be revoked without affecting fleet
- [ ] Fleet manager credential stored in a secrets manager (not in env files)

### Certificate Management (Phase 2 -- mTLS not yet implemented)
- [ ] CA private key stored in HSM or offline secure storage
- [ ] Device certificates have a bounded validity period (e.g., 1 year)
- [ ] Certificate revocation list (CRL) or OCSP configured on broker
- [ ] Device certificates use ECDSA P-256 (not RSA) for constrained devices

### Monitoring
- [ ] Alert on repeated CONNACK failures (brute force attempts)
- [ ] Alert on topic ACL violations (device attempting cross-device access)
- [ ] Monitor for unusual message rates per device
- [ ] Correlate MQTT auth failures with fleet manager device status

### Defense in Depth
- [ ] Even with broker ACLs, the fleet manager validates topic-to-payload
      device ID consistency (P0-2 fix in bridge.go)
- [ ] Verdict responses are HMAC-authenticated with per-device keys
- [ ] Policy OTA updates are signature-verified (HMAC-SHA256)
- [ ] Emergency broadcasts are signature-verified before application
- [ ] Auto-registration is disabled in production (`DCLAW_FLEET_AUTO_REGISTER=false`)
