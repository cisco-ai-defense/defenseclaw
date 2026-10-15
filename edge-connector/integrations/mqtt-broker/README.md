# MQTT broker security configuration

DefenseClaw uses an external MQTT broker. The Fleet gateway subscribes to
device heartbeat, registration, and verdict-request topics. The broker is the
publisher identity boundary: MQTT PUBLISH delivery does not give the gateway
subscriber a verified publisher ClientID. Give every device a distinct broker
credential and restrict that credential to its exact tenant, fleet, and device
topics. The bridge also validates topic and payload IDs and checks the
per-device HMAC for keyed devices.

## Authentication and per-device ACLs

Configure Mosquitto with authentication and an ACL file. Provision the
password file with interactive `mosquitto_passwd`, without `-b` so the
password does not appear in shell history or process arguments:

```bash
sudo mosquitto_passwd -c /etc/mosquitto/passwd dclaw-fleet-manager
sudo mosquitto_passwd /etc/mosquitto/passwd dclaw-device-1-1-42
```

Use a unique name including tenant, fleet, and device IDs; device ID alone
can repeat in another fleet. Replace the example identifiers for each device.
Set `DCLAW_MQTT_USER` and `DCLAW_MQTT_PASS` in the corresponding gateway/device
secret environment. The Go gateway and C daemon both send these credentials
in MQTT CONNECT; neither extracts them from URL userinfo.

Example `/etc/mosquitto/acl` for tenant 1, fleet 1, device 42:

```text
user dclaw-fleet-manager
topic readwrite defenseclaw/#

user dclaw-device-1-1-42
topic write defenseclaw/1/1/42/register
topic write defenseclaw/1/1/42/heartbeat
topic write defenseclaw/1/1/42/verdict/req
topic read defenseclaw/1/1/42/verdict/resp
topic read defenseclaw/1/1/ota/policy
topic read defenseclaw/1/1/ota/emergency
```

The fleet manager may publish commands and signed OTA messages across the
fleet. Device credentials must have read-only access to those topics. Do not
grant devices `readwrite defenseclaw/#` or wildcard access to another device's
topic. Also set `allow_anonymous false`, `password_file`, and `acl_file` in
Mosquitto's listener configuration. Verify with one device credential that
cross-device publishes are denied and cross-device messages are not delivered
before enrolling a fleet; Mosquitto may acknowledge a subscription yet still
filter unauthorized deliveries.

## TLS and mutual TLS

Production C builds support TLS with mbedTLS 3.x. Build with
`-DDCLAW_DEV_MODE=OFF`; set `DCLAW_BROKER_URL=mqtts://broker-host:8883` and
`DCLAW_CA_CERT_PATH` to the PEM CA used to verify the broker certificate.
When Mosquitto requires client certificates, also set
`DCLAW_DEVICE_CERT_PATH` and `DCLAW_DEVICE_KEY_PATH` on each device. The
gateway supports `ssl://` or `mqtts://`; use
`fleet.mqtt_require_tls: true`, `DCLAW_TLS_CA_CERT` for a private broker CA,
and `DCLAW_TLS_CLIENT_CERT` plus `DCLAW_TLS_CLIENT_KEY` for client-certificate
authentication. The gateway uses the OS trust store when no custom CA is
configured. Keep the broker's TLS private key readable only by its service
account.

Mosquitto TLS listener example (provision certificate files first):

```text
listener 8883
allow_anonymous false
password_file /etc/mosquitto/passwd
acl_file /etc/mosquitto/acl
certfile /etc/mosquitto/certs/broker.pem
keyfile /etc/mosquitto/certs/broker.key
```

For mutual TLS, configure `cafile` and `require_certificate true` on the
broker as well. Restrict broker ingress to expected networks, monitor
authentication and ACL failures, and rotate device and broker credentials
independently. The separate device HMAC key (`DCLAW_DEVICE_KEY`) and OTA
secrets (`DCLAW_OTA_HMAC_KEY`, `DCLAW_EMERGENCY_KEY`) remain required for their
respective message flows even when MQTT uses TLS.

During an upgrade, deploy the matching C connector with the Fleet gateway. Keyed heartbeat and registration messages now carry a 40-byte payload containing a durable 4-byte boot counter and 4-byte last-applied emergency sequence, followed by a 32-byte HMAC (72 bytes total). The gateway rejects older 64- and 68-byte signed formats, so stale devices stop reporting heartbeats until upgraded.
