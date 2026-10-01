#!/usr/bin/env python3
"""Listen for robot responses on MQTT. Use instead of mosquitto_sub."""
import paho.mqtt.client as mqtt
import ssl, sys, json

BROKER = "192.168.86.34"
PORT = 8883
CA = "/tmp/picoclaw-ca.crt"
USER = "hermes"
PASS = "4fgKjjUjc9dulRQ71sGjC+HQ9Q+3CTEX"
TOPIC = "/picoclaw/robot/to/hermes"

def on_connect(client, userdata, flags, reason_code, properties=None):
    print(f"✓ Connected to {BROKER}:{PORT}, listening on {TOPIC}")
    print("─" * 60)
    client.subscribe(TOPIC)

def on_message(client, userdata, msg):
    try:
        data = json.loads(msg.payload)
        text = data.get("text", data.get("message", msg.payload.decode()))
        print(f"🤖 {text}")
    except Exception:
        print(f"🤖 {msg.payload.decode()}")
    print("─" * 60)
    sys.stdout.flush()

c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="mac-demo-listener")
c.username_pw_set(USER, PASS)
c.tls_set(ca_certs=CA)
c.on_connect = on_connect
c.on_message = on_message
c.connect(BROKER, PORT)

try:
    c.loop_forever()
except KeyboardInterrupt:
    print("\nStopped.")
    c.disconnect()
