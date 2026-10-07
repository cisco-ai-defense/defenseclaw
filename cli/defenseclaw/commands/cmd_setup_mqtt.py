# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""``defenseclaw setup mqtt-broker`` -- Stand up an MQTT broker for fleet comms.

Supports Docker (eclipse-mosquitto:2) and systemd (native mosquitto package).
Verifies the broker is accepting connections and persists the broker URL to
~/.defenseclaw/.env for use by the gateway and edge devices.
"""

from __future__ import annotations

import os
import secrets
import shutil
import socket
import subprocess
import time
from pathlib import Path

import click

from defenseclaw import ux
from defenseclaw.context import pass_ctx

_MOSQUITTO_IMAGE = "eclipse-mosquitto:2"
_CONTAINER_NAME = "defenseclaw-mqtt"
_ENV_KEY = "DCLAW_MQTT_BROKER_URL"

_MOSQUITTO_CONF_TEMPLATE = """\
# DefenseClaw MQTT broker configuration
listener 1883
allow_anonymous false
password_file /mosquitto/config/passwd
persistence false
log_dest stdout
"""


def _persist_env_var(env_path: Path, key: str, value: str) -> None:
    """Append or update a KEY=VALUE line in the dotenv file."""
    env_path.parent.mkdir(parents=True, exist_ok=True)

    lines: list[str] = []
    found = False
    if env_path.exists():
        lines = env_path.read_text().splitlines(keepends=True)
        new_lines: list[str] = []
        for line in lines:
            stripped = line.strip()
            if stripped.startswith(f"{key}=") or stripped.startswith(f"export {key}="):
                new_lines.append(f"{key}={value}\n")
                found = True
            else:
                new_lines.append(line)
        lines = new_lines

    if not found:
        lines.append(f"{key}={value}\n")

    env_path.write_text("".join(lines))
    try:
        env_path.chmod(0o600)
    except OSError:
        pass


def _tcp_check(host: str, port: int, timeout: float = 5.0) -> bool:
    """Try a TCP connect to verify the broker is accepting connections."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, TimeoutError):
        return False


def _wait_for_broker(host: str, port: int, retries: int = 6) -> bool:
    """Poll the broker with exponential backoff until it accepts connections."""
    for attempt in range(retries):
        if _tcp_check(host, port):
            return True
        wait = 0.5 * (2 ** attempt)
        ux.echo(f"  Waiting for broker ({attempt + 1}/{retries})...")
        time.sleep(wait)
    return False


def _setup_docker(port: int) -> dict | bool:
    """Pull and start eclipse-mosquitto in Docker with password auth.

    Follows a strict ordering to avoid the race where the password file
    does not exist when the broker starts:
      1. Create ~/.defenseclaw/mqtt/ directory
      2. Write mosquitto.conf with listener + password_file + persistence
      3. Generate the password file using a throwaway container
      4. Start the long-lived broker container mounting the config dir
      5. Verify MQTT CONNACK with generated credentials

    Returns a dict with mqtt_user/mqtt_pass on success, or False on failure.
    """
    docker = shutil.which("docker")
    if docker is None:
        ux.err(
            "Docker is not installed or not in PATH.\n"
            "  Install Docker: https://docs.docker.com/get-docker/\n"
            "  Or use --systemd to run mosquitto natively."
        )
        return False

    ux.section("Docker MQTT Broker Setup")

    # Check if container already exists
    result = subprocess.run(
        ["docker", "inspect", _CONTAINER_NAME],
        capture_output=True, text=True,
    )
    if result.returncode == 0:
        ux.warn(f"Container '{_CONTAINER_NAME}' already exists. Removing it.")
        subprocess.run(["docker", "rm", "-f", _CONTAINER_NAME], capture_output=True)

    # Step 1: Create config directory
    conf_dir = Path.home() / ".defenseclaw" / "mqtt"
    os.makedirs(conf_dir, exist_ok=True)
    ux.ok(f"Config directory: {conf_dir}")

    # Step 2: Write mosquitto.conf with persistence enabled.
    # P1-10 fix: The listener inside the container is always 1883.
    # Docker's -p flag maps the user's external port to 1883 internally.
    # Previously this used the user's port, which broke when --port != 1883
    # because the container would listen on a non-mapped port.
    conf_file = conf_dir / "mosquitto.conf"
    mosquitto_conf = (
        "# DefenseClaw MQTT broker configuration\n"
        "listener 1883\n"
        "allow_anonymous false\n"
        "password_file /mosquitto/config/passwd\n"
        "persistence true\n"
        "persistence_location /mosquitto/data/\n"
        "log_dest stdout\n"
    )
    conf_file.write_text(mosquitto_conf)
    ux.ok("mosquitto.conf written")

    # Step 3: Generate credentials and password file using a throwaway container
    mqtt_user = "dclaw"
    mqtt_pass = secrets.token_urlsafe(24)

    ux.echo(f"  Pulling {_MOSQUITTO_IMAGE}...")
    pull = subprocess.run(
        ["docker", "pull", _MOSQUITTO_IMAGE],
        capture_output=True, text=True,
    )
    if pull.returncode != 0:
        ux.err(f"Failed to pull {_MOSQUITTO_IMAGE}: {pull.stderr.strip()}")
        return False
    ux.ok(f"Image {_MOSQUITTO_IMAGE} ready")

    ux.echo("  Generating MQTT password file...")
    passwd_result = subprocess.run(
        [
            "docker", "run", "--rm",
            "-v", f"{conf_dir}:/mosquitto/config",
            _MOSQUITTO_IMAGE,
            "mosquitto_passwd", "-b", "-c",
            "/mosquitto/config/passwd", mqtt_user, mqtt_pass,
        ],
        capture_output=True, text=True,
    )
    if passwd_result.returncode != 0:
        ux.err(f"Failed to generate MQTT password file: {passwd_result.stderr.strip()}")
        return False

    # P1-10 fix: chmod the password file to 0644 so the broker process
    # (which may run as a non-root user inside the container) can read it.
    # The mosquitto_passwd container runs as root, creating the file with
    # root:root 0600 permissions, which the broker's mosquitto user cannot
    # read — causing silent authentication failures.
    passwd_file = conf_dir / "passwd"
    try:
        passwd_file.chmod(0o644)
    except OSError:
        ux.warn("Could not chmod password file to 0644 — broker may fail to read it.")

    ux.ok(f"MQTT user '{mqtt_user}' password file generated")

    # Step 4: Start the broker container mounting config and data directories.
    # The data directory holds persistent MQTT session and retained message state.
    data_dir = conf_dir / "data"
    os.makedirs(data_dir, exist_ok=True)

    ux.echo("  Starting container...")
    run_result = subprocess.run(
        [
            "docker", "run", "-d",
            "--name", _CONTAINER_NAME,
            "-p", f"{port}:1883",
            "-v", f"{conf_dir}:/mosquitto/config",
            "-v", f"{data_dir}:/mosquitto/data",
            "--restart", "unless-stopped",
            _MOSQUITTO_IMAGE,
        ],
        capture_output=True, text=True,
    )
    if run_result.returncode != 0:
        ux.err(f"Failed to start container: {run_result.stderr.strip()}")
        return False

    ux.ok(f"Container '{_CONTAINER_NAME}' started on port {port}")

    # Step 5: Verify MQTT CONNACK with the generated credentials.
    # Try a TCP connect + minimal MQTT CONNECT packet to confirm the broker
    # is actually accepting authenticated connections, not just listening.
    ux.echo("  Verifying MQTT CONNACK...")
    connack_ok = False
    for attempt in range(6):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
                # Build a minimal MQTT 3.1.1 CONNECT packet
                client_id = b"dclaw-verify"
                user_bytes = mqtt_user.encode("utf-8")
                pass_bytes = mqtt_pass.encode("utf-8")
                # Variable header: protocol name(6) + level(1) + flags(1) + keepalive(2)
                var_header = b"\x00\x04MQTT\x04\xC2\x00\x1e"  # 0xC2 = user+pass flags
                # Payload: client_id + username + password (each length-prefixed)
                payload = (
                    len(client_id).to_bytes(2, "big") + client_id
                    + len(user_bytes).to_bytes(2, "big") + user_bytes
                    + len(pass_bytes).to_bytes(2, "big") + pass_bytes
                )
                remaining = var_header + payload
                connect_pkt = bytes([0x10, len(remaining)]) + remaining
                sock.sendall(connect_pkt)
                sock.settimeout(5)
                connack = sock.recv(4)
                if len(connack) >= 4 and connack[0] == 0x20 and connack[3] == 0x00:
                    connack_ok = True
                    break
        except (OSError, TimeoutError):
            pass
        time.sleep(0.5 * (2 ** attempt))

    if connack_ok:
        ux.ok("MQTT CONNACK verified -- broker accepts credentials")
    else:
        # P1-10 fix: If CONNACK fails, the broker is broken. Clean up the
        # container and return failure instead of reporting success.
        ux.err(
            "MQTT CONNACK verification failed -- broker is not accepting connections.\n"
            "  Cleaning up container..."
        )
        subprocess.run(["docker", "rm", "-f", _CONTAINER_NAME], capture_output=True)
        return False

    return {"mqtt_user": mqtt_user, "mqtt_pass": mqtt_pass}


def _setup_systemd(port: int) -> bool:
    """Enable and start the system mosquitto service."""
    ux.section("Systemd MQTT Broker Setup")

    mosquitto = shutil.which("mosquitto")
    if mosquitto is None:
        # Detect package manager and give appropriate install instructions
        if shutil.which("apt"):
            pkg_cmd = "sudo apt install -y mosquitto"
        elif shutil.which("dnf"):
            pkg_cmd = "sudo dnf install -y mosquitto"
        elif shutil.which("yum"):
            pkg_cmd = "sudo yum install -y mosquitto"
        else:
            pkg_cmd = "# Install mosquitto via your system package manager"

        ux.err(
            "Mosquitto is not installed.\n"
            f"  Install it first:\n"
            f"    {pkg_cmd}\n"
            "  Then re-run this command."
        )
        return False

    ux.ok("Mosquitto binary found")

    # Enable and start the service
    ux.echo("  Enabling and starting mosquitto.service...")
    for action in ("enable", "start"):
        result = subprocess.run(
            ["sudo", "systemctl", action, "mosquitto"],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            ux.err(f"systemctl {action} mosquitto failed: {result.stderr.strip()}")
            return False

    ux.ok("mosquitto.service enabled and started")
    return True


@click.command("mqtt-broker")
@click.option("--port", default=1883, type=int, help="MQTT listener port.")
@click.option("--docker", "mode", flag_value="docker", default=True, help="Run broker in Docker (default).")
@click.option("--systemd", "mode", flag_value="systemd", help="Use system mosquitto via systemd.")
@pass_ctx
def mqtt_broker(app, port: int, mode: str) -> None:
    """Set up an MQTT broker for edge-connector fleet communication.

    By default, runs ``eclipse-mosquitto:2`` in Docker. Use ``--systemd``
    to manage a native mosquitto package instead.

    After setup, persists DCLAW_MQTT_BROKER_URL to ~/.defenseclaw/.env
    and verifies the broker is accepting TCP connections.
    """
    if mode == "docker":
        result = _setup_docker(port)
        ok = result is not False
        creds = result if isinstance(result, dict) else {}
    else:
        ok = _setup_systemd(port)
        creds = {}

    if not ok:
        raise SystemExit(1)

    # Verify the broker is accepting connections
    ux.echo()
    ux.section("Verifying broker connectivity")
    if _wait_for_broker("127.0.0.1", port):
        ux.ok(f"Broker accepting connections on localhost:{port}")
    else:
        ux.warn(
            f"Could not connect to broker on port {port} after several attempts.\n"
            "  The broker may still be starting. Check with:\n"
            + (f"    docker logs {_CONTAINER_NAME}" if mode == "docker"
               else "    journalctl -u mosquitto -f")
        )

    # Persist broker URLs in the correct format for each consumer:
    #   DCLAW_MQTT_BROKER_URL = host:port  (Go bridge uses net.Dial)
    #   DCLAW_BROKER_URL      = mqtt://host:port  (C edge-connector)
    go_broker_url = f"localhost:{port}"
    c_broker_url = f"mqtt://localhost:{port}"
    env_path = Path(os.environ.get("DEFENSECLAW_HOME", Path.home() / ".defenseclaw")) / ".env"
    _persist_env_var(env_path, _ENV_KEY, go_broker_url)
    ux.ok(f"Wrote {_ENV_KEY}={go_broker_url} to {env_path}")

    _persist_env_var(env_path, "DCLAW_BROKER_URL", c_broker_url)
    ux.ok(f"Wrote DCLAW_BROKER_URL={c_broker_url} to {env_path}")

    # Persist MQTT credentials if generated
    if creds:
        _persist_env_var(env_path, "DCLAW_MQTT_USER", creds["mqtt_user"])
        _persist_env_var(env_path, "DCLAW_MQTT_PASS", creds["mqtt_pass"])
        ux.ok(f"Wrote DCLAW_MQTT_USER and DCLAW_MQTT_PASS to {env_path}")

    # Summary
    ux.echo()
    ux.section("Next Steps")
    ux.echo(
        f"  Broker URL (Go):  {go_broker_url}\n"
        f"  Broker URL (C):   {c_broker_url}\n"
        "\n"
        "  Use this URL when installing edge connectors:\n"
        f"    defenseclaw setup edge-connector install --broker-url {c_broker_url} --target <device-ip>\n"
        "\n"
        "  Or configure the gateway to use it:\n"
        "    The gateway reads DCLAW_MQTT_BROKER_URL from ~/.defenseclaw/.env automatically.\n"
        "\n"
        "  Test the full pipeline:\n"
        "    defenseclaw fleet test\n"
    )
