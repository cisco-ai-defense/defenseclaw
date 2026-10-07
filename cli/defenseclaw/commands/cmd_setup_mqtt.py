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
import tempfile
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


def _copy_staging_to_final(staging_dir: Path, final_dir: Path) -> bool:
    """Copy staging files to the final config dir, handling 1883-owned reruns.

    On first run the final dir may not exist or is owned by the CLI user.
    On reruns it is owned by 1883:1883 and the CLI user cannot write to it.
    In the rerun case we use a Docker container running as root to copy the
    files and then re-chown.

    Returns True on success.
    """
    if not final_dir.exists():
        # First run -- just move/copy the directory.
        os.makedirs(final_dir.parent, exist_ok=True)
        shutil.copytree(staging_dir, final_dir)
        return True

    # Rerun: the final dir exists.  Try a plain copy first (works if the
    # CLI user still owns it).
    test_file = final_dir / ".dclaw-write-test"
    try:
        test_file.write_text("probe")
        test_file.unlink()
        # Writable -- overwrite files directly.
        for name in ("mosquitto.conf", "passwd"):
            src = staging_dir / name
            if src.exists():
                shutil.copy2(src, final_dir / name)
        return True
    except OSError:
        pass

    # Directory is not writable (owned by 1883).  Use Docker --user 0 to
    # copy the new files in and re-chown.
    cp_result = subprocess.run(
        [
            "docker", "run", "--rm",
            "--user", "0",
            "-v", f"{staging_dir}:/staging:ro",
            "-v", f"{final_dir}:/mosquitto/config",
            _MOSQUITTO_IMAGE,
            "sh", "-c",
            "cp /staging/mosquitto.conf /mosquitto/config/mosquitto.conf && "
            "cp /staging/passwd /mosquitto/config/passwd && "
            "chown -R 1883:1883 /mosquitto/config",
        ],
        capture_output=True, text=True,
    )
    if cp_result.returncode != 0:
        ux.err(
            f"Failed to copy staging files to {final_dir} via Docker: "
            f"{cp_result.stderr.strip()}"
        )
        return False
    return True


def _setup_docker(port: int) -> dict | bool:
    """Pull and start eclipse-mosquitto in Docker with password auth.

    Uses a completely separate staging directory for all file preparation
    so that reruns (where the final dir is owned by 1883:1883) never fail
    with EACCES.  The workflow:

      1. Create a temp staging dir owned by the CLI user
      2. Write mosquitto.conf and generate passwd file in staging
      3. Start a test container from staging, verify CONNACK
      4. Stop test container
      5. Copy staging files to final config dir (creating it if needed)
      6. Set final ownership to 1883:1883
      7. Start the real container from the final dir

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

    # Check if an existing container is running -- we keep it alive until the
    # new setup is validated so the broker stays available during setup.
    existing_container = False
    result = subprocess.run(
        ["docker", "inspect", _CONTAINER_NAME],
        capture_output=True, text=True,
    )
    if result.returncode == 0:
        existing_container = True
        ux.warn(f"Container '{_CONTAINER_NAME}' already exists. Will replace after validation.")

    # ── Step 1: Create a staging directory owned by the CLI user ──────────
    # We use a random temp dir so we never collide with a 1883-owned final dir.
    staging_dir = Path(tempfile.mkdtemp(prefix="dclaw-mqtt-staging-"))
    ux.ok(f"Staging directory: {staging_dir}")

    try:
        return _setup_docker_inner(
            port, staging_dir, existing_container,
        )
    finally:
        # Always clean up the staging directory.
        shutil.rmtree(staging_dir, ignore_errors=True)


def _setup_docker_inner(
    port: int,
    staging_dir: Path,
    existing_container: bool,
) -> dict | bool:
    """Inner implementation of Docker setup using the staging dir."""

    # ── Step 2: Write mosquitto.conf in staging ──────────────────────────
    conf_file = staging_dir / "mosquitto.conf"
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
    ux.ok("mosquitto.conf written (staging)")

    # Generate credentials and password file in staging.
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

    ux.echo("  Generating MQTT password file (staging)...")
    current_uid = os.getuid()
    current_gid = os.getgid()
    passwd_result = subprocess.run(
        [
            "docker", "run", "--rm",
            "--user", f"{current_uid}:{current_gid}",
            "-v", f"{staging_dir}:/mosquitto/config",
            _MOSQUITTO_IMAGE,
            "mosquitto_passwd", "-b", "-c",
            "/mosquitto/config/passwd", mqtt_user, mqtt_pass,
        ],
        capture_output=True, text=True,
    )
    if passwd_result.returncode != 0:
        ux.err(f"Failed to generate MQTT password file: {passwd_result.stderr.strip()}")
        return False

    ux.ok(f"MQTT user '{mqtt_user}' password file generated (staging)")

    # ── Step 3: Start a test container from staging, verify CONNACK ──────
    staging_name = f"{_CONTAINER_NAME}-staging"
    # Clean up any leftover staging container from a previous failed attempt.
    subprocess.run(["docker", "rm", "-f", staging_name], capture_output=True)

    # If the existing container is using our port, use a temporary host port.
    if existing_container:
        staging_port = port + 1
    else:
        staging_port = port

    # Create a temporary data dir for the staging container.
    staging_data = staging_dir / "data"
    staging_data.mkdir(exist_ok=True)

    ux.echo("  Starting staging container for validation...")
    run_result = subprocess.run(
        [
            "docker", "run", "-d",
            "--name", staging_name,
            "-p", f"{staging_port}:1883",
            "-v", f"{staging_dir}:/mosquitto/config",
            "-v", f"{staging_data}:/mosquitto/data",
            _MOSQUITTO_IMAGE,
        ],
        capture_output=True, text=True,
    )
    if run_result.returncode != 0:
        ux.err(f"Failed to start staging container: {run_result.stderr.strip()}")
        return False

    ux.ok(f"Staging container started on port {staging_port}")

    # Verify MQTT CONNACK against the staging container.
    ux.echo("  Verifying MQTT CONNACK on staging container...")
    connack_ok = False
    for attempt in range(6):
        try:
            with socket.create_connection(("127.0.0.1", staging_port), timeout=5) as sock:
                client_id = b"dclaw-verify"
                user_bytes = mqtt_user.encode("utf-8")
                pass_bytes = mqtt_pass.encode("utf-8")
                var_header = b"\x00\x04MQTT\x04\xC2\x00\x1e"
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

    # ── Step 4: Stop test container ──────────────────────────────────────
    subprocess.run(["docker", "rm", "-f", staging_name], capture_output=True)

    if not connack_ok:
        ux.err(
            "MQTT CONNACK verification failed -- staging broker is not accepting connections.\n"
            "  Cleaned up staging container."
        )
        if existing_container:
            ux.echo(f"  Existing container '{_CONTAINER_NAME}' was NOT removed.")
        return False

    ux.ok("MQTT CONNACK verified -- staging broker accepts credentials")

    # ── Step 5: Copy staging files to final config dir ───────────────────
    final_dir = Path.home() / ".defenseclaw" / "mqtt"
    ux.echo(f"  Copying validated config to {final_dir}...")
    if not _copy_staging_to_final(staging_dir, final_dir):
        return False
    ux.ok(f"Config files installed to {final_dir}")

    # ── Step 6: Set final ownership to 1883:1883 ────────────────────────
    try:
        final_dir.chmod(0o755)
    except OSError:
        pass

    passwd_file = final_dir / "passwd"
    try:
        passwd_file.chmod(0o640)
    except OSError:
        pass

    chown_result = subprocess.run(
        [
            "docker", "run", "--rm",
            "--user", "0",
            "-v", f"{final_dir}:/mosquitto/config",
            _MOSQUITTO_IMAGE,
            "chown", "-R", "1883:1883", "/mosquitto/config",
        ],
        capture_output=True, text=True,
    )
    if chown_result.returncode != 0:
        ux.warn(
            f"Could not chown config dir to mosquitto (1883): {chown_result.stderr.strip()}\n"
            "  The broker may fail to read its configuration files."
        )

    # ── Step 7: Start the real container from the final dir ──────────────
    if existing_container:
        ux.echo(f"  Removing old container '{_CONTAINER_NAME}'...")
        subprocess.run(["docker", "rm", "-f", _CONTAINER_NAME], capture_output=True)

    data_dir = final_dir / "data"
    os.makedirs(data_dir, exist_ok=True)

    run_final = subprocess.run(
        [
            "docker", "run", "-d",
            "--name", _CONTAINER_NAME,
            "-p", f"{port}:1883",
            "-v", f"{final_dir}:/mosquitto/config",
            "-v", f"{data_dir}:/mosquitto/data",
            "--restart", "unless-stopped",
            _MOSQUITTO_IMAGE,
        ],
        capture_output=True, text=True,
    )
    if run_final.returncode != 0:
        ux.err(f"Failed to start final container: {run_final.stderr.strip()}")
        return False

    ux.ok(f"Container '{_CONTAINER_NAME}' started on port {port}")

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
