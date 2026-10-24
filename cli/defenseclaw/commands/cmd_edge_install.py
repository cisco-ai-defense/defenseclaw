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

"""``defenseclaw setup edge-connector install`` -- Build and deploy the Edge Connector.

Provides a unified install experience for the C-based edge-connector engine,
either locally or on a remote device via SSH.
"""

from __future__ import annotations

import http.client
import ipaddress
import os
import shlex
import shutil
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

import click

from defenseclaw import ux
from defenseclaw.context import pass_ctx
from defenseclaw.dotenv_utils import persist_env_var as _persist_env_var


def _fleet_api_request(api_base: str, method: str, suffix: str, token: str, body: str = "") -> tuple[int, str]:
    """Pin a local Fleet request to a socket proven to belong to this account."""
    from defenseclaw.gateway import _verify_connected_gateway_socket

    endpoint = urlsplit(api_base.rstrip("/") + suffix)
    host = endpoint.hostname
    if not host:
        raise ValueError("Fleet API host is missing")
    port = endpoint.port or (443 if endpoint.scheme == "https" else 80)
    connection_type = http.client.HTTPSConnection if endpoint.scheme == "https" else http.client.HTTPConnection
    connection = connection_type(host, port, timeout=60)
    try:
        connection.connect()
        if connection.sock is None:
            raise OSError("Fleet API socket is unavailable")
        peer_host = connection.sock.getpeername()[0]
        if ipaddress.ip_address(peer_host.split("%", 1)[0]).is_loopback:
            _verify_connected_gateway_socket(connection.sock, peer_host, port)
        elif endpoint.scheme != "https":
            raise OSError("Fleet API plaintext endpoint is not local")
        headers = {"X-DefenseClaw-Client": "true"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        if body:
            headers["Content-Type"] = "application/json"
        connection.request(method, endpoint.path or "/", body=body or None, headers=headers)
        response = connection.getresponse()
        raw = response.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise ValueError("Fleet API response is too large")
        return response.status, raw.decode("utf-8")
    finally:
        connection.close()


def _find_edge_connector_source(source_dir: Path | None = None) -> Path | None:
    """Locate Edge sources from a checkout or an explicit Fleet asset directory."""
    cli_pkg = Path(__file__).resolve().parent.parent
    candidates = []
    if source_dir is not None:
        candidates.append(source_dir / "edge-connector")
        candidates.append(source_dir)
    # Editable source checkout: its CLI package must be directly below cli/.
    if source_dir is None and cli_pkg.parent.name == "cli" and (cli_pkg.parent.parent / "pyproject.toml").is_file():
        candidates.append(cli_pkg.parent.parent / "edge-connector")
    for candidate in candidates:
        if (
            (candidate / "CMakeLists.txt").is_file()
            and (candidate / "src" / "main.c").is_file()
            and not candidate.is_symlink()
        ):
            return candidate
    return None


def _run(cmd: list[str], *, check: bool = True, timeout: int = 300, **kwargs) -> subprocess.CompletedProcess:
    """Run a command, echoing it first for transparency."""
    ux.echo(f"  $ {' '.join(cmd)}")
    return subprocess.run(cmd, check=check, timeout=timeout, **kwargs)


def _validate_ssh_identifier(value: str, label: str) -> str:
    """Reject SSH target/user values that contain shell metacharacters.

    SSH destinations and usernames should be simple alphanumeric strings
    (plus dots, hyphens, underscores for hostnames). Anything else risks
    injection when embedded in shell commands or rsync/scp arguments.
    """
    import re
    if not re.fullmatch(r'[a-zA-Z0-9_][a-zA-Z0-9._-]*', value):
        raise click.ClickException(
            f"Invalid {label}: {value!r} — only alphanumeric, dot, hyphen, "
            f"and underscore characters are allowed."
        )
    return value


def _ssh_cmd(target: str, user: str, remote_cmd: str) -> list[str]:
    """Build an SSH command list with common options.

    The remote_cmd is passed as a single argument to SSH, which forwards
    it to the remote shell.  Callers MUST use shlex.quote() on any
    user-controlled values interpolated into remote_cmd.
    """
    return [
        "ssh", "-o", "StrictHostKeyChecking=yes",
        "--", f"{user}@{target}", remote_cmd,
    ]


def _run_ssh_output(target: str, user: str, remote_cmd: str) -> str:
    """Run a remote SSH command and return its stdout."""
    cmd = _ssh_cmd(target, user, remote_cmd)
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    if result.returncode != 0:
        raise click.ClickException(f"SSH command failed: {result.stderr.strip()}")
    return result.stdout


def _check_remote_prereqs(target: str, user: str) -> bool:
    """Verify the remote device has gcc, cmake, and make."""
    ux.echo()
    ux.section("Checking remote prerequisites")
    missing = []
    for tool in ("gcc", "cmake", "make"):
        result = subprocess.run(
            _ssh_cmd(target, user, f"which {tool}"),
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode == 0:
            ux.ok(f"{tool} found")
        else:
            ux.err(f"{tool} not found")
            missing.append(tool)

    if missing:
        ux.echo()
        ux.err(
            f"Missing tools on {target}: {', '.join(missing)}\n"
            "  Install them first, e.g.:\n"
            f"    ssh {user}@{target} 'sudo apt install -y build-essential cmake'"
        )
        return False
    return True


def _copy_source(source: Path, target: str, user: str) -> str:
    """Copy the edge-connector source to the remote device. Returns remote path."""
    ux.echo()
    ux.section("Copying edge-connector source to device")
    remote_dir = _run_ssh_output(target, user, "mktemp -d /tmp/defenseclaw-XXXXXXXX").strip()
    if not remote_dir or not remote_dir.startswith("/tmp/defenseclaw-"):
        raise click.ClickException("Failed to create secure temp directory on remote host")

    rsync = shutil.which("rsync")
    if rsync:
        _run([
            "rsync", "-az", "--delete", "-e", "ssh -o StrictHostKeyChecking=yes",
            "--exclude", "build/", "--exclude", "build-*/",
            f"{source}/", f"{user}@{target}:{remote_dir}/",
        ])
    else:
        _run([
            "scp", "-o", "StrictHostKeyChecking=yes", "-r",
            f"{source}/.", f"{user}@{target}:{remote_dir}/",
        ])
    ux.ok(f"Source copied to {target}:{remote_dir}")
    return remote_dir


def _build_remote(target: str, user: str, remote_dir: str, profile: str) -> bool:
    """Run cmake && make && sudo make install on the remote device."""
    ux.echo()
    ux.section("Building on remote device")
    safe_dir = shlex.quote(remote_dir)
    safe_profile = shlex.quote(profile)
    build_script = (
        f"cd {safe_dir} && "
        f"mkdir -p build && cd build && "
        f"cmake .. -DDCLAW_PROFILE={safe_profile} -DDCLAW_DEV_MODE=OFF "
        "-DDCLAW_ALLOW_HMAC_OTA=ON -DDCLAW_BUILD_TESTS=OFF && "
        f"make -j$(nproc) && "
        f"sudo make install"
    )
    result = subprocess.run(
        _ssh_cmd(target, user, build_script),
        text=True, timeout=300,
    )
    if result.returncode != 0:
        ux.err("Remote build failed. Check the output above for details.")
        return False
    ux.ok("Edge connector built and installed on remote device")
    return True


def _load_local_env_value(key: str) -> str:
    """Read a value from ~/.defenseclaw/.env (local operator machine)."""
    env_path = Path(os.environ.get("DEFENSECLAW_HOME", Path.home() / ".defenseclaw")) / ".env"
    if not env_path.is_file():
        return ""
    try:
        for line in env_path.read_text().splitlines():
            s = line.strip()
            for prefix in (f"{key}=", f"export {key}="):
                if s.startswith(prefix):
                    return s.split("=", 1)[1].strip().strip("'\"")
    except OSError:
        pass
    return ""


def _configure_remote_env(
    target: str, user: str,
    tenant_id: str, fleet_id: str, device_id: str, broker_url: str,
    device_key: str = "",
) -> bool:
    """Write device env vars to /etc/defenseclaw/edge-connector.env on the remote.

    Returns True on success, False if the SSH env write failed.
    """
    ux.echo()
    ux.section("Configuring device environment")
    env_lines = (
        f"DCLAW_TENANT_ID={shlex.quote(str(tenant_id))}\n"
        f"DCLAW_FLEET_ID={shlex.quote(str(fleet_id))}\n"
        f"DCLAW_DEVICE_ID={shlex.quote(str(device_id))}\n"
        f"DCLAW_BROKER_URL={shlex.quote(str(broker_url))}\n"
    )

    # Provision device key from registration response (if available)
    if device_key:
        env_lines += f"DCLAW_DEVICE_KEY={shlex.quote(device_key)}\n"

    # Provision MQTT credentials from the operator's local .env
    mqtt_user = _load_local_env_value("DCLAW_MQTT_USER")
    mqtt_pass = _load_local_env_value("DCLAW_MQTT_PASS")
    if mqtt_user:
        env_lines += f"DCLAW_MQTT_USER={shlex.quote(mqtt_user)}\n"
    if mqtt_pass:
        env_lines += f"DCLAW_MQTT_PASS={shlex.quote(mqtt_pass)}\n"

    # The gateway and device must share the OTA/emergency keys. Generate each
    # once on the operator machine and retain it for gateway provisioning.
    from defenseclaw.commands.cmd_setup_edge_connector import _hmac_key

    cli_env = Path(os.environ.get("DEFENSECLAW_HOME", Path.home() / ".defenseclaw")) / ".env"
    try:
        audit_key = _hmac_key(cli_env, "DCLAW_AUDIT_KEY")
        ota_key = _hmac_key(cli_env, "DCLAW_OTA_HMAC_KEY")
        emergency_key = _hmac_key(cli_env, "DCLAW_EMERGENCY_KEY")
        for name, value in (
            ("DCLAW_AUDIT_KEY", audit_key),
            ("DCLAW_OTA_HMAC_KEY", ota_key),
            ("DCLAW_EMERGENCY_KEY", emergency_key),
        ):
            _persist_env_var(cli_env, name, value)
            env_lines += f"{name}={shlex.quote(value)}\n"
    except (OSError, ValueError) as exc:
        ux.err(f"Could not save Edge keys locally: {exc}")
        return False

    # SSH command arguments are visible in process listings and often logged.
    # Stream credentials on stdin and replace the existing file only after a
    # complete write, with the temporary file private from creation onward.
    install_script = (
        "umask 077; "
        "tmp=$(mktemp /etc/defenseclaw/.edge-connector.env.XXXXXXXX) || exit 1; "
        "trap 'rm -f \"$tmp\"' EXIT; "
        "cat > \"$tmp\" && chmod 600 \"$tmp\" && "
        "mv -f \"$tmp\" /etc/defenseclaw/edge-connector.env && "
        "trap - EXIT"
    )
    configure_cmd = (
        "sudo mkdir -p /etc/defenseclaw && sudo sh -c "
        + shlex.quote(install_script)
    )
    result = subprocess.run(
        _ssh_cmd(target, user, configure_cmd),
        input=env_lines, text=True, timeout=60,
    )
    if result.returncode == 0:
        ux.ok("Device environment configured at /etc/defenseclaw/edge-connector.env")
        if not mqtt_user:
            ux.warn("DCLAW_MQTT_USER not found in ~/.defenseclaw/.env -- configure manually on the device.")
        return True
    else:
        ux.err("Failed to write env file on remote device. The device cannot start without it.")
        return False


def _find_service_file(source: Path) -> Path | None:
    """Locate the systemd unit file relative to the edge-connector source."""
    candidate = source / "packaging" / "edge-connector.service"
    return candidate if candidate.is_file() else None


def _ensure_local_service_account() -> bool:
    """Create the identity required by the shipped unit on a fresh Linux host."""
    try:
        group = subprocess.run(["getent", "group", "defenseclaw"], capture_output=True, timeout=10)
        if group.returncode != 0:
            _run(["sudo", "groupadd", "--system", "defenseclaw"])
        account = subprocess.run(["id", "-u", "defenseclaw"], capture_output=True, timeout=10)
        if account.returncode != 0:
            _run([
                "sudo", "useradd", "--system", "--gid", "defenseclaw",
                "--home-dir", "/var/lib/defenseclaw", "--shell", "/usr/sbin/nologin", "defenseclaw",
            ])
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        ux.err(f"Could not provision defenseclaw service account: {exc}")
        return False
    return True


def _ensure_remote_service_account(target: str, user: str) -> bool:
    """Provision the unit identity on the device before enabling its service."""
    script = (
        "set -e; "
        "getent group defenseclaw >/dev/null || sudo groupadd --system defenseclaw; "
        "id -u defenseclaw >/dev/null 2>&1 || "
        "sudo useradd --system --gid defenseclaw --home-dir /var/lib/defenseclaw "
        "--shell /usr/sbin/nologin defenseclaw"
    )
    try:
        result = subprocess.run(_ssh_cmd(target, user, script), text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as exc:
        ux.err(f"Could not provision defenseclaw service account on {target}: {exc}")
        return False
    if result.returncode != 0:
        ux.err(f"Could not provision defenseclaw service account on {target}")
        return False
    return True


def _install_systemd_unit(source: Path, target: str, user: str) -> bool:
    """Install the systemd unit file and enable/start the service on the remote device."""
    service_file = _find_service_file(source)
    if service_file is None:
        ux.warn("Systemd unit file not found; skipping service installation.")
        return False

    ux.echo()
    ux.section("Installing systemd service")

    if not _ensure_remote_service_account(target, user):
        return False

    # Copy the unit file to the remote device
    remote_unit = "/etc/systemd/system/edge-connector.service"
    result = subprocess.run(
        ["scp", "-o", "StrictHostKeyChecking=yes",
         str(service_file), f"{user}@{target}:/tmp/edge-connector.service"],
        capture_output=True, text=True, timeout=60,
    )
    if result.returncode != 0:
        ux.err(f"Failed to copy unit file: {result.stderr.strip()}")
        return False

    install_cmd = (
        f"sudo mv /tmp/edge-connector.service {remote_unit} && "
        f"sudo chmod 644 {remote_unit} && "
        "sudo systemctl daemon-reload && "
        "sudo systemctl enable edge-connector && "
        "sudo systemctl start edge-connector"
    )
    result = subprocess.run(
        _ssh_cmd(target, user, install_cmd),
        text=True, timeout=60,
    )
    if result.returncode != 0:
        ux.err("Failed to install/start systemd service. Check the output above.")
        return False

    ux.ok("edge-connector.service installed, enabled, and started")
    return True


def _install_local_systemd_unit(source: Path) -> bool:
    """Install the systemd unit file and enable/start the service locally."""
    import platform
    if platform.system() != "Linux":
        ux.warn(f"Systemd is not available on {platform.system()}; skipping service installation.")
        return False

    service_file = _find_service_file(source)
    if service_file is None:
        ux.warn("Systemd unit file not found; skipping service installation.")
        return False

    ux.echo()
    ux.section("Installing systemd service (local)")
    if not _ensure_local_service_account():
        return False
    target_path = Path("/etc/systemd/system/edge-connector.service")
    try:
        _run(["sudo", "cp", str(service_file), str(target_path)])
        _run(["sudo", "chmod", "644", str(target_path)])
        _run(["sudo", "systemctl", "daemon-reload"])
        _run(["sudo", "systemctl", "enable", "edge-connector"])
        _run(["sudo", "systemctl", "start", "edge-connector"])
    except subprocess.CalledProcessError:
        ux.err("Failed to install/start systemd service locally.")
        return False
    ux.ok("edge-connector.service installed, enabled, and started")
    return True


def _register_device_via_api(
    tenant_id: str, fleet_id: str, device_id: str,
) -> str:
    """Register the device with the fleet API and return the device key hex string.

    The remote install must obtain a device key by calling the registration
    endpoint. Without this, the device cannot authenticate heartbeats or
    receive signed verdict responses.

    Returns the hex-encoded device key on success, or "" on failure.
    """
    import json as _json

    ux.echo()
    ux.section("Registering device with fleet manager")

    # The fleet API base URL comes from the operator's local env, falling back
    # to the local .env file, or defaults to the gateway on port 18970 (consistent
    # with _DEFAULT_FLEET_ENDPOINT in cmd_setup_edge_connector.py).
    api_base = (
        os.environ.get("DCLAW_FLEET_API_URL")
        or _load_local_env_value("DCLAW_FLEET_API_URL")
        or "http://127.0.0.1:18970/api/v1/fleet"
    )
    from defenseclaw.commands.cmd_setup_edge_connector import _validate_fleet_endpoint

    api_base = _validate_fleet_endpoint(api_base)
    api_token = _load_local_env_value("DCLAW_FLEET_API_TOKEN") or os.environ.get("DCLAW_FLEET_API_TOKEN", "")

    body = _json.dumps({
        "tenant_id": int(tenant_id),
        "fleet_id": int(fleet_id),
        "device_id": int(device_id),
    })
    from defenseclaw.gateway import GatewayListenerNotOwnedError

    try:
        http_status, resp_body = _fleet_api_request(api_base, "POST", "/devices", api_token, body)
    except (GatewayListenerNotOwnedError, OSError, http.client.HTTPException, ValueError, UnicodeError):
        ux.warn("Device registration API call failed or the local Fleet listener is unverified. "
                "Register the device manually via: defenseclaw edge-connector register")
        return ""
    if not 200 <= http_status < 300:
        ux.warn(f"Device registration API returned HTTP {http_status}. Register the device manually.")
        return ""

    try:
        resp = _json.loads(resp_body)
    except (_json.JSONDecodeError, ValueError):
        ux.warn("Could not parse registration response. Register the device manually.")
        return ""

    if not isinstance(resp, dict):
        ux.warn("Invalid registration response. Register the device manually.")
        return ""
    device_key = resp.get("device_key", "")

    # Handle duplicate registration (HTTP 200 vs 201)
    if http_status == 200 and not device_key:
        ux.warn("Device already registered (HTTP 200). The device key is only "
                "returned on first registration.")
        # Attempt to re-fetch the device record to check if a key is available
        try:
            get_status, get_body = _fleet_api_request(api_base, "GET", f"/devices/{device_id}", api_token)
        except (GatewayListenerNotOwnedError, OSError, http.client.HTTPException, ValueError, UnicodeError):
            get_status, get_body = 0, ""
        if 200 <= get_status < 300:
            try:
                existing = _json.loads(get_body)
                device_key = existing.get("device_key", "") if isinstance(existing, dict) else ""
                if device_key:
                    ux.ok(f"Retrieved existing device key ({len(device_key)} hex chars)")
                else:
                    ux.err("No device key available. The key was only shown on "
                           "first registration and cannot be recovered.\n"
                           "  Re-register with a new device ID, or provision "
                           "the key manually.")
            except (_json.JSONDecodeError, ValueError):
                ux.err("Could not parse device lookup response. "
                       "Provision the device key manually.")
        else:
            ux.err("Could not fetch existing device record. "
                   "Provision the device key manually.")
        return device_key

    if device_key:
        ux.ok(f"Device registered, key obtained ({len(device_key)} hex chars)")
    else:
        ux.warn("Device registered but no device_key returned "
                "(key store may not be configured).")
    return device_key


def _verify_remote_daemon(target: str, user: str) -> bool:
    """After starting the daemon, verify it's actually running.

    Checks the systemd service status, then tries the IPC socket as a
    secondary signal. Returns True if the daemon appears healthy.
    """
    ux.echo()
    ux.section("Verifying daemon health")

    # Check systemd service status
    result = subprocess.run(
        _ssh_cmd(target, user, "systemctl is-active edge-connector 2>/dev/null || "
                               "pgrep -x edge-connector >/dev/null 2>&1 && echo active || echo inactive"),
        capture_output=True, text=True, timeout=30,
    )
    status = result.stdout.strip()
    if status == "active":
        ux.ok("edge-connector daemon is running")
        return True

    ux.warn("edge-connector daemon does not appear to be running. "
            "Check logs with: ssh {user}@{target} 'journalctl -u edge-connector -n 20'")
    return False


def _start_remote_daemon(source: Path, target: str, user: str) -> bool:
    """Install the systemd unit and start the service on the remote device.

    Falls back to printing manual instructions if the unit file is missing
    or the install fails.

    Returns True if the daemon was started and verified, False otherwise.
    """
    if _install_systemd_unit(source, target, user):
        if _verify_remote_daemon(target, user):
            return True
        ux.err(
            f"Daemon failed to start on {target}. Check logs with:\n"
            f"  ssh {user}@{target} 'journalctl -u edge-connector -n 40'"
        )
        return False

    ux.echo()
    ux.section("Starting edge-connector daemon")
    ux.err("Could not install systemd service on the remote device.")
    ux.echo("  Start the daemon manually on the device:")
    ux.echo(f"    ssh {user}@{target} 'sudo edge-connector &'")
    ux.echo()
    ux.echo("  Or to run in the foreground for debugging:")
    ux.echo(f"    ssh {user}@{target} 'sudo edge-connector'")
    return False


def _provision_local_service_env(broker_url: str) -> bool:
    """Provision required independent secrets for the local C service."""
    from defenseclaw.commands.cmd_setup_edge_connector import _hmac_key, _persist_svc_env_var

    cli_env = Path(os.environ.get("DEFENSECLAW_HOME", Path.home() / ".defenseclaw")) / ".env"
    svc_env = Path("/etc/defenseclaw/edge-connector.env")
    ux.echo()
    ux.section("Provisioning service environment")
    if "\n" in broker_url or "\r" in broker_url:
        raise click.ClickException("Broker URL must be a single line")
    values = {
        "DCLAW_AUDIT_KEY": _hmac_key(cli_env, "DCLAW_AUDIT_KEY"),
        "DCLAW_OTA_HMAC_KEY": _hmac_key(cli_env, "DCLAW_OTA_HMAC_KEY"),
        "DCLAW_EMERGENCY_KEY": _hmac_key(cli_env, "DCLAW_EMERGENCY_KEY"),
        "DCLAW_BROKER_URL": broker_url,
    }
    for key in ("DCLAW_MQTT_USER", "DCLAW_MQTT_PASS"):
        value = _load_local_env_value(key)
        if value:
            values[key] = value
    try:
        for key, value in values.items():
            _persist_env_var(cli_env, key, value)
            if not _persist_svc_env_var(svc_env, key, value):
                ux.err(f"Failed to provision {key} in {svc_env}; service cannot start securely")
                return False
    except (OSError, ValueError) as exc:
        raise click.ClickException(f"Could not provision Edge service environment: {exc}") from exc
    ux.ok(f"Required Edge keys provisioned in {cli_env} and {svc_env}")
    return True


def _verify_local_service() -> bool:
    """After starting the local systemd service, verify it is running."""
    import time as _time
    _time.sleep(1)  # give systemd a moment to start the process
    result = subprocess.run(
        ["systemctl", "is-active", "edge-connector"],
        capture_output=True, text=True, timeout=30,
    )
    if result.stdout.strip() == "active":
        ux.ok("edge-connector.service is running")
        return True
    return False


def _build_local(source: Path, profile: str) -> bool:
    """Build the edge connector locally with cmake."""
    ux.echo()
    ux.section("Building edge-connector locally")
    try:
        # Wheel package directories may be read-only. Keep build outputs in a
        # private temporary directory, separate from shipped C sources.
        with tempfile.TemporaryDirectory(prefix="dclaw-edge-build-") as build_dir:
            _run(
                ["cmake", "-S", str(source), "-B", build_dir,
                 f"-DDCLAW_PROFILE={profile}", "-DDCLAW_DEV_MODE=OFF",
                 "-DDCLAW_ALLOW_HMAC_OTA=ON", "-DDCLAW_BUILD_TESTS=OFF"],
            )
            _run(["cmake", "--build", build_dir, "--parallel", str(os.cpu_count() or 1)])
            _run(["sudo", "cmake", "--install", build_dir])
    except subprocess.CalledProcessError:
        ux.err("Local build failed. Check the output above for details.")
        return False
    ux.ok("Edge connector installed at /usr/local/lib/libdclaw_core.so")
    return True


@click.command("install")
@click.option("--target", default=None, help="IP or hostname of the remote device (SSH).")
@click.option("--source-dir", type=click.Path(path_type=Path, exists=True, file_okay=False), default=None,
              help=("Extract defenseclaw-fleet-assets.tar.gz and pass its directory, "
                    "or use a source checkout (required for wheel installs)."))
@click.option("--user", default="root", help="SSH user for the remote device.")
@click.option(
    "--profile", default="STANDARD",
    type=click.Choice(["MINIMAL", "STANDARD", "EDGE"], case_sensitive=False),
    help="Build profile (maps to cmake DCLAW_PROFILE).",
)
@click.option("--tenant-id", default="1", help="Tenant ID for device registration.")
@click.option("--fleet-id", default="1", help="Fleet ID for device registration.")
@click.option("--device-id", default=None, help="Device ID (auto-generated if omitted).")
@click.option(
    "--broker-url", default="mqtts://localhost:8883",
    help="MQTT broker URL for the device (use mqtts:// for production).",
)
@pass_ctx
def edge_install(
    app,
    target: str | None,
    source_dir: Path | None,
    user: str,
    profile: str,
    tenant_id: str,
    fleet_id: str,
    device_id: str | None,
    broker_url: str,
) -> None:
    """Build and install the edge-connector engine locally or on a remote device.

    Without ``--target``, builds and installs locally using cmake/make.
    With ``--target <ip>``, copies the source to the device via SSH,
    builds remotely, configures env vars, and starts the daemon.
    """
    source = _find_edge_connector_source(source_dir) if source_dir is not None else _find_edge_connector_source()
    if source is None:
        ux.err(
            "Could not locate edge-connector/ source directory.\n"
            "  Pass --source-dir with extracted defenseclaw-fleet-assets.tar.gz, or run from\n"
            "  a complete DefenseClaw source checkout."
        )
        raise SystemExit(1)

    ux.section("Edge Connector Installer")
    ux.echo(f"  Source: {source}")
    ux.echo(f"  Profile: {profile}")

    if target:
        # --- Remote install via SSH ---
        _validate_ssh_identifier(target, "target")
        _validate_ssh_identifier(user, "user")
        ux.echo(f"  Target: {user}@{target}")

        if not _check_remote_prereqs(target, user):
            raise SystemExit(1)

        remote_dir = _copy_source(source, target, user)

        if not _build_remote(target, user, remote_dir, profile):
            raise SystemExit(1)

        if device_id is None:
            import uuid
            device_id = str(uuid.uuid4().int & 0xFFFFFFFF)  # 32-bit

        try:
            _device_id_int = int(device_id)
        except (ValueError, TypeError):
            raise click.ClickException(f"Invalid device_id: {device_id!r} — must be a numeric value")
        if _device_id_int < 0 or _device_id_int >= (1 << 32):
            raise click.ClickException(
                f"device_id {_device_id_int} out of range — must be 0 to {(1 << 32) - 1}"
            )

        device_key = _register_device_via_api(tenant_id, fleet_id, device_id)

        if not device_key:
            ux.echo()
            ux.section("Install failed")
            ux.err(
                "Device registration did not return a device key. "
                "The device is unprovisioned and cannot authenticate "
                "heartbeats or receive signed verdicts.\n"
                "  Possible causes:\n"
                "    - Device was previously registered (key only shown once)\n"
                "    - Fleet API key store is not configured\n"
                "    - Fleet API is unreachable\n"
                "  To fix:\n"
                "    - Re-register with a new device ID, or\n"
                "    - Provision the key manually via DCLAW_DEVICE_KEY"
            )
            raise SystemExit(1)

        env_ok = _configure_remote_env(target, user, tenant_id, fleet_id, device_id, broker_url,
                                       device_key=device_key)
        if not env_ok:
            ux.echo()
            ux.section("Install failed")
            ux.err(
                f"Could not write environment file on {target}.\n"
                "  The device cannot start without /etc/defenseclaw/edge-connector.env.\n"
                "  Fix SSH connectivity and re-run, or write the file manually."
            )
            raise SystemExit(1)

        daemon_ok = _start_remote_daemon(source, target, user)

        ux.echo()
        if daemon_ok:
            ux.section("Done")
            ux.ok(f"Edge connector installed on {target}")
            ux.echo(f"  Device ID: {device_id}")
            ux.echo(f"  Broker:    {broker_url}")
            ux.echo()
            ux.echo("  Verify with: defenseclaw edge-connector test")
        else:
            ux.section("Install incomplete")
            ux.err(f"Edge connector was built on {target} but the daemon "
                   "failed to start.")
            ux.echo(f"  Device ID: {device_id}")
            ux.echo(f"  Broker:    {broker_url}")
            ux.echo()
            ux.echo("  Fix the issue and start manually, or re-run this command.")
            raise SystemExit(1)
    else:
        # --- Local install ---
        for tool in ("cmake", "make"):
            if shutil.which(tool) is None:
                ux.err(
                    f"'{tool}' is not installed.\n"
                    "  On macOS:  brew install cmake\n"
                    "  On Ubuntu: sudo apt install build-essential cmake"
                )
                raise SystemExit(1)

        if not _build_local(source, profile):
            raise SystemExit(1)

        if not _provision_local_service_env(broker_url):
            raise SystemExit(1)

        # Try to install the systemd service locally
        svc_ok = _install_local_systemd_unit(source)

        if svc_ok:
            if not _verify_local_service():
                ux.err(
                    "edge-connector.service was installed but failed to start.\n"
                    "  Check logs: journalctl -u edge-connector -n 40"
                )
                raise SystemExit(1)
            ux.echo()
            ux.section("Done")
            ux.echo("  Edge connector installed at /usr/local/lib/libdclaw_core.so")
            ux.echo("  Service is running.")
            ux.echo("  Next: run 'defenseclaw setup mqtt-broker' to set up the MQTT broker.")
        else:
            ux.echo()
            ux.err(
                "Systemd service installation failed. The edge-connector binary\n"
                "  was built and installed, but the service is NOT running.\n"
                "  Start it manually or fix the systemd issue and re-run install."
            )
            raise SystemExit(1)
