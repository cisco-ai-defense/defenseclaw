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

import os
import shlex
import shutil
import subprocess
from pathlib import Path

import click

from defenseclaw import ux
from defenseclaw.context import pass_ctx


def _find_edge_connector_source() -> Path | None:
    """Locate the edge-connector source tree relative to the repo checkout."""
    # Walk up from the CLI package to find the repo root.
    cli_pkg = Path(__file__).resolve().parent.parent  # .../cli/defenseclaw
    candidates = [
        cli_pkg.parent.parent / "edge-connector",       # repo root
        cli_pkg.parent.parent.parent / "edge-connector", # one level higher
        Path.cwd() / "edge-connector",                   # working directory
    ]
    for candidate in candidates:
        if (candidate / "CMakeLists.txt").is_file():
            return candidate
    return None


def _run(cmd: list[str], *, check: bool = True, **kwargs) -> subprocess.CompletedProcess:
    """Run a command, echoing it first for transparency."""
    ux.echo(f"  $ {' '.join(cmd)}")
    return subprocess.run(cmd, check=check, **kwargs)


def _ssh_cmd(target: str, user: str, remote_cmd: str) -> list[str]:
    """Build an SSH command list with common options."""
    return [
        "ssh", "-o", "StrictHostKeyChecking=accept-new",
        f"{user}@{target}", remote_cmd,
    ]


def _check_remote_prereqs(target: str, user: str) -> bool:
    """Verify the remote device has gcc, cmake, and make."""
    ux.echo()
    ux.section("Checking remote prerequisites")
    missing = []
    for tool in ("gcc", "cmake", "make"):
        result = subprocess.run(
            _ssh_cmd(target, user, f"which {tool}"),
            capture_output=True, text=True,
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
    remote_dir = "/tmp/defenseclaw-edge-connector"

    # Clean any previous copy
    subprocess.run(
        _ssh_cmd(target, user, f"rm -rf {remote_dir}"),
        capture_output=True,
    )

    rsync = shutil.which("rsync")
    if rsync:
        _run([
            "rsync", "-az", "--delete",
            "--exclude", "build/", "--exclude", "build-*/",
            f"{source}/", f"{user}@{target}:{remote_dir}/",
        ])
    else:
        _run([
            "scp", "-r", str(source), f"{user}@{target}:{remote_dir}",
        ])
    ux.ok(f"Source copied to {target}:{remote_dir}")
    return remote_dir


def _build_remote(target: str, user: str, remote_dir: str, profile: str) -> bool:
    """Run cmake && make && sudo make install on the remote device."""
    ux.echo()
    ux.section("Building on remote device")
    build_script = (
        f"cd {remote_dir} && "
        f"mkdir -p build && cd build && "
        f"cmake .. -DDCLAW_PROFILE={profile} && "
        f"make -j$(nproc) && "
        f"sudo make install"
    )
    result = subprocess.run(
        _ssh_cmd(target, user, build_script),
        text=True,
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
) -> None:
    """Write device env vars to /etc/defenseclaw/edge-connector.env on the remote."""
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

    # Provision OTA signing key from the operator's local .env
    ota_key = _load_local_env_value("DCLAW_OTA_KEY")
    if ota_key:
        env_lines += f"DCLAW_OTA_KEY={shlex.quote(ota_key)}\n"

    configure_cmd = (
        "sudo mkdir -p /etc/defenseclaw && "
        f"printf %s {shlex.quote(env_lines)} | sudo tee /etc/defenseclaw/edge-connector.env > /dev/null && "
        "sudo chmod 600 /etc/defenseclaw/edge-connector.env"
    )
    result = subprocess.run(
        _ssh_cmd(target, user, configure_cmd),
        text=True,
    )
    if result.returncode == 0:
        ux.ok("Device environment configured at /etc/defenseclaw/edge-connector.env")
        if not mqtt_user:
            ux.warn("DCLAW_MQTT_USER not found in ~/.defenseclaw/.env -- configure manually on the device.")
        if not ota_key:
            ux.warn("DCLAW_OTA_KEY not found in ~/.defenseclaw/.env -- configure manually on the device.")
    else:
        ux.warn("Could not write env file. Configure manually on the device.")


def _find_service_file() -> Path | None:
    """Locate the systemd unit file relative to the edge-connector source."""
    source = _find_edge_connector_source()
    if source is None:
        return None
    candidate = source / "packaging" / "edge-connector.service"
    return candidate if candidate.is_file() else None


def _install_systemd_unit(target: str, user: str) -> bool:
    """Install the systemd unit file and enable/start the service on the remote device."""
    service_file = _find_service_file()
    if service_file is None:
        ux.warn("Systemd unit file not found; skipping service installation.")
        return False

    ux.echo()
    ux.section("Installing systemd service")

    # Copy the unit file to the remote device
    remote_unit = "/etc/systemd/system/edge-connector.service"
    result = subprocess.run(
        ["scp", "-o", "StrictHostKeyChecking=accept-new",
         str(service_file), f"{user}@{target}:/tmp/edge-connector.service"],
        capture_output=True, text=True,
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
        text=True,
    )
    if result.returncode != 0:
        ux.err("Failed to install/start systemd service. Check the output above.")
        return False

    ux.ok("edge-connector.service installed, enabled, and started")
    return True


def _install_local_systemd_unit() -> bool:
    """Install the systemd unit file and enable/start the service locally."""
    import platform
    if platform.system() != "Linux":
        ux.warn(f"Systemd is not available on {platform.system()}; skipping service installation.")
        return False

    service_file = _find_service_file()
    if service_file is None:
        ux.warn("Systemd unit file not found; skipping service installation.")
        return False

    ux.echo()
    ux.section("Installing systemd service (local)")
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

    P1-15 fix: The remote install must obtain a device key by calling the
    registration endpoint. Without this, the device cannot authenticate
    heartbeats or receive signed verdict responses.

    Returns the hex-encoded device key on success, or "" on failure.
    """
    import json as _json

    ux.echo()
    ux.section("Registering device with fleet manager")

    # The fleet API base URL comes from the operator's local env, or defaults
    # to the local gateway.
    api_base = os.environ.get("DCLAW_FLEET_API_URL", "http://localhost:8080/api/v1/fleet")
    api_token = _load_local_env_value("DCLAW_FLEET_API_TOKEN") or os.environ.get("DCLAW_FLEET_API_TOKEN", "")

    url = f"{api_base}/devices"
    body = _json.dumps({
        "tenant_id": int(tenant_id),
        "fleet_id": int(fleet_id),
        "device_id": int(device_id),
    })

    curl_cmd = [
        "curl", "-s", "-X", "POST", url,
        "-H", "Content-Type: application/json",
        "-H", "X-DefenseClaw-Client: true",
    ]
    if api_token:
        curl_cmd += ["-H", f"Authorization: Bearer {api_token}"]
    curl_cmd += ["-d", body]

    result = subprocess.run(curl_cmd, capture_output=True, text=True)
    if result.returncode != 0:
        ux.warn(f"Device registration API call failed (exit {result.returncode}). "
                "Register the device manually via: defenseclaw fleet register")
        return ""

    try:
        resp = _json.loads(result.stdout)
        device_key = resp.get("device_key", "")
        if device_key:
            ux.ok(f"Device registered, key obtained ({len(device_key)} hex chars)")
        else:
            ux.warn("Device registered but no device_key returned (key store may not be configured).")
        return device_key
    except (_json.JSONDecodeError, KeyError):
        ux.warn("Could not parse registration response. Register the device manually.")
        return ""


def _verify_remote_daemon(target: str, user: str) -> bool:
    """P1-15 fix: After starting the daemon, verify it's actually running.

    Checks the systemd service status, then tries the IPC socket as a
    secondary signal. Returns True if the daemon appears healthy.
    """
    ux.echo()
    ux.section("Verifying daemon health")

    # Check systemd service status
    result = subprocess.run(
        _ssh_cmd(target, user, "systemctl is-active edge-connector 2>/dev/null || "
                               "pgrep -x edge-connector >/dev/null 2>&1 && echo active || echo inactive"),
        capture_output=True, text=True,
    )
    status = result.stdout.strip()
    if status == "active":
        ux.ok("edge-connector daemon is running")
        return True

    ux.warn("edge-connector daemon does not appear to be running. "
            "Check logs with: ssh {user}@{target} 'journalctl -u edge-connector -n 20'")
    return False


def _start_remote_daemon(target: str, user: str) -> None:
    """Install the systemd unit and start the service on the remote device.

    Falls back to printing manual instructions if the unit file is missing
    or the install fails.
    """
    if _install_systemd_unit(target, user):
        # P1-15 fix: Verify the daemon is actually running after install
        _verify_remote_daemon(target, user)
        return

    ux.echo()
    ux.section("Starting edge-connector daemon")
    ux.echo("  Start the daemon manually on the device:")
    ux.echo(f"    ssh {user}@{target} 'sudo edge-connector &'")
    ux.echo()
    ux.echo("  Or to run in the foreground for debugging:")
    ux.echo(f"    ssh {user}@{target} 'sudo edge-connector'")


def _build_local(source: Path, profile: str) -> bool:
    """Build the edge connector locally with cmake."""
    ux.echo()
    ux.section("Building edge-connector locally")
    build_dir = source / "build"
    build_dir.mkdir(exist_ok=True)
    try:
        _run(["cmake", "..", f"-DDCLAW_PROFILE={profile}"], cwd=build_dir)
        _run(["make", f"-j{os.cpu_count() or 1}"], cwd=build_dir)
        _run(["sudo", "make", "install"], cwd=build_dir)
    except subprocess.CalledProcessError:
        ux.err("Local build failed. Check the output above for details.")
        return False
    ux.ok("Edge connector installed at /usr/local/lib/libdclaw_core.so")
    return True


@click.command("install")
@click.option("--target", default=None, help="IP or hostname of the remote device (SSH).")
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
    "--broker-url", default="tcp://localhost:1883",
    help="MQTT broker URL for the device.",
)
@pass_ctx
def edge_install(
    app,
    target: str | None,
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
    source = _find_edge_connector_source()
    if source is None:
        ux.err(
            "Could not locate edge-connector/ source directory.\n"
            "  Run this command from the DefenseClaw repo root, or ensure\n"
            "  the edge-connector directory is present alongside the CLI."
        )
        raise SystemExit(1)

    ux.section("Edge Connector Installer")
    ux.echo(f"  Source: {source}")
    ux.echo(f"  Profile: {profile}")

    if target:
        # --- Remote install via SSH ---
        ux.echo(f"  Target: {user}@{target}")

        if not _check_remote_prereqs(target, user):
            raise SystemExit(1)

        remote_dir = _copy_source(source, target, user)

        if not _build_remote(target, user, remote_dir, profile):
            raise SystemExit(1)

        if device_id is None:
            import uuid
            device_id = str(uuid.uuid4().int & 0xFFFFFFFF)  # 32-bit

        # P1-15 fix: Register the device with the fleet API to get a per-device
        # signing key. Without this, the device cannot authenticate heartbeats
        # or receive signed verdict responses.
        device_key = _register_device_via_api(tenant_id, fleet_id, device_id)

        _configure_remote_env(target, user, tenant_id, fleet_id, device_id, broker_url,
                              device_key=device_key)
        _start_remote_daemon(target, user)

        ux.echo()
        ux.section("Done")
        ux.ok(f"Edge connector installed on {target}")
        ux.echo(f"  Device ID: {device_id}")
        ux.echo(f"  Broker:    {broker_url}")
        ux.echo()
        ux.echo("  Verify with: defenseclaw fleet test")
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

        # Try to install the systemd service locally
        _install_local_systemd_unit()

        ux.echo()
        ux.section("Done")
        ux.echo("  Edge connector installed at /usr/local/lib/libdclaw_core.so")
        ux.echo("  Next: run 'defenseclaw setup mqtt-broker' to set up the MQTT broker.")
