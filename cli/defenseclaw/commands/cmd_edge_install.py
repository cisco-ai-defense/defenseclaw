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
import secrets
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
        "ssh", "-o", "StrictHostKeyChecking=yes",
        "--", f"{user}@{target}", remote_cmd,
    ]


def _run_ssh_output(target: str, user: str, remote_cmd: str) -> str:
    """Run a remote SSH command and return its stdout."""
    cmd = _ssh_cmd(target, user, remote_cmd)
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
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
    remote_dir = _run_ssh_output(target, user, "mktemp -d /tmp/defenseclaw-XXXXXXXX").strip()
    if not remote_dir or not remote_dir.startswith("/tmp/defenseclaw-"):
        raise click.ClickException("Failed to create secure temp directory on remote host")

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
    safe_dir = shlex.quote(remote_dir)
    safe_profile = shlex.quote(profile)
    build_script = (
        f"cd {safe_dir} && "
        f"mkdir -p build && cd build && "
        f"cmake .. -DDCLAW_PROFILE={safe_profile} -DDCLAW_DEV_MODE=OFF && "
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

    # Provision OTA signing key from the operator's local .env
    ota_key = _load_local_env_value("DCLAW_OTA_KEY")
    if ota_key:
        env_lines += f"DCLAW_OTA_KEY={shlex.quote(ota_key)}\n"

    # P1-18 fix: Generate a random audit key if none is provided.
    # The audit key is a 32-byte hex-encoded HMAC key used for tamper-evident
    # audit log signing on the device.  Without it the edge-connector falls
    # back to DEV_MODE audit (unsigned), which is disabled in production builds.
    audit_key = _load_local_env_value("DCLAW_AUDIT_KEY")
    if not audit_key:
        audit_key = secrets.token_hex(32)
        ux.echo(f"  Generated random audit key ({len(audit_key)} hex chars)")
    env_lines += f"DCLAW_AUDIT_KEY={shlex.quote(audit_key)}\n"

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
        return True
    else:
        ux.err("Failed to write env file on remote device. The device cannot start without it.")
        return False


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
        ["scp", "-o", "StrictHostKeyChecking=yes",
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

    # The fleet API base URL comes from the operator's local env, falling back
    # to the local .env file, or defaults to the gateway on port 13400 (consistent
    # with _DEFAULT_FLEET_ENDPOINT in cmd_setup_edge_connector.py).
    api_base = (
        os.environ.get("DCLAW_FLEET_API_URL")
        or _load_local_env_value("DCLAW_FLEET_API_URL")
        or "http://localhost:13400/api/v1/fleet"
    )
    api_token = _load_local_env_value("DCLAW_FLEET_API_TOKEN") or os.environ.get("DCLAW_FLEET_API_TOKEN", "")

    url = f"{api_base}/devices"
    body = _json.dumps({
        "tenant_id": int(tenant_id),
        "fleet_id": int(fleet_id),
        "device_id": int(device_id),
    })

    # M-13 fix: Use subprocess.PIPE to pass the Authorization header via stdin
    # instead of embedding the bearer token in command-line arguments, which
    # are visible in `ps` output and /proc/*/cmdline on Linux.
    curl_cmd = [
        "curl", "-s", "-o", "-", "-w", "\n%{http_code}",
        "-X", "POST", url,
        "-H", "Content-Type: application/json",
        "-H", "X-DefenseClaw-Client: true",
    ]
    stdin_data = None
    if api_token:
        curl_cmd += ["-H", "@-"]
        stdin_data = f"Authorization: Bearer {api_token}"
    curl_cmd += ["-d", body]

    result = subprocess.run(curl_cmd, capture_output=True, text=True,
                            input=stdin_data)
    if result.returncode != 0:
        ux.warn(f"Device registration API call failed (exit {result.returncode}). "
                "Register the device manually via: defenseclaw edge-connector register")
        return ""

    # Split response body from HTTP status code (last line)
    output_lines = result.stdout.rsplit("\n", 1)
    resp_body = output_lines[0] if len(output_lines) > 1 else result.stdout
    http_status = output_lines[-1].strip() if len(output_lines) > 1 else ""

    try:
        resp = _json.loads(resp_body)
    except (_json.JSONDecodeError, ValueError):
        ux.warn("Could not parse registration response. Register the device manually.")
        return ""

    device_key = resp.get("device_key", "")

    # Handle duplicate registration (HTTP 200 vs 201)
    if http_status == "200" and not device_key:
        ux.warn("Device already registered (HTTP 200). The device key is only "
                "returned on first registration.")
        # Attempt to re-fetch the device record to check if a key is available
        get_url = f"{api_base}/devices/{device_id}"
        get_cmd = ["curl", "-s", get_url, "-H", "X-DefenseClaw-Client: true"]
        get_stdin = None
        if api_token:
            get_cmd += ["-H", "@-"]
            get_stdin = f"Authorization: Bearer {api_token}"
        get_result = subprocess.run(get_cmd, capture_output=True, text=True,
                                    input=get_stdin)
        if get_result.returncode == 0:
            try:
                existing = _json.loads(get_result.stdout)
                device_key = existing.get("device_key", "")
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


def _start_remote_daemon(target: str, user: str) -> bool:
    """Install the systemd unit and start the service on the remote device.

    Falls back to printing manual instructions if the unit file is missing
    or the install fails.

    Returns True if the daemon was started and verified, False otherwise.
    """
    if _install_systemd_unit(target, user):
        # P1-15 fix: Verify the daemon is actually running after install
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


def _persist_env_var(env_path: Path, key: str, value: str) -> None:
    """Append or update a KEY=VALUE line in a dotenv file."""
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
    except OSError as e:
        import logging
        logging.getLogger(__name__).warning(
            "Failed to set restrictive permissions on %s: %s. "
            "File may be readable by other users.",
            env_path, e,
        )


def _provision_local_service_env(broker_url: str) -> None:
    """P1-15/P1-18 fix: Write DCLAW_AUDIT_KEY (and other vars) to both
    ~/.defenseclaw/.env (for CLI use) and /etc/defenseclaw/edge-connector.env
    (for the systemd service).

    On local install the service env file was never written, so the
    edge-connector built with -DDCLAW_DEV_MODE=OFF would refuse to start
    because DCLAW_AUDIT_KEY was missing from its EnvironmentFile.
    """
    cli_env = Path(os.environ.get("DEFENSECLAW_HOME", Path.home() / ".defenseclaw")) / ".env"
    svc_env = Path("/etc/defenseclaw/edge-connector.env")

    ux.echo()
    ux.section("Provisioning service environment")

    # Generate or reuse audit key
    audit_key = _load_local_env_value("DCLAW_AUDIT_KEY")
    if not audit_key:
        audit_key = secrets.token_hex(32)
        ux.echo(f"  Generated random audit key ({len(audit_key)} hex chars)")
    else:
        ux.echo(f"  Reusing existing audit key ({len(audit_key)} hex chars)")

    # Write to CLI env (~/.defenseclaw/.env)
    _persist_env_var(cli_env, "DCLAW_AUDIT_KEY", audit_key)
    ux.ok(f"Wrote DCLAW_AUDIT_KEY to {cli_env}")

    # Write to service env (/etc/defenseclaw/edge-connector.env) -- needs sudo
    env_lines: list[str] = []

    # Preserve existing lines from the service env if present
    if svc_env.exists():
        try:
            existing = subprocess.run(
                ["sudo", "cat", str(svc_env)],
                capture_output=True, text=True,
            )
            if existing.returncode == 0:
                for line in existing.stdout.splitlines():
                    s = line.strip()
                    # Skip keys we are about to write fresh
                    if any(s.startswith(f"{k}=") for k in (
                        "DCLAW_AUDIT_KEY", "DCLAW_BROKER_URL",
                        "DCLAW_MQTT_USER", "DCLAW_MQTT_PASS",
                    )):
                        continue
                    env_lines.append(line)
        except OSError:
            pass

    env_lines.append(f"DCLAW_AUDIT_KEY={audit_key}")
    env_lines.append(f"DCLAW_BROKER_URL={broker_url}")

    # Also propagate MQTT creds if available
    mqtt_user = _load_local_env_value("DCLAW_MQTT_USER")
    mqtt_pass = _load_local_env_value("DCLAW_MQTT_PASS")
    if mqtt_user:
        env_lines.append(f"DCLAW_MQTT_USER={mqtt_user}")
    if mqtt_pass:
        env_lines.append(f"DCLAW_MQTT_PASS={mqtt_pass}")

    env_content = "\n".join(env_lines) + "\n"
    svc_env_path = Path("/etc/defenseclaw/edge-connector.env")
    try:
        subprocess.run(["sudo", "mkdir", "-p", "/etc/defenseclaw"], check=True)
        subprocess.run(
            ["sudo", "tee", str(svc_env_path)],
            input=env_content.encode(),
            stdout=subprocess.DEVNULL,
            check=True,
        )
        subprocess.run(["sudo", "chmod", "600", str(svc_env_path)], check=True)
        result_ok = True
    except subprocess.CalledProcessError:
        result_ok = False
    if result_ok:
        ux.ok(f"Wrote DCLAW_AUDIT_KEY to {svc_env}")
    else:
        ux.err(f"Failed to write {svc_env}. The service may fail to start without DCLAW_AUDIT_KEY.")


def _verify_local_service() -> bool:
    """P1-15 fix: After starting the local systemd service, verify it is running."""
    import time as _time
    _time.sleep(1)  # give systemd a moment to start the process
    result = subprocess.run(
        ["systemctl", "is-active", "edge-connector"],
        capture_output=True, text=True,
    )
    if result.stdout.strip() == "active":
        ux.ok("edge-connector.service is running")
        return True
    return False


def _build_local(source: Path, profile: str) -> bool:
    """Build the edge connector locally with cmake."""
    ux.echo()
    ux.section("Building edge-connector locally")
    build_dir = source / "build"
    build_dir.mkdir(exist_ok=True)
    try:
        _run(["cmake", "..", f"-DDCLAW_PROFILE={profile}", "-DDCLAW_DEV_MODE=OFF"], cwd=build_dir)
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
    "--broker-url", default="mqtt://localhost:1883",
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

        # P1-15 fix: If registration returned no key, the device is
        # unprovisioned and cannot authenticate. Do NOT continue to the
        # success path — report the error and exit 1 so operators don't
        # mistakenly believe the install succeeded.
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

        daemon_ok = _start_remote_daemon(target, user)

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

        # P1-15 / P1-18 fix: Write audit key to the service env file so the
        # systemd unit can read it.  The edge-connector built with
        # -DDCLAW_DEV_MODE=OFF refuses to start without DCLAW_AUDIT_KEY.
        _provision_local_service_env(broker_url)

        # Try to install the systemd service locally
        svc_ok = _install_local_systemd_unit()

        if svc_ok:
            # P1-15 fix: Verify the service is actually running.
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
            # P1 fix: Do NOT print "Done" when systemd install fails.
            ux.echo()
            ux.err(
                "Systemd service installation failed. The edge-connector binary\n"
                "  was built and installed, but the service is NOT running.\n"
                "  Start it manually or fix the systemd issue and re-run install."
            )
            raise SystemExit(1)
