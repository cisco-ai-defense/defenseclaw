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


def _configure_remote_env(
    target: str, user: str,
    tenant_id: str, fleet_id: str, device_id: str, broker_url: str,
) -> None:
    """Write device env vars to /etc/defenseclaw/edge-connector.env on the remote."""
    ux.echo()
    ux.section("Configuring device environment")
    env_lines = (
        f"DCLAW_TENANT_ID={tenant_id}\\n"
        f"DCLAW_FLEET_ID={fleet_id}\\n"
        f"DCLAW_DEVICE_ID={device_id}\\n"
        f"DCLAW_BROKER_URL={broker_url}\\n"
    )
    configure_cmd = (
        "sudo mkdir -p /etc/defenseclaw && "
        f"echo -e '{env_lines}' | sudo tee /etc/defenseclaw/edge-connector.env > /dev/null && "
        "sudo chmod 600 /etc/defenseclaw/edge-connector.env"
    )
    result = subprocess.run(
        _ssh_cmd(target, user, configure_cmd),
        text=True,
    )
    if result.returncode == 0:
        ux.ok("Device environment configured at /etc/defenseclaw/edge-connector.env")
    else:
        ux.warn("Could not write env file. Configure manually on the device.")


def _start_remote_daemon(target: str, user: str) -> None:
    """Start the edge-connector daemon on the remote device."""
    ux.echo()
    ux.section("Starting edge-connector daemon")
    result = subprocess.run(
        _ssh_cmd(target, user, "sudo systemctl restart dclaw-edge-connector 2>/dev/null || dclaw-edge-connector &"),
        text=True,
    )
    if result.returncode == 0:
        ux.ok("Edge connector daemon started")
    else:
        ux.warn("Could not auto-start daemon. Start it manually on the device.")


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

        _configure_remote_env(target, user, tenant_id, fleet_id, device_id, broker_url)
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

        ux.echo()
        ux.section("Done")
        ux.echo("  Edge connector installed at /usr/local/lib/libdclaw_core.so")
        ux.echo("  Next: run 'defenseclaw setup mqtt-broker' to set up the MQTT broker.")
