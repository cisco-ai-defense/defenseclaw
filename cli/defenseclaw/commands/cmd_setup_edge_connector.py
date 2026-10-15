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

"""``defenseclaw setup edge-connector`` -- Wire the Edge Connector fleet API.

Guides the operator through building the edge-connector from source,
setting the fleet API bearer token, registering the fleet API endpoint,
and emitting a sample policy YAML.

Subcommands:
    install   Build and deploy the edge-connector engine locally or via SSH.
"""

from __future__ import annotations

import os
import secrets
import subprocess
from pathlib import Path

import click
import yaml

from defenseclaw import ux
from defenseclaw.config import (
    config_path_for_data_dir,
    locked_config_yaml,
    write_config_yaml_secure,
)
from defenseclaw.context import AppContext
from defenseclaw.dotenv_utils import persist_env_var as _persist_env_var

_TOKEN_ENV = "DCLAW_FLEET_API_TOKEN"
_DEFAULT_FLEET_ENDPOINT = "http://127.0.0.1:13400/api/v1/fleet"


def _existing_env_value(env_path: Path, name: str) -> str:
    value = os.environ.get(name, "").strip()
    if value:
        return value
    if env_path.is_file():
        for line in env_path.read_text().splitlines():
            stripped = line.strip()
            if stripped.startswith(f"{name}=") or stripped.startswith(f"export {name}="):
                return stripped.split("=", 1)[1].strip().strip("'\"")
    return ""


def _hmac_key(env_path: Path, name: str) -> str:
    value = _existing_env_value(env_path, name) or secrets.token_hex(32)
    try:
        key = bytes.fromhex(value)
    except ValueError as exc:
        raise click.ClickException(f"{name} must be a nonzero 32-byte hex key") from exc
    if len(key) != 32 or not any(key):
        raise click.ClickException(f"{name} must be a nonzero 32-byte hex key")
    return value


def _enable_fleet_config(data_dir: str) -> None:
    """Commit Fleet configuration before provisioning credentials or reporting success."""
    cfg_path = str(config_path_for_data_dir(data_dir))
    try:
        with locked_config_yaml(cfg_path):
            raw: dict = {}
            if os.path.exists(cfg_path):
                with open(cfg_path) as stream:
                    raw = yaml.safe_load(stream) or {}
            fleet_sec = raw.setdefault("fleet", {})
            fleet_sec["enabled"] = True
            fleet_sec["api_token_env"] = _TOKEN_ENV
            fleet_sec["ota_key_env"] = "DCLAW_OTA_HMAC_KEY"
            write_config_yaml_secure(cfg_path, raw)
    except Exception as exc:
        raise click.ClickException(f"Could not update config.yaml; Fleet setup is incomplete: {exc}") from exc
    ux.ok(f"Updated fleet section in {cfg_path}")

_SAMPLE_POLICY = """\
# Edge Connector fleet policy -- drop this into your policy directory
# or apply via `defenseclaw policy load`.
apiVersion: defenseclaw.dev/v1
kind: FleetPolicy
metadata:
  name: edge-default
spec:
  heartbeat_interval: 30s
  offline_threshold_multiplier: 3
  verdict_cache:
    max_entries: 4096
    ttl_allow: 24h
    ttl_block: 168h   # 7 days
    ttl_warn: 4h
  alerts:
    - type: device_offline
      severity: warning
    - type: tamper_detect
      severity: critical
    - type: block_spike
      severity: high
      threshold: 50
    - type: policy_drift
      severity: medium
"""


@click.group("edge-connector", invoke_without_command=True)
@click.option(
    "--token",
    default=None,
    help="Bearer token for fleet API auth. Generated if omitted.",
)
@click.option(
    "--endpoint",
    default=None,
    help="Fleet API base URL (default: gateway loopback on port 13400).",
)
@click.option(
    "--emit-policy",
    is_flag=True,
    help="Print a sample fleet policy YAML and exit.",
)
@click.option(
    "--non-interactive",
    is_flag=True,
    help="Skip prompts; use flag values or defaults.",
)
@click.pass_context
def edge_connector(
    ctx: click.Context,
    token: str | None,
    endpoint: str | None,
    emit_policy: bool,
    non_interactive: bool,
) -> None:
    """Configure the Edge Connector fleet management API.

    Walks through building the edge-connector binary, setting the fleet
    API bearer token in ~/.defenseclaw/.env, and registering the endpoint.
    Use ``--emit-policy`` to print a sample fleet policy YAML.

    Subcommands:

        install   Build and deploy the edge-connector engine (local or SSH).
    """
    # If a subcommand was invoked, skip the default setup wizard.
    if ctx.invoked_subcommand is not None:
        return

    ctx.ensure_object(AppContext)

    if emit_policy:
        ux.echo(_SAMPLE_POLICY)
        return

    ux.section("Edge Connector Setup")

    # --- 1. Build instructions -------------------------------------------
    ux.echo()
    ux.echo(
        "Edge Connector Engine (C):\n"
        "\n"
        "  cd edge-connector\n"
        "  mkdir build && cd build\n"
        "  cmake .. -DDCLAW_PROFILE=STANDARD -DDCLAW_DEV_MODE=OFF -DDCLAW_ALLOW_HMAC_OTA=ON\n"
        "  make -j$(nproc)\n"
        "  sudo make install\n"
        "\n"
        "  NOTE: -DDCLAW_DEV_MODE=OFF disables unsigned audit log acceptance.\n"
        "  The edge-connector requires DCLAW_AUDIT_KEY in its environment to\n"
        "  start.  This wizard provisions the key automatically to both\n"
        "  ~/.defenseclaw/.env (CLI) and /etc/defenseclaw/edge-connector.env\n"
        "  (systemd service).  For manual installs, generate a key with:\n"
        "\n"
        "    python3 -c \"import secrets; print(secrets.token_hex(32))\"\n"
        "\n"
        "  and write it to /etc/defenseclaw/edge-connector.env as:\n"
        "\n"
        "    DCLAW_AUDIT_KEY=<hex-key>\n"
        "\n"
        "Gateway (includes fleet manager):\n"
        "\n"
        "  go build -o defenseclaw ./cmd/defenseclaw\n"
    )

    # --- 2. Fleet API token ----------------------------------------------
    env_path = Path(os.environ.get("DEFENSECLAW_HOME", Path.home() / ".defenseclaw")) / ".env"

    if token is None:
        existing = os.environ.get(_TOKEN_ENV, "")
        if existing:
            ux.ok(f"{_TOKEN_ENV} already set in environment.")
            token = existing
        elif not non_interactive:
            generate = click.confirm(
                "Generate a new fleet API bearer token?", default=True
            )
            if generate:
                token = secrets.token_urlsafe(32)
            else:
                token = click.prompt("Enter fleet API token")
        else:
            token = secrets.token_urlsafe(32)

    if not token or "\n" in token or "\r" in token:
        raise click.ClickException("Fleet API token must be a nonempty single line")

    svc_env_path = Path("/etc/defenseclaw/edge-connector.env")
    audit_key = _hmac_key(env_path, "DCLAW_AUDIT_KEY")
    ota_key = _hmac_key(env_path, "DCLAW_OTA_HMAC_KEY")
    emergency_key = _hmac_key(env_path, "DCLAW_EMERGENCY_KEY")
    # A managed host can refuse config writes. Check before persisting any
    # token or key, after validating operator-supplied keys.
    _enable_fleet_config(ctx.obj.cfg.data_dir)
    try:
        for name, value in (
            (_TOKEN_ENV, token),
            ("DCLAW_AUDIT_KEY", audit_key),
            ("DCLAW_OTA_HMAC_KEY", ota_key),
            ("DCLAW_EMERGENCY_KEY", emergency_key),
        ):
            _persist_env_var(env_path, name, value)
            ux.ok(f"Wrote {name} to {env_path}")
        for name, value in (
            ("DCLAW_AUDIT_KEY", audit_key),
            ("DCLAW_OTA_HMAC_KEY", ota_key),
            ("DCLAW_EMERGENCY_KEY", emergency_key),
        ):
            if not _persist_svc_env_var(svc_env_path, name, value):
                raise click.ClickException(
                    f"Could not provision {name} in {svc_env_path}; Edge setup is incomplete"
                )
    except OSError as exc:
        raise click.ClickException(f"Could not persist Fleet credentials; setup is incomplete: {exc}") from exc

    # --- 3. Fleet API endpoint -------------------------------------------
    if endpoint is None:
        endpoint = _DEFAULT_FLEET_ENDPOINT
        if not non_interactive:
            endpoint = click.prompt("Fleet API endpoint", default=endpoint)

    ux.echo()
    ux.ok(f"Fleet API endpoint: {endpoint}")

    # --- 4. Summary ------------------------------------------------------
    ux.echo()
    ux.section("Next Steps")
    ux.echo(
        "  1. Start (or restart) the DefenseClaw gateway -- the fleet API\n"
        f"     is now mounted at {endpoint}\n"
        "  2. Point your edge-connector devices at this endpoint.\n"
        "  3. Verify the fleet is running:\n"
        "\n"
        "       defenseclaw status\n"
        "\n"
        "  4. Optionally apply a fleet policy:\n"
        "\n"
        "       defenseclaw setup edge-connector --emit-policy > fleet-policy.yaml\n"
        "       defenseclaw policy load fleet-policy.yaml\n"
        "\n"
        "  Note: Device registration currently requires the REST API.\n"
        "  Register devices via: defenseclaw edge-connector register <device-id>\n"
        "\n"
        "  Optional environment variables for edge devices:\n"
        "    DCLAW_OTA_HMAC_KEY     — Shared HMAC-SHA256 secret (hex-encoded, 32 bytes)\n"
        "    DCLAW_EMERGENCY_KEY    — Separate emergency-command HMAC secret\n"
        "    DCLAW_BROKER_URL       — MQTT broker URL for cloud escalation\n"
    )

def _persist_svc_env_var(svc_env_path: Path, key: str, value: str) -> bool:
    """Atomically replace the root-owned service env file using sudo."""
    if "\n" in value or "\r" in value:
        raise click.ClickException(f"{key} must be a single line")

    temp_path: str | None = None
    try:
        subprocess.run(["sudo", "install", "-d", "-m", "700", str(svc_env_path.parent)], check=True)
        exists = subprocess.run(
            ["sudo", "sh", "-c", 'if [ -e "$1" ]; then echo yes; else echo no; fi', "sh", str(svc_env_path)],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        if exists not in ("yes", "no"):
            raise OSError("could not determine whether the service env file exists")
        existing_lines: list[str] = []
        if exists == "yes":
            existing_lines = subprocess.run(
                ["sudo", "cat", str(svc_env_path)],
                capture_output=True, text=True, check=True,
            ).stdout.splitlines()

        found = False
        new_lines: list[str] = []
        for line in existing_lines:
            stripped = line.strip()
            if stripped.startswith(f"{key}=") or stripped.startswith(f"export {key}="):
                new_lines.append(f"{key}={value}")
                found = True
            else:
                new_lines.append(line)
        if not found:
            new_lines.append(f"{key}={value}")

        content = "\n".join(new_lines) + "\n"
        temp_path = subprocess.run(
            ["sudo", "mktemp", "-p", str(svc_env_path.parent), ".edge-connector.env.XXXXXXXX"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        if Path(temp_path).parent != svc_env_path.parent:
            raise OSError("unexpected service env staging path")
        subprocess.run(
            ["sudo", "tee", temp_path],
            input=content.encode(),
            stdout=subprocess.DEVNULL,
            check=True,
        )
        subprocess.run(["sudo", "chmod", "600", temp_path], check=True)
        subprocess.run(["sudo", "mv", temp_path, str(svc_env_path)], check=True)
        temp_path = None
        ux.ok(f"Wrote {key} to {svc_env_path}")
        return True
    except (OSError, subprocess.CalledProcessError):
        ux.warn(
            f"Could not write {key} to {svc_env_path} (sudo may have been denied).\n"
            f"  The systemd service needs this key in its EnvironmentFile to start.\n"
            f"  Repair the service env file and rerun setup."
        )
        return False
    finally:
        if temp_path:
            try:
                subprocess.run(["sudo", "rm", "--", temp_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except OSError:
                pass


# Register subcommands
from defenseclaw.commands.cmd_edge_install import edge_install  # noqa: E402

edge_connector.add_command(edge_install, "install")
