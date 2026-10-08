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
import shlex
import subprocess
from pathlib import Path

import click

from defenseclaw import ux
from defenseclaw.context import AppContext

_TOKEN_ENV = "DCLAW_FLEET_API_TOKEN"
_DEFAULT_FLEET_ENDPOINT = "http://127.0.0.1:13400/api/v1/fleet"

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
        "  cmake .. -DDCLAW_PROFILE=STANDARD -DDCLAW_DEV_MODE=OFF\n"
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

    if token:
        _persist_env_var(env_path, _TOKEN_ENV, token)
        ux.ok(f"Wrote {_TOKEN_ENV} to {env_path}")

    # --- 2b. Audit key ---------------------------------------------------
    # P1-18 fix: Generate a random audit key if none exists. The audit key is
    # a 32-byte hex-encoded HMAC key used for tamper-evident audit log signing.
    # Without it, edge-connectors built with -DDCLAW_DEV_MODE=OFF will refuse
    # to start because unsigned audit logs are only accepted in dev mode.
    existing_audit = os.environ.get("DCLAW_AUDIT_KEY", "")
    if not existing_audit:
        # Check if already in the env file
        if env_path.exists():
            for _line in env_path.read_text().splitlines():
                if _line.strip().startswith("DCLAW_AUDIT_KEY="):
                    existing_audit = _line.strip().split("=", 1)[1].strip("'\"")
                    break

    svc_env_path = Path("/etc/defenseclaw/edge-connector.env")

    if existing_audit:
        ux.ok("DCLAW_AUDIT_KEY already set.")
        # P1-18 fix: Even if the CLI env already has the key, ensure the
        # service env file also has it.
        _persist_svc_env_var(svc_env_path, "DCLAW_AUDIT_KEY", existing_audit)
    else:
        audit_key = secrets.token_hex(32)
        # P1-18 fix: Write the audit key to BOTH locations so the systemd
        # service can read it from its EnvironmentFile.
        _persist_env_var(env_path, "DCLAW_AUDIT_KEY", audit_key)
        _persist_svc_env_var(svc_env_path, "DCLAW_AUDIT_KEY", audit_key)
        ux.ok(f"Generated DCLAW_AUDIT_KEY ({len(audit_key)} hex chars) and wrote to {env_path} and {svc_env_path}")

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
        "    DCLAW_OTA_KEY          — Shared HMAC-SHA256 signing key (hex-encoded, 32 bytes)\n"
        "    DCLAW_BROKER_URL       — MQTT broker URL for cloud escalation\n"
    )


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
    # Restrict permissions on the env file (secrets inside).
    try:
        env_path.chmod(0o600)
    except OSError:
        pass


def _persist_svc_env_var(svc_env_path: Path, key: str, value: str) -> None:
    """Write a KEY=VALUE to the systemd service env file using sudo.

    P1-18 fix: The service reads /etc/defenseclaw/edge-connector.env via its
    EnvironmentFile directive.  The CLI user typically cannot write to /etc/
    directly, so we use sudo tee.
    """
    # Read existing content (if any) via sudo
    existing_lines: list[str] = []
    if svc_env_path.exists():
        try:
            result = subprocess.run(
                ["sudo", "cat", str(svc_env_path)],
                capture_output=True, text=True,
            )
            if result.returncode == 0:
                existing_lines = result.stdout.splitlines()
        except OSError:
            pass

    # Update or append the key
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
    write_cmd = (
        "sudo mkdir -p /etc/defenseclaw && "
        f"printf %s {shlex.quote(content)} | sudo tee {svc_env_path} > /dev/null && "
        f"sudo chmod 600 {svc_env_path}"
    )
    result = subprocess.run(["sh", "-c", write_cmd], capture_output=True, text=True)
    if result.returncode == 0:
        ux.ok(f"Wrote {key} to {svc_env_path}")
    else:
        # P1 fix: Never print the actual key value to the terminal.
        # The value is already persisted in ~/.defenseclaw/.env.
        redacted = value if key != "DCLAW_AUDIT_KEY" else "<generated -- see ~/.defenseclaw/.env>"
        ux.warn(
            f"Could not write {key} to {svc_env_path} (sudo may have been denied).\n"
            f"  The systemd service needs this key in its EnvironmentFile to start.\n"
            f"  Write it manually: echo '{key}={redacted}' | sudo tee -a {svc_env_path}"
        )


# Register subcommands
from defenseclaw.commands.cmd_edge_install import edge_install  # noqa: E402

edge_connector.add_command(edge_install, "install")
