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
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path

import click

from defenseclaw import ux
from defenseclaw.context import AppContext, pass_ctx

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


@click.command("edge-connector")
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
@pass_ctx
def edge_connector(
    app: AppContext,
    token: str | None,
    endpoint: str | None,
    emit_policy: bool,
    non_interactive: bool,
) -> None:
    """Configure the Edge Connector fleet management API.

    Walks through building the edge-connector binary, setting the fleet
    API bearer token in ~/.defenseclaw/.env, and registering the endpoint.
    Use ``--emit-policy`` to print a sample fleet policy YAML.
    """
    if emit_policy:
        ux.echo(_SAMPLE_POLICY)
        return

    ux.section("Edge Connector Setup")

    # --- 1. Build instructions -------------------------------------------
    ux.echo()
    ux.info(
        "Edge Connector Engine (C):\n"
        "\n"
        "  cd edge-connector\n"
        "  mkdir build && cd build\n"
        "  cmake .. -DDCLAW_PROFILE=STANDARD\n"
        "  make -j$(nproc)\n"
        "  sudo make install\n"
        "\n"
        "Fleet Manager (Go):\n"
        "\n"
        "  cd internal/fleet\n"
        "  go build -o fleet-manager ./...\n"
        "\n"
        "Or build the full gateway binary which includes the fleet API:\n"
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
        "  3. Optionally apply a fleet policy:\n"
        "\n"
        "       defenseclaw setup edge-connector --emit-policy > fleet-policy.yaml\n"
        "       defenseclaw policy load fleet-policy.yaml\n"
        "\n"
        "  Optional environment variables for edge devices:\n"
        "    DCLAW_OTA_KEY          — Ed25519 public key for OTA policy verification\n"
        "    DCLAW_MQTT_BROKER_URL  — MQTT broker URL for cloud escalation\n"
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
