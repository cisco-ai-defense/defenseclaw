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

import ipaddress
import os
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

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
_DEFAULT_FLEET_ENDPOINT = "http://127.0.0.1:18970/api/v1/fleet"


def _validate_fleet_endpoint(endpoint: str) -> str:
    """Allow plaintext bearer-token traffic only to a literal loopback IP."""
    if not endpoint or any(ord(char) <= 32 or ord(char) == 127 for char in endpoint) or "\\" in endpoint:
        raise click.ClickException("Fleet API endpoint must be a valid HTTP(S) URL")
    try:
        parsed = urlsplit(endpoint)
        host = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise click.ClickException("Fleet API endpoint must be a valid HTTP(S) URL") from exc
    if (
        parsed.scheme not in {"http", "https"}
        or not host
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or "?" in endpoint
        or "#" in endpoint
        or "%" in parsed.netloc
        or parsed.netloc.endswith(":")
        or port == 0
    ):
        raise click.ClickException(
            "Fleet API endpoint must be a valid HTTP(S) URL without credentials, query, or fragment"
        )
    if parsed.scheme == "http":
        try:
            loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            loopback = False
        if not loopback:
            raise click.ClickException("Fleet API endpoint requires HTTPS outside a literal loopback address")
    return endpoint


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


def _install_fleet_compiler(data_dir: str, source_dir: Path | None = None) -> Path:
    """Install the separately supplied compiler only when the operator enables Fleet."""
    from defenseclaw.commands.cmd_edge_install import _find_edge_connector_source
    from defenseclaw.file_permissions import make_private_directory, set_file_mode

    source_root = _find_edge_connector_source(source_dir) if source_dir is not None else _find_edge_connector_source()
    source = source_root / "tools" / "policy_compiler.py" if source_root else None
    if source is None or source.is_symlink() or not source.is_file():
        raise click.ClickException("Fleet policy compiler missing; pass --source-dir with extracted Fleet assets")
    if source.stat().st_size > 1 << 20:
        raise click.ClickException("The Fleet policy compiler is unexpectedly large")

    home = Path(data_dir).absolute()
    if home.is_symlink() or not home.is_dir():
        raise click.ClickException(f"Fleet data directory is not a real directory: {home}")
    if os.name == "nt":
        try:
            make_private_directory(home)
        except OSError as exc:
            raise click.ClickException(f"Fleet data directory is not private: {exc}") from exc
    target_dir = home / "installer"
    if target_dir.exists() or target_dir.is_symlink():
        if target_dir.is_symlink() or not target_dir.is_dir():
            raise click.ClickException(f"Fleet compiler directory is not a real directory: {target_dir}")
    else:
        target_dir.mkdir(mode=0o700)
    if os.name == "nt":
        try:
            make_private_directory(target_dir)
        except OSError as exc:
            raise click.ClickException(f"Fleet compiler directory is not private: {exc}") from exc
    else:
        for directory in (home, target_dir):
            if directory.stat().st_mode & 0o022:
                raise click.ClickException(f"Fleet compiler directory is writable by another account: {directory}")
    destination = target_dir / "policy_compiler.py"
    if destination.is_symlink():
        raise click.ClickException(f"Fleet compiler path is a symlink: {destination}")
    fd, temporary = tempfile.mkstemp(prefix=".policy_compiler.py.", dir=target_dir)
    try:
        set_file_mode(fd, temporary, stat.S_IRUSR | stat.S_IWUSR, set_owner=True)
        stream = os.fdopen(fd, "wb")
        fd = -1
        with stream as output, source.open("rb") as input_file:
            shutil.copyfileobj(input_file, output)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, destination)
    except OSError as exc:
        raise click.ClickException(f"Could not install Fleet policy compiler: {exc}") from exc
    finally:
        if fd >= 0:
            os.close(fd)
        if os.path.exists(temporary):
            os.unlink(temporary)
    return destination


def _enable_fleet_config(data_dir: str) -> None:
    """Activate Fleet after its credentials and compiler are provisioned."""
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
# Edge Connector on-device policy. Review the actions before pushing.
# Add only approved public numeric IPs to destination_allowlist when needed.
name: edge-default
skill_actions:
  critical:
    runtime: disable
  high:
    runtime: disable
  medium:
    runtime: warn
iot_extensions:
  capability_sequences:
    - sequence: [net_fetch, exec_shell]
      action: block
    - sequence: [net_fetch, actuate]
      action: block
  destination_allowlist: []
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
    help="Device registration API URL (default: local gateway on port 18970).",
)
@click.option(
    "--emit-policy",
    is_flag=True,
    help="Print a sample fleet policy YAML and exit.",
)
@click.option("--source-dir", type=click.Path(path_type=Path, exists=True, file_okay=False), default=None,
              help=("Extract defenseclaw-fleet-assets.tar.gz and pass its directory, "
                    "or use a source checkout (required for wheel installs)."))
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
    source_dir: Path | None,
    non_interactive: bool,
) -> None:
    """Configure the Edge Connector fleet management API.

    Prints Edge Connector build instructions, provisions Fleet credentials,
    and saves the Fleet API endpoint in ~/.defenseclaw/.env.
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
    if sys.platform.startswith("linux"):
        ux.echo(
            "Optional Edge Connector Engine (C, Linux device):\n"
            "\n"
            "  cd /path/to/extracted-assets/edge-connector\n"
            "  mkdir build && cd build\n"
            "  cmake .. -DDCLAW_PROFILE=STANDARD -DDCLAW_DEV_MODE=OFF -DDCLAW_ALLOW_HMAC_OTA=ON\n"
            "  make -j$(nproc)\n"
            "  sudo make install\n"
            "\n"
            "  The Linux C service requires keys, broker TLS, and a per-device identity.\n"
            "  This wizard writes its audit, OTA, and emergency keys to both\n"
            "  ~/.defenseclaw/.env and /etc/defenseclaw/edge-connector.env.\n"
            "  See edge-connector/INSTALL.md before starting the C service.\n"
        )
    else:
        ux.echo(
            "This sets up the Fleet gateway on this host. The separate C Edge\n"
            "Connector daemon deploys on Linux devices; no local C service is installed.\n"
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

    if endpoint is None:
        endpoint = _DEFAULT_FLEET_ENDPOINT
        if not non_interactive:
            endpoint = click.prompt("Fleet API endpoint", default=endpoint)
    endpoint = _validate_fleet_endpoint(endpoint)

    linux_device_host = sys.platform.startswith("linux")
    svc_env_path = Path("/etc/defenseclaw/edge-connector.env")
    audit_key = _hmac_key(env_path, "DCLAW_AUDIT_KEY")
    ota_key = _hmac_key(env_path, "DCLAW_OTA_HMAC_KEY")
    emergency_key = _hmac_key(env_path, "DCLAW_EMERGENCY_KEY")
    # Fleet remains disabled if credential provisioning fails. The compiler
    # copy is inert until the validated Fleet config is committed below.
    if source_dir is None:
        _install_fleet_compiler(ctx.obj.cfg.data_dir)
    else:
        _install_fleet_compiler(ctx.obj.cfg.data_dir, source_dir)
    try:
        for name, value in (
            (_TOKEN_ENV, token),
            ("DCLAW_FLEET_API_URL", endpoint),
            ("DCLAW_AUDIT_KEY", audit_key),
            ("DCLAW_OTA_HMAC_KEY", ota_key),
            ("DCLAW_EMERGENCY_KEY", emergency_key),
        ):
            _persist_env_var(env_path, name, value)
            ux.ok(f"Wrote {name} to {env_path}")
        if linux_device_host:
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
    _enable_fleet_config(ctx.obj.cfg.data_dir)

    ux.echo()
    ux.ok(f"Fleet API endpoint: {endpoint}")

    # --- 4. Summary ------------------------------------------------------
    ux.echo()
    ux.section("Next Steps")
    ux.echo(
        "  1. Start (or restart) the DefenseClaw gateway that hosts Fleet.\n"
        f"     Device registration will use {endpoint}\n"
        "     Fleet CLI commands use this endpoint.\n"
        "  2. Configure the Linux devices with broker TLS and per-device keys.\n"
        "  3. Verify the fleet is running:\n"
        "\n"
        "       defenseclaw edge-connector health\n"
        "\n"
        "  4. Optionally apply a fleet policy:\n"
        "\n"
        "       defenseclaw setup edge-connector --emit-policy > fleet-policy.yaml\n"
        "       defenseclaw edge-connector policy push fleet-policy.yaml\n"
        "\n"
        "  Register devices via the Fleet REST API or its CLI wrapper:\n"
        "    defenseclaw edge-connector register <device-id>\n"
        "\n"
        "  Optional environment variables for edge devices:\n"
        "    DCLAW_OTA_HMAC_KEY     — Shared HMAC-SHA256 secret (hex-encoded, 32 bytes)\n"
        "    DCLAW_EMERGENCY_KEY    — Separate emergency-command HMAC secret\n"
        "    DCLAW_BROKER_URL       — MQTT broker URL for cloud escalation\n"
    )
    if urlsplit(endpoint).scheme == "https":
        ux.echo("  The CLI uses the saved HTTPS Fleet endpoint for registration and key delivery.")
    else:
        ux.echo(
            "  This loopback command is for loopback-only test mode when Fleet explicitly\n"
            "  permits HTTP key delivery. Production registration requires an HTTPS\n"
            "  endpoint or a configured trusted TLS proxy."
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
