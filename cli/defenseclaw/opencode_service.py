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

"""This account's OpenCode V2 background server (rel-1-0-6 GAP-0026).

OpenCode V2 keeps a server running after its window closes (``opencode serve
--service``), and the server keeps the plugins it loaded: after an uninstall
it still ran the DefenseClaw plugin. Setup, connector removal and uninstall
change that plugin, so they restart the account's own server when it runs.
An open OpenCode window starts a new server by itself and reconnects
(OpenCode 2.2.5). ``/tmp/opencode``, owned by the first account that used it,
is OpenCode's own (the connector page says how to give an account its own).

The server's default port, 49374 on the release channel, is the same for
every account on a computer, so a second account's server could not start
(GAP-0053). Setup gives an account whose service.json names no port a port of
its own (ensure_account_port): derived from its uid (the RID of its SID on
Windows), claimed like the gateway's API port so two accounts never take the
same one, and written as "port" into OpenCode's own service.json, so it stays
the same on later runs and upgrades. The managed guardian uses the same scheme
(internal/enterprisepolicy/opencode_service_port.go).
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
from collections.abc import Iterator

RESTART_COMMAND = "opencode service restart"
_TIMEOUT = 30

RESTARTED = "restarted"
NOT_RESTARTED = "not-restarted"

# OpenCode 2.2.5 serves the latest/dev/beta/next channels on 49374 and the
# local channel on 49375; other channels get a port derived from their name.
DEFAULT_SERVICE_PORT = 49374
# Account ports: 24000 + (uid mod 8000), below Linux's ephemeral range
# (32768-60999) and clear of DefenseClaw's own defaults.
ACCOUNT_PORT_BASE = 24000
ACCOUNT_PORT_SPAN = 8000
_ACCOUNT_PORT_TRIES = 64
# Claims live with the gateway's port claims (bootstrap._API_PORT_CLAIM_DIR).
PORT_CLAIM_PREFIX = "defenseclaw-opencode-port-"


def account_binary(data_dir: str | None = None) -> str:
    """The OpenCode V2 this account runs (the discovery probe setup uses), or "".

    Windows keeps the documented command,
    and OpenCode V1 has no background server.
    """
    if os.name == "nt":
        return ""
    from defenseclaw.connector_contracts import normalize_agent_version
    from defenseclaw.inventory import agent_discovery

    try:
        disc = agent_discovery.discover_with_probes(
            ["opencode"], use_cache=False, refresh=True, data_dir=data_dir, persist_cache=False
        )
        signal = disc.agents.get("opencode")
    except Exception:  # noqa: BLE001 - no answer: the caller names the command instead
        return ""
    if signal is None or not signal.installed or not (signal.binary_path or "").strip():
        return ""
    if normalize_agent_version(signal.version or "").split(".", 1)[0] != "2":
        return ""
    return signal.binary_path


def _service(binary: str, action: str, *args: str) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(
            [binary, "service", action, *args],
            capture_output=True,
            text=True,
            timeout=_TIMEOUT,
            check=False,
            stdin=subprocess.DEVNULL,
        )
    except (OSError, subprocess.SubprocessError, ValueError):
        return None


def restart_if_running(binary: str) -> str:
    """Restart the account's background server when it runs.

    Returns "" (no OpenCode V2, or no server running), ``RESTARTED``, or
    ``NOT_RESTARTED`` (its state could not be read or the restart failed).
    """
    if not binary:
        return ""
    status = _service(binary, "status")
    if status is None or status.returncode != 0:
        return NOT_RESTARTED
    if status.stdout.strip().lower() in ("", "stopped"):
        return ""
    done = _service(binary, "restart")
    return RESTARTED if done is not None and done.returncode == 0 else NOT_RESTARTED


def account_port_candidates(account_id: int) -> Iterator[int]:
    """This account's service ports in the order setup tries them (stable per account)."""
    start = account_id % ACCOUNT_PORT_SPAN
    for step in range(_ACCOUNT_PORT_TRIES):
        yield ACCOUNT_PORT_BASE + (start + step) % ACCOUNT_PORT_SPAN


def service_config_path() -> str:
    """OpenCode's service.json: the XDG config folder, ~/.config on every OS."""
    root = os.environ.get("XDG_CONFIG_HOME", "").strip() or os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(root, "opencode", "service.json")


def _read_service_config() -> tuple[dict | None, bool]:
    """(the service.json object, whether a file is there); None when it is not
    a regular JSON object this setup may change."""
    path = service_config_path()
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return {}, False
    except OSError:
        return None, True
    if not stat.S_ISREG(info.st_mode) or info.st_size > 64 * 1024:
        return None, True
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return None, True
    return (data, True) if isinstance(data, dict) else (None, True)


def _configured_port() -> int | None:
    """The port the account set in OpenCode's service.json, or None."""
    data, _ = _read_service_config()
    port = (data or {}).get("port")
    return port if isinstance(port, int) and not isinstance(port, bool) else None


def _windows() -> bool:
    from defenseclaw import bootstrap

    return bootstrap._windows_port_claims()


def _account_id() -> int | None:
    """The uid, or on Windows the RID (last part) of the account SID."""
    if not _windows():
        return os.getuid() if hasattr(os, "getuid") else None
    from defenseclaw import bootstrap

    sid = bootstrap._windows_own_sid()
    tail = sid.rsplit("-", 1)[-1] if sid.upper().startswith("S-1-") else ""
    return int(tail) if tail.isdigit() else None


def _claim(port: int) -> bool:
    """Claim *port* for this account (True), unless another account holds it.

    POSIX: an empty file of this uid in /var/tmp (bootstrap._reserve_api_port).
    Windows: a file in %ProgramData% that holds this account's SID, the form
    the gateway's Windows port claims use (bootstrap._windows_claim_sid).
    """
    from defenseclaw import bootstrap

    if not _windows():
        return bootstrap._reserve_api_port(port, PORT_CLAIM_PREFIX)
    own = bootstrap._windows_own_sid()
    if not own:
        return False
    path = os.path.join(bootstrap._api_port_claim_dir(), f"{PORT_CLAIM_PREFIX}{port}")
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
    except FileExistsError:
        return bootstrap._windows_claim_sid(path).upper() == own.upper()
    except OSError:
        return True  # a claim is only a hint
    try:
        os.write(fd, own.encode("ascii"))
    finally:
        os.close(fd)
    return True


def _port_available(port: int) -> bool:
    from defenseclaw import bootstrap

    return (
        bootstrap._api_port_free("127.0.0.1", port)
        and not bootstrap._api_port_claimed_by_other_account(port, PORT_CLAIM_PREFIX)
        and _claim(port)
    )


def _write_port(port: int) -> None:
    from defenseclaw.file_permissions import atomic_write_private_bytes

    data, _ = _read_service_config()
    if data is None:
        raise OSError(f"{service_config_path()} is not a JSON object this setup may change")
    data = dict(data)
    data["port"] = port
    path = service_config_path()
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    atomic_write_private_bytes(path, (json.dumps(data, indent=2) + "\n").encode("utf-8"), protect_parent=False)


def ensure_account_port() -> str:
    """Give this account's background server a port of its own.

    Only when service.json names no port: the first free, unclaimed port of
    account_port_candidates, written as "port" into OpenCode's service.json
    (OpenCode keeps its other keys and adds its password at the next start).
    Linux, macOS and Windows. Returns a line for the output ("" when nothing
    changed); a line that starts with "!" is a warning.
    """
    data, exists = _read_service_config()
    manual = "give this account its own with 'opencode service set port <free port>'"
    if data is None:
        return (
            f"!{service_config_path()} is not a JSON object, so OpenCode's background server keeps its port "
            f"({DEFAULT_SERVICE_PORT} is shared by every account here): {manual}."
        )
    if _configured_port() is not None or "port" in data:
        return ""
    account_id = _account_id()
    if account_id is None:
        return ""
    for port in account_port_candidates(account_id):
        if not _port_available(port):
            continue
        try:
            _write_port(port)
        except OSError as exc:
            return (
                f"!OpenCode's background server port could not be set ({exc}; "
                f"{DEFAULT_SERVICE_PORT} is shared by every account here): {manual}."
            )
        return (
            f"OpenCode's background server uses port {port} for this account ({service_config_path()}): "
            f"its default, {DEFAULT_SERVICE_PORT}, is shared by every account on this computer."
        )
    return (
        f"!No free port for OpenCode's background server ({DEFAULT_SERVICE_PORT} is shared by every account here): "
        f"{manual}."
    )


def report_port(line: str) -> None:
    """Print what ensure_account_port did."""
    from defenseclaw import ux

    if line.startswith("!"):
        ux.warn(line[1:])
    elif line:
        ux.ok(line)


def report(outcome: str, *, what: str) -> None:
    """Say what happened to the server; *what* is how the plugin changed."""
    from defenseclaw import ux

    if outcome == RESTARTED:
        ux.ok(
            f"Restarted OpenCode's background server ({RESTART_COMMAND}), so it {what}; "
            "an open OpenCode window reconnects to it."
        )
    elif outcome == NOT_RESTARTED:
        ux.warn(
            f"OpenCode's background server may still run the DefenseClaw plugin it loaded before: run "
            f"'{RESTART_COMMAND}' (or 'opencode service stop')."
        )
