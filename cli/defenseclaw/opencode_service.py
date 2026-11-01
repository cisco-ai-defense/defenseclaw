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
(OpenCode 2.2.5). Its default port, shared by every account on a computer,
and ``/tmp/opencode``, owned by the first account that used it, are
OpenCode's own (the connector page says how to give an account its own).
"""

from __future__ import annotations

import os
import subprocess

RESTART_COMMAND = "opencode service restart"
_TIMEOUT = 30

RESTARTED = "restarted"
NOT_RESTARTED = "not-restarted"


def account_binary(data_dir: str | None = None) -> str:
    """The OpenCode V2 this account runs (the discovery probe setup uses), or "".

    Windows keeps the documented command (OpenCode V2 there is Preview),
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


def _service(binary: str, action: str) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(
            [binary, "service", action],
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
