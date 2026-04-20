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

"""Gateway-related helpers shared by every Click command.

This module hosts two cohesive but independent responsibilities:

* :class:`OrchestratorClient` — the HTTP client the Python CLI uses to
  talk to the running sidecar at ``http://{host}:{api_port}``.  Mirrors
  the endpoints exposed in ``internal/gateway/api.go``.
* :func:`resolve_gateway_binary` — the single source of truth for where
  the Python CLI looks for the ``defenseclaw-gateway`` executable on
  disk.  See the helper's own docstring for the resolution order and
  the UX bug that prompted it.
"""

from __future__ import annotations

import os
import shutil
from typing import Any

import requests

PLUGIN_MUTATION_TIMEOUT = 90


class OrchestratorClient:
    def __init__(self, host: str = "127.0.0.1", port: int = 18970, timeout: int = 5,
                 token: str = "", plugin_timeout: int | None = None) -> None:
        self.base_url = f"http://{host}:{port}"
        self.timeout = timeout
        self.plugin_timeout = max(timeout, plugin_timeout or PLUGIN_MUTATION_TIMEOUT)
        self._session = requests.Session()
        self._session.headers["X-DefenseClaw-Client"] = "python-cli"
        if token:
            self._session.headers["Authorization"] = f"Bearer {token}"

    def health(self) -> dict[str, Any]:
        resp = self._session.get(f"{self.base_url}/health", timeout=self.timeout)
        resp.raise_for_status()
        return resp.json()

    def status(self) -> dict[str, Any]:
        resp = self._session.get(f"{self.base_url}/status", timeout=self.timeout)
        resp.raise_for_status()
        return resp.json()

    def disable_skill(self, skill_key: str) -> dict[str, Any]:
        resp = self._session.post(
            f"{self.base_url}/skill/disable",
            json={"skillKey": skill_key},
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def enable_skill(self, skill_key: str) -> dict[str, Any]:
        resp = self._session.post(
            f"{self.base_url}/skill/enable",
            json={"skillKey": skill_key},
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def patch_config(self, path: str, value: Any) -> dict[str, Any]:
        resp = self._session.post(
            f"{self.base_url}/config/patch",
            json={"path": path, "value": value},
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def list_skills(self) -> dict[str, Any]:
        resp = self._session.get(f"{self.base_url}/skills", timeout=self.timeout)
        resp.raise_for_status()
        return resp.json()

    def get_tools_catalog(self) -> dict[str, Any]:
        resp = self._session.get(f"{self.base_url}/tools/catalog", timeout=self.timeout)
        resp.raise_for_status()
        return resp.json()

    def disable_plugin(self, plugin_name: str) -> dict[str, Any]:
        resp = self._session.post(
            f"{self.base_url}/plugin/disable",
            json={"pluginName": plugin_name},
            timeout=self.plugin_timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def enable_plugin(self, plugin_name: str) -> dict[str, Any]:
        resp = self._session.post(
            f"{self.base_url}/plugin/enable",
            json={"pluginName": plugin_name},
            timeout=self.plugin_timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def scan_skill(self, target: str, name: str = "") -> dict[str, Any]:
        """Request a skill scan on the remote sidecar host.

        The sidecar runs the skill-scanner locally against the target path
        on that machine and returns the ScanResult JSON.
        """
        resp = self._session.post(
            f"{self.base_url}/v1/skill/scan",
            json={"target": target, "name": name},
            timeout=120,
        )
        resp.raise_for_status()
        return resp.json()

    def is_running(self) -> bool:
        try:
            self.health()
            return True
        except (requests.ConnectionError, requests.Timeout):
            return False


# ---------------------------------------------------------------------------
# Binary resolver
# ---------------------------------------------------------------------------
#
# Every caller that needs to shell out to the Go sidecar used to write
# ``shutil.which("defenseclaw-gateway")`` inline and treat a ``None``
# result as "not installed".  That silently misbehaves right after
# ``make all``: the binary is installed at ``~/.local/bin/defenseclaw-
# gateway`` (the ``INSTALL_DIR`` in the ``Makefile``) but the user's
# current shell hasn't picked up the ``PATH`` entry that ``scripts/
# add-to-path.sh`` just appended to their rc file.  Opening a new shell
# (or ``source``ing the rc file) fixes it, but we should not make users
# debug that to run ``defenseclaw tui``.  The helper below centralises
# the lookup and adds a fallback to the canonical install path so the
# CLI stays usable in the very same shell that ran ``make all``.


GATEWAY_BIN_NAME = "defenseclaw-gateway"

_CANONICAL_INSTALL_DIR = os.path.join(os.path.expanduser("~"), ".local", "bin")


def canonical_install_path() -> str:
    """Return the canonical install path written by ``make gateway-install``.

    Exposed so error messages and the upgrade command can reference the
    exact same path instead of each hard-coding the string.
    """
    return os.path.join(_CANONICAL_INSTALL_DIR, GATEWAY_BIN_NAME)


def resolve_gateway_binary() -> str | None:
    """Return the first resolvable path to the gateway binary, or ``None``.

    Resolution order:

    1. ``DEFENSECLAW_GATEWAY_BIN`` — explicit env override used by
       tests, packagers, and vendored distributions that drop the
       binary somewhere non-standard.  Returned verbatim (even when the
       file is missing) so the real ``exec`` error surfaces to the
       caller rather than a generic "not found" from here.
    2. ``shutil.which(GATEWAY_BIN_NAME)`` — honours ``PATH``.  The
       happy path for installed releases and for users whose shell has
       already sourced the updated rc file.
    3. :func:`canonical_install_path` — the ``~/.local/bin`` fallback
       that keeps ``defenseclaw tui`` working in the same shell that
       just ran ``make all``.

    ``None`` only if every option above fails to resolve to a runnable
    file on disk.  Callers own the user-facing error message.
    """
    override = os.environ.get("DEFENSECLAW_GATEWAY_BIN", "").strip()
    if override:
        return override

    via_path = shutil.which(GATEWAY_BIN_NAME)
    if via_path:
        return via_path

    canonical = canonical_install_path()
    if _is_runnable_file(canonical):
        return canonical

    return None


def _is_runnable_file(path: str) -> bool:
    try:
        return os.path.isfile(path) and os.access(path, os.X_OK)
    except OSError:
        return False
