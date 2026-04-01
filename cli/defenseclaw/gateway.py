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

"""HTTP client for the Go orchestrator's REST API.

Communicates with the sidecar at http://{host}:{api_port}.
Mirrors the endpoints exposed in internal/gateway/api.go.
"""

from __future__ import annotations

from typing import Any

import requests


class OrchestratorClient:
    def __init__(self, host: str = "127.0.0.1", port: int = 18970, timeout: int = 5,
                 token: str = "") -> None:
        self.base_url = f"http://{host}:{port}"
        self.timeout = timeout
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
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def enable_plugin(self, plugin_name: str) -> dict[str, Any]:
        resp = self._session.post(
            f"{self.base_url}/plugin/enable",
            json={"pluginName": plugin_name},
            timeout=self.timeout,
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
