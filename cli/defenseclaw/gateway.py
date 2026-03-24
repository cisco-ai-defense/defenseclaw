"""HTTP client for the Go orchestrator's REST API.

Communicates with the sidecar at http://{host}:{api_port}.
Mirrors the endpoints exposed in internal/gateway/api.go.
"""

from __future__ import annotations

from typing import Any

import requests


class OrchestratorClient:
    def __init__(self, host: str = "127.0.0.1", port: int = 18790, timeout: int = 5) -> None:
        self.base_url = f"http://{host}:{port}"
        self.timeout = timeout

    def health(self) -> dict[str, Any]:
        resp = requests.get(f"{self.base_url}/health", timeout=self.timeout)
        resp.raise_for_status()
        return resp.json()

    def status(self) -> dict[str, Any]:
        resp = requests.get(f"{self.base_url}/status", timeout=self.timeout)
        resp.raise_for_status()
        return resp.json()

    def disable_skill(self, skill_key: str) -> dict[str, Any]:
        resp = requests.post(
            f"{self.base_url}/skill/disable",
            json={"skillKey": skill_key},
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def enable_skill(self, skill_key: str) -> dict[str, Any]:
        resp = requests.post(
            f"{self.base_url}/skill/enable",
            json={"skillKey": skill_key},
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def patch_config(self, path: str, value: Any) -> dict[str, Any]:
        resp = requests.post(
            f"{self.base_url}/config/patch",
            json={"path": path, "value": value},
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def list_skills(self) -> dict[str, Any]:
        resp = requests.get(f"{self.base_url}/skills", timeout=self.timeout)
        resp.raise_for_status()
        return resp.json()

    def get_tools_catalog(self) -> dict[str, Any]:
        resp = requests.get(f"{self.base_url}/tools/catalog", timeout=self.timeout)
        resp.raise_for_status()
        return resp.json()

    def is_running(self) -> bool:
        try:
            self.health()
            return True
        except (requests.ConnectionError, requests.Timeout):
            return False
