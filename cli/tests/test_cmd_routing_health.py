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

"""Doctor and status coverage for semantic-routing runtime health."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from click.testing import CliRunner
from defenseclaw.commands import cmd_doctor, cmd_status
from defenseclaw.config import RoutingConfig

from tests.helpers import cleanup_app, make_app_context


def _doctor_cfg(
    *,
    enabled: bool = True,
    remote_endpoint: str = "",
    port: int = 8799,
    model_count: int = 2,
):
    return SimpleNamespace(
        routing=SimpleNamespace(
            enabled=enabled,
            remote={"endpoint": remote_endpoint} if remote_endpoint else {},
            port=port,
            models=[{} for _ in range(model_count)],
        )
    )


def _routing_check(cfg, *, live_health=None):
    result = cmd_doctor._DoctorResult()
    cmd_doctor._check_semantic_routing(cfg, result, live_health=live_health)
    assert len(result.checks) == 1
    return result.checks[0]


def test_doctor_uses_live_running_routing_health_without_fallback_probe(monkeypatch) -> None:
    probe = pytest.fail
    monkeypatch.setattr(cmd_doctor, "_http_probe", probe)

    check = _routing_check(
        _doctor_cfg(),
        live_health={"routing": {"state": "running"}},
    )

    assert check["status"] == "pass"
    assert check["detail"] == "managed Docker; healthy; 2 model(s)"


def test_doctor_surfaces_live_routing_error_with_bounded_last_error(monkeypatch) -> None:
    monkeypatch.setattr(cmd_doctor, "_http_probe", pytest.fail)
    last_error = "x" * 256 + "must-not-appear"

    check = _routing_check(
        _doctor_cfg(remote_endpoint="https://router.example.test"),
        live_health={"routing": {"state": "error", "last_error": last_error}},
    )

    assert check["status"] == "fail"
    assert "remote; gateway reports router error" in check["detail"]
    assert "x" * 256 in check["detail"]
    assert "must-not-appear" not in check["detail"]
    assert "setup routing --status" in check["remediation"]


def test_doctor_distinguishes_disabled_config_from_disabled_runtime(monkeypatch) -> None:
    monkeypatch.setattr(cmd_doctor, "_http_probe", pytest.fail)

    configured_off = _routing_check(_doctor_cfg(enabled=False))
    runtime_off = _routing_check(
        _doctor_cfg(enabled=True),
        live_health={"routing": {"state": "disabled"}},
    )

    assert configured_off["status"] == "skip"
    assert configured_off["detail"] == "disabled"
    assert runtime_off["status"] == "fail"
    assert "configured enabled" in runtime_off["detail"]


@pytest.mark.parametrize(
    ("remote_endpoint", "status_code", "want_status", "want_url"),
    [
        ("", 200, "pass", "http://127.0.0.1:8799/health"),
        ("https://router.example.test/base/", 0, "fail", "https://router.example.test/base/health"),
    ],
)
def test_doctor_falls_back_to_bounded_classifier_probe(
    monkeypatch,
    remote_endpoint: str,
    status_code: int,
    want_status: str,
    want_url: str,
) -> None:
    calls: list[tuple[str, float]] = []

    def probe(url: str, *, timeout: float):
        calls.append((url, timeout))
        return status_code, ""

    monkeypatch.setattr(cmd_doctor, "_http_probe", probe)
    check = _routing_check(_doctor_cfg(remote_endpoint=remote_endpoint))

    assert check["status"] == want_status
    assert calls == [(want_url, 2.0)]


@pytest.mark.parametrize(
    ("enabled", "live", "want"),
    [
        (
            True,
            {"routing": {"state": "running"}},
            {"configured": True, "runtime_state": "running", "mode": "managed"},
        ),
        (
            True,
            {"routing": {"state": "error", "last_error": "classifier unavailable"}},
            {
                "configured": True,
                "runtime_state": "error",
                "mode": "managed",
                "last_error": "classifier unavailable",
            },
        ),
        (
            False,
            None,
            {"configured": False, "runtime_state": "disabled", "mode": "managed"},
        ),
    ],
)
def test_status_projects_running_error_and_disabled_routing(enabled, live, want) -> None:
    cfg = SimpleNamespace(
        routing=RoutingConfig(
            enabled=enabled,
            version="0.3.0",
            port=8799,
            models=[{"name": "fast"}],
        )
    )

    state = cmd_status._semantic_routing_status(cfg, health=live)

    for key, value in want.items():
        assert state[key] == value
    assert state["version"] == "0.3.0"
    assert state["port"] == 8799
    assert state["model_count"] == 1


def test_status_json_preserves_routing_last_error(monkeypatch) -> None:
    app, tmp_dir, db_path = make_app_context()
    app.cfg.routing.enabled = True
    app.cfg.routing.models = [{"name": "fast"}]
    last_error = "classifier unavailable"
    monkeypatch.setattr(
        cmd_status,
        "_fetch_runtime_bound_health",
        lambda _client, _cfg: {
            "routing": {"state": "error", "last_error": last_error},
        },
    )
    try:
        result = CliRunner().invoke(
            cmd_status.status,
            ["--json"],
            obj=app,
            catch_exceptions=False,
        )
        assert result.exit_code == 0, result.output
        document = json.loads(result.output)
        assert document["sidecar"] == {"running": True}
        assert document["semantic_routing"]["runtime_state"] == "error"
        assert document["semantic_routing"]["last_error"] == last_error
    finally:
        cleanup_app(app, db_path, tmp_dir)
