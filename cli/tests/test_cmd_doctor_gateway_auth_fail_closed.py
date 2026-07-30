"""Fail-closed regression coverage for Doctor's gateway auth diagnostics."""

from __future__ import annotations

import json
import os
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from defenseclaw.commands.cmd_doctor import (
    _check_gateway_auth,
    _check_sidecar,
    _DoctorResult,
    _GatewayTrust,
)
from defenseclaw.config import GatewayConfig
from defenseclaw.doctor_gateway import PIDRecord, ProcessEvidence


def _cfg(data_dir: str) -> SimpleNamespace:
    gateway = GatewayConfig(
        api_bind="127.0.0.1",
        api_port=18_970,
        fleet_mode="disabled",
    )
    gateway.watcher.enabled = False
    return SimpleNamespace(
        data_dir=data_dir,
        gateway=gateway,
        guardrail=SimpleNamespace(enabled=False),
        openshell=None,
        _source_config_version=8,
        active_connectors=lambda: [],
        active_connector=lambda: "codex",
    )


def _trusted_gateway(data_dir: str, *, pid: int = 4242) -> _GatewayTrust:
    executable = os.path.join(data_dir, "bin", "defenseclaw-gateway")
    record = PIDRecord(
        "ok",
        pid=pid,
        executable=executable,
        start_identity="start-1",
        data_dir=data_dir,
    )
    process = ProcessEvidence(
        "ok",
        pid=pid,
        executable=executable,
        start_identity="start-1",
    )
    return _GatewayTrust(
        "trusted",
        "managed gateway owns the configured API endpoint",
        pid,
        home_bound=True,
        record=record,
        process=process,
    )


def _healthy_document() -> str:
    return json.dumps(
        {
            "gateway": {"state": "disabled"},
            "watcher": {"state": "disabled"},
            "guardrail": {"state": "disabled"},
            "api": {"state": "running"},
            "telemetry": {"state": "running"},
            "sandbox": {"state": "disabled"},
        }
    )


def _runtime_document(data_dir: str, *, pid: int = 4242) -> str:
    return json.dumps({"runtime": {"pid": pid, "data_dir": data_dir}})


@pytest.mark.parametrize(
    "stale_env_name",
    [
        "DEFENSECLAW_GATEWAY_TOKEN",
        "OPENCLAW_GATEWAY_TOKEN",
    ],
)
def test_doctor_fails_actionably_when_cli_env_token_differs_from_daemon_dotenv(
    tmp_path,
    monkeypatch,
    stale_env_name,
):
    """A green daemon probe must not hide the token the normal CLI will use."""
    daemon_token = "daemon-dotenv-token-must-not-render"
    stale_cli_token = "stale-exported-token-must-not-render"
    (tmp_path / ".env").write_text(
        f"DEFENSECLAW_GATEWAY_TOKEN={daemon_token}\n",
        encoding="utf-8",
    )
    os.chmod(tmp_path / ".env", 0o600)

    monkeypatch.delenv("DEFENSECLAW_GATEWAY_TOKEN", raising=False)
    monkeypatch.delenv("OPENCLAW_GATEWAY_TOKEN", raising=False)
    monkeypatch.setenv(stale_env_name, stale_cli_token)

    cfg = _cfg(str(tmp_path))
    result = _DoctorResult()
    with (
        patch(
            "defenseclaw.commands.cmd_doctor._trusted_gateway_listener",
            return_value=_trusted_gateway(str(tmp_path)),
        ),
        patch(
            "defenseclaw.commands.cmd_doctor._http_probe",
            return_value=(200, _runtime_document(str(tmp_path))),
        ),
    ):
        _check_gateway_auth(cfg, result)

    failures = [row for row in result.checks if row["status"] == "fail"]
    assert result.failed >= 1, result.to_dict()
    assert failures, result.to_dict()
    diagnostic = "\n".join(row["detail"] for row in failures)
    assert stale_env_name in diagnostic
    assert "unset" in diagnostic.lower() or "update" in diagnostic.lower()
    assert daemon_token not in repr(result.to_dict())
    assert stale_cli_token not in repr(result.to_dict())


@pytest.mark.parametrize(
    ("status_result", "expected_detail"),
    [
        pytest.param((0, "connection reset"), "could not be verified", id="transport-failure"),
        pytest.param((0, "redirect refused"), "could not be verified", id="redirect-refused"),
        pytest.param((500, "internal error"), "HTTP 500", id="http-500"),
    ],
)
def test_healthy_trusted_gateway_fails_when_status_auth_cannot_be_verified(
    tmp_path,
    status_result,
    expected_detail,
):
    """Public health success cannot turn an inconclusive auth probe green."""
    token = "status-probe-token-must-not-render"
    (tmp_path / ".env").write_text(
        f"DEFENSECLAW_GATEWAY_TOKEN={token}\n",
        encoding="utf-8",
    )
    os.chmod(tmp_path / ".env", 0o600)

    cfg = _cfg(str(tmp_path))
    result = _DoctorResult()
    with (
        patch(
            "defenseclaw.commands.cmd_doctor._trusted_gateway_listener",
            return_value=_trusted_gateway(str(tmp_path)),
        ),
        patch(
            "defenseclaw.commands.cmd_doctor._http_probe",
            side_effect=[(200, _healthy_document()), status_result],
        ),
    ):
        _check_sidecar(cfg, result)
        _check_gateway_auth(cfg, result)

    sidecar_row = next(row for row in result.checks if row["label"] == "Sidecar API")
    auth_row = next(row for row in result.checks if row["label"] == "Gateway authentication")
    assert sidecar_row["status"] == "pass"
    assert auth_row["status"] == "fail"
    assert result.failed == 1, result.to_dict()
    assert expected_detail in auth_row["detail"]
    assert token not in repr(result.to_dict())


@pytest.mark.parametrize(
    ("response_kind", "expected_detail"),
    [
        pytest.param("malformed", "metadata is malformed", id="malformed-json"),
        pytest.param("missing-runtime", "runtime PID is unavailable", id="missing-runtime"),
        pytest.param("invalid-pid", "runtime PID is unavailable", id="invalid-pid"),
        pytest.param("mismatched-pid", "identity does not match", id="mismatched-pid"),
        pytest.param("missing-data-dir", "data home is unavailable", id="missing-data-dir"),
        pytest.param("mismatched-data-dir", "different canonical data home", id="mismatched-data-dir"),
    ],
)
def test_gateway_auth_fails_closed_when_runtime_attestation_is_invalid(
    tmp_path,
    monkeypatch,
    response_kind,
    expected_detail,
):
    token = "runtime-attestation-token-must-not-render"
    (tmp_path / ".env").write_text(
        f"DEFENSECLAW_GATEWAY_TOKEN={token}\n",
        encoding="utf-8",
    )
    os.chmod(tmp_path / ".env", 0o600)
    monkeypatch.delenv("DEFENSECLAW_GATEWAY_TOKEN", raising=False)
    monkeypatch.delenv("OPENCLAW_GATEWAY_TOKEN", raising=False)

    bodies = {
        "malformed": "{",
        "missing-runtime": json.dumps({}),
        "invalid-pid": json.dumps({"runtime": {"pid": "not-a-pid", "data_dir": str(tmp_path)}}),
        "mismatched-pid": _runtime_document(str(tmp_path), pid=4243),
        "missing-data-dir": json.dumps({"runtime": {"pid": 4242}}),
        "mismatched-data-dir": _runtime_document(str(tmp_path / "other")),
    }

    result = _DoctorResult()
    with (
        patch(
            "defenseclaw.commands.cmd_doctor._trusted_gateway_listener",
            return_value=_trusted_gateway(str(tmp_path)),
        ),
        patch(
            "defenseclaw.commands.cmd_doctor._http_probe",
            return_value=(200, bodies[response_kind]),
        ),
    ):
        attempted = _check_gateway_auth(_cfg(str(tmp_path)), result)

    auth_row = next(row for row in result.checks if row["label"] == "Gateway authentication")
    assert attempted is True
    assert auth_row["status"] == "fail"
    assert expected_detail in auth_row["detail"]
    assert token not in repr(result.to_dict())
