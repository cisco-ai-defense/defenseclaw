# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Contract tests for the Python CLI's canonical-v8 logger handoff."""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import click
import pytest
import requests
from click.testing import CliRunner
from defenseclaw import config as config_module
from defenseclaw.audit_actions import ACTION_POLICY_RELOAD
from defenseclaw.logger import (
    CanonicalObservabilityError,
    CanonicalObservabilityUnavailableError,
    Logger,
)
from defenseclaw.main import cli
from defenseclaw.models import Finding, ScanResult
from urllib3.exceptions import NewConnectionError


class _Recorder:
    def __init__(self) -> None:
        self.payloads: list[dict] = []
        self.closed = False

    def emit_cli_observability(self, payload) -> None:
        self.payloads.append(dict(payload))

    def close(self) -> None:
        self.closed = True


@pytest.mark.parametrize(
    ("document", "expected"),
    [
        ("config_version: 8\n", 8),
        ('config_version: "8"\n', 8),
        ("config_version: true\n", 0),
        ("config_version: 8\nconfig_version: 8\n", 0),
        ("- config_version\n- 8\n", 0),
        ("data_dir: /tmp/example\n", 0),
    ],
)
def test_config_version_preflight_reads_only_one_exact_discriminator(
    tmp_path: Path,
    document: str,
    expected: int,
) -> None:
    path = tmp_path / "config.yaml"
    path.write_text(document, encoding="utf-8")
    assert config_module.source_config_version(path=str(path)) == expected


def test_config_version_preflight_rejects_malformed_yaml(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("config_version: [8\n", encoding="utf-8")
    with pytest.raises(config_module.ConfigVersionError, match="schema version"):
        config_module.source_config_version(path=str(path))


def test_config_version_preflight_normalizes_invalid_utf8(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_bytes(b"config_version: 8\ninvalid: \xff\n")
    with pytest.raises(config_module.ConfigVersionError, match="schema version"):
        config_module.source_config_version(path=str(path))


def test_activity_preserves_raw_source_for_route_specific_redaction() -> None:
    recorder = _Recorder()
    logger = Logger(recorder)
    logger.log_activity(
        actor="cli:alice",
        action=ACTION_POLICY_RELOAD,
        target_type="policy",
        target_id="default",
        before={"owner": "alice@example.com", "mode": "warn"},
        after={"owner": "alice@example.com", "mode": "block"},
        diff=[
            {
                "path": "mode",
                "op": "replace",
                "before": "warn",
                "after": "block",
            }
        ],
        version_from="abc123",
        version_to="def456",
    )

    assert recorder.payloads == [
        {
            "kind": "activity",
            "run_id": "",
            "activity": {
                "actor": "cli:alice",
                "action": ACTION_POLICY_RELOAD,
                "target_type": "policy",
                "target_id": "default",
                "before": {"owner": "alice@example.com", "mode": "warn"},
                "after": {"owner": "alice@example.com", "mode": "block"},
                "diff": [
                    {
                        "path": "mode",
                        "op": "replace",
                        "before": "warn",
                        "after": "block",
                    }
                ],
                "version_from": "abc123",
                "version_to": "def456",
                "severity": "INFO",
            },
        }
    ]


def test_action_alert_and_scan_use_one_canonical_ingress() -> None:
    recorder = _Recorder()
    logger = Logger(recorder)
    with patch.dict(os.environ, {"DEFENSECLAW_RUN_ID": "python-run-id"}):
        logger.log_action("policy-reload", "default", "owner=alice@example.com")
        logger.log_alert(
            "scanner",
            "HIGH",
            "skill-scanner timed out",
            {"duration_ms": 30_000},
        )
        logger.log_scan(
            ScanResult(
                scanner="skill-scanner",
                target="/tmp/skill",
                timestamp=datetime(2026, 7, 6, tzinfo=timezone.utc),
                findings=[
                    Finding(
                        id="finding-1",
                        severity="HIGH",
                        title="Unsafe instruction",
                        description="contact alice@example.com",
                        scanner="skill-scanner",
                    )
                ],
                duration=timedelta(milliseconds=1250),
            )
        )

    assert [payload["kind"] for payload in recorder.payloads] == ["action", "alert", "scan"]
    assert all(payload["run_id"] == "python-run-id" for payload in recorder.payloads)
    assert recorder.payloads[0]["action"]["details"] == "owner=alice@example.com"
    assert recorder.payloads[1]["alert"]["details"] == {"duration_ms": 30_000}
    assert recorder.payloads[2]["scan"]["duration_ms"] == 1250
    assert recorder.payloads[2]["scan"]["findings"][0]["description"] == "contact alice@example.com"


def test_python_finding_wire_shape_matches_canonical_ingress_dto() -> None:
    finding = Finding(
        id="finding-1",
        severity="HIGH",
        title="Unsafe instruction",
        description="source-backed evidence",
        location="SKILL.md:7",
        remediation="Remove the instruction",
        scanner="skill-scanner",
        tags=["prompt-injection"],
        rule_id="skill.rule-1",
        line_number=7,
    )

    assert finding.to_dict() == {
        "id": "finding-1",
        "severity": "HIGH",
        "title": "Unsafe instruction",
        "description": "source-backed evidence",
        "location": "SKILL.md:7",
        "remediation": "Remove the instruction",
        "scanner": "skill-scanner",
        "tags": ["prompt-injection"],
        "rule_id": "skill.rule-1",
        "line_number": 7,
    }
    assert Finding(id="finding-2", severity="INFO", title="Informational").to_dict() == {
        "id": "finding-2",
        "severity": "INFO",
        "title": "Informational",
        "description": "",
        "location": "",
        "remediation": "",
        "scanner": "",
        "tags": [],
    }


def test_logger_rejects_store_shaped_legacy_dependency() -> None:
    with pytest.raises(TypeError, match="canonical Observability v8 recorder"):
        Logger(object())


def test_transport_failure_is_bounded_and_fails_closed() -> None:
    class BrokenRecorder:
        def emit_cli_observability(self, _payload) -> None:
            raise RuntimeError("private endpoint and source payload")

        def close(self) -> None:
            return

    with pytest.raises(
        CanonicalObservabilityError,
        match="canonical Observability v8 admission was not confirmed",
    ) as caught:
        Logger(BrokenRecorder()).log_action("policy-reload", "default", "secret")
    assert "private endpoint" not in str(caught.value)
    assert "secret" not in str(caught.value)


def test_from_config_is_lazy_and_builds_authenticated_gateway_client_on_emit() -> None:
    gateway = SimpleNamespace(
        api_bind="0.0.0.0",
        api_port=18970,
        resolved_token=lambda: "gateway-token",
    )
    cfg = SimpleNamespace(config_version=8, gateway=gateway, openshell=None, guardrail=None)
    recorder = _Recorder()
    with patch("defenseclaw.logger.OrchestratorClient", return_value=recorder) as client:
        logger = Logger.from_config(cfg)
        client.assert_not_called()
        logger.log_action("policy-reload", "default", "changed")
    client.assert_called_once_with(host="127.0.0.1", port=18970, timeout=10, token="gateway-token")
    assert recorder.payloads[0]["kind"] == "action"
    assert recorder.closed


def test_from_config_defers_missing_auth_failure_until_emit() -> None:
    cfg = SimpleNamespace(
        config_version=8,
        gateway=SimpleNamespace(
            api_bind="",
            api_port=18970,
            resolved_token=lambda: "",
        ),
        openshell=None,
        guardrail=None,
    )
    logger = Logger.from_config(cfg)
    with pytest.raises(CanonicalObservabilityUnavailableError, match="authentication is unavailable"):
        logger.log_action("policy-reload", "default", "changed")


@pytest.mark.parametrize(
    "transport_error",
    [
        requests.ConnectTimeout("connect timed out"),
        requests.ConnectionError(NewConnectionError(None, "connection refused")),
    ],
)
def test_from_config_classifies_only_preconnect_failure_as_unavailable(
    transport_error: requests.RequestException,
) -> None:
    cfg = SimpleNamespace(
        config_version=8,
        gateway=SimpleNamespace(
            api_bind="127.0.0.1",
            api_port=18970,
            resolved_token=lambda: "gateway-token",
        ),
        openshell=None,
        guardrail=None,
    )

    class OfflineRecorder:
        def emit_cli_observability(self, _payload) -> None:
            raise transport_error

        def close(self) -> None:
            return

    with (
        patch("defenseclaw.logger.OrchestratorClient", return_value=OfflineRecorder()),
        pytest.raises(CanonicalObservabilityUnavailableError, match="runtime is unavailable") as caught,
    ):
        Logger.from_config(cfg).log_action("setup-hook-connector", "config", "secret")
    assert "private endpoint" not in str(caught.value)
    assert "secret" not in str(caught.value)


@pytest.mark.parametrize(
    "transport_error",
    [
        requests.ReadTimeout("private read timeout"),
        requests.Timeout("private ambiguous timeout"),
        requests.ConnectionError("private post-write reset"),
    ],
)
def test_from_config_keeps_ambiguous_transport_failure_fail_closed(
    transport_error: requests.RequestException,
) -> None:
    cfg = SimpleNamespace(
        config_version=8,
        gateway=SimpleNamespace(
            api_bind="127.0.0.1",
            api_port=18970,
            resolved_token=lambda: "gateway-token",
        ),
        openshell=None,
        guardrail=None,
    )

    class AmbiguousRecorder:
        def emit_cli_observability(self, _payload) -> None:
            raise transport_error

        def close(self) -> None:
            return

    with (
        patch("defenseclaw.logger.OrchestratorClient", return_value=AmbiguousRecorder()),
        pytest.raises(CanonicalObservabilityError) as caught,
    ):
        Logger.from_config(cfg).log_action("setup-hook-connector", "config", "secret")
    assert type(caught.value) is CanonicalObservabilityError
    assert "private" not in str(caught.value)
    assert "secret" not in str(caught.value)


def test_from_config_keeps_server_rejection_fail_closed() -> None:
    cfg = SimpleNamespace(
        config_version=8,
        gateway=SimpleNamespace(
            api_bind="127.0.0.1",
            api_port=18970,
            resolved_token=lambda: "gateway-token",
        ),
        openshell=None,
        guardrail=None,
    )

    class RejectingRecorder:
        def emit_cli_observability(self, _payload) -> None:
            raise requests.HTTPError("private rejection body")

        def close(self) -> None:
            return

    with (
        patch("defenseclaw.logger.OrchestratorClient", return_value=RejectingRecorder()),
        pytest.raises(CanonicalObservabilityError) as caught,
    ):
        Logger.from_config(cfg).log_action("setup-hook-connector", "config", "secret")
    assert type(caught.value) is CanonicalObservabilityError
    assert "private rejection body" not in str(caught.value)
    assert "secret" not in str(caught.value)


def test_from_config_refreshes_token_created_after_logger_initialization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("DEFENSECLAW_GATEWAY_TOKEN", raising=False)
    gateway = SimpleNamespace(
        api_bind="127.0.0.1",
        api_port=18970,
        resolved_token=lambda: os.environ.get("DEFENSECLAW_GATEWAY_TOKEN", ""),
    )
    cfg = SimpleNamespace(
        config_version=8,
        data_dir=str(tmp_path),
        gateway=gateway,
        openshell=None,
        guardrail=None,
    )
    logger = Logger.from_config(cfg)

    # Model EnsureGatewayToken writing .env during the command's first
    # gateway restart, after config and Logger were already constructed.
    (tmp_path / ".env").write_text("DEFENSECLAW_GATEWAY_TOKEN=fresh-token\n", encoding="utf-8")
    recorder = _Recorder()
    with patch("defenseclaw.logger.OrchestratorClient", return_value=recorder) as client:
        logger.log_action("setup-hook-connector", "config", "connector=codex")

    client.assert_called_once_with(host="127.0.0.1", port=18970, timeout=10, token="fresh-token")
    assert recorder.payloads[0]["kind"] == "action"
    assert recorder.closed


def test_explicit_no_runtime_capability_buffers_and_writes_nothing() -> None:
    logger = Logger.no_runtime()
    logger.log_action("policy-reload", "default", "owner=alice@example.com")
    logger.log_activity(
        actor="cli:alice",
        action="policy-reload",
        target_type="policy",
        target_id="default",
        before={"owner": "alice@example.com"},
    )
    logger.close()


def test_no_runtime_capability_is_confined_to_bootstrap_and_recovery() -> None:
    package = Path(__file__).resolve().parents[1] / "defenseclaw"
    callers = {
        path.relative_to(package).as_posix()
        for path in package.rglob("*.py")
        if path.name != "logger.py" and "Logger.no_runtime()" in path.read_text()
    }
    assert callers == {
        "bootstrap.py",
        "commands/cmd_init.py",
        "main.py",
    }


def test_ordinary_command_rejects_v7_before_logger_construction() -> None:
    with (
        patch("defenseclaw.config.source_config_version", return_value=7),
        patch("defenseclaw.config.load") as config_loader,
        patch("defenseclaw.logger.Logger.from_config") as logger_factory,
    ):
        result = CliRunner().invoke(cli, ["status"])
    assert result.exit_code == 1
    assert "run 'defenseclaw upgrade' first" in result.output
    config_loader.assert_not_called()
    logger_factory.assert_not_called()


def test_upgrade_can_migrate_v7_without_constructing_runtime_logger() -> None:
    legacy = SimpleNamespace(_source_config_version=7, audit_db="legacy.db")

    @click.command("upgrade")
    def upgrade_probe() -> None:
        click.echo("upgrade-v7-command-ran")

    previous = cli.commands["upgrade"]
    cli.commands["upgrade"] = upgrade_probe
    try:
        with (
            patch("defenseclaw.config.load", return_value=legacy),
            patch("defenseclaw.db.Store") as store_factory,
            patch("defenseclaw.logger.Logger.from_config") as runtime_factory,
            patch("defenseclaw.logger.Logger.no_runtime") as recovery_factory,
        ):
            result = CliRunner().invoke(cli, ["upgrade"])
    finally:
        cli.commands["upgrade"] = previous

    assert result.exit_code == 0, result.output
    assert "upgrade-v7-command-ran" in result.output
    store_factory.assert_not_called()
    runtime_factory.assert_not_called()
    recovery_factory.assert_not_called()


def test_real_v8_config_reaches_an_ordinary_command(tmp_path: Path) -> None:
    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        "\n".join(
            (
                "config_version: 8",
                f'data_dir: "{tmp_path}"',
                "observability:",
                "  local:",
                f'    path: "{tmp_path / "audit.db"}"',
            )
        )
        + "\n",
        encoding="utf-8",
    )

    @click.command("v8-gate-probe")
    def probe() -> None:
        click.echo("ordinary-v8-command-ran")

    cli.add_command(probe)
    store = SimpleNamespace(init=lambda: None, close=lambda: None)
    logger = SimpleNamespace(close=lambda: None)
    try:
        with (
            patch.dict(
                os.environ,
                {
                    "DEFENSECLAW_CONFIG": str(config_file),
                    "DEFENSECLAW_HOME": str(tmp_path),
                },
            ),
            patch("defenseclaw.db.Store", return_value=store),
            patch("defenseclaw.logger.Logger.from_config", return_value=logger) as logger_factory,
            patch(
                "defenseclaw.commands.cmd_config.validate_config",
                return_value=SimpleNamespace(ok=True, parse_error="", errors=[]),
            ),
        ):
            result = CliRunner().invoke(cli, ["v8-gate-probe"])
    finally:
        cli.commands.pop("v8-gate-probe", None)

    assert result.exit_code == 0, result.output
    assert "ordinary-v8-command-ran" in result.output
    logger_factory.assert_called_once()


def test_close_closes_only_the_canonical_transport() -> None:
    recorder = _Recorder()
    logger = Logger(recorder)
    logger.close()
    assert recorder.closed
