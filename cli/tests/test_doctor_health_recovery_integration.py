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

"""Doctor integration contracts for compatibility and state recovery."""

from __future__ import annotations

import os
import sqlite3
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest
from defenseclaw.commands import cmd_doctor
from defenseclaw.commands.cmd_doctor import _DoctorResult, _GatewayTrust
from defenseclaw.doctor_engine import RepairDecision
from defenseclaw.doctor_gateway import ListenerEvidence
from defenseclaw.doctor_health import ComponentEvidence, HealthStatus
from defenseclaw.doctor_recovery import DeviceKeyHealthStatus, inspect_device_key


@pytest.fixture(autouse=True)
def _canonical_v8_validator_stub(monkeypatch):
    """Keep repair-graph tests independent of an installed gateway binary."""
    from defenseclaw.config_inspect import ConfigInspectError

    def inspect_v8_config(operation: str, *, config_path: str, **_kwargs):
        assert operation == "validate"
        with open(config_path, encoding="utf-8") as stream:
            config_text = stream.read()
        if config_text.strip() != "config_version: 8":
            raise ConfigInspectError("candidate field=config_version; reason=must equal 8")
        return SimpleNamespace(valid=True)

    monkeypatch.setattr(
        "defenseclaw.config_inspect.inspect_v8_config",
        inspect_v8_config,
    )


def _private_data_dir(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir(mode=0o700)
    from defenseclaw.file_permissions import make_private_directory

    make_private_directory(data_dir)
    return data_dir


def _cfg(data_dir, *, connector: str = "cursor"):
    config_path = data_dir / "config.yaml"
    if not config_path.exists():
        config_path.write_text("config_version: 8\n", encoding="utf-8")
    gateway = SimpleNamespace(
        device_key_file=os.fspath(data_dir / "device.key"),
        api_port=18789,
        api_host="127.0.0.1",
        host="127.0.0.1",
        resolved_token=lambda: "",
    )
    guardrail = SimpleNamespace(
        connector=connector,
        connectors={},
        effective_enabled=lambda _connector: True,
    )
    return SimpleNamespace(
        data_dir=os.fspath(data_dir),
        audit_db=os.fspath(data_dir / "audit.db"),
        gateway=gateway,
        guardrail=guardrail,
        active_connectors=lambda: [connector],
    )


def test_unsupported_connector_is_typed_and_never_blanket_applied(tmp_path) -> None:
    data_dir = _private_data_dir(tmp_path)
    cfg = _cfg(data_dir)
    discovery = SimpleNamespace(
        agents={
            "cursor": SimpleNamespace(
                installed=True,
                version="cursor 0.1.0",
                configured=True,
                active=True,
            )
        }
    )
    components = (
        ComponentEvidence("cli", "0.8.6"),
        ComponentEvidence("gateway", "0.8.6"),
        ComponentEvidence("plugin", "", status="missing"),
    )

    result = _DoctorResult()
    with (
        patch("defenseclaw.doctor_health.read_cached_discovery", return_value=discovery),
        patch("defenseclaw.doctor_health.probe_component_evidence", return_value=components),
    ):
        cmd_doctor._check_component_connector_compatibility(cfg, ["cursor"], result)

    connector = next(row for row in result.checks if row["check_id"] == "doctor.connector.cursor.compatibility")
    assert connector["status"] == "fail"
    assert connector["reason_code"] == "connector-version-outside-contract"
    assert "supported=" in connector["detail"]
    assert "trusted vendor distribution" in connector["remediation"]

    repairs = _DoctorResult(mode="repair")
    with (
        patch("defenseclaw.doctor_health.read_cached_discovery", return_value=discovery),
        patch.object(
            cmd_doctor,
            "_fix_connector_compatibility_review",
            side_effect=AssertionError("manual connector repair was executed"),
        ),
    ):
        cmd_doctor._run_fixers(
            cfg,
            repairs,
            assume_yes=True,
            json_out=True,
            fix_ids=("doctor.connector.compatibility.review",),
        )
    assert [row["state"] for row in repairs.repairs] == [
        "noop",
        "requires_confirmation",
    ]


def test_unsupported_connector_can_refresh_evidence_only_after_attended_approval(
    tmp_path,
) -> None:
    data_dir = _private_data_dir(tmp_path)
    cfg = _cfg(data_dir)
    discovery = SimpleNamespace(
        agents={
            "cursor": SimpleNamespace(
                installed=True,
                version="cursor 0.1.0",
                configured=True,
                active=True,
            )
        }
    )
    result = _DoctorResult(mode="repair")

    with (
        patch(
            "defenseclaw.doctor_health.read_cached_discovery",
            return_value=discovery,
        ),
        patch("click.confirm", return_value=True),
        patch(
            "defenseclaw.inventory.agent_discovery.discover_agents",
            return_value=discovery,
        ) as discover,
    ):
        cmd_doctor._run_fixers(
            cfg,
            result,
            assume_yes=False,
            json_out=False,
            fix_ids=("doctor.connector.compatibility.review",),
        )

    assert [row["state"] for row in result.repairs] == ["noop", "manual"]
    discover.assert_called_once_with(
        use_cache=False,
        refresh=True,
        data_dir=str(data_dir),
    )
    assert "no version change was attempted" in result.repairs[-1]["detail"]


def test_component_version_drift_is_in_fix_plan_but_never_blanket_applied(tmp_path) -> None:
    data_dir = _private_data_dir(tmp_path)
    cfg = _cfg(data_dir)
    components = (
        ComponentEvidence("cli", "0.8.6"),
        ComponentEvidence("gateway", "0.8.5"),
        ComponentEvidence("plugin", "", status="missing"),
    )
    result = _DoctorResult(mode="repair")

    with (
        patch(
            "defenseclaw.doctor_health.probe_component_evidence",
            return_value=components,
        ),
        patch.object(
            cmd_doctor,
            "_fix_component_compatibility_review",
            side_effect=AssertionError("component upgrade was executed"),
        ),
    ):
        cmd_doctor._run_fixers(
            cfg,
            result,
            assume_yes=True,
            json_out=True,
            fix_ids=("doctor.component.compatibility.review",),
        )

    assert [row["state"] for row in result.repairs] == ["noop", "manual"]
    assert "defenseclaw upgrade --version 0.8.6" in result.repairs[-1]["detail"]


def test_dry_run_projects_token_creation_into_token_env_plan(tmp_path) -> None:
    data_dir = _private_data_dir(tmp_path)
    (data_dir / "config.yaml").write_text("config_version: 8\n", encoding="utf-8")
    cfg = _cfg(data_dir)
    cfg.gateway.token_env = ""
    cfg.save = Mock()
    result = _DoctorResult(mode="plan", passive=True)

    with patch.dict(
        os.environ,
        {
            key: value
            for key, value in os.environ.items()
            if key not in {"DEFENSECLAW_GATEWAY_TOKEN", "OPENCLAW_GATEWAY_TOKEN"}
        },
        clear=True,
    ):
        cmd_doctor._run_fixers(
            cfg,
            result,
            assume_yes=True,
            json_out=True,
            dry_run=True,
            fix_ids=("doctor.gateway.token-env.canonicalize",),
        )

    assert [(row["repair_id"], row["state"]) for row in result.repairs] == [
        ("doctor.config.canonical-v8.preflight", "noop"),
        ("doctor.credentials.dotenv.protect", "noop"),
        ("doctor.gateway.token.ensure", "applicable"),
        ("doctor.gateway.token-env.canonicalize", "applicable"),
    ]
    assert "repoint gateway.token_env" in result.repairs[-1]["detail"]
    assert cfg.gateway.token_env == ""
    cfg.save.assert_not_called()
    assert not (data_dir / ".env").exists()


def test_projected_managed_token_discloses_live_gateway_restart_without_probe(
    tmp_path,
) -> None:
    data_dir = _private_data_dir(tmp_path)
    cfg = _cfg(data_dir)
    cfg._doctor_projected_repair_state_keys = (  # noqa: SLF001 - planner projection seam.
        "gateway-token-canonical-present",
    )
    trusted = _GatewayTrust(
        "trusted",
        "managed gateway identity is current",
        pid=4242,
        home_bound=True,
    )

    with (
        patch.object(cmd_doctor, "_managed_gateway_process_trust", return_value=trusted),
        patch.object(cmd_doctor, "pid_file_fingerprint", return_value=(1, 2, 3, 4, b"pid")),
        patch.object(
            cmd_doctor,
            "_daemon_effective_gateway_token",
            return_value=("", "", ""),
        ),
        patch.object(cmd_doctor, "_trusted_gateway_listener", return_value=trusted),
        patch.object(cmd_doctor, "_http_probe") as probe,
    ):
        tag, detail = cmd_doctor._fix_gateway_token_drift(
            cfg,
            assume_yes=True,
            plan_only=True,
        )

    assert tag == "plan"
    assert "restart verified sidecar pid 4242" in detail
    assert "no placeholder credential was sent" in detail
    probe.assert_not_called()


@pytest.mark.parametrize(
    ("projected_ids", "rotation_required"),
    (
        (("doctor.gateway.token.reconcile-runtime",), False),
        (("doctor.gateway.token.ensure",), True),
    ),
)
def test_projected_gateway_restart_subsumes_service_restart_plan(
    tmp_path,
    projected_ids,
    rotation_required,
) -> None:
    data_dir = _private_data_dir(tmp_path)
    cfg = _cfg(data_dir)
    cfg._doctor_projected_repair_ids = projected_ids  # noqa: SLF001 - planner seam.
    cfg._doctor_gateway_token_rotation_required = rotation_required  # noqa: SLF001

    with patch.object(cmd_doctor, "_http_probe") as probe:
        tag, detail = cmd_doctor._fix_gateway_service(
            cfg,
            assume_yes=True,
            plan_only=True,
        )

    assert tag == "skip"
    assert "already" in detail
    assert "restart" in detail
    probe.assert_not_called()


def test_projected_exposure_rotation_subsumes_runtime_token_restart(tmp_path) -> None:
    data_dir = _private_data_dir(tmp_path)
    cfg = _cfg(data_dir)
    cfg._doctor_projected_repair_ids = (  # noqa: SLF001 - planner projection seam.
        "doctor.gateway.token.ensure",
    )
    cfg._doctor_gateway_token_rotation_required = True  # noqa: SLF001

    with (
        patch.object(cmd_doctor, "_managed_gateway_process_trust") as process,
        patch.object(cmd_doctor, "_http_probe") as probe,
    ):
        tag, detail = cmd_doctor._fix_gateway_token_drift(
            cfg,
            assume_yes=True,
            plan_only=True,
        )

    assert tag == "skip"
    assert "A/B restart" in detail
    process.assert_not_called()
    probe.assert_not_called()


def test_dry_run_projects_stale_pid_removal_into_gateway_start_plan(tmp_path) -> None:
    data_dir = _private_data_dir(tmp_path)
    cfg = _cfg(data_dir)
    pid_file = data_dir / "gateway.pid"
    pid_file.write_text("not-a-pid\n", encoding="utf-8")
    os.chmod(pid_file, 0o600)
    noop = RepairDecision("noop", "already healthy")
    noop_fixer = Mock(return_value=("skip", "already converged"))
    result = _DoctorResult(mode="plan", passive=True)

    with (
        patch.object(cmd_doctor, "_plan_audit_db_recovery", return_value=noop),
        patch.object(cmd_doctor, "_plan_device_key_recovery", return_value=noop),
        patch.object(
            cmd_doctor,
            "_plan_component_compatibility_gate",
            return_value=noop,
        ),
        patch.object(
            cmd_doctor,
            "_plan_connector_compatibility_gate",
            return_value=noop,
        ),
        patch.object(cmd_doctor, "_fix_dotenv_perms", noop_fixer),
        patch.object(cmd_doctor, "_fix_gateway_token", noop_fixer),
        patch.object(cmd_doctor, "_fix_gateway_token_env", noop_fixer),
        patch.object(
            cmd_doctor,
            "_verified_listener_gateway_evidence",
            return_value=ListenerEvidence("missing", reason="not bound"),
        ),
        patch.object(
            cmd_doctor,
            "_managed_gateway_listener_evidence",
            return_value=ListenerEvidence("missing", reason="not bound"),
        ),
        patch.object(cmd_doctor, "_http_probe", return_value=(0, "unreachable")),
    ):
        cmd_doctor._run_fixers(
            cfg,
            result,
            assume_yes=True,
            json_out=True,
            dry_run=True,
            fix_ids=("doctor.gateway.service.reconcile",),
        )

    states = {
        row["repair_id"]: row["state"]
        for row in result.repairs
    }
    assert states["doctor.gateway.pid.remove-stale"] == "applicable"
    assert states["doctor.gateway.token.reconcile-runtime"] == "noop"
    assert states["doctor.gateway.service.reconcile"] == "applicable"
    assert "start the verified managed gateway" in next(
        row["detail"]
        for row in result.repairs
        if row["repair_id"] == "doctor.gateway.service.reconcile"
    )
    assert pid_file.read_text(encoding="utf-8") == "not-a-pid\n"


def test_exposed_legacy_token_plan_discloses_config_repoint(tmp_path) -> None:
    data_dir = _private_data_dir(tmp_path)
    cfg = _cfg(data_dir)
    cfg.gateway.token_env = "OPENCLAW_GATEWAY_TOKEN"
    cfg._doctor_gateway_token_rotation_required = True  # noqa: SLF001 - exposure precondition.

    with patch.object(
        cmd_doctor,
        "_daemon_effective_gateway_token",
        return_value=("existing-redacted-token", "OPENCLAW_GATEWAY_TOKEN", "managed dotenv"),
    ):
        tag, detail = cmd_doctor._fix_gateway_token(
            cfg,
            assume_yes=True,
            plan_only=True,
        )

    assert tag == "plan"
    assert "repoint gateway.token_env" in detail
    assert "OPENCLAW_GATEWAY_TOKEN" in detail
    assert "DEFENSECLAW_GATEWAY_TOKEN" in detail
    token_spec = next(
        spec
        for spec in cmd_doctor._doctor_repair_specs()
        if spec.repair_id == "doctor.gateway.token.ensure"
    )
    assert any("legacy token provider" in effect for effect in token_spec.effects)


def test_lifecycle_repairs_depend_on_compatibility_and_runtime_token_reconcile() -> None:
    specs = {spec.repair_id: spec for spec in cmd_doctor._doctor_repair_specs()}

    runtime = specs["doctor.gateway.token.reconcile-runtime"]
    service = specs["doctor.gateway.service.reconcile"]

    assert "doctor.component.compatibility.gate" in runtime.dependencies
    assert "doctor.connector.compatibility.gate" in runtime.dependencies
    assert "doctor.gateway.token.reconcile-runtime" in service.dependencies
    assert "doctor.component.compatibility.gate" in service.dependencies
    assert "doctor.connector.compatibility.gate" in service.dependencies


def test_unavailable_or_untested_compatibility_is_advisory_not_a_lifecycle_block(
    tmp_path,
) -> None:
    data_dir = _private_data_dir(tmp_path)
    cfg = _cfg(data_dir)
    component = SimpleNamespace(
        component="gateway",
        status=HealthStatus.UNAVAILABLE,
        reason_code="component-not-available",
    )
    connector = SimpleNamespace(
        connector="cursor",
        status=HealthStatus.UNTESTED,
        reason_code="connector-version-not-observed",
    )

    with (
        patch.object(
            cmd_doctor,
            "_component_compatibility_problems",
            return_value=(component,),
        ),
        patch.object(
            cmd_doctor,
            "_connector_compatibility_problems",
            return_value=(connector,),
        ),
    ):
        component_gate = cmd_doctor._plan_component_compatibility_gate(cfg)
        connector_gate = cmd_doctor._plan_connector_compatibility_gate(cfg)

    assert component_gate.state == "noop"
    assert connector_gate.state == "noop"
    assert "no positive" in component_gate.detail
    assert "no positively unsupported" in connector_gate.detail


def test_positive_unsupported_compatibility_blocks_gateway_lifecycle(tmp_path) -> None:
    data_dir = _private_data_dir(tmp_path)
    cfg = _cfg(data_dir)
    noop_fixer = Mock(return_value=("skip", "already converged"))
    token_drift = Mock(return_value=("pass", "must not restart"))
    service = Mock(return_value=("pass", "must not start"))
    unsupported = RepairDecision(
        "manual",
        "installed gateway version is outside the supported release contract",
    )
    result = _DoctorResult(mode="repair")

    with (
        patch.object(cmd_doctor, "_fix_stale_pid", noop_fixer),
        patch.object(cmd_doctor, "_fix_dotenv_perms", noop_fixer),
        patch.object(cmd_doctor, "_fix_gateway_token", noop_fixer),
        patch.object(cmd_doctor, "_fix_gateway_token_env", noop_fixer),
        patch.object(cmd_doctor, "_fix_gateway_token_drift", token_drift),
        patch.object(cmd_doctor, "_fix_gateway_service", service),
        patch.object(
            cmd_doctor,
            "_plan_audit_db_recovery",
            return_value=RepairDecision("noop", "healthy"),
        ),
        patch.object(
            cmd_doctor,
            "_plan_device_key_recovery",
            return_value=RepairDecision("noop", "healthy"),
        ),
        patch.object(
            cmd_doctor,
            "_plan_component_compatibility_gate",
            return_value=unsupported,
        ),
        patch.object(
            cmd_doctor,
            "_plan_connector_compatibility_gate",
            return_value=RepairDecision("noop", "supported"),
        ),
    ):
        cmd_doctor._run_fixers(
            cfg,
            result,
            assume_yes=True,
            json_out=True,
            fix_ids=("doctor.gateway.service.reconcile",),
        )

    token_drift.assert_not_called()
    service.assert_not_called()
    assert next(
        row
        for row in result.repairs
        if row["repair_id"] == "doctor.component.compatibility.gate"
    )["state"] == "manual"
    assert next(
        row
        for row in result.repairs
        if row["repair_id"] == "doctor.gateway.service.reconcile"
    )["state"] == "blocked"


@pytest.mark.parametrize("config_text", (None, "config_version: 7\n"))
def test_missing_or_noncanonical_config_blocks_every_real_repair(
    tmp_path,
    config_text,
) -> None:
    data_dir = _private_data_dir(tmp_path)
    cfg = _cfg(data_dir)
    config_path = data_dir / "config.yaml"
    if config_text is None:
        config_path.unlink()
    else:
        config_path.write_text(config_text, encoding="utf-8")
    cfg.save = Mock()
    appliers = {
        name: Mock(return_value=("pass", "must not run"))
        for name in (
            "_fix_stale_pid",
            "_fix_audit_db_recovery",
            "_fix_device_key_recovery",
            "_fix_gateway_token",
            "_fix_gateway_token_env",
            "_fix_gateway_token_drift",
            "_fix_gateway_service",
        )
    }
    result = _DoctorResult(mode="repair")

    with (
        patch.object(cmd_doctor, "_fix_stale_pid", appliers["_fix_stale_pid"]),
        patch.object(
            cmd_doctor,
            "_fix_audit_db_recovery",
            appliers["_fix_audit_db_recovery"],
        ),
        patch.object(
            cmd_doctor,
            "_fix_device_key_recovery",
            appliers["_fix_device_key_recovery"],
        ),
        patch.object(cmd_doctor, "_fix_gateway_token", appliers["_fix_gateway_token"]),
        patch.object(
            cmd_doctor,
            "_fix_gateway_token_env",
            appliers["_fix_gateway_token_env"],
        ),
        patch.object(
            cmd_doctor,
            "_fix_gateway_token_drift",
            appliers["_fix_gateway_token_drift"],
        ),
        patch.object(
            cmd_doctor,
            "_fix_gateway_service",
            appliers["_fix_gateway_service"],
        ),
    ):
        cmd_doctor._run_fixers(
            cfg,
            result,
            assume_yes=True,
            json_out=True,
            fix_ids=(
                "doctor.gateway.service.reconcile",
                "doctor.identity.device-key.initialize",
            ),
        )

    assert result.repairs[0]["repair_id"] == "doctor.config.canonical-v8.preflight"
    assert result.repairs[0]["state"] == "blocked"
    assert all(applier.call_count == 0 for applier in appliers.values())
    cfg.save.assert_not_called()
    assert not (data_dir / ".env").exists()
    assert not (data_dir / "audit.db").exists()
    assert not (data_dir / "device.key").exists()


def test_missing_audit_database_repair_initializes_verified_schema(tmp_path) -> None:
    data_dir = _private_data_dir(tmp_path)
    cfg = _cfg(data_dir)

    with patch.object(cmd_doctor, "_recovery_gateway_blocker", return_value=""):
        planned = cmd_doctor._plan_audit_db_recovery(cfg)
        tag, detail = cmd_doctor._fix_audit_db_recovery(cfg, assume_yes=True)

    assert planned.state == "applicable"
    assert tag == "pass", detail
    with sqlite3.connect(cfg.audit_db) as connection:
        assert connection.execute("PRAGMA quick_check").fetchone() == ("ok",)
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' AND name IN ('audit_events', 'scan_results', 'findings')"
            )
        }
        assert tables == {"audit_events", "scan_results", "findings"}


def test_audit_read_only_uri_preserves_question_and_fragment_path_bytes(
    tmp_path,
) -> None:
    data_dir = _private_data_dir(tmp_path)
    cfg = _cfg(data_dir)
    special_name = "audit#.db" if os.name == "nt" else "audit?#.db"
    cfg.audit_db = os.fspath(data_dir / special_name)

    with patch.object(cmd_doctor, "_recovery_gateway_blocker", return_value=""):
        tag, detail = cmd_doctor._fix_audit_db_recovery(cfg, assume_yes=True)
    assert tag == "pass", detail

    result = _DoctorResult()
    cmd_doctor._check_audit_db(cfg, result)

    assert result.checks[0]["status"] == "pass"
    assert result.checks[0]["reason_code"] == ""


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode custody regression")
def test_audit_check_and_repair_plan_reject_world_readable_database(tmp_path) -> None:
    data_dir = _private_data_dir(tmp_path)
    cfg = _cfg(data_dir)

    with patch.object(cmd_doctor, "_recovery_gateway_blocker", return_value=""):
        tag, detail = cmd_doctor._fix_audit_db_recovery(cfg, assume_yes=True)
    assert tag == "pass", detail
    os.chmod(cfg.audit_db, 0o644)

    result = _DoctorResult()
    cmd_doctor._check_audit_db(cfg, result)
    planned = cmd_doctor._plan_audit_db_recovery(cfg)

    assert result.checks[0]["status"] == "fail"
    assert result.checks[0]["reason_code"] == "audit-db-custody-invalid"
    assert planned.state == "blocked"
    assert planned.blockers == ("audit-db-custody-invalid",)


def test_audit_recovery_removes_stale_pid_dependency_in_one_run(tmp_path) -> None:
    data_dir = _private_data_dir(tmp_path)
    cfg = _cfg(data_dir)
    pid_file = data_dir / "gateway.pid"
    pid_file.write_text("not-a-pid\n", encoding="utf-8")
    os.chmod(pid_file, 0o600)

    result = _DoctorResult(mode="repair")
    with patch.object(
        cmd_doctor,
        "_verified_listener_gateway_evidence",
        return_value=ListenerEvidence("missing", reason="not bound"),
    ):
        cmd_doctor._run_fixers(
            cfg,
            result,
            assume_yes=True,
            json_out=True,
            fix_ids=("doctor.state.audit-db.initialize",),
        )

    assert [(row["repair_id"], row["state"]) for row in result.repairs] == [
        ("doctor.config.canonical-v8.preflight", "noop"),
        ("doctor.gateway.pid.remove-stale", "applied"),
        ("doctor.state.audit-db.initialize", "applied"),
    ]
    assert not pid_file.exists()
    assert os.path.exists(cfg.audit_db)


def test_audit_recovery_dry_run_projects_stale_pid_removal_without_writes(tmp_path) -> None:
    data_dir = _private_data_dir(tmp_path)
    cfg = _cfg(data_dir)
    pid_file = data_dir / "gateway.pid"
    pid_file.write_text("not-a-pid\n", encoding="utf-8")
    os.chmod(pid_file, 0o600)

    result = _DoctorResult(mode="plan", passive=True)
    with patch.object(
        cmd_doctor,
        "_verified_listener_gateway_evidence",
        return_value=ListenerEvidence("missing", reason="not bound"),
    ):
        cmd_doctor._run_fixers(
            cfg,
            result,
            assume_yes=True,
            json_out=True,
            dry_run=True,
            fix_ids=("doctor.state.audit-db.initialize",),
        )

    assert [(row["repair_id"], row["state"]) for row in result.repairs] == [
        ("doctor.config.canonical-v8.preflight", "noop"),
        ("doctor.gateway.pid.remove-stale", "applicable"),
        ("doctor.state.audit-db.initialize", "applicable"),
    ]
    assert pid_file.read_text(encoding="utf-8") == "not-a-pid\n"
    assert not os.path.exists(cfg.audit_db)


def test_audit_recovery_dry_run_does_not_project_noop_pid_as_absent(tmp_path) -> None:
    data_dir = _private_data_dir(tmp_path)
    cfg = _cfg(data_dir)
    result = _DoctorResult(mode="plan", passive=True)

    with (
        patch.object(
            cmd_doctor,
            "_fix_stale_pid",
            return_value=("skip", "pid belongs to the current managed gateway"),
        ),
        patch.object(
            cmd_doctor,
            "_managed_gateway_process_trust",
            return_value=_GatewayTrust(
                "trusted",
                "managed gateway process identity is current",
                pid=4242,
                home_bound=True,
            ),
        ),
        patch.object(
            cmd_doctor,
            "_verified_listener_gateway_evidence",
            return_value=ListenerEvidence("missing", reason="not bound yet"),
        ),
    ):
        cmd_doctor._run_fixers(
            cfg,
            result,
            assume_yes=True,
            json_out=True,
            dry_run=True,
            fix_ids=("doctor.state.audit-db.initialize",),
        )

    assert [(row["repair_id"], row["state"]) for row in result.repairs] == [
        ("doctor.config.canonical-v8.preflight", "noop"),
        ("doctor.gateway.pid.remove-stale", "noop"),
        ("doctor.state.audit-db.initialize", "blocked"),
    ]
    assert "gateway process is running" in result.repairs[-1]["detail"]
    assert not os.path.exists(cfg.audit_db)


def test_existing_corrupt_state_blocks_lifecycle_without_replacement(tmp_path) -> None:
    data_dir = _private_data_dir(tmp_path)
    cfg = _cfg(data_dir)
    audit_path = data_dir / "audit.db"
    device_path = data_dir / "device.key"
    audit_path.write_bytes(b"not a sqlite database")
    device_path.write_bytes(b"not an Ed25519 private key")
    os.chmod(audit_path, 0o600)
    os.chmod(device_path, 0o600)

    audit_plan = cmd_doctor._plan_audit_db_recovery(cfg)
    device_plan = cmd_doctor._plan_device_key_recovery(cfg)
    assert audit_plan.state == "blocked"
    assert device_plan.state == "blocked"
    assert "will not replace it" in audit_plan.detail
    assert "will not replace it" in device_plan.detail

    token_drift = Mock(return_value=("pass", "must not restart"))
    service = Mock(return_value=("pass", "must not start"))
    noop_fixer = Mock(return_value=("skip", "already converged"))
    result = _DoctorResult(mode="repair")
    with (
        patch.object(cmd_doctor, "_fix_stale_pid", noop_fixer),
        patch.object(cmd_doctor, "_fix_dotenv_perms", noop_fixer),
        patch.object(cmd_doctor, "_fix_gateway_token", noop_fixer),
        patch.object(cmd_doctor, "_fix_gateway_token_env", noop_fixer),
        patch.object(cmd_doctor, "_fix_gateway_token_drift", token_drift),
        patch.object(cmd_doctor, "_fix_gateway_service", service),
        patch.object(
            cmd_doctor,
            "_plan_component_compatibility_gate",
            return_value=RepairDecision("noop", "supported"),
        ),
        patch.object(
            cmd_doctor,
            "_plan_connector_compatibility_gate",
            return_value=RepairDecision("noop", "supported"),
        ),
    ):
        cmd_doctor._run_fixers(
            cfg,
            result,
            assume_yes=True,
            json_out=True,
            fix_ids=("doctor.gateway.service.reconcile",),
        )

    token_drift.assert_not_called()
    service.assert_not_called()
    assert next(
        row
        for row in result.repairs
        if row["repair_id"] == "doctor.gateway.service.reconcile"
    )["state"] == "blocked"
    assert audit_path.read_bytes() == b"not a sqlite database"
    assert device_path.read_bytes() == b"not an Ed25519 private key"


def test_recovery_requires_managed_process_absence_before_listener_absence(
    tmp_path,
) -> None:
    data_dir = _private_data_dir(tmp_path)
    cfg = _cfg(data_dir)

    with (
        patch.object(
            cmd_doctor,
            "_managed_gateway_process_trust",
            return_value=_GatewayTrust(
                "trusted",
                "managed gateway process identity is current",
                pid=4242,
                home_bound=True,
            ),
        ),
        patch.object(
            cmd_doctor,
            "_verified_listener_gateway_evidence",
            return_value=ListenerEvidence("missing", reason="not bound yet"),
        ) as listener,
    ):
        blocker = cmd_doctor._recovery_gateway_blocker(cfg)

    assert "gateway process is running" in blocker
    listener.assert_not_called()


def test_device_identity_requires_explicit_attended_repair(tmp_path) -> None:
    data_dir = _private_data_dir(tmp_path)
    cfg = _cfg(data_dir)
    result = _DoctorResult(mode="repair")

    health = _DoctorResult()
    cmd_doctor._check_device_identity(cfg, health)
    assert health.checks[-1]["status"] == "fail"
    assert health.checks[-1]["reason_code"] == "device-key-missing"
    assert "doctor.identity.device-key.initialize" in health.checks[-1]["remediation"]

    with patch.object(cmd_doctor, "_recovery_gateway_blocker", return_value=""):
        cmd_doctor._run_fixers(
            cfg,
            result,
            assume_yes=True,
            json_out=True,
            fix_ids=("doctor.identity.device-key.initialize",),
        )

    assert [(row["repair_id"], row["state"]) for row in result.repairs] == [
        ("doctor.config.canonical-v8.preflight", "noop"),
        ("doctor.gateway.pid.remove-stale", "noop"),
        ("doctor.identity.device-key.initialize", "requires_confirmation"),
    ]
    assert not os.path.exists(cfg.gateway.device_key_file)

    with (
        patch.object(cmd_doctor, "_recovery_gateway_blocker", return_value=""),
        patch("click.confirm", return_value=True),
    ):
        tag, detail = cmd_doctor._fix_device_key_recovery(cfg, assume_yes=False)
    assert tag == "pass", detail
    assert (
        inspect_device_key(
            cfg.gateway.device_key_file,
            data_dir=cfg.data_dir,
        ).status
        is DeviceKeyHealthStatus.VALID
    )
    repaired_health = _DoctorResult()
    cmd_doctor._check_device_identity(cfg, repaired_health)
    assert repaired_health.checks[-1]["status"] == "pass"
    assert repaired_health.checks[-1]["reason_code"] == "device-key-provenance-valid"
