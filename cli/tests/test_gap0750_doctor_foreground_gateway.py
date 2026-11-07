"""GAP-0750: Doctor, status and the gateway CLI name a foreground gateway alike.

A gateway started in the foreground has no PID file. Status proves it is this
account's own process (_foreground_gateway_status_owner). Doctor used its own
port-holder test and called the same process foreign, telling the user to
stop it. Doctor now asks the same proof; the token stays unsent.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from defenseclaw.commands import cmd_doctor
from defenseclaw.doctor_gateway import ListenerEvidence, PIDRecord

from tests.test_cmd_doctor_windows_gateway import FakeEvidence
from tests.test_gap0604_foreground_status import _proof

UNVERIFIED = "gateway listener identity is unverified: no PID file"


@pytest.fixture
def cfg(tmp_path: Path):
    data_dir = tmp_path / "home"
    data_dir.mkdir()
    return SimpleNamespace(
        data_dir=str(data_dir),
        deployment_mode="",
        gateway=SimpleNamespace(api_bind="127.0.0.1", api_port=18789),
    )


def _run_sidecar(cfg, platform: str, *, probe=(0, UNVERIFIED), **changes):
    stack, _ = _proof(platform, **changes)
    r = cmd_doctor._DoctorResult(quiet=True)
    with (
        stack,
        patch.object(
            cmd_doctor, "_trusted_gateway_listener", return_value=cmd_doctor._GatewayTrust("missing", "no PID file")
        ),
        patch.object(cmd_doctor, "_gateway_start_in_progress", return_value=(False, None)),
        patch.object(cmd_doctor, "_gateway_health_probe", return_value=probe),
    ):
        cmd_doctor._check_sidecar(cfg, r)
    return r


def _sidecar_rows(r):
    return [c for c in r.checks if c["label"] == "Sidecar API"]


@pytest.mark.parametrize("platform", ["win32", "darwin"])
@pytest.mark.parametrize("probe", [(0, UNVERIFIED), (0, "connection reset"), (503, "unavailable")])
def test_own_foreground_gateway_is_not_called_foreign(cfg, platform: str, probe) -> None:
    r = _run_sidecar(cfg, platform, probe=probe, listener_pids=(4242, 4242, 4242, 4242))
    rows = _sidecar_rows(r)
    assert [row["status"] for row in rows] == ["warn"]
    text = rows[0]["detail"] + " " + str(rows[0]["remediation"])
    assert "PID 4242" in text
    assert "own foreground gateway" in text
    assert "token are skipped" in text
    assert "not by this account" not in text
    assert "Stop that process" not in text
    assert "setup gateway --api-port" not in text
    assert r.failed == 0
    assert r.sidecar_unverified is True
    assert r.gateway_down == "foreground"


@pytest.mark.parametrize("platform", ["win32", "darwin"])
def test_doctor_row_and_status_name_the_same_process(cfg, platform: str) -> None:
    stack, _ = _proof(platform, listener_pids=(4242, 4242, 4242, 4242))
    with stack:
        owner = cmd_doctor._foreground_gateway_status_owner(cfg)
        assert owner is not None
        assert cmd_doctor._foreign_gateway_port_holder(cfg, status_only=True) == ""
    r = _run_sidecar(cfg, platform, listener_pids=(4242, 4242, 4242, 4242))
    assert f"PID {owner.pid}" in _sidecar_rows(r)[0]["detail"]


@pytest.mark.parametrize(
    ("platform", "changes"),
    [("win32", {"peer_sid": "S-1-5-21-2000"}), ("darwin", {"process_uid": 2000})],
)
def test_other_account_holder_stays_foreign(cfg, platform: str, changes: dict) -> None:
    r = _run_sidecar(cfg, platform, **changes)
    rows = _sidecar_rows(r)
    assert [row["status"] for row in rows] == ["fail"]
    assert "held by PID 4242" in rows[0]["detail"]
    assert "own foreground gateway" not in rows[0]["detail"]
    assert r.gateway_down == "foreign"


@pytest.mark.parametrize("platform", ["win32", "darwin"])
def test_no_listener_is_still_a_stopped_gateway(cfg, platform: str) -> None:
    stack, _ = _proof(platform, listener_pids=(None, None, None, None))
    r = cmd_doctor._DoctorResult(quiet=True)
    with (
        stack,
        patch.object(cmd_doctor, "_gateway_port_holder", return_value=""),
        patch.object(
            cmd_doctor, "_trusted_gateway_listener", return_value=cmd_doctor._GatewayTrust("missing", "no PID file")
        ),
        patch.object(cmd_doctor, "_gateway_start_in_progress", return_value=(False, None)),
        patch.object(cmd_doctor, "_gateway_health_probe", return_value=(0, "connection refused")),
    ):
        cmd_doctor._check_sidecar(cfg, r)
    rows = _sidecar_rows(r)
    assert [row["status"] for row in rows] == ["fail"]
    assert "not running" in rows[0]["detail"]
    assert r.gateway_down == "stopped"


@pytest.mark.parametrize("platform", ["linux"])
def test_proof_is_not_used_on_linux(cfg, platform: str) -> None:
    stack, _ = _proof(platform)
    with stack:
        assert cmd_doctor._own_foreground_gateway(cfg) is None


def test_failed_proof_is_not_proven(cfg) -> None:
    with patch.object(cmd_doctor, "_foreground_gateway_status_owner", side_effect=OSError("denied")):
        assert cmd_doctor._own_foreground_gateway(cfg) is None


@pytest.mark.parametrize("platform", ["win32", "darwin"])
def test_policy_row_is_skipped_not_failed_for_a_foreground_gateway(cfg, platform: str) -> None:
    r = _run_sidecar(cfg, platform, listener_pids=(4242, 4242, 4242, 4242))
    with patch.object(cmd_doctor, "_doctor_secure_client", return_value=False):
        cmd_doctor._check_policy_state(cfg, r, live_health=None)
    policy = [c for c in r.checks if c["label"] == "Policy"]
    assert [row["status"] for row in policy] == ["skip"]
    assert r.failed == 0


@pytest.mark.parametrize("platform", ["win32", "darwin"])
def test_fix_does_not_restart_or_blame_a_foreground_gateway(cfg, platform: str) -> None:
    stack, _ = _proof(platform, listener_pids=(4242, 4242, 4242, 4242))
    with (
        stack,
        patch.object(cmd_doctor, "_doctor_config_present", return_value=True),
        patch.object(cmd_doctor, "_gateway_health_probe", return_value=(0, UNVERIFIED)),
        patch.object(
            cmd_doctor, "_trusted_gateway_listener_for_lifecycle",
            return_value=cmd_doctor._GatewayTrust("missing", "no PID file"),
        ),
    ):
        status, detail = cmd_doctor._fix_gateway_service(cfg, assume_yes=True, plan_only=True)
    assert status == "skip"
    assert "own foreground gateway (PID 4242)" in detail
    assert "Stop that process" not in detail


@pytest.mark.parametrize(
    ("platform", "changes"),
    [("win32", {"peer_sid": "S-1-5-21-2000"}), ("darwin", {"process_uid": 2000})],
)
def test_fix_still_refuses_another_accounts_holder(cfg, platform: str, changes: dict) -> None:
    stack, _ = _proof(platform, **changes)
    with (
        stack,
        patch.object(cmd_doctor, "_doctor_config_present", return_value=True),
        patch.object(cmd_doctor, "_gateway_health_probe", return_value=(0, UNVERIFIED)),
        patch.object(
            cmd_doctor, "_trusted_gateway_listener_for_lifecycle",
            return_value=cmd_doctor._GatewayTrust("missing", "no PID file"),
        ),
    ):
        status, detail = cmd_doctor._fix_gateway_service(cfg, assume_yes=True, plan_only=True)
    assert status == "fail"
    assert "held by PID 4242" in detail


WINDOWS_ROWS = ("Gateway PID identity", "Gateway listener owner", "Gateway token drift", "Gateway home")


def _windows_pass(cfg, r, *, proof_changes=None, listener=None, gateway_down=None):
    """Run the Windows gateway diagnostics after the Sidecar row, as Doctor does."""
    if gateway_down is not None:
        r.gateway_down = gateway_down
    stack, probe = _proof("win32", listener_pids=(4242, 4242, 4242, 4242), **(proof_changes or {}))
    evidence = FakeEvidence(record=PIDRecord("missing"), listener=listener)
    with stack, patch.object(cmd_doctor, "_daemon_effective_gateway_token", return_value=("dummy", "", "test")):
        cmd_doctor._check_windows_gateway_diagnostics(cfg, r, evidence=evidence, platform_name="win32")
    return probe


def _windows_rows(r):
    return {c["label"]: c for c in r.checks if c["label"] in WINDOWS_ROWS}


def test_windows_diagnostics_do_not_fail_the_proven_foreground_gateway(cfg) -> None:
    r = _run_sidecar(cfg, "win32", listener_pids=(4242, 4242, 4242, 4242))
    assert r.gateway_down == "foreground"
    probe = _windows_pass(cfg, r)
    rows = _windows_rows(r)
    assert set(rows) == set(WINDOWS_ROWS)
    assert {row["status"] for row in rows.values()} == {"skip"}
    assert all("PID 4242" in row["detail"] and "own foreground gateway" in row["detail"] for row in rows.values())
    assert "not by this account" not in " ".join(row["detail"] for row in rows.values())
    assert r.failed == 0
    probe.assert_not_called()


def test_windows_diagnostics_fail_when_the_listener_is_another_accounts_now(cfg) -> None:
    r = _run_sidecar(cfg, "win32", listener_pids=(4242, 4242, 4242, 4242))
    _windows_pass(cfg, r, proof_changes={"peer_sid": "S-1-5-21-2000"})
    rows = _windows_rows(r)
    assert rows["Gateway listener owner"]["status"] == "fail"
    assert "not by this account's gateway" in rows["Gateway listener owner"]["detail"]
    assert rows["Gateway PID identity"]["status"] == "fail"
    assert rows["Gateway token drift"]["status"] == "fail"


def test_windows_diagnostics_fail_when_the_listener_pid_changed(cfg) -> None:
    r = _run_sidecar(cfg, "win32", listener_pids=(4242, 4242, 4242, 4242))
    _windows_pass(cfg, r, listener=ListenerEvidence("ok", pid=9999))
    rows = _windows_rows(r)
    assert rows["Gateway listener owner"]["status"] == "fail"
    assert rows["Gateway PID identity"]["status"] == "fail"


def test_windows_diagnostics_fail_when_no_foreground_proof_was_made(cfg) -> None:
    r = cmd_doctor._DoctorResult(quiet=True)
    _windows_pass(cfg, r, gateway_down="foreign")
    rows = _windows_rows(r)
    assert rows["Gateway listener owner"]["status"] == "fail"
    assert "not by this account's gateway" in rows["Gateway listener owner"]["detail"]
    assert rows["Gateway PID identity"]["status"] == "fail"
