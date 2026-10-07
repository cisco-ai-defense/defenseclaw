# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""The Kernel sensor (Tetragon) doctor row and the enterprise.tetragon intent reader."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest
from click.testing import CliRunner
from defenseclaw.commands import cmd_config, cmd_doctor
from defenseclaw.commands.cmd_doctor import _check_kernel_sensor, _DoctorResult
from defenseclaw.config import effective_tetragon, runtime_plane_c_selected, tetragon_configured_mode

_UNIX_INFO = {"server_address": "unix:///var/run/tetragon/tetragon.sock", "pid": 4242}
_PLANE_C = SimpleNamespace(enabled=True, enable_host_plane=True, planes=["a", "b", "c"])
_NO_PLANE_C = SimpleNamespace(enabled=True, enable_host_plane=False, planes=["a", "b"])


def _cfg(*, managed: bool, runtime: Any = _PLANE_C) -> SimpleNamespace:
    return SimpleNamespace(
        deployment_mode="managed_enterprise" if managed else "",
        data_dir="",
        ai_discovery=SimpleNamespace(runtime=runtime),
    )


def _health(backend: dict | None = None, kernel: dict | None = None, components: dict | None = None) -> dict:
    plane_c: dict[str, Any] = {"available": True, "running": True, "mechanism": "tetragon"}
    if backend is not None:
        plane_c["backend"] = backend
    policy: dict[str, Any] = {"effective_digest": "sha256:" + "a" * 64}
    if kernel is not None:
        policy["kernel"] = kernel
    if components is not None:
        policy["components"] = components
    return {"ai_runtime": {"state": "running", "details": {"planes": {"c": plane_c}}}, "policy": policy}


def _row(
    tmp_path: Path,
    *,
    info: dict | None,
    cfg: SimpleNamespace,
    health: dict | None = None,
    mode: str | None = None,
    os_name: str = "linux",
) -> list[dict]:
    info_path = tmp_path / "tetragon-info.json"
    info_path.unlink(missing_ok=True)
    if info is not None:
        info_path.write_text(json.dumps(info), encoding="utf-8")
    document = {"enterprise": {"tetragon": {"mode": mode}}} if mode else {}
    result = _DoctorResult()
    _check_kernel_sensor(cfg, result, live_health=health, info_path=str(info_path), os_name=os_name, document=document)
    return result.checks


def _only(checks: list[dict]) -> dict:
    assert len(checks) == 1, checks
    assert checks[0]["label"] == "Kernel sensor (Tetragon)"
    assert checks[0]["check_id"] == "doctor.runtime.tetragon"
    return checks[0]


def test_no_row_without_tetragon_or_off_linux(tmp_path: Path) -> None:
    # Most Linux hosts have no Tetragon: no noise.
    assert _row(tmp_path, info=None, cfg=_cfg(managed=True)) == []
    assert _row(tmp_path, info=None, cfg=_cfg(managed=False)) == []
    assert _row(tmp_path, info=None, cfg=_cfg(managed=True), mode="consume") == []
    # macOS and Windows have no Tetragon agent release.
    for os_name in ("darwin", "windows"):
        assert _row(tmp_path, info=_UNIX_INFO, cfg=_cfg(managed=True), os_name=os_name) == []


def test_oss_host_with_tetragon_explains_why_it_is_not_used(tmp_path: Path) -> None:
    row = _only(_row(tmp_path, info=_UNIX_INFO, cfg=_cfg(managed=False)))
    assert row["status"] == "skip"
    assert row["reason_code"] == "tetragon-not-used-per-user"
    assert "root-only" in row["detail"] and "kernel policy control" in row["detail"]


@pytest.mark.parametrize("managed", [True, False])
def test_tcp_api_is_a_warning_on_any_install(tmp_path: Path, managed: bool) -> None:
    info = {"server_address": "localhost:54321", "pid": 4242}
    row = _only(_row(tmp_path, info=info, cfg=_cfg(managed=managed), health=_health()))
    assert row["status"] == "warn"
    assert row["reason_code"] == "tetragon-tcp-api"
    assert "any local account can load kernel policies" in row["detail"]
    assert "unix" in row["remediation"]


def test_managed_tetragon_backend_passes_with_version_mode_and_loss(tmp_path: Path) -> None:
    backend = {"kind": "tetragon", "version": "1.7.1", "mode": "observe", "events_lost": 0, "loss_known": True}
    row = _only(_row(tmp_path, info=_UNIX_INFO, cfg=_cfg(managed=True), health=_health(backend), mode="observe"))
    assert row["status"] == "pass"
    assert row["detail"] == "Tetragon v1.7.1, observe, 0 events lost"

    unknown_loss = dict(backend, loss_known=False)
    row = _only(_row(tmp_path, info=_UNIX_INFO, cfg=_cfg(managed=True), health=_health(unknown_loss)))
    assert row["detail"] == "Tetragon v1.7.1, observe, events lost unknown"

    # The pass names your own Tetragon policies when the helper reports them.
    yours = dict(
        backend,
        customer_policies=[
            {"name": "10-file-sensitive", "mode": "enforce"},
            {"name": "20-net-connect", "mode": "monitor"},
        ],
        customer_events={"seen": 40, "forwarded": 12, "dropped": 0},
    )
    row = _only(_row(tmp_path, info=_UNIX_INFO, cfg=_cfg(managed=True), health=_health(yours)))
    assert row["detail"] == (
        "Tetragon v1.7.1, observe, 0 events lost; your Tetragon policies: 2 loaded (1 enforcing); 12 agent events forwarded"
    )


def test_managed_fallback_names_the_reason(tmp_path: Path) -> None:
    backend = {"kind": "native", "fallback_reason": "tetragon_unsupported_version: 1.5.0"}
    row = _only(_row(tmp_path, info=_UNIX_INFO, cfg=_cfg(managed=True), health=_health(backend)))
    assert row["status"] == "warn"
    assert row["reason_code"] == "tetragon-fallback"
    assert row["detail"] == (
        "present, but the helper uses cn_proc: this Tetragon version is not supported (tetragon_unsupported_version)"
    )
    assert "tetragon verify" in row["remediation"]
    # A gateway that reports no backend at all (an older helper) also falls back.
    row = _only(_row(tmp_path, info=_UNIX_INFO, cfg=_cfg(managed=True), health=_health()))
    assert row["reason_code"] == "tetragon-fallback"


def test_orphaned_kernel_policies_fail(tmp_path: Path) -> None:
    kernel = {"kernel_policy": "sha256:" + "b" * 64, "orphaned": ["defenseclaw-controls-0a1b2c3d"]}
    for cfg in (_cfg(managed=True), _cfg(managed=True, runtime=_NO_PLANE_C)):
        row = _only(_row(tmp_path, info=_UNIX_INFO, cfg=cfg, health=_health({"kind": "tetragon"}, kernel), mode="off"))
        assert row["status"] == "fail"
        assert row["reason_code"] == "kernel-policy-orphaned"
        assert "defenseclaw-controls-0a1b2c3d" in row["detail"]
        assert "--tetragon-cleanup" in row["remediation"]


def test_managed_kernel_policy_not_applied_and_pause_warn(tmp_path: Path) -> None:
    backend = {"kind": "tetragon", "version": "1.7.1", "mode": "enforce", "events_lost": 0, "loss_known": True}
    stale = _health(
        backend,
        kernel={"kernel_policy": "sha256:" + "1" * 64},
        components={"kernel_policy": "sha256:" + "2" * 64},
    )
    row = _only(_row(tmp_path, info=_UNIX_INFO, cfg=_cfg(managed=True), health=stale, mode="enforce"))
    assert (row["status"], row["reason_code"]) == ("warn", "kernel-policy-not-applied")
    assert "sha256:111111111111" in row["detail"] and "sha256:222222222222" in row["detail"]

    paused = _health(backend, kernel={"paused_until": "2026-10-07T14:05:00Z"})
    row = _only(_row(tmp_path, info=_UNIX_INFO, cfg=_cfg(managed=True), health=paused, mode="enforce"))
    assert (row["status"], row["reason_code"]) == ("warn", "kernel-enforce-paused")
    assert "2026-10-07T14:05:00Z" in row["detail"]


def test_managed_plane_c_off_mode_off_and_absent_tetragon(tmp_path: Path) -> None:
    row = _only(_row(tmp_path, info=_UNIX_INFO, cfg=_cfg(managed=True, runtime=_NO_PLANE_C), health=_health()))
    assert (row["status"], row["reason_code"]) == ("skip", "tetragon-plane-c-off")
    assert "enable_host_plane" in row["detail"]

    row = _only(_row(tmp_path, info=_UNIX_INFO, cfg=_cfg(managed=True), health=_health(), mode="off"))
    assert (row["status"], row["reason_code"]) == ("skip", "tetragon-mode-off")

    # The administrator asked for observe, but this host runs no Tetragon.
    row = _only(_row(tmp_path, info=None, cfg=_cfg(managed=True), health=_health(), mode="observe"))
    assert (row["status"], row["reason_code"]) == ("warn", "tetragon-unavailable")

    row = _only(_row(tmp_path, info=_UNIX_INFO, cfg=_cfg(managed=True), health=None))
    assert row["status"] == "skip" and "gateway is not running" in row["detail"]


def test_doctor_never_opens_the_tetragon_socket(tmp_path: Path) -> None:
    # The row reads the info file and /health only: no socket, no binary.
    backend = {"kind": "tetragon", "version": "1.7.1", "mode": "consume", "events_lost": 0, "loss_known": True}
    with (
        patch("socket.socket", side_effect=AssertionError("doctor opened a socket")),
        patch("subprocess.run", side_effect=AssertionError("doctor ran a binary")),
    ):
        row = _only(_row(tmp_path, info=_UNIX_INFO, cfg=_cfg(managed=True), health=_health(backend)))
    assert row["status"] == "pass"


# --- enterprise.tetragon as the helper runs it (shared by doctor and config get) ---


def _document(**block: Any) -> dict:
    return {"deployment_mode": "managed_enterprise", "enterprise": {"profile": "standalone", "tetragon": block}}


def test_effective_tetragon_defaults_sources_and_caps(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DEFENSECLAW_DEPLOYMENT_MODE", raising=False)
    managed = {"deployment_mode": "managed_enterprise", "runtime": _PLANE_C, "os_name": "linux"}

    view = effective_tetragon({}, **managed)
    assert view == {
        "mode": ("consume", "builtin"),
        "burn_in": ("168h", "builtin"),
        "enforce_ack": ("", "builtin"),
        "customer_events": ("agent", "builtin"),
    }

    view = effective_tetragon(_document(mode="enforce", burn_in=0, enforce_ack="sha256:3f9c2a7d41b0"), **managed)
    assert view["mode"] == ("enforce", "config:enterprise.tetragon.mode")
    assert view["burn_in"] == ("0", "config:enterprise.tetragon.burn_in")
    assert view["enforce_ack"] == ("sha256:3f9c2a7d41b0", "config:enterprise.tetragon.enforce_ack")

    # An ack with a mode that never reads it is kept but says so.
    view = effective_tetragon(_document(mode="observe", enforce_ack="sha256:3f9c2a7d41b0"), **managed)
    assert view["enforce_ack"][1].endswith("(inert: the mode is not enforce)")

    # The list form of a ring upgrade, as Go marshals it: canonical, one item
    # is the string.
    ring = ["sha256:3f9c2a7d41b0", " sha256:08b71155b713", "", "sha256:3f9c2a7d41b0"]
    view = effective_tetragon(_document(mode="enforce", enforce_ack=ring), **managed)
    assert view["enforce_ack"] == (
        ["sha256:3f9c2a7d41b0", "sha256:08b71155b713"],
        "config:enterprise.tetragon.enforce_ack",
    )
    view = effective_tetragon(_document(mode="enforce", enforce_ack=["sha256:3f9c2a7d41b0"]), **managed)
    assert view["enforce_ack"][0] == "sha256:3f9c2a7d41b0"
    assert effective_tetragon(_document(enforce_ack=[]), **managed)["enforce_ack"][0] == ""

    # customer_events: PyYAML reads an unquoted off as False; the off mode
    # has no event stream, so the key is inert there.
    view = effective_tetragon(_document(customer_events=False), **managed)
    assert view["customer_events"] == ("off", "config:enterprise.tetragon.customer_events")
    view = effective_tetragon(_document(mode="off", customer_events="Agent"), **managed)
    assert view["customer_events"] == ("agent", "config:enterprise.tetragon.customer_events (inert: the mode is off)")

    # The caps the lifecycle renders: Plane C off, not managed, not Linux.
    capped = effective_tetragon(_document(mode="observe"), **dict(managed, runtime=_NO_PLANE_C))
    assert capped["mode"] == (
        "off",
        "config:enterprise.tetragon.mode, capped: Plane C is off (ai_discovery.runtime.enable_host_plane)",
    )
    assert effective_tetragon({}, **dict(managed, deployment_mode=""))["mode"][0] == "off"
    assert "ignore" in effective_tetragon(_document(mode="enforce"), **dict(managed, os_name="darwin"))["mode"][1]
    # A written off is never "capped".
    assert effective_tetragon(_document(mode="off"), **dict(managed, os_name="windows"))["mode"] == (
        "off",
        "config:enterprise.tetragon.mode",
    )


def test_an_unquoted_off_reads_as_off(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # PyYAML's safe_load reads `mode: off` as False; Go and the v8 schema read "off".
    import yaml

    document = yaml.safe_load("enterprise:\n  profile: standalone\n  tetragon:\n    mode: off\n")
    assert document["enterprise"]["tetragon"]["mode"] is False
    assert tetragon_configured_mode(document) == "off"
    monkeypatch.delenv("DEFENSECLAW_DEPLOYMENT_MODE", raising=False)
    view = effective_tetragon(document, deployment_mode="managed_enterprise", runtime=_PLANE_C, os_name="linux")
    assert view["mode"] == ("off", "config:enterprise.tetragon.mode")

    result = _DoctorResult()
    info_path = tmp_path / "tetragon-info.json"
    info_path.write_text(json.dumps(_UNIX_INFO), encoding="utf-8")
    _check_kernel_sensor(
        _cfg(managed=True), result, live_health=_health(), info_path=str(info_path), os_name="linux", document=document
    )
    assert _only(result.checks)["reason_code"] == "tetragon-mode-off"


def test_runtime_plane_c_selected_mirrors_effective_planes() -> None:
    assert runtime_plane_c_selected(SimpleNamespace(enabled=True, enable_host_plane=True, planes=[]))
    assert runtime_plane_c_selected(SimpleNamespace(enabled=True, enable_host_plane=True, planes=[" C ", "a"]))
    assert not runtime_plane_c_selected(SimpleNamespace(enabled=True, enable_host_plane=True, planes=["a", "b"]))
    assert not runtime_plane_c_selected(SimpleNamespace(enabled=True, enable_host_plane=False, planes=["c"]))
    assert not runtime_plane_c_selected(SimpleNamespace(enabled=False, enable_host_plane=True, planes=[]))
    assert not runtime_plane_c_selected(None)


def test_config_get_effective_prints_the_tetragon_intent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path))
    monkeypatch.delenv("DEFENSECLAW_CONFIG", raising=False)
    monkeypatch.delenv("DEFENSECLAW_DEPLOYMENT_MODE", raising=False)
    config_path = tmp_path / "config.yaml"
    config_path.write_text("config_version: 9\ngateway: {}\nobservability: {}\n", encoding="utf-8")
    with patch.object(cmd_config.config_module, "config_path", return_value=config_path):
        mode = CliRunner().invoke(cmd_config.config_cmd, ["get", "enterprise.tetragon.mode", "--effective"])
        block = CliRunner().invoke(
            cmd_config.config_cmd, ["get", "enterprise.tetragon", "--effective", "--format", "json"]
        )
    assert mode.exit_code == 0, mode.output
    # A per-user install never uses Tetragon, whatever the default says.
    assert mode.stdout == "off\n"
    assert "builtin, capped:" in mode.stderr
    assert block.exit_code == 0, block.output
    assert json.loads(block.stdout) == {"mode": "off", "burn_in": "168h", "enforce_ack": "", "customer_events": "agent"}
    assert "burn_in=builtin" in block.stderr


def test_doctor_registers_the_row_after_the_services_checks() -> None:
    import inspect

    source = inspect.getsource(cmd_doctor)
    services = source.index('r.set_section("services")')
    credentials = source.index('r.set_section("credentials")')
    call = source.index("_check_kernel_sensor(cfg, r, live_health=sidecar_health)")
    assert services < call < credentials
