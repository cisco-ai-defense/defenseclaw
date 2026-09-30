# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""#958: the claw.mode openclaw default without OpenClaw reads as "not installed".

The gateway reports its OpenClaw fleet uplink off instead of reconnecting
forever (internal/gateway/fleet_openclaw_presence.go). These tests pin the
Python mirror and the CLI surfaces that must agree with it: doctor's gateway
expectation and OpenClaw gateway row, and the OPENCLAW_GATEWAY_TOKEN
requirement behind ``defenseclaw keys`` and the TUI Keys pill.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw import credentials, openclaw_presence
from defenseclaw.commands import cmd_doctor
from defenseclaw.config import (
    ClawConfig,
    Config,
    GatewayConfig,
    GuardrailConfig,
    PerConnectorGuardrailConfig,
)


@pytest.fixture
def no_openclaw_binary(monkeypatch):
    monkeypatch.setattr(openclaw_presence, "openclaw_binary_installed", lambda: False)


def _cfg(tmp_path: Path, **overrides) -> Config:
    """The claw.mode default install: no connector, loopback host, OpenClaw paths empty."""
    home = tmp_path / ".openclaw"
    kwargs = dict(
        data_dir=str(tmp_path / "dc"),
        claw=ClawConfig(mode="openclaw", home_dir=str(home), config_file=str(home / "openclaw.json")),
        guardrail=GuardrailConfig(),
        gateway=GatewayConfig(),
    )
    kwargs.update(overrides)
    return Config(**kwargs)


def _configure_openclaw(cfg: Config) -> None:
    path = Path(cfg.claw.config_file)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('{"gateway": {"mode": "local"}}', encoding="utf-8")


@pytest.mark.parametrize(
    ("mutate", "not_installed"),
    [
        (lambda cfg: None, True),
        (lambda cfg: setattr(cfg.gateway, "fleet_mode", "auto"), True),
        (lambda cfg: setattr(cfg.gateway, "fleet_mode", " AUTO "), True),
        (lambda cfg: setattr(cfg.gateway, "host", ""), True),
        (lambda cfg: setattr(cfg.gateway, "host", "localhost"), True),
        (lambda cfg: setattr(cfg.gateway, "host", "[::1]"), True),
        (
            lambda cfg: setattr(
                cfg.guardrail,
                "connectors",
                {"codex": PerConnectorGuardrailConfig(), "hermes": PerConnectorGuardrailConfig()},
            ),
            True,
        ),
        # Every other shape keeps the previous behaviour.
        (_configure_openclaw, False),
        (lambda cfg: setattr(cfg.guardrail, "connector", "openclaw"), False),
        (lambda cfg: setattr(cfg.guardrail, "connectors", {"OpenClaw": PerConnectorGuardrailConfig()}), False),
        (lambda cfg: setattr(cfg.gateway, "host", "10.0.0.5"), False),
        (lambda cfg: setattr(cfg.gateway, "host", "0.0.0.0"), False),
        (lambda cfg: setattr(cfg.gateway, "host", "gw.example.com"), False),
        (lambda cfg: setattr(cfg.gateway, "fleet_mode", "enabled"), False),
        (lambda cfg: setattr(cfg.gateway, "fleet_mode", "enabledd"), False),
        (lambda cfg: setattr(cfg.gateway, "fleet_mode", "disabled"), False),
        (lambda cfg: setattr(cfg.claw, "mode", "zeptoclaw"), False),
        (lambda cfg: setattr(cfg.claw, "mode", "codex"), False),
    ],
    ids=[
        "default_empty_fleet_mode",
        "default_auto",
        "default_auto_mixed_case",
        "empty_host",
        "localhost",
        "ipv6_loopback",
        "connectors_map_without_openclaw",
        "openclaw_json_present",
        "explicit_guardrail_connector",
        "openclaw_in_connectors_map",
        "remote_host",
        "bind_all_host",
        "fqdn_host",
        "fleet_mode_enabled",
        "fleet_mode_typo",
        "fleet_mode_disabled",
        "zeptoclaw",
        "codex",
    ],
)
def test_rule_matches_the_gateway(tmp_path, no_openclaw_binary, mutate, not_installed):
    cfg = _cfg(tmp_path)
    mutate(cfg)
    assert openclaw_presence.openclaw_implied_but_not_installed(cfg) is not_installed


def test_openclaw_json_in_home_dir_counts(tmp_path, no_openclaw_binary):
    cfg = _cfg(tmp_path)
    _configure_openclaw(cfg)
    cfg.claw.config_file = str(tmp_path / "elsewhere.json")
    assert not openclaw_presence.openclaw_implied_but_not_installed(cfg)


def test_openclaw_binary_counts(tmp_path, monkeypatch):
    monkeypatch.setattr(openclaw_presence, "openclaw_binary_installed", lambda: True)
    assert not openclaw_presence.openclaw_implied_but_not_installed(_cfg(tmp_path))


def test_binary_probe_finds_openclaw_on_path(tmp_path, monkeypatch):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    name = "openclaw.cmd" if os.name == "nt" else "openclaw"
    binary = bindir / name
    binary.write_text("#!/bin/sh\n", encoding="utf-8")
    binary.chmod(0o755)
    monkeypatch.setenv("PATH", str(bindir))
    monkeypatch.setattr(openclaw_presence, "_openclaw_binary_fallbacks", lambda: [])
    assert openclaw_presence.openclaw_binary_installed()
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    assert not openclaw_presence.openclaw_binary_installed()


@pytest.mark.skipif(os.name == "nt", reason="Windows maps a file used as a directory to not-found")
def test_uninspectable_openclaw_path_counts_as_present(tmp_path, no_openclaw_binary):
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("", encoding="utf-8")
    cfg = _cfg(tmp_path)
    cfg.claw.config_file = str(blocker / "openclaw.json")
    cfg.claw.home_dir = str(blocker)
    assert not openclaw_presence.openclaw_implied_but_not_installed(cfg)


def test_config_candidates_mirror_go(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    default = os.path.normpath(str(tmp_path / ".openclaw" / "openclaw.json"))
    loader_defaults = Config(claw=ClawConfig(mode="openclaw"))
    assert openclaw_presence.openclaw_config_candidates(loader_defaults) == [default]
    empty = Config(claw=ClawConfig(mode="openclaw", home_dir="", config_file=""))
    assert openclaw_presence.openclaw_config_candidates(empty) == [default]
    custom = Config(claw=ClawConfig(mode="openclaw", home_dir="/srv/oc"))
    assert openclaw_presence.openclaw_config_candidates(custom) == [
        default,
        os.path.normpath("/srv/oc/openclaw.json"),
    ]


def test_doctor_does_not_expect_the_fleet_uplink(tmp_path, no_openclaw_binary):
    cfg = _cfg(tmp_path)
    assert cmd_doctor._gateway_fleet_expected_enabled(cfg) is False
    assert cmd_doctor._subsystem_expected_enabled(cfg, "gateway") is False
    _configure_openclaw(cfg)
    assert cmd_doctor._gateway_fleet_expected_enabled(cfg) is True


def test_doctor_reports_the_openclaw_gateway_off(tmp_path, no_openclaw_binary, monkeypatch):
    probes: list[str] = []

    def fake_probe(url, **_kwargs):
        probes.append(url)
        return 0, ""

    monkeypatch.setattr(cmd_doctor, "_http_probe", fake_probe)
    cfg = _cfg(tmp_path)

    result = cmd_doctor._DoctorResult()
    cmd_doctor._check_openclaw_gateway(cfg, result)
    assert probes == [], "doctor probed an OpenClaw gateway that is not installed"
    row = result.checks[-1]
    assert (row["status"], row["label"], row["detail"]) == ("skip", "OpenClaw gateway", "off (OpenClaw is not installed)")

    _configure_openclaw(cfg)
    result = cmd_doctor._DoctorResult()
    cmd_doctor._check_openclaw_gateway(cfg, result)
    assert len(probes) == 1
    assert result.checks[-1]["status"] == "fail"


def test_openclaw_gateway_token_follows_the_rule(tmp_path, no_openclaw_binary):
    cfg = _cfg(tmp_path)
    assert credentials._openclaw_gateway_token(cfg) is credentials.Requirement.NOT_USED
    _configure_openclaw(cfg)
    assert credentials._openclaw_gateway_token(cfg) is credentials.Requirement.REQUIRED


def test_doctor_sidecar_row_shows_the_gateway_summary(tmp_path, no_openclaw_binary, monkeypatch):
    health = {
        "gateway": {
            "state": "disabled",
            "details": {
                "summary": openclaw_presence.OPENCLAW_NOT_INSTALLED_SUMMARY,
                "reason": openclaw_presence.OPENCLAW_NOT_INSTALLED_REASON,
            },
        },
        "watcher": {"state": "disabled"},
        "guardrail": {"state": "disabled"},
        "api": {"state": "running"},
        "telemetry": {"state": "running"},
    }
    monkeypatch.setattr(cmd_doctor, "_http_probe", lambda *_a, **_k: (200, json.dumps(health)))
    cfg = _cfg(tmp_path)

    result = cmd_doctor._DoctorResult()
    cmd_doctor._check_sidecar(cfg, result)
    gateway_rows = [c for c in result.checks if c["label"].strip() == "└─ gateway"]
    assert [(c["status"], c["detail"]) for c in gateway_rows] == [
        ("skip", "disabled — OpenClaw gateway off (OpenClaw is not installed)"),
    ]


def test_version_omits_the_plugin_row(tmp_path, no_openclaw_binary):
    from defenseclaw.commands import cmd_version

    cfg = _cfg(tmp_path)
    assert cmd_version._openclaw_active_in(cfg) is False
    _configure_openclaw(cfg)
    assert cmd_version._openclaw_active_in(cfg) is True


def _component_rows(cfg, monkeypatch):
    from defenseclaw.doctor_health import ComponentEvidence

    components = (
        ComponentEvidence("cli", "0.8.6"),
        ComponentEvidence("gateway", "0.8.6"),
        ComponentEvidence("plugin", "", status="missing"),
    )
    monkeypatch.setattr("defenseclaw.doctor_health.read_cached_discovery", lambda _data_dir: None)
    monkeypatch.setattr("defenseclaw.doctor_health.probe_component_evidence", lambda **_kw: components)
    result = cmd_doctor._DoctorResult()
    cmd_doctor._check_component_connector_compatibility(cfg, cmd_doctor._doctor_active_connectors(cfg), result)
    problems = cmd_doctor._component_compatibility_problems_for_executable(cfg, None)
    return result.checks, [finding.component for finding in problems]


def test_doctor_does_not_require_the_plugin(tmp_path, no_openclaw_binary, monkeypatch):
    cfg = _cfg(tmp_path)
    rows, problems = _component_rows(cfg, monkeypatch)
    plugin = next(r for r in rows if r["check_id"] == "doctor.component.plugin.compatibility")
    assert plugin["status"] == "skip", rows
    assert "plugin" not in problems

    _configure_openclaw(cfg)
    rows, problems = _component_rows(cfg, monkeypatch)
    plugin = next(r for r in rows if r["check_id"] == "doctor.component.plugin.compatibility")
    assert plugin["status"] == "fail"
    assert "plugin" in problems


def test_version_reads_a_sandbox_only_config(tmp_path, no_openclaw_binary, monkeypatch):
    """A config.yaml with only an openshell block relies on the claw.mode default."""
    from defenseclaw.commands import cmd_version

    home = tmp_path / "dc"
    home.mkdir()
    (home / "config.yaml").write_text("config_version: 8\nopenshell:\n  enabled: true\n", encoding="utf-8")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("DEFENSECLAW_HOME", str(home))
    monkeypatch.delenv("DEFENSECLAW_CONFIG", raising=False)
    assert cmd_version._openclaw_connector_active() is False
    openclaw = tmp_path / ".openclaw"
    openclaw.mkdir()
    (openclaw / "openclaw.json").write_text("{}", encoding="utf-8")
    assert cmd_version._openclaw_connector_active() is True


def test_expand_matches_the_gateways_rule(monkeypatch, tmp_path):
    # internal/config/claw.go expandPath expands only a leading "~/": a bare
    # "~" or "~user/..." stays as written on both sides, so the gateway and
    # doctor check the same candidates.
    monkeypatch.setenv("HOME", str(tmp_path))
    assert openclaw_presence._expand("~/.openclaw/openclaw.json") == str(tmp_path / ".openclaw" / "openclaw.json")
    assert openclaw_presence._expand("~alice/.openclaw") == "~alice/.openclaw"
    assert openclaw_presence._expand("~") == "~"
    assert openclaw_presence._expand("/opt/openclaw") == "/opt/openclaw"


@pytest.mark.parametrize("health", [None, {"connectors": [{"name": "openclaw", "state": "running"}]}])
def test_status_says_the_openclaw_gateway_is_off_when_it_is_not_installed(tmp_path, no_openclaw_binary, health):
    # `defenseclaw status` listed OpenClaw as RUNNING on a machine where it
    # is only the claw.mode default and not installed, while the gateway
    # reported its OpenClaw gateway off (#958).
    import contextlib
    import io

    from defenseclaw.commands import cmd_status

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        cmd_status._print_agents(_cfg(tmp_path), health=health)
    out = buf.getvalue()
    assert "OFF" in out and "OpenClaw is not installed" in out, out
    assert "RUNNING" not in out, out
