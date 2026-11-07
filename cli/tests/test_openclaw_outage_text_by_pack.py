# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""GAP-0824: the fail-mode views say what OpenClaw model requests do while the gateway is down.

The old text said the requests are always blocked, whatever the value says. They follow the
outage mode the gateway resolves: open (continue with a warning) on the default and permissive
packs, closed on strict and for an explicit closed. ZeptoClaw requests stay blocked.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner
from defenseclaw.commands import cmd_guardrail

from tests.test_fail_mode_runtime import _runtime_cfg
from tests.test_fcux_cli_messages_b11 import _app, _fail_mode

_CONTINUES = "continue with a warning while the gateway is down"
_BLOCKED = "blocked while the gateway is down"


def _single(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, name: str, pack: str, saved: str = ""):
    cfg, _home = _runtime_cfg(monkeypatch, tmp_path, {name: ""})
    cfg.guardrail.connectors = {}
    cfg.guardrail.connector = name
    cfg.guardrail.rule_pack = pack
    if saved:
        cfg.guardrail.hook_fail_mode = saved
        cfg.guardrail._hook_fail_mode_saved = True
    return cfg


def _words(text: str) -> str:
    return " ".join(text.split())


@pytest.mark.parametrize(
    ("pack", "saved", "want"),
    [
        ("default", "", "open"),
        ("permissive", "", "open"),
        ("default", "open", "open"),
        ("default", "closed", "closed"),
        ("strict", "", "closed"),
    ],
)
def test_the_fail_mode_view_shows_the_openclaw_tier_the_gateway_resolves(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, pack: str, saved: str, want: str
) -> None:
    cfg = _single(monkeypatch, tmp_path, "openclaw", pack, saved)
    shown = CliRunner().invoke(cmd_guardrail.fail_mode_cmd, [], obj=_app(cfg))
    assert shown.exit_code == 0, shown.output
    line = next(x for x in _words(shown.output).split(" - ") if "OpenClaw (openclaw):" in x)
    assert f"OpenClaw (openclaw): {want} (proxy-backed, no hooks:" in line
    assert (_CONTINUES in line) is (want == "open")
    assert (_BLOCKED in line) is (want == "closed")


def test_a_closed_value_on_openclaw_says_the_requests_are_blocked(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cfg = _single(monkeypatch, tmp_path, "openclaw", "default", "open")
    result = _fail_mode(cfg, "closed")
    assert result.exit_code == 0, result.output
    out = _words(result.output)
    assert "Its proxied model requests are blocked while the gateway is down." in out
    assert "whatever this value says" not in out
    assert _CONTINUES not in out


def test_an_open_value_on_openclaw_says_the_requests_continue(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cfg = _single(monkeypatch, tmp_path, "openclaw", "default", "closed")
    result = _fail_mode(cfg, "open")
    assert result.exit_code == 0, result.output
    out = _words(result.output)
    assert "Its proxied model requests continue with a warning while the gateway is down." in out
    assert "blocked while the gateway is down, whatever" not in out


def test_an_open_value_on_strict_openclaw_says_strict_still_blocks(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cfg = _single(monkeypatch, tmp_path, "openclaw", "strict", "closed")
    result = _fail_mode(cfg, "open")
    assert result.exit_code == 0, result.output
    out = _words(result.output)
    assert "the strict policy (or a managed host) blocks them whatever this value says" in out
    assert _CONTINUES not in out


@pytest.mark.parametrize("mode", ["open", "closed"])
def test_zeptoclaw_requests_stay_blocked_whatever_the_value_says(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, mode: str
) -> None:
    cfg = _single(monkeypatch, tmp_path, "zeptoclaw", "default", "closed" if mode == "open" else "open")
    shown = CliRunner().invoke(cmd_guardrail.fail_mode_cmd, [], obj=_app(cfg))
    assert shown.exit_code == 0, shown.output
    assert "ZeptoClaw (zeptoclaw): closed (proxy-backed, no hooks: blocked while the gateway is down)" in _words(
        shown.output
    )
    result = _fail_mode(cfg, mode)
    assert result.exit_code == 0, result.output
    assert "blocked while the gateway is down, whatever this value says" in _words(result.output)
    assert _CONTINUES not in _words(result.output)


@pytest.mark.parametrize("entry", [False, True])
@pytest.mark.parametrize(
    ("name", "pack", "want"),
    [
        ("openclaw", "default", "open"),
        ("openclaw", "permissive", "open"),
        ("openclaw", "strict", "closed"),
        ("zeptoclaw", "default", "closed"),
    ],
)
def test_the_scoped_fail_mode_view_matches_the_unscoped_view_for_a_proxy_connector(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, name: str, pack: str, want: str, entry: bool
) -> None:
    from defenseclaw.config import PerConnectorGuardrailConfig

    cfg = _single(monkeypatch, tmp_path, name, pack)
    if entry:
        cfg.guardrail.connectors = {name: PerConnectorGuardrailConfig()}
    unscoped = CliRunner().invoke(cmd_guardrail.fail_mode_cmd, [], obj=_app(cfg))
    scoped = CliRunner().invoke(cmd_guardrail.fail_mode_cmd, ["--connector", name], obj=_app(cfg))
    assert unscoped.exit_code == 0, unscoped.output
    assert scoped.exit_code == 0, scoped.output
    out = _words(scoped.output)
    assert f"{want} (proxy-backed, no hooks:" in out
    assert "hook_fail_mode: unknown" not in out
    assert (_CONTINUES in out) is (want == "open")
    assert (_BLOCKED in out) is (want == "closed")
    assert f"{want} (proxy-backed, no hooks:" in _words(unscoped.output)


def _two_connector_config(tmp_path: Path, *, global_off: bool = False, openclaw_off: bool = False, saved: str = ""):
    from defenseclaw.config import PerConnectorGuardrailConfig, default_config

    cfg = default_config()
    cfg.data_dir = str(tmp_path)
    cfg.guardrail.enabled = not global_off
    cfg.guardrail.rule_pack = "default"
    cfg.guardrail.connectors = {
        "codex": PerConnectorGuardrailConfig(),
        "openclaw": PerConnectorGuardrailConfig(enabled=False if openclaw_off else None),
    }
    if saved:
        cfg.guardrail.hook_fail_mode = saved
        cfg.guardrail._hook_fail_mode_saved = True
    return cfg


@pytest.mark.parametrize(
    ("global_off", "openclaw_off", "want"),
    [
        (False, False, "open (proxy-backed, no hooks:"),
        (True, False, "disabled (no hooks)"),
        (False, True, "disabled (no hooks)"),
    ],
)
def test_the_scoped_proxy_view_matches_the_unscoped_view_for_an_unsaved_default_and_both_disabled_forms(
    tmp_path: Path, global_off: bool, openclaw_off: bool, want: str
) -> None:
    cfg = _two_connector_config(tmp_path, global_off=global_off, openclaw_off=openclaw_off)
    unscoped = _words(CliRunner().invoke(cmd_guardrail.fail_mode_cmd, [], obj=_app(cfg)).output)
    scoped_run = CliRunner().invoke(cmd_guardrail.fail_mode_cmd, ["--connector", "openclaw"], obj=_app(cfg))
    assert scoped_run.exit_code == 0, scoped_run.output
    scoped = _words(scoped_run.output)
    assert f"OpenClaw (openclaw): {want}" in unscoped
    assert f"hook_fail_mode: {want}" in scoped
    # Nothing is saved: the schema default (closed) is not an inherited value, and a proxy-backed
    # connector has no hook script to be missing.
    assert "inherited from global default" not in scoped
    assert "Runtime drift" not in scoped
    assert "hook-script-missing" not in scoped
    if want.startswith("open"):
        assert _CONTINUES in scoped
    else:
        assert _CONTINUES not in scoped


def test_a_saved_global_closed_is_still_shown_as_inherited_by_the_scoped_proxy_view(tmp_path: Path) -> None:
    cfg = _two_connector_config(tmp_path, saved="closed")
    scoped = _words(
        CliRunner().invoke(cmd_guardrail.fail_mode_cmd, ["--connector", "openclaw"], obj=_app(cfg)).output
    )
    assert "closed (proxy-backed, no hooks:" in scoped
    assert "inherited from global default (closed)" in scoped
    assert "Runtime drift" not in scoped
