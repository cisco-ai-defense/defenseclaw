"""GAP-1254 / GAP-1814: a per-user Copilot setup that cannot remove the
leftover machine key names the file and the entry on the terminal."""

from __future__ import annotations

import json

import pytest
from defenseclaw.commands import cmd_setup


@pytest.fixture
def no_managed_host(monkeypatch):
    monkeypatch.setattr("defenseclaw.upgrade_shim.managed_deployment", lambda: None)


def _write(path, document) -> str:
    path.write_text(json.dumps(document), encoding="utf-8")
    return str(path)


def test_leftover_key_is_named_with_the_file(tmp_path, capsys, no_managed_host):
    path = _write(tmp_path / "managed-settings.json", {"enabledPlugins": {"defenseclaw@defenseclaw": True}})

    assert cmd_setup._warn_leftover_copilot_managed_plugin_key(path) is True

    out = capsys.readouterr().out
    assert path in out
    assert "defenseclaw@defenseclaw" in out
    assert 'marketplace "defenseclaw" is not found' in out
    assert "Ask an administrator to delete that entry" in out


def test_bom_file_with_the_key_is_named(tmp_path, capsys, no_managed_host):
    path = tmp_path / "managed-settings.json"
    path.write_bytes(b"\xef\xbb\xbf" + json.dumps({"enabledPlugins": {"defenseclaw@defenseclaw": True}}).encode())

    assert cmd_setup._warn_leftover_copilot_managed_plugin_key(str(path)) is True
    assert "defenseclaw@defenseclaw" in capsys.readouterr().out


@pytest.mark.parametrize(
    "document",
    [
        {"enabledPlugins": {"other@market": True}},
        {"enabledPlugins": {"defenseclaw@defenseclaw": False}},
        {"model": "x"},
        [],
    ],
)
def test_no_line_without_the_leftover_key(tmp_path, capsys, no_managed_host, document):
    path = _write(tmp_path / "managed-settings.json", document)

    assert cmd_setup._warn_leftover_copilot_managed_plugin_key(path) is False
    assert capsys.readouterr().out == ""


def test_no_line_when_the_file_is_missing_or_invalid(tmp_path, capsys, no_managed_host):
    assert cmd_setup._warn_leftover_copilot_managed_plugin_key(str(tmp_path / "absent.json")) is False
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    assert cmd_setup._warn_leftover_copilot_managed_plugin_key(str(bad)) is False
    assert capsys.readouterr().out == ""


def test_no_line_on_a_managed_host(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr("defenseclaw.upgrade_shim.managed_deployment", lambda: "standalone")
    path = _write(tmp_path / "managed-settings.json", {"enabledPlugins": {"defenseclaw@defenseclaw": True}})

    assert cmd_setup._warn_leftover_copilot_managed_plugin_key(path) is False
    assert capsys.readouterr().out == ""
