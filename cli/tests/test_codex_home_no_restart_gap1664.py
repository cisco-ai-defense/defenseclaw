"""GAP-1664: setup codex --no-restart says when this shell's CODEX_HOME is not the folder the gateway uses."""

from __future__ import annotations

import os

import pytest
from defenseclaw.commands import cmd_setup


class _Cfg:
    def __init__(self, data_dir: str) -> None:
        self.data_dir = data_dir


@pytest.fixture
def cfg(tmp_path):
    return _Cfg(str(tmp_path / "dc"))


def _run(monkeypatch, capsys, cfg, *, codex_home, recorded, running):
    if codex_home is None:
        monkeypatch.delenv("CODEX_HOME", raising=False)
    else:
        monkeypatch.setenv("CODEX_HOME", codex_home)
    monkeypatch.setattr(cmd_setup, "_recorded_codex_root", lambda _data_dir: recorded)
    monkeypatch.setattr(cmd_setup, "_is_pid_alive", lambda _path: running)
    cmd_setup._warn_codex_home_not_applied_without_restart(cfg)
    captured = capsys.readouterr()
    return captured.out + captured.err


def test_a_codex_home_the_running_gateway_does_not_use_is_named(monkeypatch, capsys, cfg, tmp_path):
    wanted = str(tmp_path / "moved-codex")
    default = str(tmp_path / "home" / ".codex")
    text = _run(monkeypatch, capsys, cfg, codex_home=wanted, recorded=default, running=True)
    assert f"CODEX_HOME={os.path.abspath(wanted)}" in text
    assert default in text
    assert "without --no-restart" in text


def test_the_folder_already_registered_says_nothing(monkeypatch, capsys, cfg, tmp_path):
    wanted = str(tmp_path / "moved-codex")
    assert _run(monkeypatch, capsys, cfg, codex_home=wanted, recorded=wanted, running=True) == ""


def test_an_unset_codex_home_says_nothing(monkeypatch, capsys, cfg, tmp_path):
    assert _run(monkeypatch, capsys, cfg, codex_home=None, recorded=str(tmp_path / ".codex"), running=True) == ""


def test_a_running_gateway_without_a_codex_folder_yet_is_named(monkeypatch, capsys, cfg, tmp_path):
    text = _run(monkeypatch, capsys, cfg, codex_home=str(tmp_path / "moved"), recorded=None, running=True)
    assert "without --no-restart" in text


def test_a_stopped_gateway_without_a_codex_folder_says_nothing(monkeypatch, capsys, cfg, tmp_path):
    # Its next start from this shell takes CODEX_HOME.
    assert _run(monkeypatch, capsys, cfg, codex_home=str(tmp_path / "moved"), recorded=None, running=False) == ""


def test_the_recorded_root_comes_from_the_registration_then_the_backup(monkeypatch, tmp_path):
    data_dir = str(tmp_path / "dc")
    registered = str(tmp_path / "reg" / "config.toml")
    backed_up = str(tmp_path / "bak" / "config.toml")
    files = {
        os.path.join(data_dir, cmd_setup._HOOK_CONTRACT_LOCK_FILENAME): b"lock",
        cmd_setup._codex_backup_path(data_dir): b"backup",
    }

    def capture(path, _maximum, _label, **_kwargs):
        body = files.get(os.path.abspath(path))
        return (body is not None, body or b"", None)

    monkeypatch.setattr(cmd_setup, "_capture_protected_setup_file", capture)
    monkeypatch.setattr(cmd_setup, "_codex_backup_identity", lambda _body: {"path": backed_up})
    monkeypatch.setattr(cmd_setup, "_codex_registration_path", lambda _body: registered)
    assert cmd_setup._recorded_codex_root(data_dir) == os.path.dirname(registered)
    monkeypatch.setattr(cmd_setup, "_codex_registration_path", lambda _body: None)
    assert cmd_setup._recorded_codex_root(data_dir) == os.path.dirname(backed_up)

    def unreadable(*_args, **_kwargs):
        raise OSError("not a private regular file")

    monkeypatch.setattr(cmd_setup, "_capture_protected_setup_file", unreadable)
    assert cmd_setup._recorded_codex_root(data_dir) is None
