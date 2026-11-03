# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""GAP-0581 / GAP-0333: setup says what it put back in a settings file that went missing."""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path

import defenseclaw.agent_config_notice as notice_module
from defenseclaw.agent_config_notice import put_back_notes, wait_for_put_back


def _notice(data_dir: Path, connector: str, logical: str, at: float | None = None, **fields) -> None:
    folder = data_dir / "connector_backups" / connector
    folder.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() if at is None else at))
    body = {"version": 1, "at": stamp, **fields}
    (folder / f"{logical}.restore-notice").write_text(json.dumps(body), encoding="utf-8")


def test_setup_names_each_put_back_settings_file(tmp_path: Path) -> None:
    _notice(tmp_path, "claudecode", "settings.json", path="/home/u/.claude/settings.json", source="last_good")
    _notice(tmp_path, "codex", "config.toml", path="/home/u/.codex/config.toml", source="hooks_only", settings_lost=True)
    notes = put_back_notes(str(tmp_path), ["claudecode", "codex", "cursor"])
    assert notes[0].startswith("Claude Code settings /home/u/.claude/settings.json was missing; DefenseClaw put back")
    assert "with your settings" in notes[0]
    assert "enter your own settings (model, permissions, MCP servers) again" in notes[1]
    assert len(notes) == 2


def test_a_put_back_is_reported_once(tmp_path: Path) -> None:
    """GAP-0333: reported by the next setup that looks, then not again."""
    _notice(tmp_path, "hermes", "config.yaml", path="/home/u/.hermes/config.yaml", source="last_good")
    assert len(put_back_notes(str(tmp_path), ["hermes"])) == 1
    assert put_back_notes(str(tmp_path), ["hermes"]) == []
    # The next put-back writes a new notice with a new time and is reported again.
    _notice(tmp_path, "hermes", "config.yaml", at=time.time() + 5, path="/home/u/.hermes/config.yaml", source="last_good")
    assert len(put_back_notes(str(tmp_path), ["hermes"])) == 1


def test_a_put_back_made_before_the_command_started_is_still_reported(tmp_path: Path) -> None:
    """GAP-0333: the background watchdog restores a lost file within a second, before setup runs."""
    _notice(tmp_path, "hermes", "config.yaml", at=time.time() - 3600, path="/home/u/.hermes/config.yaml", source="last_good")
    assert len(put_back_notes(str(tmp_path), ["hermes"])) == 1


def test_a_hooks_only_copy_is_reported_as_hooks_not_settings(tmp_path: Path) -> None:
    """GAP-0333: the copy held DefenseClaw's hooks only, so no settings came back."""
    _notice(tmp_path, "hermes", "config.yaml", path="/home/u/.hermes/config.yaml", source="last_good", hooks_only=True)
    notes = put_back_notes(str(tmp_path), ["hermes"])
    assert len(notes) == 1
    assert "put its hooks back" in notes[0] and "hooks only" in notes[0]
    assert "settings" not in notes[0]
    _notice(tmp_path, "hermes", "config.yaml", at=time.time() + 5, path="/home/u/.hermes/config.yaml", source="last_good")
    assert "with your settings" in put_back_notes(str(tmp_path), ["hermes"])[0]


def test_the_restart_step_reports_a_put_back_when_it_does_not_wait_for_the_runtime(tmp_path: Path, monkeypatch) -> None:
    """GAP-0333: the note was printed only by a restart step that waited for the connector runtime."""
    from defenseclaw.commands import cmd_setup

    _notice(tmp_path, "hermes", "config.yaml", path="/home/u/.hermes/config.yaml", source="last_good", hooks_only=True)
    monkeypatch.setattr(cmd_setup, "_restart_defense_gateway", lambda *a, **k: True)
    warned: list[str] = []
    monkeypatch.setattr(cmd_setup.ux, "warn", lambda text, *a, **k: warned.append(str(text)))
    cmd_setup._restart_services(str(tmp_path), connector="hermes", teardown=True)
    assert warned == []  # a teardown restart puts nothing back and says nothing
    cmd_setup._restart_services(str(tmp_path), connector="hermes")
    assert len(warned) == 1 and "put its hooks back" in warned[0] and "settings" not in warned[0], warned


def test_setup_waits_for_a_put_back_the_gateway_has_not_made_yet(tmp_path: Path) -> None:
    """GAP-0333: the put-back finished after the restart step had read the notices."""
    config = tmp_path / "home" / "config.yaml"
    config.parent.mkdir()
    folder = tmp_path / "connector_backups" / "hermes"
    folder.mkdir(parents=True)
    (folder / "config.yaml.last-good").write_text(json.dumps({"version": 1, "path": str(config)}), encoding="utf-8")

    def put_back() -> None:
        time.sleep(0.4)
        config.write_text("hooks: {}\n", encoding="utf-8")

    thread = threading.Thread(target=put_back)
    started = time.monotonic()
    thread.start()
    wait_for_put_back(str(tmp_path), ["hermes"], timeout=10, interval=0.05)
    thread.join()
    assert config.exists() and 0.3 < time.monotonic() - started < 5
    # No kept copy for the connector, or the file already there: nothing to wait for.
    started = time.monotonic()
    wait_for_put_back(str(tmp_path), ["hermes", "codex"], timeout=10, interval=0.05)
    config.unlink()
    wait_for_put_back(str(tmp_path), ["codex"], timeout=10, interval=0.05)
    assert time.monotonic() - started < 1
    # A file that never comes back is waited for no longer than the bound.
    started = time.monotonic()
    wait_for_put_back(str(tmp_path), ["hermes"], timeout=0.3, interval=0.05)
    assert 0.25 < time.monotonic() - started < 3
    assert notice_module._SEEN_SUFFIX == "-seen"
