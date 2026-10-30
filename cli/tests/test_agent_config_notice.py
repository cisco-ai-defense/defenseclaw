# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""GAP-0581: setup says what it put back in a settings file that went missing."""

from __future__ import annotations

import json
import time
from pathlib import Path

from defenseclaw.agent_config_notice import put_back_notes


def _notice(data_dir: Path, connector: str, logical: str, **fields) -> None:
    folder = data_dir / "connector_backups" / connector
    folder.mkdir(parents=True, exist_ok=True)
    body = {"version": 1, "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), **fields}
    (folder / f"{logical}.restore-notice").write_text(json.dumps(body), encoding="utf-8")


def test_setup_names_each_put_back_settings_file(tmp_path: Path) -> None:
    started = time.time()
    _notice(tmp_path, "claudecode", "settings.json", path="/home/u/.claude/settings.json", source="last_good")
    _notice(tmp_path, "codex", "config.toml", path="/home/u/.codex/config.toml", source="hooks_only", settings_lost=True)
    notes = put_back_notes(str(tmp_path), ["claudecode", "codex", "cursor"], started)
    assert notes[0].startswith("Claude Code settings /home/u/.claude/settings.json was missing; DefenseClaw put back")
    assert "with your settings" in notes[0]
    assert "enter your own settings (model, permissions, MCP servers) again" in notes[1]
    assert len(notes) == 2
    # A notice an earlier setup wrote is not this setup's news.
    assert put_back_notes(str(tmp_path), ["claudecode"], started + 3600) == []
