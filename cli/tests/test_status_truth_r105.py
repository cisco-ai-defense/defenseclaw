# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""``defenseclaw status`` says the truth plainly (r105 cli-tui-obs round b)."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from defenseclaw import hook_integrity
from defenseclaw.commands import cmd_status


def test_disable_all_hooks_shows_degraded_in_status(tmp_path: Path, monkeypatch) -> None:
    # GAP-1634: the alert and doctor said so; the status connector line did not.
    settings = tmp_path / "home" / ".claude" / "settings.json"
    settings.parent.mkdir(parents=True)
    settings.write_text(json.dumps({"disableAllHooks": True, "hooks": {}}))
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    (data_dir / "hook_contract_lock.json").write_text(
        json.dumps({"connectors": {"claudecode": {"locations": {"hook_config_paths": [str(settings)]}}}})
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(hook_integrity, "hook_runtime_problems", lambda *_a, **_k: [])
    monkeypatch.setattr(hook_integrity, "hook_registration_problems", lambda *_a, **_k: [])
    cfg = SimpleNamespace(data_dir=str(data_dir), deployment_mode="")
    suffix = cmd_status._hook_runtime_degraded_suffix(cfg, "claudecode")  # noqa: SLF001
    assert "DEGRADED" in suffix and "disableAllHooks" in suffix, suffix
    assert "restart Claude Code" in suffix, suffix
