# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""``defenseclaw status`` says the truth plainly (r105 cli-tui-obs round b)."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from defenseclaw import hook_integrity
from defenseclaw.commands import cmd_status


@pytest.mark.parametrize(
    ("uid_map", "owner", "hidden"),
    [
        ("         0          0 4294967295\n", 65534, False),  # the initial namespace
        ("      1001       1001          1\n", 65534, True),  # Codex workspace sandbox
        ("      1001       1001          1\n", 0, False),  # a mapped owner is real
        ("      1001          0          1\n", 65534, True),
    ],
)
def test_namespace_hides_owner_reads_overflowuid_and_uid_map(monkeypatch, uid_map, owner, hidden) -> None:
    # GAP-1547: every GAP-1395 test patched this helper; this one runs it.
    import io
    import os

    from defenseclaw import file_permissions

    files = {"/proc/sys/kernel/overflowuid": "65534\n", "/proc/self/uid_map": uid_map}
    monkeypatch.setattr(file_permissions.sys, "platform", "linux")
    monkeypatch.setattr(file_permissions, "open", lambda path, *a, **k: io.StringIO(files[path]), raising=False)
    info = os.stat_result((0o40755, 0, 0, 1, owner, owner, 0, 0, 0, 0))
    assert file_permissions.namespace_hides_owner(info) is hidden


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
