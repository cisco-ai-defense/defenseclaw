# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Lean regressions for the registry CLI fix-only batch 9
(GAP-2208, GAP-2209, GAP-2210, GAP-2212)."""

from __future__ import annotations

import os
from types import SimpleNamespace

import pytest
import yaml
from click.testing import CliRunner
from defenseclaw.commands import cmd_registry
from defenseclaw.config import RegistrySource
from defenseclaw.registries.cache import SourceIndex
from defenseclaw.registries.manifest import Manifest, ManifestEntry

from tests.helpers import cleanup_app, make_app_context


@pytest.fixture
def registry_app(monkeypatch):
    app, tmp_dir, db_path = make_app_context()
    app.cfg.config_path = os.path.join(tmp_dir, "config.yaml")
    app.cfg.save()
    monkeypatch.setattr(cmd_registry, "sys", SimpleNamespace(stdin=SimpleNamespace(isatty=lambda: True)))
    yield app
    cleanup_app(app, db_path, tmp_dir)


def _run(app, *args: str):
    return CliRunner().invoke(cmd_registry.registry, list(args), obj=app)


def test_require_no_enforce_turns_enforcement_back_off(registry_app) -> None:
    # GAP-2208
    result = _run(registry_app, "require", "--type", "mcp", "--enabled", "--enforce")
    assert result.exit_code == 0, result.output
    assert "--disabled --no-enforce" in result.output
    assert registry_app.cfg.asset_policy.mode == "action"

    result = _run(registry_app, "require", "--type", "mcp", "--disabled", "--no-enforce")
    assert result.exit_code == 0, result.output
    assert "Asset policy enforcement is off (mode=observe)" in result.output
    assert registry_app.cfg.asset_policy.mode == "observe"
    with open(registry_app.cfg.config_path, encoding="utf-8") as fh:
        saved = yaml.safe_load(fh)["asset_policy"]
    assert saved["mode"] == "observe" and saved["mcp"]["registry_required"] is False


@pytest.mark.parametrize("flags", [["--auto-sync"], ["--sync-interval-hours", "1"]])
def test_add_and_edit_refuse_scheduled_sync_flags(registry_app, flags) -> None:
    # GAP-2209
    for sub in ("add", "edit"):
        assert "auto-sync" not in _run(registry_app, sub, "--help").output
    add = ["add", "s1", "--kind", "clawhub", "--content", "skill", "--non-interactive"]
    result = _run(registry_app, *add, *flags)
    assert result.exit_code == 2 and "scheduled sync is not available yet" in result.output
    assert not registry_app.cfg.registries.sources
    assert _run(registry_app, *add).exit_code == 0
    result = _run(registry_app, "edit", "s1", "--non-interactive", *flags)
    assert result.exit_code == 2 and "scheduled sync is not available yet" in result.output


def test_list_names_a_source_whose_last_sync_failed(registry_app, monkeypatch) -> None:
    # GAP-2210
    registry_app.cfg.registries.sources = [
        RegistrySource(id="ok-src", kind="clawhub", last_sync="2026-10-03T04:20:13Z", last_status="ok"),
        RegistrySource(id="bad-src", kind="clawhub", last_sync="2026-10-03T04:22:48Z",
                       last_status="error: fetch failed"),
    ]
    counts = {"ok-src": dict(entry_count=1, clean_count=1), "bad-src": dict(entry_count=1, error_count=1)}
    monkeypatch.setattr(cmd_registry, "load_index", lambda _d, sid: SourceIndex(source_id=sid, **counts[sid]))
    result = _run(registry_app, "list")
    assert result.exit_code == 0, result.output
    assert "1 (0/0/0/1)" in result.output and "total (clean/warning/blocked/error)" in result.output
    assert "The last sync of bad-src failed" in result.output and "registry show bad-src" in result.output
    assert "last sync of ok-src" not in result.output


def test_registry_test_counts_one_mcp_server_in_the_singular(registry_app, monkeypatch) -> None:
    # GAP-2212
    registry_app.cfg.registries.sources = [RegistrySource(id="m1", kind="clawhub", content="mcp")]
    manifest = Manifest(entries=[ManifestEntry(name="srv", type="mcp")])
    monkeypatch.setattr(cmd_registry, "fetch_manifest", lambda *_a, **_k: (manifest, b"x"))
    result = _run(registry_app, "test", "m1")
    assert result.exit_code == 0, result.output
    assert "1 (0 skills, 1 MCP server)" in result.output
