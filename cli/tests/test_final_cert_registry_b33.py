# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Lean regression for the registry fix-only batch 33 (GAP-2537)."""

from __future__ import annotations

import os
from types import SimpleNamespace

import pytest
from click.testing import CliRunner
from defenseclaw.commands import cmd_registry
from defenseclaw.registries.manifest import ManifestError, parse_manifest

from tests.helpers import cleanup_app, make_app_context

BROKEN = "schema_version: 1\nentries: [ { name: t2r3-broken, type: mcp\n"


@pytest.fixture
def registry_app(monkeypatch):
    app, tmp_dir, db_path = make_app_context()
    app.cfg.config_path = os.path.join(tmp_dir, "config.yaml")
    app.cfg.save()
    monkeypatch.setattr(cmd_registry, "sys", SimpleNamespace(stdin=SimpleNamespace(isatty=lambda: True)))
    yield app, tmp_dir
    cleanup_app(app, db_path, tmp_dir)


def _run(app, *args: str):
    return CliRunner().invoke(cmd_registry.registry, list(args), obj=app)


def test_syntax_errors_are_one_line_with_position() -> None:
    with pytest.raises(ManifestError) as yerr:
        parse_manifest(BROKEN, origin="/x/registry-bad.yaml")
    assert str(yerr.value) == (
        "/x/registry-bad.yaml is not valid YAML (line 2, column 42: expected ',' or '}', but got '<stream end>')"
    )
    with pytest.raises(ManifestError) as jerr:
        parse_manifest('{"schema_version": 1,\n "entries": [}')
    assert str(jerr.value).startswith("manifest is not valid JSON (line 2, column 14: ")
    assert "\n" not in str(jerr.value)


def test_test_and_sync_name_the_broken_manifest(registry_app) -> None:
    app, tmp_dir = registry_app
    bad = os.path.join(tmp_dir, "registry-bad.yaml")
    with open(bad, "w", encoding="utf-8") as fh:
        fh.write(BROKEN)
    add = _run(app, "add", "t2r3-bad", "--kind", "file", "--url", bad, "--content", "mcp", "--non-interactive")
    assert add.exit_code == 0, add.output
    want = f"{bad} is not valid YAML (line 2, column 42: expected ',' or '}}', but got '<stream end>')"

    test = _run(app, "test", "t2r3-bad")
    assert test.exit_code == 2
    assert f"error: {want}" in test.output and "<unicode string>" not in test.output

    sync = _run(app, "sync", "t2r3-bad")
    assert sync.exit_code == 1
    assert f"t2r3-bad: {want}\n" in sync.output and "<unicode string>" not in sync.output
    assert app.cfg.registries.sources[0].last_status == f"error: {want}"
