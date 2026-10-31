# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""rel-1-0-6 GAP-0153: an uninstall whose config.yaml does not load says so.

The plan used to drop the load error without a word and go on from the
connector records; the teardown still goes on, and the plan names the error.
"""

from __future__ import annotations

import contextlib
import io
import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.commands import cmd_uninstall  # noqa: E402


@pytest.fixture(autouse=True)
def _no_ambient_agent_configs(monkeypatch):
    monkeypatch.setattr(cmd_uninstall, "_agent_config_wiring_files", lambda: [])


def _plan(data_dir: Path, load):
    (data_dir / "config.yaml").write_text("config_version: [\n", encoding="utf-8")
    with (
        patch.object(cmd_uninstall.config_module, "default_data_path", return_value=str(data_dir)),
        patch.object(cmd_uninstall.config_module, "load", side_effect=load),
    ):
        return cmd_uninstall._build_plan(
            wipe_data=True, binaries=True, revert_openclaw=True, remove_plugin=True, platform_name="linux"
        )


def _rendered(plan) -> str:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        cmd_uninstall._render_plan(plan, dry_run=True)
    return buf.getvalue()


def test_plan_names_the_config_load_error(tmp_path):
    plan = _plan(tmp_path, RuntimeError("config.yaml:1: invalid YAML\n  fix that line"))

    assert plan.config_error == "config.yaml:1: invalid YAML fix that line"
    out = _rendered(plan)
    assert "config.yaml did not load (config.yaml:1: invalid YAML fix that line)" in out
    assert f"the teardown goes on from the connector records in {tmp_path}" in out


def test_plan_says_nothing_when_the_config_loads(tmp_path):
    plan = _plan(tmp_path, lambda: None)

    assert plan.config_error == ""
    assert "did not load" not in _rendered(plan)


def test_long_config_error_stays_one_bounded_line():
    text = cmd_uninstall._one_line("x" * 1000 + "\nmore")
    assert len(text) == 400 and text.endswith("...") and "\n" not in text
