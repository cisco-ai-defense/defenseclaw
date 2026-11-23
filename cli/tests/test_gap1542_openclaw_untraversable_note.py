# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""rel-1-0-10 GAP-1542: the permission-denied note for openclaw.json names the
first folder the account cannot enter, not only the file."""

from __future__ import annotations

import os
import sys
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from defenseclaw import openclaw_plugin_config as occ

pytestmark = pytest.mark.skipif(
    sys.platform == "win32" or (hasattr(os, "geteuid") and os.geteuid() == 0),
    reason="POSIX folder permissions, not root",
)


def _cfg(config_file, data_dir):
    return SimpleNamespace(claw=SimpleNamespace(home_dir=os.path.dirname(config_file), config_file=config_file), data_dir=data_dir)


def _notes(cfg):
    block = {"plugin_account": "ocl-oc", "hooks": {"mode": "proxy"}}
    with patch.object(occ, "_openclaw_connector_block", return_value=block):
        return occ.openclaw_separate_user_notes(cfg)


def test_the_note_names_the_first_folder_the_account_cannot_enter(tmp_path):
    shut = tmp_path / "oc-home"
    inner = shut / ".openclaw"
    inner.mkdir(parents=True)
    config_file = inner / "openclaw.json"
    config_file.write_text("{}", encoding="utf-8")
    shut.chmod(0o000)
    try:
        notes = _notes(_cfg(str(config_file), str(tmp_path / "dc")))
    finally:
        shut.chmod(0o700)
    assert len(notes) == 1, notes
    assert f": it cannot enter {shut}, so setup did not check it" in notes[0]
    assert str(config_file) in notes[0]


def test_a_file_that_refuses_on_its_own_keeps_the_file_note(tmp_path):
    config_file = tmp_path / "openclaw.json"
    config_file.write_text("{}", encoding="utf-8")
    config_file.chmod(0o000)
    try:
        notes = _notes(_cfg(str(config_file), str(tmp_path / "dc")))
    finally:
        config_file.chmod(0o600)
    assert len(notes) == 1, notes
    assert "it cannot enter" not in notes[0]
    assert f"This account cannot read {config_file}, so setup did not check it" in notes[0]
