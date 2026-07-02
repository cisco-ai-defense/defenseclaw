# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Direct coverage for shared plugin-directory filtering."""

from __future__ import annotations

import os
from unittest.mock import patch

from defenseclaw.inventory.plugin_directories import plugin_directory_entries


def test_plugin_directory_entries_missing_root(tmp_path) -> None:
    assert plugin_directory_entries(os.fspath(tmp_path / "missing")) == []


def test_plugin_directory_entries_handles_list_error(tmp_path) -> None:
    with patch(
        "defenseclaw.inventory.plugin_directories.os.listdir",
        side_effect=OSError("unreadable"),
    ):
        assert plugin_directory_entries(os.fspath(tmp_path)) == []


def test_plugin_directory_entries_filters_and_sorts(tmp_path) -> None:
    for name in ("zeta", "alpha", "cache", ".hidden", "..plugin-appserver.staging-1"):
        (tmp_path / name).mkdir()
    (tmp_path / "ordinary-file").write_text("not a plugin directory", encoding="utf-8")

    assert plugin_directory_entries(os.fspath(tmp_path)) == [
        ("alpha", os.fspath(tmp_path / "alpha")),
        ("zeta", os.fspath(tmp_path / "zeta")),
    ]
