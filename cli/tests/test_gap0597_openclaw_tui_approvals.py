# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""GAP-0597: OpenClaw 2026.10.9 shows DefenseClaw approvals in openclaw tui,
and Allow once works there (TST-17954, TST-17958). Setup, doctor and the
plugin hint name it; setup warns only for an OpenClaw whose tui does not
show the requests or whose version is unknown."""

from __future__ import annotations

import pytest
from defenseclaw.connector_contracts import OPENCLAW_APPROVAL_SURFACES, openclaw_tui_shows_approvals

from tests.test_openclaw_setup_advisories import _setup, _with_plugin

pytestmark = pytest.mark.usefixtures("openclaw_proxy_topology")


@pytest.mark.parametrize(
    ("version", "shows"),
    [
        ("OpenClaw 2026.10.9 (abc1234)", True),
        ("OpenClaw 2026.11.2", True),
        ("OpenClaw 2026.9.8", False),
        ("OpenClaw 2026.6.8 (844f405)", False),
        ("", False),
        (None, False),
    ],
)
def test_openclaw_tui_shows_approvals(version, shows) -> None:
    assert openclaw_tui_shows_approvals(version) is shows


def test_surfaces_name_openclaw_tui_from_2026_10_9() -> None:
    assert "openclaw tui from OpenClaw 2026.10.9" in OPENCLAW_APPROVAL_SURFACES
    assert "do not show them" not in OPENCLAW_APPROVAL_SURFACES


def test_setup_on_2026_10_9_names_the_tui_without_a_warning(tmp_path, capsys) -> None:
    out = _setup(tmp_path, capsys, cfg=_with_plugin(), human_approval=True, version="OpenClaw 2026.10.9 (abc1234)")
    assert "openclaw tui" in out and "Control UI" in out
    approval_lines = [line for line in out.splitlines() if "approval requests" in line]
    assert approval_lines and not any("⚠" in line for line in approval_lines), out


def test_setup_on_an_older_openclaw_still_warns(tmp_path, capsys) -> None:
    out = _setup(tmp_path, capsys, cfg=_with_plugin(), human_approval=True)
    approval_lines = [line for line in out.splitlines() if "approval requests" in line]
    assert approval_lines and any("⚠" in line for line in approval_lines), out
