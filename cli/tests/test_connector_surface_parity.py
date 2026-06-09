# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0
"""Connector-surface parity.

KNOWN_CONNECTORS is the source of truth for recognized connectors. Several
user-facing surfaces hardcode their own connector lists (the quickstart /
init wizards, doctor labels, agent discovery, the TUI label maps). When a new
connector is added (opencode was the case that motivated this test) it is easy
to wire the gateway + a few tested lists but miss these. This test fails loudly
if any KNOWN_CONNECTOR is absent from a surface it must appear in.
"""

from __future__ import annotations

from defenseclaw.commands.cmd_doctor import _CONNECTOR_LABELS
from defenseclaw.commands.cmd_init import init_cmd
from defenseclaw.commands.cmd_quickstart import quickstart_cmd
from defenseclaw.connector_paths import KNOWN_CONNECTORS
from defenseclaw.inventory.agent_discovery import DISCOVERY_PRECEDENCE, _SPECS
from defenseclaw.tui.services.catalog_state import friendly_connector_name as catalog_friendly_name
from defenseclaw.tui.services.overview_state import friendly_connector_name as overview_friendly_name

KNOWN = set(KNOWN_CONNECTORS)


def _click_choices(cmd, param_name: str) -> set[str]:
    for p in cmd.params:
        if p.name == param_name:
            return set(p.type.choices)
    raise AssertionError(f"{cmd.name} has no param {param_name!r}")


def test_quickstart_offers_every_known_connector() -> None:
    choices = _click_choices(quickstart_cmd, "agent_name")
    assert KNOWN <= choices, f"quickstart --agent missing: {KNOWN - choices}"


def test_init_offers_every_known_connector() -> None:
    choices = _click_choices(init_cmd, "connector")
    assert KNOWN <= choices, f"init --connector missing: {KNOWN - choices}"


def test_doctor_labels_cover_every_known_connector() -> None:
    assert KNOWN <= set(_CONNECTOR_LABELS), f"doctor labels missing: {KNOWN - set(_CONNECTOR_LABELS)}"


def test_agent_discovery_covers_opencode() -> None:
    assert "opencode" in DISCOVERY_PRECEDENCE
    assert "opencode" in _SPECS


def test_tui_label_maps_have_explicit_opencode_case() -> None:
    # The fallback path would capitalize to "Opencode"; the explicit case
    # returns "OpenCode". Asserting the latter proves the case exists.
    assert overview_friendly_name("opencode") == "OpenCode"
    assert catalog_friendly_name("opencode") == "OpenCode"
