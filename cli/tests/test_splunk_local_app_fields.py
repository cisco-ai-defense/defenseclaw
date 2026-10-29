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

"""Splunk local-mode app: each field is extracted once, not twice (GAP-0039)."""

from __future__ import annotations

import configparser
import re
from pathlib import Path
from xml.etree import ElementTree

ROOT = Path(__file__).resolve().parents[2]
APP = ROOT / "bundles/splunk_local_bridge/splunk/apps/defenseclaw_local_mode/default"
EXPORTER = ROOT / "bundles/splunk_local_bridge/s3_exporter/export_splunk_to_s3.py"


def _conf(name: str) -> configparser.RawConfigParser:
    parser = configparser.RawConfigParser(strict=True, interpolation=None)
    parser.optionxform = str
    parser.read(APP / name, encoding="utf-8")
    return parser


def test_macros_do_not_run_spath_on_top_of_kv_mode_json() -> None:
    # KV_MODE=json already extracts every field at search time; spath extracts it
    # again, so every multivalue field doubles and so does every count by it.
    macros = _conf("macros.conf")
    assert len(macros.sections()) > 20
    for name in macros.sections():
        assert not re.search(r"\bspath\b", macros[name]["definition"]), name
    assert not re.search(r"^\s*\|\s*spath\s*$", EXPORTER.read_text(encoding="utf-8"), re.MULTILINE)


def test_every_sourcetype_the_macros_search_extracts_json_once() -> None:
    props = _conf("props.conf")
    macros = _conf("macros.conf")
    searched = set()
    for name in macros.sections():
        searched.update(re.findall(r'sourcetype\s*=\s*"([^"]+)"', macros[name]["definition"]))
    assert searched
    for sourcetype in sorted(searched):
        assert props[sourcetype]["KV_MODE"] == "json", sourcetype


def _ai_runtime_query(title: str) -> str:
    view = ElementTree.parse(APP / "data/ui/views/ai_runtime_planes.xml").getroot()
    panels = [panel for panel in view.iter("panel") if panel.findtext("title") == title]
    assert len(panels) == 1, title
    query = panels[0].findtext("./single/search/query") or panels[0].findtext("./chart/search/query")
    assert query, title
    return query


def test_ai_runtime_activity_counts_distinct_required_finding_ids() -> None:
    macros = _conf("macros.conf")
    fields = macros["defenseclaw_demo_ai_runtime_fields"]["definition"]
    assert re.search(r'runtime_finding_id=coalesce\([^\n]+, "\(unknown\)"\)', fields)

    searches = (
        ("Agent activity with no hook decision", "runtime_hook_seen", "runtime_tactic", "stats count"),
        # Each native hit (its control and target) once (GAP-1400).
        (
            "Would-block by control (monitor mode)",
            "runtime_kernel_outcome",
            "runtime_kernel_control runtime_kernel_target",
            "timechart",
        ),
    )
    for title, filter_field, distinct_field, aggregation in searches:
        query = _ai_runtime_query(title)
        commands = [command.strip() for command in query.split(" | ")]
        assert filter_field in commands[1], title
        next_command = 2
        if aggregation == "timechart":
            assert commands[next_command] == "sort 0 + _time", title
            next_command += 1
        assert commands[next_command] == f"dedup host runtime_finding_id {distinct_field}", title
        assert commands[next_command + 1].startswith(aggregation), title

    assert _ai_runtime_query("Would-block (monitor mode)") == (
        '`defenseclaw_demo_ai_runtime_events` | where event_name="ai.runtime.plane_health" '
        'AND runtime_plane="c" | stats sum(runtime_kernel_would_block_delta) as would_block'
    )
