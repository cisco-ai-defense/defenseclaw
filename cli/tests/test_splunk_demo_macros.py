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

"""The local Splunk app's demo macros read the fields the v8 HEC adapter emits."""

from __future__ import annotations

import html
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
APP = REPO_ROOT / "bundles/splunk_local_bridge/splunk/apps/defenseclaw_local_mode/default"
MACROS = APP / "macros.conf"
PROPS = APP / "props.conf"
SAVED = APP / "savedsearches.conf"
VIEWS = APP / "data/ui/views"
HEC = REPO_ROOT / "internal/observability/destinations/push/splunk_hec.go"


def test_body_fields_are_read_under_the_hec_record() -> None:
    """GAP-0093: the v8 HEC event nests the canonical record under "record"
    (with a few top-level compatibility aliases), so a body attribute arrives as
    the flattened field record.body.<key>. Every macro that reads 'body.<key>'
    reads 'record.body.<key>' first; the AI Runtime Planes panels and the kernel
    macros showed (unknown) and 0 on live HEC data without it."""
    assert '`"event":{"record":`' in HEC.read_text(encoding="utf-8"), "the HEC envelope changed: recheck the macros"
    text = MACROS.read_text(encoding="utf-8")
    reads = re.findall(r"coalesce\('body\.([A-Za-z0-9_.]+)'", text) + re.findall(r", 'body\.([A-Za-z0-9_.]+)'", text)
    assert reads, "no macro reads a body field"
    missing = sorted({key for key in reads if f"coalesce('record.body.{key}', 'body.{key}'" not in text})
    assert not missing, f"macros read body fields without the record.body field the HEC event carries: {missing}"
    # Nothing reads a body field outside a coalesce that offers the HEC name.
    bare = [m.group(0) for m in re.finditer(r"(?<![.\w])'body\.[A-Za-z0-9_.]+'", text)]
    assert len(bare) == len(reads), f"a body field read outside coalesce('record.body...', ...): {bare}"


def _stanzas(path: Path) -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    name = None
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        header = re.fullmatch(r"\[(.+)\]", line)
        if header:
            name = header.group(1)
            out.setdefault(name, {})
        elif name is not None and "=" in line:
            key, value = line.split("=", 1)
            out[name][key.strip()] = value.strip()
    return out


def _expand(search: str, macros: dict[str, str], depth: int = 0) -> str:
    assert depth < 20, f"macro loop in {search[:80]}"
    return re.sub(r"`([A-Za-z0-9_]+)`", lambda m: _expand(macros[m.group(1)], macros, depth + 1) if m.group(1) in macros else m.group(0), search)


def _extractions(search: str, sourcetype: str, auto_json: set[str]) -> int:
    """How many values a field of one event of sourcetype gets: one from the
    sourcetype's KV_MODE=json, one more from every spath that reads its _raw."""
    count = 1 if sourcetype in auto_json else 0
    for command in search.split("|"):
        words = command.split()
        if not words or words[0] != "spath":
            continue
        if "input=dc_spath_input" in words:
            count += 0 if sourcetype in auto_json else 1
        elif not any(word.startswith("input=") for word in words):
            count += 1
    return count


def _parts(search: str) -> list[str]:
    """A search and each of its [ ... ] subsearches (append, join), apart:
    each reads its own events. Brackets in a quoted string (a regex) are text."""
    main: list[str] = []
    subs: list[str] = []
    current: list[str] = []
    depth, quoted, escaped = 0, False, False
    for char in search:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char == "[":
            depth += 1
            if depth == 1:
                current = []
                continue
        elif char == "]" and depth > 0:
            depth -= 1
            if depth == 0:
                subs.append("".join(current))
                continue
        (current if depth else main).append(char)
    return ["".join(main)] + [part for sub in subs for part in _parts(sub)]


def test_no_search_extracts_a_field_twice() -> None:
    """GAP-0093 (TH r5): defenseclaw_demo_all_events ran | spath over
    defenseclaw:json events, which props.conf already extracts (KV_MODE=json).
    Every field then had two identical values: stats by a field counted each
    event twice (kernel denials by control 16+4 for 10 events) and tonumber()
    of a two-value field was null (the kernel event, would-block and burn-in
    hour sums were blank). Every macro, dashboard search and saved search gives
    a field of such an event one value."""
    auto_json = {name for name, keys in _stanzas(PROPS).items() if keys.get("KV_MODE", "").lower() == "json"}
    assert "defenseclaw:json" in auto_json, auto_json
    macros = {name: keys["definition"] for name, keys in _stanzas(MACROS).items() if "definition" in keys}
    helper = macros["defenseclaw_spath_unextracted"]
    assert set(re.findall(r'sourcetype=="([^"]+)"', helper)) == auto_json, "the spath helper must skip exactly the KV_MODE=json sourcetypes"
    searches = dict(macros)
    for name, keys in _stanzas(SAVED).items():
        if "search" in keys:
            searches["savedsearches.conf:" + name] = keys["search"]
    for view in sorted(VIEWS.glob("*.xml")):
        for i, query in enumerate(re.findall(r"<query>(.*?)</query>", view.read_text(encoding="utf-8"), re.S)):
            searches[f"{view.name}#{i}"] = html.unescape(query)
    assert len(searches) > 100, len(searches)
    doubled = []
    for name, search in searches.items():
        for part in _parts(_expand(search, macros)):
            named = set(re.findall(r'sourcetype="([^"]+)"', part))
            for sourcetype in sorted(named & auto_json if named else auto_json):
                if _extractions(part, sourcetype, auto_json) > 1:
                    doubled.append(f"{name} ({sourcetype})")
    assert not doubled, f"these searches extract a field of a KV_MODE=json event twice: {doubled}"
    # The AI Runtime Planes sums read one value per event.
    runtime = _expand("`defenseclaw_demo_kernel_events`", macros)
    for field in ("runtime_kernel_count", "runtime_kernel_would_block_delta", "runtime_kernel_covered_hours", "runtime_kernel_needed_hours"):
        assert f"{field}=tonumber(coalesce('record.body." in runtime, field
    assert _extractions(runtime, "defenseclaw:json", auto_json) == 1
