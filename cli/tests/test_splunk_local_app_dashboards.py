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

"""Static invariants for the bundled local Splunk app dashboards."""

from __future__ import annotations

import re
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_SOURCE_BRIDGE = _REPO_ROOT / "bundles" / "splunk_local_bridge"
_PACKAGED_BRIDGE = _REPO_ROOT / "cli" / "defenseclaw" / "_data" / "splunk_local_bridge"
_APP_NAMESPACE = "defenseclaw_local_mode"
_APP_DIR = _SOURCE_BRIDGE / "splunk" / "apps" / _APP_NAMESPACE
_VIEWS_DIR = _APP_DIR / "default" / "data" / "ui" / "views"


def _stanza_names(path: Path) -> list[str]:
    names: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.match(r"\[([^]]+)\]", line.strip())
        if match:
            names.append(match.group(1))
    return names


def _macro_key(raw_name: str) -> tuple[str, int]:
    match = re.match(r"(.+)\((\d+)\)$", raw_name)
    if match:
        return match.group(1), int(match.group(2))
    return raw_name, 0


def _macro_call_key(raw_call: str) -> tuple[str, int]:
    if "(" not in raw_call:
        return raw_call, 0
    name, arg_text = raw_call.split("(", 1)
    arg_text = arg_text.rsplit(")", 1)[0]
    if not arg_text:
        return name, 0
    return name, len(arg_text.split(","))


def _macro_definitions(path: Path) -> dict[tuple[str, int], str]:
    definitions: dict[tuple[str, int], str] = {}
    current: tuple[str, int] | None = None
    for line in path.read_text(encoding="utf-8").splitlines():
        stanza = re.match(r"\[([^]]+)\]", line.strip())
        if stanza:
            current = _macro_key(stanza.group(1))
            continue
        if current and line.startswith("definition = "):
            definitions[current] = line.removeprefix("definition = ").strip()
    return definitions


def _searches_from_conf(path: Path) -> list[tuple[str, str]]:
    searches: list[tuple[str, str]] = []
    current = ""
    for line in path.read_text(encoding="utf-8").splitlines():
        stanza = re.match(r"\[([^]]+)\]", line.strip())
        if stanza:
            current = stanza.group(1)
            continue
        if current and line.startswith("search = "):
            searches.append((current, line.removeprefix("search = ").strip()))
    return searches


def _dashboard_queries() -> list[tuple[str, str]]:
    queries: list[tuple[str, str]] = []
    for view in sorted(_VIEWS_DIR.glob("*.xml")):
        root = ET.parse(view).getroot()
        for index, search in enumerate(root.findall(".//search"), start=1):
            query = (search.findtext("query") or "").strip()
            if query:
                queries.append((f"{view.name} search#{index}", query))
    return queries


def _expanded_generating_prefix(search: str, macros: dict[tuple[str, int], str]) -> str:
    text = search.strip()
    seen: set[tuple[str, int]] = set()
    while text.startswith("`"):
        end = text.find("`", 1)
        if end == -1:
            return text
        key = _macro_call_key(text[1:end])
        if key in seen:
            return text
        seen.add(key)
        definition = macros.get(key)
        if definition is None:
            return text
        text = f"{definition.strip()} {text[end + 1:].strip()}".strip()
    return text


class SplunkLocalAppDashboardTests(unittest.TestCase):
    def test_all_dashboard_xml_files_parse(self):
        views = sorted(_VIEWS_DIR.glob("*.xml"))
        self.assertEqual(len(views), 12)
        for view in views:
            root = ET.parse(view).getroot()
            self.assertIn(root.tag, {"dashboard", "form"}, view)
            self.assertTrue(root.findtext("label"), f"{view} must have a label")

    def test_nav_references_existing_views(self):
        nav = ET.parse(_APP_DIR / "default" / "data" / "ui" / "nav" / "default.xml").getroot()
        view_names = {path.stem for path in _VIEWS_DIR.glob("*.xml")}
        nav_refs = [elem.attrib["name"] for elem in nav.findall(".//view")]
        self.assertTrue(nav_refs)
        self.assertEqual([], [ref for ref in nav_refs if ref not in view_names])

    def test_dashboard_links_use_app_namespace(self):
        wrong_links: list[str] = []
        for view in sorted(_VIEWS_DIR.glob("*.xml")):
            root = ET.parse(view).getroot()
            for link in root.findall(".//link"):
                text = link.text or ""
                match = re.search(r"/app/([^/]+)/", text)
                if match and match.group(1) != _APP_NAMESPACE:
                    wrong_links.append(f"{view.name}: {text}")
        self.assertEqual([], wrong_links)

    def test_macro_references_are_defined_with_expected_arity(self):
        macros = _macro_definitions(_APP_DIR / "default" / "macros.conf")
        spl_sources = [
            ("macros.conf", (_APP_DIR / "default" / "macros.conf").read_text(encoding="utf-8")),
            *_searches_from_conf(_APP_DIR / "default" / "savedsearches.conf"),
            *_dashboard_queries(),
        ]
        missing: list[str] = []
        for source, spl in spl_sources:
            for raw_call in re.findall(r"`([^`]+)`", spl):
                key = _macro_call_key(raw_call)
                if key not in macros:
                    missing.append(f"{source}: `{raw_call}`")
        self.assertEqual([], missing)

    def test_dashboard_and_saved_searches_start_with_generating_command(self):
        macros = _macro_definitions(_APP_DIR / "default" / "macros.conf")
        searches = _dashboard_queries()
        searches.extend(
            (f"saved search {name}", search)
            for name, search in _searches_from_conf(_APP_DIR / "default" / "savedsearches.conf")
        )

        invalid: list[str] = []
        for name, search in searches:
            expanded = _expanded_generating_prefix(search, macros).lower()
            # Simple XML dashboard dispatch prepends the implicit search command
            # before expanding a leading macro. Saved searches do not, so those
            # still need an explicit generating command.
            dashboard_query = ".xml search#" in name
            valid_prefixes = ("search ", "|", "index=") if dashboard_query else ("search ", "|")
            if not expanded.startswith(valid_prefixes):
                invalid.append(f"{name}: {search}")
        self.assertEqual([], invalid)

    def test_gateway_logs_accept_default_hec_gateway_envelopes(self):
        macros = _macro_definitions(_APP_DIR / "default" / "macros.conf")
        definition = macros[("openclaw_gateway_logs_base", 0)]
        for expected in (
            'sourcetype="openclaw:gateway:json"',
            'sourcetype="defenseclaw:json"',
            'sourcetype="_json"',
            'event_type="lifecycle"',
            'event_type="error"',
            'event_type="diagnostic"',
            "'lifecycle.subsystem'",
            "'error.message'",
            "'diagnostic.message'",
        ):
            self.assertIn(expected, definition)

    def test_source_and_packaged_splunk_app_stay_in_sync(self):
        source_app = _SOURCE_BRIDGE / "splunk" / "apps" / _APP_NAMESPACE
        packaged_app = _PACKAGED_BRIDGE / "splunk" / "apps" / _APP_NAMESPACE
        if not packaged_app.exists():
            self.skipTest("generated package-data copy is not present in this checkout")
        source_files = sorted(path.relative_to(source_app) for path in source_app.rglob("*") if path.is_file())
        packaged_files = sorted(path.relative_to(packaged_app) for path in packaged_app.rglob("*") if path.is_file())
        self.assertEqual(source_files, packaged_files)
        for relative in source_files:
            self.assertEqual(
                (source_app / relative).read_bytes(),
                (packaged_app / relative).read_bytes(),
                f"packaged Splunk app file differs: {relative}",
            )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
