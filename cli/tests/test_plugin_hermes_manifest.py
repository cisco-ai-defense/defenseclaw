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

"""Hermes plugin.yaml manifests (GAP-1334, GAP-1350)."""

from __future__ import annotations

from defenseclaw.scanner.plugin_scanner.scanner import scan_plugin


def _rule_ids(result) -> list[str]:
    return [finding.rule_id for finding in result.findings]


def test_hermes_plugin_yaml_is_a_manifest(tmp_path):
    plugin = tmp_path / "spotify"
    plugin.mkdir()
    (plugin / "plugin.yaml").write_text(
        'name: spotify\nversion: 1.0.0\ndescription: "Native Spotify integration — 7 tools"\nkind: backend\n',
        encoding="utf-8",
    )
    (plugin / "__init__.py").write_text("def register(ctx):\n    return None\n", encoding="utf-8")

    result = scan_plugin(str(plugin))

    assert result.findings == [], _rule_ids(result)
    assert result.metadata.manifest_name == "spotify"
    assert result.metadata.manifest_version == "1.0.0"


def test_missing_manifest_has_no_none_location(tmp_path):
    plugin = tmp_path / "bare"
    plugin.mkdir()
    (plugin / "index.js").write_text("module.exports = {};\n", encoding="utf-8")

    result = scan_plugin(str(plugin))

    assert "MANIFEST-MISSING" in _rule_ids(result)
    assert "PERM-NONE" not in _rule_ids(result)
    assert not any(str(f.location or "").endswith("/none") for f in result.findings)

