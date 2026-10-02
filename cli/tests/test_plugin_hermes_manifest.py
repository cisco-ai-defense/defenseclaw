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

"""Hermes plugin.yaml manifests and UTF-8 connector files (GAP-1334/1350/1375)."""

from __future__ import annotations

import os
import subprocess
import sys

import yaml
from defenseclaw.scanner.plugin_scanner.scanner import scan_plugin

_CLI_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


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


def test_yaml_connector_merge_reads_utf8_under_a_non_utf8_locale(tmp_path):
    """GAP-1375: Windows cp1252 broke 'mcp set' for Hermes' UTF-8 config.yaml."""
    config = tmp_path / "config.yaml"
    config.write_text("# Hermes — stock comment\nmodel: x\n", encoding="utf-8")
    code = (
        "import sys; from defenseclaw import connector_paths as c; "
        "c._atomic_yaml_merge(sys.argv[1], ('mcp_servers', 'deepwiki'), {'url': 'https://example.invalid/mcp'})"
    )
    env = {**os.environ, "LC_ALL": "C", "LANG": "C", "PYTHONUTF8": "0", "PYTHONCOERCECLOCALE": "0",
           "PYTHONPATH": _CLI_ROOT}
    proc = subprocess.run([sys.executable, "-c", code, str(config)], env=env, capture_output=True, text=True)

    assert proc.returncode == 0, proc.stderr
    data = yaml.safe_load(config.read_text(encoding="utf-8"))
    assert data["mcp_servers"]["deepwiki"]["url"] == "https://example.invalid/mcp"
    assert data["model"] == "x"
