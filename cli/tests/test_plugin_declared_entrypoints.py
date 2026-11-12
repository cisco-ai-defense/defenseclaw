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

"""The gateway watcher asks the scanner loader which entrypoints a manifest declares (GAP-0645)."""

from __future__ import annotations

import base64
import json

import pytest
from click.testing import CliRunner
from defenseclaw.commands.cmd_plugin import plugin
from defenseclaw.scanner.plugin_scanner import scanner

_MANIFESTS = {
    "yaml-1.2-directive": ("plugin.yaml", "%YAML 1.2\n---\nname: p\nmain: lib/run.js\n"),
    "yaml-1.2-binary-padding": ("plugin.yaml", "%YAML 1.2\n---\nname: p\nmain: lib/run.js\nx: !!binary YQ==abc\n"),
    "recursive-merge": ("plugin.yaml", "name: p\nmain: lib/run.js\nr: &r\n  <<: *r\n  a: 1\n"),
    "binary-key-padding": ("plugin.yaml", "bin:\n  !!binary YQ==: a.js\n  !!binary YQ==abc: __pycache__/p.cpython-312.pyc\n"),
    "merge-override": ("plugin.yml", "base: &b\n  main: old.js\n<<: *b\nmain: __pycache__/p.cpython-312.pyc\n"),
    "json-bin-map": ("package.json", json.dumps({"main": "a.js", "bin": {"x": "b.js"}})),
    "json-infinity": ("package.json", "{\"x\": -Infinity, \"main\": \"a.js\"}"),
    "refused-yaml": ("plugin.yaml", "name: [unclosed\n"),
    "refused-json": ("package.json", "{\"main\": "),
    "not-a-mapping": ("plugin.yaml", "- a\n- b\n"),
}


@pytest.mark.parametrize("name", sorted(_MANIFESTS))
def test_declared_entrypoints_equal_what_a_scan_reads(tmp_path, name):
    rel, body = _MANIFESTS[name]
    (tmp_path / rel).write_text(body, encoding="utf-8")
    manifest = scanner._load_manifest(str(tmp_path))
    expected = list(manifest.entrypoints) if manifest else []
    assert scanner.declared_entrypoints({rel: body.encode()}) == expected


def test_declared_entrypoints_unites_every_manifest_present():
    found = scanner.declared_entrypoints(
        {"package.json": b"{\"main\": \"a.js\"}", "plugin.yaml": b"entry: c.js\nmain: a.js\n"}
    )
    assert found == ["a.js", "c.js"]


def test_declared_entrypoints_decodes_as_a_scan_does():
    # A scan opens a manifest in UTF-8 text mode: CRLF is folded, other bytes raise.
    assert scanner.declared_entrypoints({"plugin.yaml": b"main: lib/run.js\r\n"}) == ["lib/run.js"]
    with pytest.raises(UnicodeDecodeError):
        scanner.declared_entrypoints({"package.json": b"{\"main\": \"\xff\"}"})


def test_declared_entrypoints_ignores_names_that_are_not_manifest_candidates():
    assert scanner.declared_entrypoints({"notes.yaml": b"main: a.js\n"}) == []


def test_manifest_entrypoints_command_reads_stdin():
    request = {"manifests": {"plugin.yaml": base64.b64encode(b"%YAML 1.2\n---\nmain: lib/run.js\n").decode()}}
    result = CliRunner().invoke(plugin, ["manifest-entrypoints"], input=json.dumps(request))
    assert result.exit_code == 0, result.output
    assert json.loads(result.output) == {"entrypoints": ["lib/run.js"]}


def test_manifest_entrypoints_command_fails_rather_than_answering_empty():
    request = {"manifests": {"package.json": base64.b64encode(b"{\"main\": \"\xff\"}").decode()}}
    result = CliRunner().invoke(plugin, ["manifest-entrypoints"], input=json.dumps(request))
    assert result.exit_code != 0
