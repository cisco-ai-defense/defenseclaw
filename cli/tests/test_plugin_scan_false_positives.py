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

"""Plugin scan false positives on ordinary plugins (GAP-2165, GAP-2168)."""

from __future__ import annotations

from pathlib import Path

from defenseclaw.scanner import rulepack
from defenseclaw.scanner.plugin_scanner.scanner import scan_plugin

_DEFAULT_PACK = Path(__file__).resolve().parents[2] / "policies" / "guardrail" / "default"


def _rule_ids(result) -> set[str]:
    return {f.rule_id for f in result.findings}


def test_single_file_plugin_has_no_manifest_finding(tmp_path: Path) -> None:
    plugin = tmp_path / "probe.js"
    plugin.write_text("export const Probe = async () => ({});\n")

    result = scan_plugin(str(plugin))

    assert "MANIFEST-MISSING" not in _rule_ids(result)
    assert result.findings == []


def test_plugin_folder_without_manifest_still_reports_it(tmp_path: Path) -> None:
    (tmp_path / "index.js").write_text("export const Probe = 1;\n")

    assert "MANIFEST-MISSING" in _rule_ids(scan_plugin(str(tmp_path)))


def test_rule_pack_overlay_skips_personal_data_rules_on_source() -> None:
    pack = rulepack.load_rule_pack(str(_DEFAULT_PACK))
    source = (
        "def build(first_name, last_name, email):\n"
        "    body = {}\n"
        '    body.update({k: v for k, v in (("firstName", first_name), '
        '("lastName", last_name), ("email", email)) if v})\n'
        "    return body\n"
        'parser.add_argument("--phone", help="for example +15551234567")\n'
    )

    assert not pack.is_empty()
    assert not [r.rule_id for r in pack.rules if r.category == "enterprise-data"]
    assert pack.scan_text(source, location="auth.py", python=True) == []


def test_python_host_plugin_sidecar_may_exit(tmp_path: Path) -> None:
    sidecar = tmp_path / "sidecar"
    sidecar.mkdir()
    (sidecar / "index.mjs").write_text("if (!port) { process.exit(1); }\n")
    (tmp_path / "plugin.yaml").write_text("name: probe\nversion: 1.0.0\n")

    assert "GW-PROCESS-EXIT" not in _rule_ids(scan_plugin(str(tmp_path)))

    (tmp_path / "plugin.yaml").unlink()
    (tmp_path / "package.json").write_text('{"name": "probe", "version": "1.0.0"}\n')

    assert "GW-PROCESS-EXIT" in _rule_ids(scan_plugin(str(tmp_path)))
