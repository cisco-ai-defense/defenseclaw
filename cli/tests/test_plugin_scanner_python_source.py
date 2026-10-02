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

"""GAP-1736/GAP-1877: the plugin scanner reads Python (Hermes) plugin source."""

from __future__ import annotations

import os

from defenseclaw.scanner.plugin_scanner.analyzers import scan_source_files


def test_python_plugin_source_is_scanned(tmp_path):
    plugin = tmp_path / "pyplug"
    plugin.mkdir()
    (plugin / "plugin.yaml").write_text("name: pyplug\n")
    (plugin / "__init__.py").write_text(
        "import subprocess\n"
        "# subprocess.run('only a comment')\n"
        "subprocess.run('echo dccert-block-marker', shell=True)\n"
    )

    findings: list = []
    sources: list = []
    count, _ = scan_source_files(str(plugin), findings, set(), "default", sources)

    assert count == 1
    assert [os.path.basename(sf.path) for sf in sources] == ["__init__.py"]
    hits = [f for f in findings if f.rule_id == "SRC-PY-SUBPROCESS"]
    assert [f.location for f in hits] == ["__init__.py:3"]


def test_python_strings_docstrings_and_js_rules_do_not_fire(tmp_path):
    """GAP-1877: rule text in strings/docstrings and JS-only rules stay quiet on .py."""
    plugin = tmp_path / "guidance"
    plugin.mkdir()
    (plugin / "plugin.yaml").write_text("name: guidance\n")
    (plugin / "patterns.py").write_text(
        '"""Warns about eval( and child_process.exec() in edited code."""\n'
        "from typing import (\n"
        "    Any,\n"
        ")\n"
        '_REMINDER = """\n'
        "Avoid child_process.exec() and new Function( and spawn(cmd).\n"
        '"""\n'
        'RULES = [r"\\beval\\s*\\(", "subprocess.run(", "process.exit("]\n'
        "def check(text):\n"
        '    """Return True when the text reads a local file over http get."""\n'
        "    return bool(text)\n"
    )

    findings: list = []
    scan_source_files(str(plugin), findings, set(), "default", [])
    assert [(f.rule_id, f.location) for f in findings] == []


def test_python_real_calls_still_flagged(tmp_path):
    plugin = tmp_path / "runner"
    plugin.mkdir()
    (plugin / "plugin.yaml").write_text("name: runner\n")
    (plugin / "run.py").write_text(
        'import subprocess\nsubprocess.run(["git", "status"])\neval(user_text)\nexec(code)\n'
    )

    findings: list = []
    scan_source_files(str(plugin), findings, set(), "default", [])
    got = sorted((f.rule_id, f.location) for f in findings)
    assert got == [("SRC-EVAL", "run.py:3"), ("SRC-EXEC", "run.py:4"), ("SRC-PY-SUBPROCESS", "run.py:2")]
    assert 'subprocess.run(["git", "status"])' in next(f.evidence for f in findings if f.rule_id == "SRC-PY-SUBPROCESS")


def test_internal_host_rule_needs_a_host_and_a_network_call(tmp_path):
    """GAP-1982: dict .get() and bare identifiers are not SSRF-INTERNAL-HOST."""
    quiet = tmp_path / "quiet"
    quiet.mkdir()
    (quiet / "plugin.yaml").write_text("name: quiet\n")
    (quiet / "adapter.py").write_text(
        'def f(val, profile, app, preset, image_url, logger, Path, P):\n'
        '    a = {"local": bool(val.get("local")) or profile in ("x",)}\n'
        '    b = {P.TRUSTED_PRIVATE: 1}.get(preset, P.PRIVATE)\n'
        '    logger.info("app %s (corp=%s)", app.get("name", "default"), app.get("corp_id", ""))\n'
        '    local = Path(image_url) if not image_url.startswith(("http://", "https://")) else None\n'
        '    return a, b, local\n'
    )
    findings: list = []
    scan_source_files(str(quiet), findings, set(), "default", [])
    assert [f.location for f in findings if f.rule_id == "SSRF-INTERNAL-HOST"] == []

    for body in (
        'import requests\nrequests.get("http://metadata.internal/v1")\n',
        'import httpx\nhttpx.post(url="https://intranet.corp/api")\n',
        'import urllib.request\nurllib.request.urlopen("http://localhost:8080/x")\n',
        'const r = await fetch("http://localhost:3000/api");\n',
    ):
        plug = tmp_path / f"loud{len(list(tmp_path.iterdir()))}"
        plug.mkdir()
        (plug / "plugin.yaml").write_text("name: loud\n")
        name = "index.js" if body.startswith("const") else "main.py"
        (plug / name).write_text(body)
        findings = []
        scan_source_files(str(plug), findings, set(), "default", [])
        assert [f.rule_id for f in findings if f.rule_id == "SSRF-INTERNAL-HOST"] == ["SSRF-INTERNAL-HOST"], body
