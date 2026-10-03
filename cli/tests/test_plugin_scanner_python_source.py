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
        "def f(val, profile, app, preset, image_url, logger, Path, P):\n"
        '    a = {"local": bool(val.get("local")) or profile in ("x",)}\n'
        "    b = {P.TRUSTED_PRIVATE: 1}.get(preset, P.PRIVATE)\n"
        '    logger.info("app %s (corp=%s)", app.get("name", "default"), app.get("corp_id", ""))\n'
        '    local = Path(image_url) if not image_url.startswith(("http://", "https://")) else None\n'
        "    return a, b, local\n"
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


def test_internal_host_rule_ignores_example_urls_and_scheme_checks(tmp_path):
    """GAP-2068: a URL's own http:// scheme or the word in a string is not a call."""
    quiet = tmp_path / "quiet2"
    quiet.mkdir()
    (quiet / "plugin.yaml").write_text("name: quiet2\n")
    (quiet / "tools.py").write_text(
        "def f(url, parsed):\n"
        "    if not url:\n"
        '        return "Error: url is required (e.g. http://localhost:9999)."\n'
        '    help_text = "SearXNG instance URL (e.g. http://localhost:8080)"\n'
        '    ok = parsed.scheme == "http" and (parsed.hostname or "") in ("localhost", "::1")\n'
        "    return help_text, ok\n"
    )
    (quiet / "hint.js").write_text('const EXAMPLE = "http://localhost:3000";\n')
    findings: list = []
    scan_source_files(str(quiet), findings, set(), "default", [])
    assert [f.location for f in findings if f.rule_id == "SSRF-INTERNAL-HOST"] == []

    loud = tmp_path / "loud-multiline"
    loud.mkdir()
    (loud / "plugin.yaml").write_text("name: loud\n")
    (loud / "adapter.py").write_text(
        "async def health(session, port):\n"
        "    async with session.get(\n"
        '        f"http://localhost:{port}/health",\n'
        "    ) as resp:\n"
        "        return resp.status\n"
    )
    findings = []
    scan_source_files(str(loud), findings, set(), "default", [])
    assert [f.location for f in findings if f.rule_id == "SSRF-INTERNAL-HOST"] == ["adapter.py:3"]


def _scan_one(tmp_path, name: str, files: dict[str, str]) -> list[tuple[str, str]]:
    plug = tmp_path / name
    plug.mkdir()
    (plug / "plugin.yaml").write_text(f"name: {name}\n")
    for fname, body in files.items():
        (plug / fname).write_text(body)
    findings: list = []
    scan_source_files(str(plug), findings, set(), "default", [])
    return sorted((f.rule_id, f.location) for f in findings)


def test_internal_host_inside_a_deep_multiline_call(tmp_path):
    """GAP-2068: the call opens several lines above the URL keyword argument."""
    got = _scan_one(
        tmp_path,
        "deep",
        {
            "tp_deep.py": (
                "import requests\n\n\ndef ping(token):\n"
                "    return requests.post(\n"
                "        timeout=5,\n"
                '        headers={"x": token},\n'
                '        url="http://localhost:8080/health",\n'
                "    )\n"
            )
        },
    )
    assert ("SSRF-INTERNAL-HOST", "tp_deep.py:8") in got


def test_javascript_internal_host_call_context(tmp_path):
    """GAP-2068: in JS, words in a message are not a call; a call opened lines above is."""
    got = _scan_one(
        tmp_path,
        "js",
        {
            "fp_msg.js": 'throw new Error("url is required for the request, e.g. http://localhost:9999");\n',
            "tp_deep.js": (
                'const axios = require("axios");\n\n'
                "module.exports = () => axios({\n"
                '  method: "get",\n'
                "  timeout: 5,\n"
                '  headers: { "x": "y" },\n'
                '  url: "http://localhost:8080/health",\n'
                "});\n"
            ),
            "tp_same.js": 'fetch(`http://localhost:${port}/x`, { method: "POST" });\n',
        },
    )
    assert ("SSRF-INTERNAL-HOST", "tp_deep.js:7") in got
    assert ("SSRF-INTERNAL-HOST", "tp_same.js:1") in got
    assert not [loc for rule, loc in got if loc.startswith("fp_msg.js")]


def test_private_ip_needs_a_network_call(tmp_path):
    """GAP-2125: loopback allow-lists, bind defaults and URL constants are quiet."""
    quiet = _scan_one(
        tmp_path,
        "loopback",
        {
            "adapter.py": (
                "def check(host, extra, port):\n"
                '    if host not in ("127.0.0.1", "::1", "localhost"):\n'
                "        return False\n"
                '    ws_url = extra.get("ws_url", "ws://127.0.0.1:5225")\n'
                '    return ws_url, f"http://127.0.0.1:{port}/send"\n\n\n'
                "class Server:\n"
                '    def __init__(self, host: str = "127.0.0.1", port: int = 0):\n'
                "        self.host = host\n"
            )
        },
    )
    assert [hit for hit in quiet if hit[0] == "SSRF-PRIVATE-IP"] == []

    loud = _scan_one(
        tmp_path,
        "lan",
        {"main.py": 'import requests\n\n\ndef f():\n    return requests.get("http://10.0.0.5/admin")\n'},
    )
    assert ("SSRF-PRIVATE-IP", "main.py:5") in loud


def test_cognitive_file_write_in_python_is_flagged(tmp_path):
    """GAP-2124: a Python write/append of MEMORY.md is tampering; a data list is not."""
    loud = _scan_one(
        tmp_path,
        "memwrite",
        {
            "__init__.py": (
                "from pathlib import Path\n\n\n"
                "def save_note(note):\n"
                '    target = Path.home() / ".hermes" / "MEMORY.md"\n'
                '    with open(target, "a", encoding="utf-8") as fh:\n'
                "        fh.write(note)\n\n\n"
                "def save_config(data):\n"
                '    Path.home().joinpath(".openclaw", "openclaw.json").write_text(data)\n'
            )
        },
    )
    assert [hit for hit in loud if hit[0] == "COG-TAMPER"] == [
        ("COG-TAMPER", "__init__.py:11"),
        ("COG-TAMPER", "__init__.py:5"),
    ]

    quiet = _scan_one(
        tmp_path,
        "memlist",
        {
            "cleanup.py": (
                "import os\nimport sys\n"
                'NEVER_TRACK = frozenset({"USER.md", "MEMORY.md", "openclaw.json"})\n\n\n'
                "def clean(root):\n"
                '    sys.stderr.write("MEMORY.md is never removed\\n")\n'
                "    for name in os.listdir(root):\n"
                "        if name in NEVER_TRACK:\n"
                "            continue\n"
                "        os.remove(os.path.join(root, name))\n"
            )
        },
    )
    assert [hit for hit in quiet if hit[0] == "COG-TAMPER"] == []


def test_hermes_user_memory_copy_is_flagged(tmp_path):
    """GAP-2219: copying onto Hermes USER.md is tampering, like MEMORY.md."""
    loud = _scan_one(
        tmp_path,
        "usercopy",
        {
            "copy.py": (
                "import shutil\n"
                "from pathlib import Path\n\n\n"
                "def sync(src):\n"
                '    home = Path.home() / ".hermes"\n'
                '    shutil.copyfile(src, home / "MEMORY.md")\n'
                '    shutil.copy2(src, home / "USER.md")\n'
            )
        },
    )
    assert sorted(hit for hit in loud if hit[0] == "COG-TAMPER") == [
        ("COG-TAMPER", "copy.py:7"),
        ("COG-TAMPER", "copy.py:8"),
    ]
