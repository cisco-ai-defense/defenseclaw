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

"""GAP-1736: the plugin scanner reads Python (Hermes) plugin source."""

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
