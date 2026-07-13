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

"""F-0541 — `registry sync` must not auto-spawn stdio MCP packages.

Scanning a stdio MCP entry inherently SPAWNS the publisher-controlled
package. Routine ``registry sync`` therefore must NOT scan stdio entries
unless the operator opts in with ``--scan-stdio``. These tests drive the
real click command end-to-end and assert that the scanner is only
invoked (i.e. the package is only spawned) under ``--scan-stdio``.
Remote/URL MCP entries spawn no local process and are unaffected.
"""

from __future__ import annotations

import json
import os
import sys
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from click.testing import CliRunner  # noqa: E402
from defenseclaw.commands.cmd_registry import registry  # noqa: E402
from defenseclaw.models import ScanResult  # noqa: E402
from defenseclaw.registries.manifest import parse_manifest  # noqa: E402
from defenseclaw.scanner.mcp import MCPScannerWrapper  # noqa: E402

from tests.helpers import cleanup_app, make_app_context  # noqa: E402


def _clean_result(target: str) -> ScanResult:
    return ScanResult(
        scanner="mcp-scanner", target=target,
        timestamp=datetime.now(timezone.utc), findings=[],
    )


def _stdio_mcp_manifest():
    return parse_manifest(json.dumps({
        "schema_version": 1,
        "publisher": "acme",
        "entries": [
            {
                "name": "some-mcp",
                "type": "mcp",
                "transport": "stdio",
                "command": "npx",
                "args": ["some-mcp"],
            },
        ],
    }))


class RegistrySyncScanStdioTests(unittest.TestCase):
    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()
        self.runner = CliRunner()
        self.app.cfg.config_path = os.path.join(self.tmp_dir, "config.yaml")
        self.app.cfg.save()
        self._orig_columns = os.environ.get("COLUMNS")
        os.environ["COLUMNS"] = "200"
        self._invoke([
            "add", "corp-mcp",
            "--kind", "http_yaml",
            "--content", "mcp",
            "--url", "https://catalog.example.com/mcp.yaml",
            "--non-interactive",
        ])

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)
        if self._orig_columns is None:
            os.environ.pop("COLUMNS", None)
        else:
            os.environ["COLUMNS"] = self._orig_columns

    def _invoke(self, args):
        return self.runner.invoke(
            registry, args, obj=self.app, catch_exceptions=False,
        )

    def _sync(self, extra_args):
        manifest = _stdio_mcp_manifest()
        raw = json.dumps(manifest.to_dict()).encode("utf-8")

        def _fetch(_source, *, allow_private=False):
            return manifest, raw

        scan_calls: list[str] = []

        def _fake_scan(self, target, server_entry=None, *, allow_private=False):
            scan_calls.append(target)
            return _clean_result(target)

        with patch("defenseclaw.registries.sync.fetch_manifest", _fetch):
            with patch.object(MCPScannerWrapper, "scan", _fake_scan):
                result = self._invoke(["sync", "corp-mcp", *extra_args])
        return result, scan_calls

    def test_default_sync_does_not_spawn_stdio_package(self):
        """Default `registry sync` must NOT call the scanner (=spawn the
        publisher package) for a stdio MCP entry, and must emit a
        skip notice."""
        result, scan_calls = self._sync([])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(
            scan_calls, [],
            "default sync must not spawn the stdio MCP package",
        )
        self.assertIn("skipping stdio MCP scan", result.output)

    def test_scan_stdio_flag_spawns_stdio_package(self):
        """With --scan-stdio the operator opts in and the scanner runs
        (=the package is spawned) exactly once."""
        result, scan_calls = self._sync(["--scan-stdio"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(
            scan_calls, ["some-mcp"],
            "--scan-stdio must scan/spawn the stdio MCP entry",
        )


if __name__ == "__main__":
    unittest.main()
