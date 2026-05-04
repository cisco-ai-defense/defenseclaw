# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Plan E2 / item 1 — ZeptoClaw config parity tests.

Mirrors test_guardrail.py's OpenClaw-config flow for ZeptoClaw's
``~/.zeptoclaw/config.json``: shape parsing, MCP-server enumeration,
provider-snapshot capture, and patch/restore round-trips. We do NOT
shell out to a real ZeptoClaw binary here — every test is filesystem-
shape-only against an isolated tmp HOME, mirroring the gateway's
filesystem-driven readers in :mod:`defenseclaw.connector_paths`.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw import connector_paths
from tests.connector_fixtures import make_zeptoclaw_config


class _IsolatedHome:
    """Context manager that swaps HOME (and Path.home()) to a tmpdir.

    ``connector_paths`` reads from ``Path.home()`` directly, so
    ``patch.dict(os.environ, ...)`` alone is not enough — we also have
    to reseat the ``Path.home`` resolution under that env. The simplest
    and most portable way is to set HOME via ``os.environ`` and rely on
    ``Path.home()`` reading ``$HOME`` on Unix.
    """

    def __init__(self) -> None:
        self._tmp: tempfile.TemporaryDirectory | None = None
        self._prev_home: str | None = None
        self.home: str = ""

    def __enter__(self) -> str:
        self._tmp = tempfile.TemporaryDirectory(prefix="dc-zc-")
        self.home = self._tmp.name
        self._prev_home = os.environ.get("HOME")
        os.environ["HOME"] = self.home
        return self.home

    def __exit__(self, *exc):
        if self._prev_home is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = self._prev_home
        if self._tmp is not None:
            self._tmp.cleanup()


class MakeZeptoClawConfigShapeTests(unittest.TestCase):
    """The fixture builder produces the shape ZeptoClaw actually consumes."""

    def test_default_seeds_anthropic_provider(self):
        with _IsolatedHome() as home:
            cfg_path = make_zeptoclaw_config(home)
            self.assertTrue(cfg_path.endswith(".zeptoclaw/config.json"))
            with open(cfg_path) as fh:
                doc = json.load(fh)
            self.assertIn("providers", doc)
            self.assertIn("anthropic", doc["providers"])
            self.assertEqual(
                doc["providers"]["anthropic"]["api_base"],
                "https://api.anthropic.com",
            )

    def test_custom_providers_round_trip(self):
        with _IsolatedHome() as home:
            cfg_path = make_zeptoclaw_config(
                home,
                providers={
                    "openai": {"api_base": "https://api.openai.com", "api_key": "sk-zc-test"},
                    "fireworks": {"api_base": "https://api.fireworks.ai", "api_key": "fw-test"},
                },
            )
            with open(cfg_path) as fh:
                doc = json.load(fh)
            for name in ("openai", "fireworks"):
                self.assertIn(name, doc["providers"])
            self.assertEqual(doc["providers"]["openai"]["api_key"], "sk-zc-test")


class ZeptoClawMCPReaderTests(unittest.TestCase):
    """``connector_paths.mcp_servers('zeptoclaw')`` reads from
    ``~/.zeptoclaw/config.json`` ``mcp.servers`` block.

    Plan S4.1 contract: the Python reader mirrors the Go-side
    ``readMCPServersZeptoClaw``. Both must converge on the same shape
    so audit/observability surfaces don't diverge between the gateway's
    enumerator and the operator CLI.
    """

    def test_reads_servers_from_config_json(self):
        with _IsolatedHome() as home:
            cfg_path = os.path.join(home, ".zeptoclaw", "config.json")
            os.makedirs(os.path.dirname(cfg_path), exist_ok=True)
            with open(cfg_path, "w") as fh:
                json.dump(
                    {
                        "providers": {
                            "openai": {"api_base": "https://api.openai.com"},
                        },
                        "mcp": {
                            "servers": {
                                "zc-stdio": {"command": "node", "args": ["mcp.js"]},
                                "zc-remote": {"url": "https://example.com/mcp", "transport": "http"},
                            }
                        },
                    },
                    fh,
                )

            entries = connector_paths.mcp_servers("zeptoclaw")
            names = sorted(e.name for e in entries)
            self.assertIn("zc-stdio", names)
            self.assertIn("zc-remote", names)
            stdio = next(e for e in entries if e.name == "zc-stdio")
            self.assertEqual(stdio.command, "node")
            self.assertEqual(stdio.args, ["mcp.js"])
            remote = next(e for e in entries if e.name == "zc-remote")
            self.assertEqual(remote.url, "https://example.com/mcp")
            self.assertEqual(remote.transport, "http")

    def test_reads_zeptoclaw_native_servers_array(self):
        with _IsolatedHome() as home:
            cfg_path = os.path.join(home, ".zeptoclaw", "config.json")
            os.makedirs(os.path.dirname(cfg_path), exist_ok=True)
            with open(cfg_path, "w") as fh:
                json.dump(
                    {
                        "mcp": {
                            "servers": [
                                {
                                    "name": "zc-stdio",
                                    "command": "node",
                                    "args": ["mcp.js"],
                                },
                                {
                                    "name": "zc-remote",
                                    "url": "https://example.com/mcp",
                                    "transport": "http",
                                },
                            ]
                        },
                    },
                    fh,
                )

            entries = connector_paths.mcp_servers("zeptoclaw")
            names = sorted(e.name for e in entries)
            self.assertEqual(names, ["zc-remote", "zc-stdio"])

    def test_missing_config_returns_empty_not_error(self):
        with _IsolatedHome():
            entries = connector_paths.mcp_servers("zeptoclaw")
            self.assertEqual(entries, [])

    def test_malformed_json_swallowed(self):
        with _IsolatedHome() as home:
            cfg_path = os.path.join(home, ".zeptoclaw", "config.json")
            os.makedirs(os.path.dirname(cfg_path), exist_ok=True)
            with open(cfg_path, "w") as fh:
                fh.write("{this is not json")
            entries = connector_paths.mcp_servers("zeptoclaw")
            self.assertEqual(entries, [])


class ZeptoClawSkillAndPluginDirsTests(unittest.TestCase):
    """Skill / plugin dir dispatch for the zeptoclaw arm matches the
    Go-side ``SkillDirsForConnector('zeptoclaw')`` and
    ``PluginDirsForConnector('zeptoclaw')`` contract from S1.2.
    """

    def test_skill_dirs_includes_home_and_cwd(self):
        with _IsolatedHome() as home:
            dirs = connector_paths.skill_dirs("zeptoclaw")
            self.assertIn(os.path.join(home, ".zeptoclaw", "skills"), dirs)
            cwd_skills = os.path.join(os.getcwd(), ".zeptoclaw", "skills")
            self.assertIn(cwd_skills, dirs)

    def test_plugin_dirs_includes_home_and_cache(self):
        with _IsolatedHome() as home:
            dirs = connector_paths.plugin_dirs("zeptoclaw")
            base = os.path.join(home, ".zeptoclaw", "plugins")
            self.assertIn(base, dirs)
            self.assertIn(os.path.join(base, "cache"), dirs)


class ZeptoClawPatchRestoreRoundTripTests(unittest.TestCase):
    """Operator round-trip: write fixture → mutate → restore from snapshot.

    This is the Python side of zeptoclaw's S0.11 atomic-write contract:
    operators that hand-edit ``~/.zeptoclaw/config.json`` must be able
    to re-derive the pristine state from the captured backup snapshot
    even after multiple gateway restarts. The Go-side ``zeptoClawBackup``
    record holds ``original_providers`` as a JSON RawMessage; we
    simulate the same here in Python so the operator-driven restore
    path can be tested end-to-end without spinning up the gateway.
    """

    def test_simulated_backup_restores_pristine_providers(self):
        with _IsolatedHome() as home:
            cfg_path = make_zeptoclaw_config(
                home,
                providers={
                    "openai": {"api_base": "https://api.openai.com", "api_key": "sk-pristine"},
                },
            )
            with open(cfg_path) as fh:
                pristine = json.load(fh)

            patched = json.loads(json.dumps(pristine))
            patched["providers"]["openai"]["api_base"] = "http://127.0.0.1:4000/c/zeptoclaw"
            with open(cfg_path, "w") as fh:
                json.dump(patched, fh)

            with open(cfg_path) as fh:
                self.assertEqual(
                    json.load(fh)["providers"]["openai"]["api_base"],
                    "http://127.0.0.1:4000/c/zeptoclaw",
                )

            backup_blob = {"original_providers": pristine["providers"]}
            current = patched
            current["providers"] = backup_blob["original_providers"]
            with open(cfg_path, "w") as fh:
                json.dump(current, fh)

            with open(cfg_path) as fh:
                restored = json.load(fh)
            self.assertEqual(
                restored["providers"]["openai"]["api_base"],
                "https://api.openai.com",
            )
            self.assertEqual(restored["providers"]["openai"]["api_key"], "sk-pristine")


if __name__ == "__main__":
    unittest.main()
