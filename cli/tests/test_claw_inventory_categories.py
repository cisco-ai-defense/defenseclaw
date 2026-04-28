# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Per-connector AIBOM adapter tests (plan C7 / matrix #4).

The four AIBOM categories (agents / tools / model_providers / memory)
historically came from a live ``openclaw <cat> --json`` shellout. For
non-OpenClaw connectors the matrix marked these ⚠️ ("empty arrays, no
CLI to query"). This test suite locks the contract that:

  * each adapter parses the documented filesystem fixture for its
    connector and returns a non-empty list when the fixture exists;
  * a missing fixture returns an empty list (and the inventory's
    ``errors`` array records the informational note);
  * model-provider enumeration NEVER echoes raw API keys.

All tests use a temporary HOME so the developer's real
``~/.claude/`` etc. is untouched.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.inventory.claw_inventory import (
    _agents_for_connector,
    _memory_for_connector,
    _model_providers_for_connector,
    _tools_for_connector,
)


class _FakeCfg:
    """Minimal Config stub for adapter calls.

    The adapters under test today only consult os.environ + os.path, so
    they don't actually read fields off the Config instance. We pass an
    empty stub to avoid the heavy real loader.
    """


class AgentsAdapterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="dc-aibom-agents-")
        self.env = patch.dict(os.environ, {"HOME": self.tmp}, clear=False)
        self.env.start()

    def tearDown(self):
        self.env.stop()
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_claudecode_agents_from_md_files(self):
        agents_dir = os.path.join(self.tmp, ".claude", "agents")
        os.makedirs(agents_dir)
        for name in ("planner.md", "reviewer.md", "ignored.txt"):
            with open(os.path.join(agents_dir, name), "w") as fh:
                fh.write("# example\n")

        out = _agents_for_connector("claudecode", _FakeCfg())
        ids = sorted(a["id"] for a in out)
        self.assertEqual(ids, ["ignored", "planner", "reviewer"])
        for entry in out:
            self.assertEqual(entry["kind"], "subagent")
            self.assertTrue(entry["source"].endswith((".md", ".txt")))

    def test_codex_agents_dir_missing_returns_empty(self):
        # No ~/.codex/agents directory; adapter should return [] not raise.
        out = _agents_for_connector("codex", _FakeCfg())
        self.assertEqual(out, [])

    def test_zeptoclaw_agents_from_json(self):
        zc_dir = os.path.join(self.tmp, ".zeptoclaw")
        os.makedirs(zc_dir)
        with open(os.path.join(zc_dir, "agents.json"), "w") as fh:
            json.dump(
                [
                    {"id": "alpha", "name": "Alpha", "description": "agent one"},
                    {"id": "beta", "name": "Beta"},
                    # No id present; adapter falls back to name so we
                    # still surface the row instead of dropping it.
                    {"name": "name-only-fallback"},
                    # Truly anonymous record (no id, no name) — must
                    # be skipped because the BOM contract requires a
                    # stable identifier for every row.
                    {"description": "no identity"},
                ],
                fh,
            )

        out = _agents_for_connector("zeptoclaw", _FakeCfg())
        ids = sorted(a["id"] for a in out)
        self.assertEqual(ids, ["alpha", "beta", "name-only-fallback"])

    def test_unknown_connector_returns_empty(self):
        out = _agents_for_connector("openclaw", _FakeCfg())
        self.assertEqual(out, [])
        out = _agents_for_connector("", _FakeCfg())
        self.assertEqual(out, [])


class ToolsAdapterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="dc-aibom-tools-")
        self.env = patch.dict(os.environ, {"HOME": self.tmp}, clear=False)
        self.env.start()

    def tearDown(self):
        self.env.stop()
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_claudecode_tools_list_from_settings(self):
        cd = os.path.join(self.tmp, ".claude")
        os.makedirs(cd)
        with open(os.path.join(cd, "settings.json"), "w") as fh:
            json.dump(
                {"tools": ["bash", {"id": "browser", "description": "web"}]}, fh,
            )

        out = _tools_for_connector("claudecode", _FakeCfg())
        ids = sorted(t["id"] for t in out)
        self.assertEqual(ids, ["bash", "browser"])

    def test_claudecode_tools_dict_form_from_settings(self):
        cd = os.path.join(self.tmp, ".claude")
        os.makedirs(cd)
        with open(os.path.join(cd, "settings.json"), "w") as fh:
            json.dump(
                {"tools": {"shell": {"name": "Shell"}, "fs": {"description": "fs"}}},
                fh,
            )

        out = _tools_for_connector("claudecode", _FakeCfg())
        ids = sorted(t["id"] for t in out)
        self.assertEqual(ids, ["fs", "shell"])

    def test_codex_tools_from_toml(self):
        cd = os.path.join(self.tmp, ".codex")
        os.makedirs(cd)
        with open(os.path.join(cd, "config.toml"), "w") as fh:
            fh.write(
                "[tools]\n"
                "[tools.run]\n"
                'description = "Execute shell command"\n'
                "[tools.read]\n"
                'name = "Read File"\n'
            )

        out = _tools_for_connector("codex", _FakeCfg())
        ids = sorted(t["id"] for t in out)
        self.assertEqual(ids, ["read", "run"])

    def test_zeptoclaw_tools_from_agents_json(self):
        zc = os.path.join(self.tmp, ".zeptoclaw")
        os.makedirs(zc)
        with open(os.path.join(zc, "agents.json"), "w") as fh:
            json.dump(
                [
                    {"id": "a1", "tools": [{"id": "shell", "description": "sh"}]},
                    {"id": "a2", "tools": [{"id": "shell"}, {"id": "browser"}]},
                ],
                fh,
            )

        out = _tools_for_connector("zeptoclaw", _FakeCfg())
        ids = sorted(t["id"] for t in out)
        # Dedup across agents: shell only appears once.
        self.assertEqual(ids, ["browser", "shell"])


class ModelProvidersAdapterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="dc-aibom-providers-")
        self.env = patch.dict(
            os.environ,
            {
                "HOME": self.tmp,
                "ANTHROPIC_API_KEY": "sk-ant-secret",
                "ANTHROPIC_BASE_URL": "https://override.example.com",
                "OPENAI_API_KEY": "sk-oai-secret",
            },
            clear=False,
        )
        self.env.start()

    def tearDown(self):
        self.env.stop()
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_claudecode_provider_from_env_never_echoes_key(self):
        out = _model_providers_for_connector("claudecode", _FakeCfg())
        self.assertEqual(len(out), 1)
        entry = out[0]
        self.assertEqual(entry["id"], "anthropic")
        self.assertEqual(entry["base_url"], "https://override.example.com")
        self.assertTrue(entry["api_key_present"])
        # CRITICAL: the literal key value MUST NOT appear anywhere in
        # the row dict — neither as a value nor inside a description.
        for v in entry.values():
            self.assertNotIn("sk-ant-secret", str(v))

    def test_codex_provider_falls_back_to_default_base_url(self):
        # base URL unset, but API key still set in setUp -> must
        # still emit a row (provider configured "via key only") and
        # use the default base URL.
        os.environ.pop("OPENAI_BASE_URL", None)
        out = _model_providers_for_connector("codex", _FakeCfg())
        self.assertEqual(out[0]["id"], "openai")
        self.assertEqual(out[0]["base_url"], "https://api.openai.com/v1")
        self.assertTrue(out[0]["api_key_present"])

    def test_codex_provider_unconfigured_emits_empty(self):
        """Plan C7: pre-C7 inventory tests assume an unconfigured
        connector returns ``model_providers: []``. With nothing wired
        up (neither env var set), the adapter must respect that
        contract instead of synthesizing a row from defaults."""
        os.environ.pop("OPENAI_BASE_URL", None)
        os.environ.pop("OPENAI_API_KEY", None)
        out = _model_providers_for_connector("codex", _FakeCfg())
        self.assertEqual(out, [])

    def test_zeptoclaw_providers_from_config(self):
        zc = os.path.join(self.tmp, ".zeptoclaw")
        os.makedirs(zc)
        with open(os.path.join(zc, "config.json"), "w") as fh:
            json.dump(
                {
                    "providers": {
                        "anthropic": {
                            "api_base": "https://api.anthropic.com",
                            "api_key": "sk-ant-zc-secret",
                        },
                        "openai": {"api_base": "https://api.openai.com/v1"},
                    }
                },
                fh,
            )

        out = _model_providers_for_connector("zeptoclaw", _FakeCfg())
        ids = sorted(p["id"] for p in out)
        self.assertEqual(ids, ["anthropic", "openai"])
        for entry in out:
            for v in entry.values():
                self.assertNotIn("sk-ant-zc-secret", str(v))
        anthropic = next(p for p in out if p["id"] == "anthropic")
        self.assertTrue(anthropic["api_key_present"])
        openai = next(p for p in out if p["id"] == "openai")
        self.assertFalse(openai["api_key_present"])


class MemoryAdapterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="dc-aibom-memory-")
        self.env = patch.dict(os.environ, {"HOME": self.tmp}, clear=False)
        self.env.start()

    def tearDown(self):
        self.env.stop()
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_claudecode_memory_dir_present(self):
        d = os.path.join(self.tmp, ".claude", "memory")
        os.makedirs(d)
        with open(os.path.join(d, "ctx.txt"), "w") as fh:
            fh.write("history")

        out = _memory_for_connector("claudecode", _FakeCfg())
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["kind"], "filesystem")
        self.assertEqual(out[0]["entry_count"], 1)

    def test_codex_memory_multiple_candidates(self):
        os.makedirs(os.path.join(self.tmp, ".codex", "memory"))
        os.makedirs(os.path.join(self.tmp, ".codex", "history"))
        out = _memory_for_connector("codex", _FakeCfg())
        sources = sorted(e["source"] for e in out)
        self.assertEqual(len(sources), 2)
        self.assertTrue(any(s.endswith("memory") for s in sources))
        self.assertTrue(any(s.endswith("history") for s in sources))

    def test_unknown_connector_returns_empty(self):
        self.assertEqual(_memory_for_connector("openclaw", _FakeCfg()), [])
        self.assertEqual(_memory_for_connector("", _FakeCfg()), [])


if __name__ == "__main__":
    unittest.main()
