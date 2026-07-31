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

"""Tests for OpenClaw AIBOM live inventory (defenseclaw aibom scan).

Covers: full build, category filter, summary, error reporting, partial
failure, timeout, human output modes, and CLI integration.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from click.testing import CliRunner
from defenseclaw import connector_paths
from defenseclaw.config import (
    ClawConfig,
    Config,
    MCPActionsConfig,
    PluginActionsConfig,
    SeverityAction,
    SkillActionsConfig,
)
from defenseclaw.inventory.claw_inventory import (
    ALL_CATEGORIES,
    _admission_verdict,
    _agents_for_connector,
    _agents_from_codex_toml_dirs,
    _build_actions_map_for_type,
    _build_scan_map_for_type,
    _build_summary,
    _CmdResult,
    _fetch_all,
    _format_scan,
    _format_verdict,
    _parse_mcp,
    _parse_plugins,
    _parse_skills,
    _parse_tools,
    _policy_detail_suffix,
    _read_skill_description,
    _resolve_categories,
    _rules_for_connector,
    _run_openclaw,
    _scan_detail_suffix,
    build_claw_aibom,
    claw_aibom_to_scan_result,
    enrich_with_policy,
    format_claw_aibom_human,
)
from defenseclaw.models import ActionEntry

from tests.helpers import seed_cached_plugin

# ---------------------------------------------------------------------------
# Fixtures — canonical JSON payloads returned by ``openclaw … --json``
# ---------------------------------------------------------------------------

SKILLS_JSON = {
    "workspaceDir": "/home/test/.openclaw/workspace",
    "managedSkillsDir": "/home/test/.openclaw/skills",
    "skills": [
        {
            "name": "github",
            "description": "GitHub integration",
            "emoji": "",
            "eligible": True,
            "disabled": False,
            "source": "openclaw-bundled",
            "bundled": True,
            "missing": {"bins": [], "anyBins": [], "env": [], "config": [], "os": []},
        },
        {
            "name": "weather",
            "description": "Weather lookup",
            "emoji": "\u26c5",
            "eligible": True,
            "disabled": False,
            "source": "openclaw-bundled",
            "bundled": True,
            "missing": {"bins": ["weather-cli"], "anyBins": [], "env": [], "config": [], "os": []},
        },
    ],
}

PLUGINS_JSON = {
    "workspaceDir": "/home/test/.openclaw/workspace",
    "plugins": [
        {
            "id": "anthropic",
            "name": "Anthropic Provider",
            "version": "1.0.0",
            "origin": "bundled",
            "enabled": True,
            "status": "loaded",
            "toolNames": [],
            "providerIds": ["anthropic"],
            "hookNames": [],
            "channelIds": [],
            "cliCommands": [],
            "services": [],
        },
        {
            "id": "memory-core",
            "name": "Memory Core",
            "version": "1.0.0",
            "origin": "bundled",
            "enabled": True,
            "status": "loaded",
            "toolNames": ["memory_search", "memory_get"],
            "providerIds": [],
            "hookNames": [],
            "channelIds": [],
            "cliCommands": [],
            "services": [],
        },
    ],
}

MCP_JSON = {
    "servers": {
        "filesystem": {"command": "npx", "args": ["-y", "mcp-fs"], "transport": "stdio"},
    },
}

AGENTS_JSON = [
    {
        "id": "main",
        "workspace": "/home/test/.openclaw/workspace",
        "model": "anthropic/claude-sonnet-4-5",
        "isDefault": True,
        "bindings": 0,
    },
]

AGENTS_DEFAULTS = {
    "defaults": {
        "model": {"primary": "anthropic/claude-sonnet-4-5", "fallbacks": ["openai/gpt-4.1"]},
        "subagents": {"maxConcurrent": 8},
    },
}

MODELS_STATUS = {
    "configPath": "/home/test/.openclaw/openclaw.json",
    "defaultModel": "anthropic/claude-sonnet-4-5",
    "fallbacks": [],
    "allowed": ["anthropic/claude-sonnet-4-5"],
    "auth": {
        "providers": [],
        "missingProvidersInUse": ["anthropic"],
    },
}

MODELS_LIST = {
    "count": 1,
    "models": [
        {
            "key": "anthropic/claude-sonnet-4-5",
            "name": "Claude Sonnet 4.5",
            "available": False,
            "local": False,
            "input": "text+image",
            "contextWindow": 200000,
        },
    ],
}

MEMORY_STATUS = [
    {
        "agentId": "main",
        "status": {
            "backend": "builtin",
            "files": 12,
            "chunks": 340,
            "dbPath": "/home/test/.openclaw/memory/main.sqlite",
            "provider": "none",
            "sources": ["memory"],
            "workspaceDir": "/home/test/.openclaw/workspace",
            "fts": {"available": True},
            "vector": {"enabled": True},
        },
    },
]

DISPATCH: dict[tuple[str, ...], object] = {
    ("skills", "list"): SKILLS_JSON,
    ("plugins", "list"): PLUGINS_JSON,
    ("mcp", "list"): MCP_JSON,
    ("agents", "list"): AGENTS_JSON,
    ("config", "get", "agents"): AGENTS_DEFAULTS,
    ("models", "status"): MODELS_STATUS,
    ("models", "list"): MODELS_LIST,
    ("memory", "status"): MEMORY_STATUS,
}


def _mock_run(args, **_kwargs):
    """Fake ``subprocess.run`` that dispatches on openclaw subcommand args."""
    key = tuple(a for a in args[1:] if a != "--json")
    payload = DISPATCH.get(key)

    class FakeProc:
        returncode = 0 if payload is not None else 1
        stdout = json.dumps(payload) if payload is not None else ""
        stderr = ""

    return FakeProc()


def _make_cfg(tmp: str) -> Config:
    ddir = os.path.join(tmp, ".defenseclaw")
    os.makedirs(ddir, exist_ok=True)
    return Config(
        data_dir=ddir,
        audit_db=os.path.join(ddir, "audit.db"),
        quarantine_dir=os.path.join(tmp, "q"),
        plugin_dir=os.path.join(tmp, "p"),
        policy_dir=os.path.join(tmp, "pol"),
        claw=ClawConfig(
            mode="openclaw",
            home_dir=os.path.join(tmp, "oc"),
            config_file=os.path.join(tmp, "oc", "openclaw.json"),
        ),
    )


class TestLiveClawInventory(unittest.TestCase):
    """Core happy-path tests for build_claw_aibom and friends."""

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="dc-claw-test-")
        self.cfg = _make_cfg(self.tmp)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    @patch("defenseclaw.inventory.claw_inventory.subprocess.run", side_effect=_mock_run)
    def test_build_live(self, _mock_sub):
        inv = build_claw_aibom(self.cfg, live=True)
        self.assertTrue(inv["live"])
        self.assertEqual(len(inv["skills"]), 2)
        self.assertEqual(inv["skills"][0]["id"], "github")
        self.assertEqual(len(inv["plugins"]), 2)
        self.assertEqual(len(inv["mcp"]), 1)
        self.assertEqual(inv["mcp"][0]["id"], "filesystem")
        self.assertTrue(any(a["id"] == "main" for a in inv["agents"]))
        self.assertTrue(any(t["id"] == "memory_search" for t in inv["tools"]))
        self.assertTrue(any(m.get("default_model") for m in inv["model_providers"]))
        self.assertEqual(len(inv["memory"]), 1)
        self.assertEqual(inv["memory"][0]["files"], 12)

    @patch("defenseclaw.inventory.claw_inventory.subprocess.run", side_effect=_mock_run)
    def test_version_bumped_to_4_for_rules_schema(self, _):
        inv = build_claw_aibom(self.cfg, live=True)
        self.assertEqual(inv["version"], 4)

    @patch("defenseclaw.inventory.claw_inventory.subprocess.run", side_effect=_mock_run)
    def test_scan_result_has_eight_findings(self, _):
        inv = build_claw_aibom(self.cfg, live=True)
        result = claw_aibom_to_scan_result(inv, self.cfg)
        self.assertEqual(result.scanner, "aibom-claw")
        self.assertEqual(len(result.findings), 8)
        titles = [f.title for f in result.findings]
        self.assertTrue(any("Skills" in t for t in titles))
        self.assertTrue(any("Memory" in t for t in titles))

    @patch("defenseclaw.inventory.claw_inventory.subprocess.run", side_effect=_mock_run)
    def test_human_output_no_crash(self, _):
        inv = build_claw_aibom(self.cfg, live=True)
        format_claw_aibom_human(inv)

    @patch("defenseclaw.inventory.claw_inventory.subprocess.run", side_effect=_mock_run)
    def test_human_summary_only(self, _):
        inv = build_claw_aibom(self.cfg, live=True)
        format_claw_aibom_human(inv, summary_only=True)

    @patch("defenseclaw.inventory.claw_inventory.subprocess.run", side_effect=FileNotFoundError)
    def test_fallback_when_openclaw_missing(self, _):
        inv = build_claw_aibom(self.cfg, live=True)
        self.assertEqual(inv["skills"], [])
        self.assertEqual(inv["plugins"], [])
        self.assertEqual(inv["mcp"], [])
        self.assertEqual(inv["memory"], [])

    @patch("defenseclaw.inventory.claw_inventory.subprocess.run", side_effect=FileNotFoundError)
    def test_errors_populated_when_openclaw_missing(self, _):
        inv = build_claw_aibom(self.cfg, live=True)
        self.assertGreater(len(inv["errors"]), 0)
        for err in inv["errors"]:
            self.assertIn("openclaw not found", err["error"])
            self.assertIn("openclaw", err["command"])

    @patch("defenseclaw.inventory.claw_inventory.subprocess.run", side_effect=_mock_run)
    def test_no_errors_on_success(self, _):
        inv = build_claw_aibom(self.cfg, live=True)
        self.assertEqual(inv["errors"], [])


class TestSummary(unittest.TestCase):
    """Tests for the summary dict added to inventory."""

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="dc-claw-test-")
        self.cfg = _make_cfg(self.tmp)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    @patch("defenseclaw.inventory.claw_inventory.subprocess.run", side_effect=_mock_run)
    def test_summary_present(self, _):
        inv = build_claw_aibom(self.cfg, live=True)
        self.assertIn("summary", inv)
        summary = inv["summary"]
        self.assertIn("total_items", summary)
        self.assertIn("skills", summary)
        self.assertIn("errors", summary)

    @patch("defenseclaw.inventory.claw_inventory.subprocess.run", side_effect=_mock_run)
    def test_summary_counts_match_arrays(self, _):
        inv = build_claw_aibom(self.cfg, live=True)
        summary = inv["summary"]
        self.assertEqual(summary["skills"]["count"], len(inv["skills"]))
        self.assertEqual(summary["plugins"]["count"], len(inv["plugins"]))
        self.assertEqual(summary["mcp"]["count"], len(inv["mcp"]))
        self.assertEqual(summary["agents"]["count"], len(inv["agents"]))
        self.assertEqual(summary["rules"]["count"], len(inv["rules"]))
        self.assertEqual(summary["tools"]["count"], len(inv["tools"]))
        self.assertEqual(summary["model_providers"]["count"], len(inv["model_providers"]))
        self.assertEqual(summary["memory"]["count"], len(inv["memory"]))

    @patch("defenseclaw.inventory.claw_inventory.subprocess.run", side_effect=_mock_run)
    def test_summary_total_is_sum(self, _):
        inv = build_claw_aibom(self.cfg, live=True)
        summary = inv["summary"]
        manual_total = sum(
            summary[c]["count"]
            for c in ("skills", "plugins", "mcp", "agents", "rules", "tools", "model_providers", "memory")
        )
        self.assertEqual(summary["total_items"], manual_total)

    @patch("defenseclaw.inventory.claw_inventory.subprocess.run", side_effect=_mock_run)
    def test_summary_skill_eligible_count(self, _):
        inv = build_claw_aibom(self.cfg, live=True)
        expected = sum(1 for s in inv["skills"] if s.get("eligible"))
        self.assertEqual(inv["summary"]["skills"]["eligible"], expected)

    @patch("defenseclaw.inventory.claw_inventory.subprocess.run", side_effect=_mock_run)
    def test_summary_plugin_loaded_disabled(self, _):
        inv = build_claw_aibom(self.cfg, live=True)
        ps = inv["summary"]["plugins"]
        expected_loaded = sum(1 for p in inv["plugins"] if p.get("enabled"))
        expected_disabled = sum(1 for p in inv["plugins"] if not p.get("enabled"))
        self.assertEqual(ps["loaded"], expected_loaded)
        self.assertEqual(ps["disabled"], expected_disabled)

    @patch("defenseclaw.inventory.claw_inventory.subprocess.run", side_effect=_mock_run)
    def test_summary_errors_count(self, _):
        inv = build_claw_aibom(self.cfg, live=True)
        self.assertEqual(inv["summary"]["errors"], len(inv["errors"]))

    @patch("defenseclaw.inventory.claw_inventory.subprocess.run", side_effect=FileNotFoundError)
    def test_summary_errors_count_when_failing(self, _):
        inv = build_claw_aibom(self.cfg, live=True)
        self.assertGreater(inv["summary"]["errors"], 0)
        self.assertEqual(inv["summary"]["errors"], len(inv["errors"]))


class TestCategoryFilter(unittest.TestCase):
    """Tests for the --only category filter."""

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="dc-claw-test-")
        self.cfg = _make_cfg(self.tmp)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    @patch("defenseclaw.inventory.claw_inventory.subprocess.run", side_effect=_mock_run)
    def test_only_skills(self, mock_sub):
        inv = build_claw_aibom(self.cfg, live=True, categories={"skills"})
        self.assertEqual(len(inv["skills"]), 2)
        self.assertEqual(inv["plugins"], [])
        self.assertEqual(inv["mcp"], [])
        self.assertEqual(inv["agents"], [])
        self.assertEqual(inv["rules"], [])
        self.assertEqual(inv["tools"], [])
        self.assertEqual(inv["model_providers"], [])
        self.assertEqual(inv["memory"], [])

    @patch("defenseclaw.inventory.claw_inventory.subprocess.run", side_effect=_mock_run)
    def test_only_skills_limits_commands(self, mock_sub):
        build_claw_aibom(self.cfg, live=True, categories={"skills"})
        called_cmds = set()
        for call in mock_sub.call_args_list:
            args = call[0][0]
            key = tuple(a for a in args[1:] if a != "--json")
            called_cmds.add(key)
        self.assertIn(("skills", "list"), called_cmds)
        self.assertNotIn(("memory", "status"), called_cmds)
        self.assertNotIn(("models", "list"), called_cmds)

    @patch("defenseclaw.inventory.claw_inventory.subprocess.run", side_effect=_mock_run)
    def test_only_skills_and_mcp(self, mock_sub):
        inv = build_claw_aibom(self.cfg, live=True, categories={"skills", "mcp"})
        self.assertEqual(len(inv["skills"]), 2)
        self.assertEqual(len(inv["mcp"]), 1)
        self.assertEqual(inv["plugins"], [])
        self.assertEqual(inv["memory"], [])

    @patch("defenseclaw.inventory.claw_inventory.subprocess.run", side_effect=_mock_run)
    def test_only_tools_fetches_plugins_list(self, mock_sub):
        """tools category depends on plugins_list command."""
        inv = build_claw_aibom(self.cfg, live=True, categories={"tools"})
        self.assertGreater(len(inv["tools"]), 0)
        called_cmds = set()
        for call in mock_sub.call_args_list:
            args = call[0][0]
            key = tuple(a for a in args[1:] if a != "--json")
            called_cmds.add(key)
        self.assertIn(("plugins", "list"), called_cmds)

    @patch("defenseclaw.inventory.claw_inventory.subprocess.run", side_effect=_mock_run)
    def test_models_alias(self, _):
        """'models' is the user-facing name for model_providers."""
        inv = build_claw_aibom(self.cfg, live=True, categories={"models"})
        self.assertGreater(len(inv["model_providers"]), 0)
        self.assertEqual(inv["skills"], [])

    @patch("defenseclaw.inventory.claw_inventory.subprocess.run", side_effect=_mock_run)
    def test_invalid_category_ignored(self, _):
        inv = build_claw_aibom(self.cfg, live=True, categories={"skills", "nonexistent"})
        self.assertEqual(len(inv["skills"]), 2)

    @patch("defenseclaw.inventory.claw_inventory.subprocess.run", side_effect=_mock_run)
    def test_empty_categories_means_all(self, _):
        """Empty set after filtering invalid names falls back to all."""
        inv = build_claw_aibom(self.cfg, live=True, categories={"nonexistent"})
        self.assertGreater(len(inv["skills"]), 0)
        self.assertGreater(len(inv["plugins"]), 0)

    @patch("defenseclaw.inventory.claw_inventory.subprocess.run", side_effect=_mock_run)
    def test_none_categories_means_all(self, _):
        inv = build_claw_aibom(self.cfg, live=True, categories=None)
        self.assertGreater(len(inv["skills"]), 0)
        self.assertGreater(len(inv["memory"]), 0)


class TestResolveCategoriesUnit(unittest.TestCase):
    """Unit tests for _resolve_categories helper."""

    def test_none_returns_all(self):
        self.assertEqual(_resolve_categories(None), ALL_CATEGORIES)

    def test_valid_categories(self):
        result = _resolve_categories({"skills", "mcp"})
        self.assertEqual(result, frozenset({"skills", "mcp"}))

    def test_alias_model_providers(self):
        result = _resolve_categories({"model_providers"})
        self.assertIn("models", result)

    def test_case_insensitive(self):
        result = _resolve_categories({"SKILLS", "MCP"})
        self.assertIn("skills", result)
        self.assertIn("mcp", result)

    def test_whitespace_stripped(self):
        result = _resolve_categories({"  skills  "})
        self.assertIn("skills", result)

    def test_all_invalid_falls_back_to_all(self):
        result = _resolve_categories({"bogus", "fake"})
        self.assertEqual(result, ALL_CATEGORIES)


class TestErrorReporting(unittest.TestCase):
    """Tests for error capture and propagation."""

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="dc-claw-test-")
        self.cfg = _make_cfg(self.tmp)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    @patch("defenseclaw.inventory.claw_inventory.subprocess.run")
    def test_partial_failure(self, mock_sub):
        """One command fails, others succeed — errors list has exactly one entry."""

        def _partial_mock(args, **kwargs):
            key = tuple(a for a in args[1:] if a != "--json")
            if key == ("skills", "list"):
                proc = MagicMock()
                proc.returncode = 1
                proc.stdout = ""
                proc.stderr = "error: something broke"
                return proc
            return _mock_run(args, **kwargs)

        mock_sub.side_effect = _partial_mock
        inv = build_claw_aibom(self.cfg, live=True)

        self.assertEqual(inv["skills"], [])
        self.assertEqual(len(inv["plugins"]), 2)
        self.assertEqual(len(inv["mcp"]), 1)
        self.assertEqual(len(inv["memory"]), 1)

        self.assertEqual(len(inv["errors"]), 1)
        err = inv["errors"][0]
        self.assertIn("skills list", err["command"])
        self.assertIn("exit code 1", err["error"])
        self.assertIn("something broke", err["error"])

    @patch("defenseclaw.inventory.claw_inventory.subprocess.run")
    def test_timeout_error(self, mock_sub):
        """Timeout is reported as an error."""

        def _timeout_mock(args, **kwargs):
            key = tuple(a for a in args[1:] if a != "--json")
            if key == ("mcp", "list"):
                raise subprocess.TimeoutExpired(cmd=args, timeout=30)
            return _mock_run(args, **kwargs)

        mock_sub.side_effect = _timeout_mock
        inv = build_claw_aibom(self.cfg, live=True)

        self.assertEqual(inv["mcp"], [])
        self.assertEqual(len(inv["skills"]), 2)

        timeout_errs = [e for e in inv["errors"] if "timed out" in e["error"]]
        self.assertEqual(len(timeout_errs), 1)
        self.assertIn("mcp list", timeout_errs[0]["command"])

    @patch("defenseclaw.inventory.claw_inventory.subprocess.run")
    def test_bad_json_error(self, mock_sub):
        """Unparseable JSON is reported as an error."""

        def _bad_json_mock(args, **kwargs):
            key = tuple(a for a in args[1:] if a != "--json")
            if key == ("agents", "list"):
                proc = MagicMock()
                proc.returncode = 0
                proc.stdout = "not valid json{{"
                proc.stderr = ""
                return proc
            return _mock_run(args, **kwargs)

        mock_sub.side_effect = _bad_json_mock
        inv = build_claw_aibom(self.cfg, live=True)

        json_errs = [e for e in inv["errors"] if "no JSON" in e["error"]]
        self.assertEqual(len(json_errs), 1)
        self.assertIn("agents list", json_errs[0]["command"])

    @patch("defenseclaw.inventory.claw_inventory.subprocess.run")
    def test_nonzero_exit_includes_stderr_snippet(self, mock_sub):
        """Non-zero exit includes up to 200 chars of stderr in error."""

        def _fail_mock(args, **kwargs):
            key = tuple(a for a in args[1:] if a != "--json")
            if key == ("memory", "status"):
                proc = MagicMock()
                proc.returncode = 2
                proc.stdout = ""
                proc.stderr = "fatal: memory backend unavailable"
                return proc
            return _mock_run(args, **kwargs)

        mock_sub.side_effect = _fail_mock
        inv = build_claw_aibom(self.cfg, live=True)

        mem_errs = [e for e in inv["errors"] if "memory" in e["command"]]
        self.assertEqual(len(mem_errs), 1)
        self.assertIn("exit code 2", mem_errs[0]["error"])
        self.assertIn("memory backend unavailable", mem_errs[0]["error"])


class TestDeduplication(unittest.TestCase):
    """Verify plugins_list is only called once even when multiple categories need it."""

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="dc-claw-test-")
        self.cfg = _make_cfg(self.tmp)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    @patch("defenseclaw.inventory.claw_inventory.subprocess.run", side_effect=_mock_run)
    def test_plugins_list_called_once(self, mock_sub):
        """plugins, tools, and models all need plugins_list — only one call."""
        build_claw_aibom(self.cfg, live=True, categories={"plugins", "tools", "models"})
        plugins_calls = [
            c for c in mock_sub.call_args_list
            if tuple(a for a in c[0][0][1:] if a != "--json") == ("plugins", "list")
        ]
        self.assertEqual(len(plugins_calls), 1)

    @patch("defenseclaw.inventory.claw_inventory.subprocess.run", side_effect=_mock_run)
    def test_full_scan_plugins_list_called_once(self, mock_sub):
        """Full scan (all categories) also only calls plugins_list once."""
        build_claw_aibom(self.cfg, live=True)
        plugins_calls = [
            c for c in mock_sub.call_args_list
            if tuple(a for a in c[0][0][1:] if a != "--json") == ("plugins", "list")
        ]
        self.assertEqual(len(plugins_calls), 1)


class TestRunOpenclawUnit(unittest.TestCase):
    """Unit tests for the _run_openclaw function itself."""

    @patch("defenseclaw.inventory.claw_inventory.subprocess.run")
    def test_success_stdout(self, mock_sub):
        mock_sub.return_value = MagicMock(
            returncode=0,
            stdout='{"skills": []}',
            stderr="",
        )
        result = _run_openclaw("skills", "list")
        self.assertIsInstance(result, _CmdResult)
        self.assertEqual(result.data, {"skills": []})
        self.assertIsNone(result.error)

    @patch("defenseclaw.inventory.claw_inventory.subprocess.run")
    def test_success_stderr_fallback(self, mock_sub):
        """Some openclaw commands write JSON to stderr."""
        mock_sub.return_value = MagicMock(
            returncode=0,
            stdout="",
            stderr='{"skills": [{"name": "test"}]}',
        )
        result = _run_openclaw("skills", "list")
        self.assertIsNotNone(result.data)
        self.assertIsNone(result.error)

    @patch("defenseclaw.inventory.claw_inventory.subprocess.run", side_effect=FileNotFoundError)
    def test_file_not_found(self, _):
        result = _run_openclaw("skills", "list")
        self.assertIsNone(result.data)
        self.assertIn("not found", result.error)

    @patch("defenseclaw.inventory.claw_inventory.subprocess.run")
    def test_timeout(self, mock_sub):
        mock_sub.side_effect = subprocess.TimeoutExpired(cmd=["openclaw"], timeout=30)
        result = _run_openclaw("skills", "list")
        self.assertIsNone(result.data)
        self.assertIn("timed out", result.error)

    @patch("defenseclaw.inventory.claw_inventory.subprocess.run")
    def test_nonzero_exit(self, mock_sub):
        mock_sub.return_value = MagicMock(
            returncode=1,
            stdout="",
            stderr="error: boom",
        )
        result = _run_openclaw("skills", "list")
        self.assertIsNone(result.data)
        self.assertIn("exit code 1", result.error)
        self.assertIn("boom", result.error)

    @patch("defenseclaw.inventory.claw_inventory.subprocess.run")
    def test_empty_output(self, mock_sub):
        mock_sub.return_value = MagicMock(
            returncode=0,
            stdout="",
            stderr="",
        )
        result = _run_openclaw("skills", "list")
        self.assertIsNone(result.data)
        self.assertIn("no JSON", result.error)

    @patch("defenseclaw.inventory.claw_inventory.subprocess.run")
    def test_command_string_in_result(self, mock_sub):
        mock_sub.return_value = MagicMock(
            returncode=0,
            stdout="{}",
            stderr="",
        )
        result = _run_openclaw("models", "status")
        self.assertIn("openclaw models status --json", result.command)

    @patch("defenseclaw.inventory.claw_inventory.subprocess.run")
    def test_stderr_json_with_trailing_warnings(self, mock_sub):
        """JSON on stderr followed by Node.js warnings should still parse."""
        json_part = '{"skills": [{"name": "test-skill"}]}'
        warning = (
            "\n(node:12345) [MODULE_TYPELESS_PACKAGE_JSON] Warning: "
            "Module type not specified"
        )
        mock_sub.return_value = MagicMock(
            returncode=0,
            stdout="",
            stderr=json_part + warning,
        )
        result = _run_openclaw("skills", "list")
        self.assertIsNotNone(result.data)
        self.assertEqual(result.data["skills"][0]["name"], "test-skill")
        self.assertIsNone(result.error)

    @patch("defenseclaw.inventory.claw_inventory.subprocess.run")
    def test_stderr_json_with_leading_warnings(self, mock_sub):
        """Node.js warnings BEFORE JSON on stderr should still parse."""
        warning = (
            "(node:52830) [MODULE_TYPELESS_PACKAGE_JSON] Warning: "
            "Module type not specified\n"
            "Reparsing as ES module because module syntax was detected.\n"
        )
        json_part = '{"skills": [{"name": "leading-test"}]}'
        mock_sub.return_value = MagicMock(
            returncode=0,
            stdout="",
            stderr=warning + json_part,
        )
        result = _run_openclaw("skills", "list")
        self.assertIsNotNone(result.data)
        self.assertEqual(result.data["skills"][0]["name"], "leading-test")
        self.assertIsNone(result.error)


class TestParserUnits(unittest.TestCase):
    """Unit tests for individual _parse_* functions."""

    def test_parse_skills_none(self):
        self.assertEqual(_parse_skills(None), [])

    def test_parse_skills_empty_dict(self):
        self.assertEqual(_parse_skills({}), [])

    def test_parse_skills_happy(self):
        rows = _parse_skills(SKILLS_JSON)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["id"], "github")
        self.assertTrue(rows[0]["eligible"])

    def test_parse_plugins_none(self):
        self.assertEqual(_parse_plugins(None), [])

    def test_parse_plugins_happy(self):
        rows = _parse_plugins(PLUGINS_JSON)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["id"], "anthropic")

    def test_parse_mcp_none(self):
        self.assertEqual(_parse_mcp(None), [])

    def test_parse_mcp_dict_servers(self):
        rows = _parse_mcp(MCP_JSON)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["id"], "filesystem")

    def test_parse_mcp_list_format(self):
        rows = _parse_mcp([{"id": "srv1"}, {"id": "srv2"}])
        self.assertEqual(len(rows), 2)

    def test_parse_tools_from_plugins(self):
        rows = _parse_tools(PLUGINS_JSON)
        tool_ids = {t["id"] for t in rows}
        self.assertIn("memory_search", tool_ids)
        self.assertIn("memory_get", tool_ids)

    def test_parse_tools_deduplicates(self):
        duped = {
            "plugins": [
                {"id": "a", "toolNames": ["shared_tool"]},
                {"id": "b", "toolNames": ["shared_tool", "unique_tool"]},
            ]
        }
        rows = _parse_tools(duped)
        ids = [r["id"] for r in rows]
        self.assertEqual(ids.count("shared_tool"), 1)
        self.assertIn("unique_tool", ids)


class TestBuildSummaryUnit(unittest.TestCase):
    """Unit tests for the _build_summary helper."""

    def test_empty_inventory(self):
        inv = {
            "skills": [], "plugins": [], "mcp": [], "agents": [],
            "tools": [], "model_providers": [], "memory": [], "errors": [],
        }
        s = _build_summary(inv)
        self.assertEqual(s["total_items"], 0)
        self.assertEqual(s["errors"], 0)

    def test_with_data(self):
        inv = {
            "skills": [{"eligible": True}, {"eligible": False}],
            "plugins": [{"status": "loaded", "enabled": True}, {"enabled": False}],
            "mcp": [{}],
            "agents": [{}],
            "tools": [{}, {}],
            "model_providers": [{}],
            "memory": [{}],
            "errors": [{"command": "x", "error": "y"}],
        }
        s = _build_summary(inv)
        self.assertEqual(s["total_items"], 10)
        self.assertEqual(s["skills"]["count"], 2)
        self.assertEqual(s["skills"]["eligible"], 1)
        self.assertEqual(s["plugins"]["loaded"], 1)
        self.assertEqual(s["plugins"]["disabled"], 1)
        self.assertEqual(s["errors"], 1)


class TestFetchAll(unittest.TestCase):
    """Tests for the parallel _fetch_all dispatcher."""

    @patch("defenseclaw.inventory.claw_inventory.subprocess.run", side_effect=_mock_run)
    def test_empty_needed(self, _):
        cache, errors = _fetch_all(set())
        self.assertEqual(cache, {})
        self.assertEqual(errors, [])

    @patch("defenseclaw.inventory.claw_inventory.subprocess.run", side_effect=_mock_run)
    def test_single_command(self, mock_sub):
        cache, errors = _fetch_all({"skills_list"})
        self.assertIn("skills_list", cache)
        self.assertEqual(errors, [])
        self.assertEqual(mock_sub.call_count, 1)

    @patch("defenseclaw.inventory.claw_inventory.subprocess.run", side_effect=_mock_run)
    def test_all_commands(self, mock_sub):
        all_keys = set(_CmdResult.__doc__ or "") or set()  # dummy
        all_keys = set(k for k in [
            "skills_list", "plugins_list", "mcp_list", "agents_list",
            "config_agents", "models_status", "models_list", "memory_status",
        ])
        cache, errors = _fetch_all(all_keys)
        self.assertEqual(len(cache), 8)
        self.assertEqual(errors, [])

    @patch("defenseclaw.inventory.claw_inventory.subprocess.run", side_effect=FileNotFoundError)
    def test_all_fail(self, _):
        cache, errors = _fetch_all({"skills_list", "mcp_list"})
        self.assertEqual(len(errors), 2)
        for key in ("skills_list", "mcp_list"):
            self.assertIsNone(cache.get(key))


class TestHumanErrors(unittest.TestCase):
    """Tests that error rendering doesn't crash."""

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="dc-claw-test-")
        self.cfg = _make_cfg(self.tmp)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    @patch("defenseclaw.inventory.claw_inventory.subprocess.run", side_effect=FileNotFoundError)
    def test_human_output_with_errors(self, _):
        inv = build_claw_aibom(self.cfg, live=True)
        self.assertGreater(len(inv["errors"]), 0)
        format_claw_aibom_human(inv)

    @patch("defenseclaw.inventory.claw_inventory.subprocess.run", side_effect=FileNotFoundError)
    def test_human_summary_only_with_errors(self, _):
        inv = build_claw_aibom(self.cfg, live=True)
        format_claw_aibom_human(inv, summary_only=True)


class TestCLIIntegration(unittest.TestCase):
    """Integration tests for the `aibom scan` Click command."""

    def setUp(self) -> None:
        from tests.helpers import make_app_context
        self.app, self.tmp_dir, self.db_path = make_app_context()

    def tearDown(self) -> None:
        from tests.helpers import cleanup_app
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    @patch("defenseclaw.inventory.claw_inventory.subprocess.run", side_effect=_mock_run)
    def test_scan_json(self, _):
        from defenseclaw.commands.cmd_aibom import aibom
        runner = CliRunner()
        result = runner.invoke(aibom, ["scan", "--json"], obj=self.app)
        self.assertEqual(result.exit_code, 0, result.output)
        data = json.loads(result.stdout)
        self.assertIn("summary", data)
        self.assertIn("skills", data)
        self.assertEqual(len(data["skills"]), 2)

    @patch("defenseclaw.inventory.claw_inventory.subprocess.run", side_effect=_mock_run)
    def test_scan_human(self, _):
        from defenseclaw.commands.cmd_aibom import aibom
        runner = CliRunner()
        result = runner.invoke(aibom, ["scan"], obj=self.app)
        self.assertEqual(result.exit_code, 0, result.output)

    @patch("defenseclaw.inventory.claw_inventory.subprocess.run", side_effect=_mock_run)
    def test_scan_summary_flag(self, _):
        from defenseclaw.commands.cmd_aibom import aibom
        runner = CliRunner()
        result = runner.invoke(aibom, ["scan", "--summary"], obj=self.app)
        self.assertEqual(result.exit_code, 0, result.output)

    @patch("defenseclaw.inventory.claw_inventory.subprocess.run", side_effect=_mock_run)
    def test_scan_only_filter(self, _):
        from defenseclaw.commands.cmd_aibom import aibom
        runner = CliRunner()
        result = runner.invoke(aibom, ["scan", "--json", "--only", "skills,mcp"], obj=self.app)
        self.assertEqual(result.exit_code, 0, result.output)
        data = json.loads(result.stdout)
        self.assertEqual(len(data["skills"]), 2)
        self.assertEqual(len(data["mcp"]), 1)
        self.assertEqual(data["plugins"], [])
        self.assertEqual(data["memory"], [])

    @patch("defenseclaw.inventory.claw_inventory.subprocess.run", side_effect=FileNotFoundError)
    def test_scan_with_errors_shows_warning(self, _):
        from defenseclaw.commands.cmd_aibom import aibom
        runner = CliRunner()
        result = runner.invoke(aibom, ["scan", "--json"], obj=self.app)
        self.assertEqual(result.exit_code, 0)
        stderr = result.stderr if getattr(result, "stderr_bytes", None) is not None else result.output
        self.assertIn("Warning", stderr)
        self.assertIn("failed", stderr)

    def test_codex_and_claude_limitations_keep_cli_successful(self):
        from defenseclaw.commands.cmd_aibom import aibom

        runner = CliRunner()
        with patch.object(Config, "active_connectors", return_value=["codex", "claudecode"]), \
             patch.object(Config, "skill_dirs", return_value=[]), \
             patch.object(Config, "plugin_dirs", return_value=[]), \
             patch.object(Config, "mcp_servers", return_value=[]), \
             patch("defenseclaw.inventory.claw_inventory._agents_for_connector", return_value=[]), \
             patch("defenseclaw.inventory.claw_inventory._tools_for_connector", return_value=[]), \
             patch("defenseclaw.inventory.claw_inventory._model_providers_for_connector", return_value=[]), \
             patch("defenseclaw.inventory.claw_inventory._memory_for_connector", return_value=[]):
            for connector in ("codex", "claudecode"):
                with self.subTest(connector=connector):
                    result = runner.invoke(
                        aibom, ["scan", "--json", "--connector", connector], obj=self.app,
                    )
                    self.assertEqual(result.exit_code, 0, result.output)
                    data = json.loads(result.stdout)
                    self.assertEqual(data["errors"], [])
                    self.assertEqual(
                        len(data["limitations"]),
                        3 if connector == "codex" else 4,
                    )
                    self.assertNotIn("failed", result.stderr.lower())

    def test_combined_codex_claude_has_four_limitations_without_warning(self):
        from defenseclaw.commands.cmd_aibom import aibom

        runner = CliRunner()
        with patch.object(
            Config, "active_connectors", return_value=["codex", "claudecode"],
        ), patch(
            "defenseclaw.inventory.claw_inventory._model_providers_for_connector",
            return_value=[],
        ), patch(
            "defenseclaw.inventory.claw_inventory._memory_for_connector",
            return_value=[],
        ):
            result = runner.invoke(
                aibom, ["scan", "--json", "--only", "models,memory"], obj=self.app,
            )

        self.assertEqual(result.exit_code, 0, result.output)
        data = json.loads(result.stdout)
        self.assertEqual(len(data), 2)
        self.assertEqual(sum(len(inv["limitations"]) for inv in data), 4)
        self.assertTrue(all(inv["errors"] == [] for inv in data))
        self.assertNotIn("failed", result.stderr.lower())

    def test_human_limitations_are_informational_not_warning(self):
        from defenseclaw.commands.cmd_aibom import aibom

        runner = CliRunner()
        with patch.object(Config, "active_connectors", return_value=["codex"]), \
             patch.object(Config, "skill_dirs", return_value=[]), \
             patch.object(Config, "plugin_dirs", return_value=[]), \
             patch.object(Config, "mcp_servers", return_value=[]), \
             patch("defenseclaw.inventory.claw_inventory._agents_for_connector", return_value=[]), \
             patch("defenseclaw.inventory.claw_inventory._tools_for_connector", return_value=[]), \
             patch("defenseclaw.inventory.claw_inventory._model_providers_for_connector", return_value=[]), \
             patch("defenseclaw.inventory.claw_inventory._memory_for_connector", return_value=[]):
            result = runner.invoke(aibom, ["scan", "--connector", "codex"], obj=self.app)

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Unsupported inventory capabilities", result.stdout)
        self.assertIn("informational", result.stdout)
        self.assertNotIn("command(s) failed", result.output)

    def test_mixed_real_failure_warns_once_and_keeps_limitations_separate(self):
        from defenseclaw.commands.cmd_aibom import aibom

        runner = CliRunner()
        with patch.object(Config, "active_connectors", return_value=["codex"]), patch(
            "defenseclaw.inventory.claw_inventory._enumerate_skills_filesystem",
            side_effect=PermissionError("skills directory denied"),
        ), patch.object(Config, "plugin_dirs", return_value=[]), \
             patch.object(Config, "mcp_servers", return_value=[]), \
             patch("defenseclaw.inventory.claw_inventory._agents_for_connector", return_value=[]), \
             patch("defenseclaw.inventory.claw_inventory._tools_for_connector", return_value=[]), \
             patch("defenseclaw.inventory.claw_inventory._model_providers_for_connector", return_value=[]), \
             patch("defenseclaw.inventory.claw_inventory._memory_for_connector", return_value=[]):
            result = runner.invoke(
                aibom, ["scan", "--json", "--connector", "codex"], obj=self.app,
            )

        self.assertEqual(result.exit_code, 0, result.output)
        json_start = result.stdout.find("{")
        self.assertGreaterEqual(json_start, 0)
        data = json.loads(result.stdout[json_start:])
        self.assertEqual(len(data["errors"]), 1)
        self.assertEqual(len(data["limitations"]), 3)
        self.assertIn("1 connector inventory command(s) failed", result.output)


class TestLiveIsFalse(unittest.TestCase):
    """When live=False, no commands should be dispatched."""

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="dc-claw-test-")
        self.cfg = _make_cfg(self.tmp)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    @patch("defenseclaw.inventory.claw_inventory.subprocess.run")
    def test_no_subprocess_calls(self, mock_sub):
        inv = build_claw_aibom(self.cfg, live=False)
        mock_sub.assert_not_called()
        self.assertEqual(inv["skills"], [])
        self.assertEqual(inv["errors"], [])
        self.assertFalse(inv["live"])


# ---------------------------------------------------------------------------
# Policy enrichment — _admission_verdict
# ---------------------------------------------------------------------------


class _StoreWithPolicyMixin:
    """Provides a temp Store with init() for policy tests."""

    def setUp(self) -> None:
        from tests.helpers import make_temp_store
        self.store, self.db_path = make_temp_store()
        self.skill_actions = SkillActionsConfig()

    def tearDown(self) -> None:
        self.store.close()
        try:
            os.unlink(self.db_path)
        except OSError:
            pass

    def _pe(self):
        from defenseclaw.enforce import PolicyEngine
        return PolicyEngine(self.store)


class TestAdmissionVerdictBlocked(_StoreWithPolicyMixin, unittest.TestCase):
    """Blocked items short-circuit before allow/scan checks."""

    def test_blocked_with_reason(self):
        pe = self._pe()
        pe.block("skill", "bad-skill", "known malware")
        entry = ActionEntry(
            id="x", target_type="skill", target_name="bad-skill",
            reason="known malware",
        )
        verdict, detail = _admission_verdict(
            pe, "skill", "bad-skill", None, entry, self.skill_actions,
        )
        self.assertEqual(verdict, "blocked")
        self.assertEqual(detail, "known malware")

    def test_blocked_without_action_entry(self):
        pe = self._pe()
        pe.block("plugin", "evil-plugin", "blocked")
        verdict, detail = _admission_verdict(
            pe, "plugin", "evil-plugin", None, None, self.skill_actions,
        )
        self.assertEqual(verdict, "blocked")
        self.assertEqual(detail, "block list")

    def test_blocked_overrides_clean_scan(self):
        pe = self._pe()
        pe.block("skill", "dual-status", "policy override")
        scan = {"finding_count": 0, "max_severity": "INFO", "target": "/x"}
        entry = ActionEntry(
            id="y", target_type="skill", target_name="dual-status",
            reason="policy override",
        )
        verdict, _ = _admission_verdict(
            pe, "skill", "dual-status", scan, entry, self.skill_actions,
        )
        self.assertEqual(verdict, "blocked")


class TestAdmissionVerdictAllowed(_StoreWithPolicyMixin, unittest.TestCase):
    """Allowed items skip scanning."""

    def test_allowed_with_reason(self):
        pe = self._pe()
        pe.allow("skill", "trusted", "security team approved")
        entry = ActionEntry(
            id="a", target_type="skill", target_name="trusted",
            reason="security team approved",
        )
        verdict, detail = _admission_verdict(
            pe, "skill", "trusted", None, entry, self.skill_actions,
        )
        self.assertEqual(verdict, "allowed")
        self.assertEqual(detail, "security team approved")

    def test_allowed_without_action_entry(self):
        pe = self._pe()
        pe.allow("mcp", "local-server", "ok")
        verdict, detail = _admission_verdict(
            pe, "mcp", "local-server", None, None, self.skill_actions,
        )
        self.assertEqual(verdict, "allowed")
        self.assertEqual(detail, "allow list")


class TestAdmissionVerdictQuarantined(_StoreWithPolicyMixin, unittest.TestCase):
    """Quarantined items are rejected."""

    def test_quarantined(self):
        pe = self._pe()
        self.store.set_action_field("skill", "suspect", "file", "quarantine", "under review")
        entry = ActionEntry(
            id="q", target_type="skill", target_name="suspect",
            reason="under review",
        )
        verdict, detail = _admission_verdict(
            pe, "skill", "suspect", None, entry, self.skill_actions,
        )
        self.assertEqual(verdict, "rejected")
        self.assertIn("quarantined", detail)
        self.assertIn("under review", detail)

    def test_quarantined_without_action_entry(self):
        pe = self._pe()
        self.store.set_action_field("plugin", "risky", "file", "quarantine", "auto")
        verdict, detail = _admission_verdict(
            pe, "plugin", "risky", None, None, self.skill_actions,
        )
        self.assertEqual(verdict, "rejected")
        self.assertIn("quarantined", detail)


class TestAdmissionVerdictUnscanned(_StoreWithPolicyMixin, unittest.TestCase):
    """Items with no block/allow/quarantine and no scan are unscanned."""

    def test_unscanned(self):
        pe = self._pe()
        verdict, detail = _admission_verdict(
            pe, "skill", "new-skill", None, None, self.skill_actions,
        )
        self.assertEqual(verdict, "unscanned")
        self.assertEqual(detail, "no scan result")


class TestAdmissionVerdictClean(_StoreWithPolicyMixin, unittest.TestCase):
    """Items with scan results and zero findings are clean."""

    def test_clean_scan(self):
        pe = self._pe()
        scan = {"finding_count": 0, "max_severity": "INFO", "target": "/x"}
        verdict, detail = _admission_verdict(
            pe, "skill", "safe-skill", scan, None, self.skill_actions,
        )
        self.assertEqual(verdict, "clean")
        self.assertEqual(detail, "scan clean")


class TestAdmissionVerdictRejected(_StoreWithPolicyMixin, unittest.TestCase):
    """Central policy defaults reject high-severity findings."""

    def test_critical_rejected_by_policy_defaults(self):
        pe = self._pe()
        scan = {"finding_count": 1, "max_severity": "CRITICAL", "target": "/x"}
        verdict, detail = _admission_verdict(
            pe, "skill", "dangerous", scan, None, self.skill_actions,
        )
        self.assertEqual(verdict, "rejected")
        self.assertIn("1 findings", detail)
        self.assertIn("CRITICAL", detail)

    def test_high_rejected_by_policy_defaults(self):
        pe = self._pe()
        scan = {"finding_count": 5, "max_severity": "HIGH", "target": "/x"}
        verdict, detail = _admission_verdict(
            pe, "plugin", "risky-plugin", scan, None, self.skill_actions,
        )
        self.assertEqual(verdict, "rejected")
        self.assertIn("5 findings", detail)
        self.assertIn("HIGH", detail)

    def test_strict_actions_reject_critical(self):
        pe = self._pe()
        strict = SkillActionsConfig(
            critical=SeverityAction(file="quarantine", runtime="disable", install="block"),
        )
        scan = {"finding_count": 1, "max_severity": "CRITICAL", "target": "/x"}
        verdict, detail = _admission_verdict(
            pe, "skill", "dangerous", scan, None, strict,
        )
        self.assertEqual(verdict, "rejected")
        self.assertIn("CRITICAL", detail)

    def test_strict_actions_reject_high(self):
        pe = self._pe()
        strict = SkillActionsConfig(
            high=SeverityAction(file="quarantine", runtime="disable", install="block"),
        )
        scan = {"finding_count": 5, "max_severity": "HIGH", "target": "/x"}
        verdict, detail = _admission_verdict(
            pe, "plugin", "risky-plugin", scan, None, strict,
        )
        self.assertEqual(verdict, "rejected")
        self.assertIn("HIGH", detail)


class TestAdmissionVerdictWarning(_StoreWithPolicyMixin, unittest.TestCase):
    """Policy defaults still warn on medium findings without reject actions."""

    def test_warning_medium(self):
        pe = self._pe()
        scan = {"finding_count": 2, "max_severity": "MEDIUM", "target": "/x"}
        verdict, detail = _admission_verdict(
            pe, "skill", "so-so", scan, None, self.skill_actions,
        )
        self.assertEqual(verdict, "warning")
        self.assertIn("2 findings", detail)
        self.assertIn("MEDIUM", detail)

    def test_low_mcp_rejected_by_policy_override(self):
        pe = self._pe()
        scan = {"finding_count": 1, "max_severity": "LOW", "target": "/x"}
        verdict, detail = _admission_verdict(
            pe, "mcp", "minor-issues", scan, None, self.skill_actions,
        )
        self.assertEqual(verdict, "rejected")
        self.assertIn("LOW", detail)

    def test_custom_actions_do_not_override_loaded_policy_defaults(self):
        """When centralized policy data is in effect, config fallback actions do not take precedence."""
        pe = self._pe()
        strict = SkillActionsConfig(
            medium=SeverityAction(file="quarantine", runtime="disable", install="block"),
        )
        scan = {"finding_count": 3, "max_severity": "MEDIUM", "target": "/x"}
        verdict, _ = _admission_verdict(
            pe, "skill", "strict-check", scan, None, strict,
        )
        self.assertEqual(verdict, "warning")


# ---------------------------------------------------------------------------
# Policy enrichment — map builders
# ---------------------------------------------------------------------------


class TestBuildActionsMap(_StoreWithPolicyMixin, unittest.TestCase):

    def test_empty_store(self):
        result = _build_actions_map_for_type(self.store, "skill")
        self.assertEqual(result, {})

    def test_with_entries(self):
        pe = self._pe()
        pe.block("skill", "a", "reason-a")
        pe.allow("skill", "b", "reason-b")
        result = _build_actions_map_for_type(self.store, "skill")
        self.assertIn("a", result)
        self.assertIn("b", result)
        self.assertEqual(result["a"].reason, "reason-a")

    def test_different_target_types(self):
        pe = self._pe()
        pe.block("skill", "s1", "x")
        pe.block("plugin", "p1", "y")
        skill_map = _build_actions_map_for_type(self.store, "skill")
        plugin_map = _build_actions_map_for_type(self.store, "plugin")
        self.assertIn("s1", skill_map)
        self.assertNotIn("p1", skill_map)
        self.assertIn("p1", plugin_map)

    def test_exception_returns_empty(self):
        broken = MagicMock()
        broken.list_actions_by_type.side_effect = RuntimeError("db error")
        result = _build_actions_map_for_type(broken, "skill")
        self.assertEqual(result, {})


class TestBuildScanMap(_StoreWithPolicyMixin, unittest.TestCase):

    def test_empty_store(self):
        result = _build_scan_map_for_type(self.store, "skill-scanner")
        self.assertEqual(result, {})

    def test_with_scan_results(self):
        import uuid
        from datetime import datetime, timezone
        self.store.insert_scan_result(
            str(uuid.uuid4()), "skill-scanner", "/path/to/my-skill",
            datetime.now(timezone.utc), 500, 2, "HIGH", "{}",
        )
        result = _build_scan_map_for_type(self.store, "skill-scanner")
        self.assertIn("my-skill", result)
        self.assertEqual(result["my-skill"]["finding_count"], 2)
        self.assertEqual(result["my-skill"]["max_severity"], "HIGH")

    def test_basename_keying(self):
        """Scan targets are indexed by basename and raw target aliases."""
        import uuid
        from datetime import datetime, timezone
        self.store.insert_scan_result(
            str(uuid.uuid4()), "plugin-scanner",
            "/long/path/to/web-search",
            datetime.now(timezone.utc), 100, 0, "INFO", "{}",
        )
        result = _build_scan_map_for_type(self.store, "plugin-scanner")
        self.assertIn("web-search", result)
        self.assertIn("/long/path/to/web-search", result)

    def test_null_severity_defaults_to_info(self):
        import uuid
        from datetime import datetime, timezone
        self.store.insert_scan_result(
            str(uuid.uuid4()), "mcp-scanner", "/mcp/test",
            datetime.now(timezone.utc), 200, 0, None, "{}",
        )
        result = _build_scan_map_for_type(self.store, "mcp-scanner")
        self.assertEqual(result["test"]["max_severity"], "INFO")

    def test_exception_returns_empty(self):
        broken = MagicMock()
        broken.latest_scans_by_scanner.side_effect = RuntimeError("db error")
        result = _build_scan_map_for_type(broken, "skill-scanner")
        self.assertEqual(result, {})


# ---------------------------------------------------------------------------
# Policy enrichment — formatters
# ---------------------------------------------------------------------------


class TestFormatVerdict(unittest.TestCase):

    def test_no_verdict(self):
        self.assertEqual(_format_verdict({}), "[dim]-[/dim]")

    def test_blocked(self):
        out = _format_verdict({"policy_verdict": "blocked"})
        self.assertIn("blocked", out)
        self.assertIn("bold red", out)

    def test_rejected_with_detail(self):
        out = _format_verdict({
            "policy_verdict": "rejected",
            "policy_detail": "3 findings, max HIGH",
        })
        self.assertIn("rejected", out)
        self.assertIn("3 findings", out)

    def test_warning_with_detail(self):
        out = _format_verdict({
            "policy_verdict": "warning",
            "policy_detail": "2 findings, max MEDIUM",
        })
        self.assertIn("warning", out)
        self.assertIn("2 findings", out)

    def test_clean(self):
        out = _format_verdict({"policy_verdict": "clean"})
        self.assertIn("clean", out)
        self.assertIn("green", out)

    def test_allowed(self):
        out = _format_verdict({"policy_verdict": "allowed"})
        self.assertIn("allowed", out)
        self.assertIn("cyan", out)

    def test_unscanned(self):
        out = _format_verdict({"policy_verdict": "unscanned"})
        self.assertIn("unscanned", out)

    def test_detail_not_shown_for_clean(self):
        out = _format_verdict({
            "policy_verdict": "clean",
            "policy_detail": "scan clean",
        })
        self.assertNotIn("scan clean", out)

    def test_unknown_verdict(self):
        out = _format_verdict({"policy_verdict": "custom-thing"})
        self.assertIn("custom-thing", out)


class TestFormatScan(unittest.TestCase):

    def test_no_scan(self):
        self.assertEqual(_format_scan({}), "[dim]-[/dim]")

    def test_clean_scan(self):
        out = _format_scan({"scan_findings": 0, "scan_severity": "INFO"})
        self.assertIn("clean", out)
        self.assertIn("green", out)

    def test_critical_findings(self):
        out = _format_scan({"scan_findings": 3, "scan_severity": "CRITICAL"})
        self.assertIn("3", out)
        self.assertIn("CRITICAL", out)
        self.assertIn("bold red", out)

    def test_high_findings(self):
        out = _format_scan({"scan_findings": 1, "scan_severity": "HIGH"})
        self.assertIn("1", out)
        self.assertIn("HIGH", out)
        self.assertIn("red", out)

    def test_medium_findings(self):
        out = _format_scan({"scan_findings": 5, "scan_severity": "MEDIUM"})
        self.assertIn("5", out)
        self.assertIn("MEDIUM", out)
        self.assertIn("yellow", out)

    def test_low_findings(self):
        out = _format_scan({"scan_findings": 2, "scan_severity": "LOW"})
        self.assertIn("2", out)
        self.assertIn("LOW", out)
        self.assertIn("cyan", out)

    def test_info_findings(self):
        out = _format_scan({"scan_findings": 1, "scan_severity": "INFO"})
        self.assertIn("1", out)
        self.assertIn("INFO", out)
        self.assertIn("dim", out)

    def test_none_findings_key_absent(self):
        self.assertEqual(_format_scan({"scan_severity": "HIGH"}), "[dim]-[/dim]")


class TestScanDetailSuffix(unittest.TestCase):

    def test_none(self):
        self.assertEqual(_scan_detail_suffix(None), "")

    def test_zero_scanned(self):
        self.assertEqual(_scan_detail_suffix({"scanned": 0, "total_findings": 0}), "")

    def test_scanned_no_findings(self):
        result = _scan_detail_suffix({"scanned": 5, "total_findings": 0, "unscanned": 3})
        self.assertIn("5 scanned", result)
        self.assertNotIn("findings", result)
        self.assertTrue(result.startswith(" · "))

    def test_scanned_with_findings(self):
        result = _scan_detail_suffix({"scanned": 10, "total_findings": 7, "unscanned": 2})
        self.assertIn("10 scanned", result)
        self.assertIn("7 findings", result)

    def test_empty_dict(self):
        self.assertEqual(_scan_detail_suffix({}), "")


class TestPolicyDetailSuffix(unittest.TestCase):

    def test_none(self):
        self.assertEqual(_policy_detail_suffix(None), "")

    def test_empty_dict(self):
        self.assertEqual(_policy_detail_suffix({}), "")

    def test_all_zeros(self):
        counts = {"blocked": 0, "rejected": 0, "warning": 0, "clean": 0, "unscanned": 0}
        self.assertEqual(_policy_detail_suffix(counts), "")

    def test_mixed_counts(self):
        counts = {"blocked": 2, "rejected": 1, "warning": 0, "clean": 5, "unscanned": 10}
        result = _policy_detail_suffix(counts)
        self.assertIn("2 blocked", result)
        self.assertIn("1 rejected", result)
        self.assertNotIn("warning", result)
        self.assertIn("5 clean", result)
        self.assertIn("10 unscanned", result)
        self.assertTrue(result.startswith(" · "))

    def test_only_unscanned(self):
        result = _policy_detail_suffix({"unscanned": 50})
        self.assertIn("50 unscanned", result)

    def test_order_blocked_before_clean(self):
        counts = {"blocked": 1, "clean": 3}
        result = _policy_detail_suffix(counts)
        self.assertLess(result.index("blocked"), result.index("clean"))


# ---------------------------------------------------------------------------
# Policy enrichment — enrich_with_policy end-to-end
# ---------------------------------------------------------------------------


class TestEnrichWithPolicy(_StoreWithPolicyMixin, unittest.TestCase):
    """End-to-end test: populate store, build inventory, enrich, verify."""

    def _make_inventory(self):
        return {
            "skills": [
                {"id": "github", "eligible": True, "source": "bundled"},
                {"id": "discord", "eligible": False, "source": "bundled"},
                {"id": "weather", "eligible": True, "source": "bundled"},
                {"id": "new-skill", "eligible": True, "source": "user"},
                {"id": "peekaboo", "eligible": False, "source": "bundled"},
            ],
            "plugins": [
                {"id": "memory-core", "enabled": True},
                {"id": "defenseclaw", "enabled": True},
                {"id": "web-search", "enabled": False},
            ],
            "mcp": [
                {"id": "local-db", "transport": "stdio"},
            ],
            "summary": {
                "skills": {"count": 5},
                "plugins": {"count": 3},
                "mcp": {"count": 1},
            },
        }

    def _seed_store(self):
        import uuid
        from datetime import datetime, timezone
        pe = self._pe()
        now = datetime.now(timezone.utc)

        pe.allow("skill", "github", "approved")
        pe.block("skill", "discord", "excessive permissions")

        self.store.insert_scan_result(
            str(uuid.uuid4()), "skill-scanner", "/skills/weather",
            now, 500, 0, "INFO", "{}",
        )
        self.store.insert_scan_result(
            str(uuid.uuid4()), "skill-scanner", "/skills/peekaboo",
            now, 1000, 3, "HIGH", "{}",
        )

        pe.block("plugin", "defenseclaw", "self-ref")
        pe.allow("plugin", "memory-core", "core")

        self.store.insert_scan_result(
            str(uuid.uuid4()), "plugin-scanner", "/plugins/web-search",
            now, 300, 1, "MEDIUM", "{}",
        )

        pe.allow("mcp", "local-db", "internal use")

    def test_skills_enriched(self):
        self._seed_store()
        inv = self._make_inventory()
        enrich_with_policy(inv, self.store, self.skill_actions)

        by_id = {s["id"]: s for s in inv["skills"]}
        self.assertEqual(by_id["github"]["policy_verdict"], "allowed")
        self.assertEqual(by_id["discord"]["policy_verdict"], "blocked")
        self.assertEqual(by_id["weather"]["policy_verdict"], "clean")
        self.assertEqual(by_id["new-skill"]["policy_verdict"], "unscanned")
        self.assertEqual(by_id["peekaboo"]["policy_verdict"], "rejected")

    def test_scan_data_attached_to_items(self):
        self._seed_store()
        inv = self._make_inventory()
        enrich_with_policy(inv, self.store, self.skill_actions)

        by_id = {s["id"]: s for s in inv["skills"]}
        self.assertEqual(by_id["weather"]["scan_findings"], 0)
        self.assertEqual(by_id["weather"]["scan_severity"], "INFO")
        self.assertEqual(by_id["peekaboo"]["scan_findings"], 3)
        self.assertEqual(by_id["peekaboo"]["scan_severity"], "HIGH")
        self.assertNotIn("scan_findings", by_id["github"])
        self.assertNotIn("scan_findings", by_id["new-skill"])

    def test_scan_data_on_plugins(self):
        self._seed_store()
        inv = self._make_inventory()
        enrich_with_policy(inv, self.store, self.skill_actions)

        by_id = {p["id"]: p for p in inv["plugins"]}
        self.assertEqual(by_id["web-search"]["scan_findings"], 1)
        self.assertEqual(by_id["web-search"]["scan_severity"], "MEDIUM")
        self.assertNotIn("scan_findings", by_id["defenseclaw"])

    def test_plugins_enriched(self):
        self._seed_store()
        inv = self._make_inventory()
        enrich_with_policy(inv, self.store, self.skill_actions)

        by_id = {p["id"]: p for p in inv["plugins"]}
        self.assertEqual(by_id["defenseclaw"]["policy_verdict"], "blocked")
        self.assertEqual(by_id["memory-core"]["policy_verdict"], "allowed")
        self.assertEqual(by_id["web-search"]["policy_verdict"], "warning")

    def test_mcp_enriched(self):
        self._seed_store()
        inv = self._make_inventory()
        enrich_with_policy(inv, self.store, self.skill_actions)

        self.assertEqual(inv["mcp"][0]["policy_verdict"], "allowed")

    def test_first_party_allows_use_resolved_inventory_paths(self):
        import uuid
        from datetime import datetime, timezone

        tmp = tempfile.mkdtemp(prefix="dc-inventory-policy-")
        try:
            cfg = Config(
                data_dir=os.path.join(tmp, ".defenseclaw"),
                audit_db=os.path.join(tmp, ".defenseclaw", "audit.db"),
                quarantine_dir=os.path.join(tmp, "q"),
                plugin_dir=os.path.join(tmp, "p"),
                policy_dir=os.path.join(tmp, "pol"),
                claw=ClawConfig(
                    mode="openclaw",
                    home_dir=os.path.join(tmp, ".openclaw"),
                    config_file=os.path.join(tmp, ".openclaw", "openclaw.json"),
                ),
            )
            os.makedirs(os.path.join(cfg.policy_dir, "rego"), exist_ok=True)
            with open(os.path.join(cfg.policy_dir, "rego", "data.json"), "w") as f:
                json.dump({
                    "config": {"allow_list_bypass_scan": True, "scan_on_install": True},
                    "actions": {},
                    "scanner_overrides": {},
                    "first_party_allow_list": [
                        {
                            "target_type": "plugin",
                            "target_name": "defenseclaw",
                            "reason": "first-party DefenseClaw plugin",
                            "source_path_contains": [".openclaw/extensions"],
                        },
                        {
                            "target_type": "skill",
                            "target_name": "codeguard",
                            "reason": "first-party DefenseClaw skill",
                            "source_path_contains": [".openclaw/skills"],
                        },
                    ],
                }, f)

            os.makedirs(os.path.join(cfg.claw.home_dir, "skills", "codeguard"), exist_ok=True)
            os.makedirs(os.path.join(cfg.claw.home_dir, "extensions", "defenseclaw"), exist_ok=True)

            now = datetime.now(timezone.utc)
            self.store.insert_scan_result(
                str(uuid.uuid4()), "skill-scanner", "/tmp/downloads/codeguard",
                now, 100, 0, "INFO", "{}",
            )
            self.store.insert_scan_result(
                str(uuid.uuid4()), "plugin-scanner", "/tmp/dclaw-plugin-fetch-abc123/defenseclaw",
                now, 100, 0, "INFO", "{}",
            )

            inv = {
                "skills": [{"id": "codeguard", "source": "user"}],
                "plugins": [{"id": "defenseclaw", "enabled": True}],
                "mcp": [],
                "summary": {"skills": {"count": 1}, "plugins": {"count": 1}, "mcp": {"count": 0}},
            }

            enrich_with_policy(
                inv, self.store, self.skill_actions,
                policy_dir=cfg.policy_dir, cfg=cfg,
            )

            # F-0742: the codeguard row is ``source: user`` (operator-supplied
            # provenance). It must NOT be blessed by the first-party allow
            # list just because its resolved path lands under
            # ``.openclaw/skills`` — that bypass is reserved for genuinely
            # bundled first-party assets. The user-sourced row stays
            # unscanned (its only scan target, /tmp/downloads/codeguard,
            # does not match the resolved on-disk path — F-0423).
            self.assertEqual(inv["skills"][0]["policy_verdict"], "unscanned")
            # The defenseclaw plugin has no untrusted source marker, so the
            # first-party allow still applies on its resolved provenance.
            self.assertEqual(inv["plugins"][0]["policy_verdict"], "allowed")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_inventory_uses_per_target_fallback_actions_when_policy_missing(self):
        import uuid
        from datetime import datetime, timezone

        tmp = tempfile.mkdtemp(prefix="dc-inventory-fallback-")
        cfg = Config(
            policy_dir=os.path.join(tmp, "missing-policy"),
            plugin_actions=PluginActionsConfig(
                high=SeverityAction(file="quarantine", runtime="disable", install="block"),
            ),
            mcp_actions=MCPActionsConfig(
                high=SeverityAction(file="none", runtime="enable", install="block"),
            ),
        )

        now = datetime.now(timezone.utc)
        self.store.insert_scan_result(
            str(uuid.uuid4()), "plugin-scanner", "/tmp/plugins/risky-plugin",
            now, 100, 1, "HIGH", "{}",
        )
        self.store.insert_scan_result(
            str(uuid.uuid4()), "mcp-scanner", "/tmp/mcp/risky-mcp",
            now, 100, 1, "HIGH", "{}",
        )

        inv = {
            "skills": [],
            "plugins": [{"id": "risky-plugin", "enabled": True}],
            "mcp": [{"id": "risky-mcp", "transport": "stdio"}],
            "summary": {"skills": {"count": 0}, "plugins": {"count": 1}, "mcp": {"count": 1}},
        }

        enrich_with_policy(
            inv, self.store, self.skill_actions,
            policy_dir=cfg.policy_dir, cfg=cfg,
        )

        self.assertEqual(inv["plugins"][0]["policy_verdict"], "rejected")
        self.assertEqual(inv["mcp"][0]["policy_verdict"], "rejected")
        shutil.rmtree(tmp, ignore_errors=True)

    def test_plugin_policy_enrichment_uses_install_name_aliases(self):
        import uuid
        from datetime import datetime, timezone

        tmp = tempfile.mkdtemp(prefix="dc-inventory-plugin-alias-")
        try:
            cfg = Config(
                data_dir=os.path.join(tmp, ".defenseclaw"),
                audit_db=os.path.join(tmp, ".defenseclaw", "audit.db"),
                quarantine_dir=os.path.join(tmp, "q"),
                plugin_dir=os.path.join(tmp, "p"),
                policy_dir=os.path.join(tmp, "missing-policy"),
                claw=ClawConfig(
                    mode="openclaw",
                    home_dir=os.path.join(tmp, ".openclaw"),
                    config_file=os.path.join(tmp, ".openclaw", "openclaw.json"),
                ),
            )
            os.makedirs(os.path.join(cfg.claw.home_dir, "extensions", "xai-plugin"), exist_ok=True)

            pe = self._pe()
            pe.allow("plugin", "xai-plugin", "reviewed")

            now = datetime.now(timezone.utc)
            self.store.insert_scan_result(
                str(uuid.uuid4()), "plugin-scanner",
                os.path.join(cfg.claw.home_dir, "extensions", "xai-plugin"),
                now, 100, 1, "MEDIUM", "{}",
            )

            inv = {
                "skills": [],
                "plugins": [{"id": "xai", "name": "@openclaw/xai-plugin", "enabled": True}],
                "mcp": [],
                "summary": {"skills": {"count": 0}, "plugins": {"count": 1}, "mcp": {"count": 0}},
            }

            enrich_with_policy(
                inv, self.store, self.skill_actions,
                policy_dir=cfg.policy_dir, cfg=cfg,
            )

            self.assertEqual(inv["plugins"][0]["policy_verdict"], "allowed")
            self.assertEqual(inv["plugins"][0]["scan_findings"], 1)
            self.assertEqual(inv["plugins"][0]["scan_severity"], "MEDIUM")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_mcp_policy_enrichment_matches_url_scan_targets(self):
        import uuid
        from datetime import datetime, timezone

        tmp = tempfile.mkdtemp(prefix="dc-inventory-mcp-url-")
        try:
            cfg = Config(
                policy_dir=os.path.join(tmp, "missing-policy"),
                mcp_actions=MCPActionsConfig(
                    high=SeverityAction(file="none", runtime="enable", install="block"),
                ),
            )

            now = datetime.now(timezone.utc)
            self.store.insert_scan_result(
                str(uuid.uuid4()), "mcp-scanner", "https://example.com/mcp/sse",
                now, 100, 2, "HIGH", "{}",
            )

            inv = {
                "skills": [],
                "plugins": [],
                "mcp": [{"id": "remote-mcp", "url": "https://example.com/mcp/sse", "transport": "sse"}],
                "summary": {"skills": {"count": 0}, "plugins": {"count": 0}, "mcp": {"count": 1}},
            }

            enrich_with_policy(
                inv, self.store, self.skill_actions,
                policy_dir=cfg.policy_dir, cfg=cfg,
            )

            self.assertEqual(inv["mcp"][0]["policy_verdict"], "rejected")
            self.assertEqual(inv["mcp"][0]["scan_findings"], 2)
            self.assertEqual(inv["mcp"][0]["scan_severity"], "HIGH")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_summary_policy_counts(self):
        self._seed_store()
        inv = self._make_inventory()
        enrich_with_policy(inv, self.store, self.skill_actions)

        ps = inv["summary"]["policy_skills"]
        self.assertEqual(ps["blocked"], 1)
        self.assertEqual(ps["allowed"], 1)
        self.assertEqual(ps["clean"], 1)
        self.assertEqual(ps["rejected"], 1)
        self.assertEqual(ps.get("warning", 0), 0)
        self.assertEqual(ps["unscanned"], 1)

        pp = inv["summary"]["policy_plugins"]
        self.assertEqual(pp["blocked"], 1)
        self.assertEqual(pp["allowed"], 1)
        self.assertEqual(pp["warning"], 1)

        pm = inv["summary"]["policy_mcp"]
        self.assertEqual(pm["allowed"], 1)

    def test_summary_scan_counts(self):
        self._seed_store()
        inv = self._make_inventory()
        enrich_with_policy(inv, self.store, self.skill_actions)

        ss = inv["summary"]["scan_skills"]
        self.assertEqual(ss["scanned"], 2)
        self.assertEqual(ss["unscanned"], 3)
        self.assertEqual(ss["total_findings"], 3)

        sp = inv["summary"]["scan_plugins"]
        self.assertEqual(sp["scanned"], 1)
        self.assertEqual(sp["unscanned"], 2)
        self.assertEqual(sp["total_findings"], 1)

        sm = inv["summary"]["scan_mcp"]
        self.assertEqual(sm["scanned"], 0)
        self.assertEqual(sm["unscanned"], 1)

    def test_no_store_is_noop(self):
        inv = self._make_inventory()
        enrich_with_policy(inv, None, self.skill_actions)
        self.assertNotIn("policy_verdict", inv["skills"][0])

    def test_empty_skills_list(self):
        inv = {"skills": [], "plugins": [], "mcp": [], "summary": {}}
        enrich_with_policy(inv, self.store, self.skill_actions)
        self.assertNotIn("policy_skills", inv["summary"])

    def test_items_without_id_are_skipped(self):
        inv = {
            "skills": [{"eligible": True}],
            "plugins": [],
            "mcp": [],
            "summary": {"skills": {"count": 1}},
        }
        enrich_with_policy(inv, self.store, self.skill_actions)
        self.assertNotIn("policy_verdict", inv["skills"][0])


# ---------------------------------------------------------------------------
# Policy enrichment — CLI integration with policy data
# ---------------------------------------------------------------------------


class TestCLIIntegrationWithPolicy(unittest.TestCase):
    """aibom scan CLI command includes policy data in JSON output."""

    def setUp(self) -> None:
        from tests.helpers import make_app_context
        self.app, self.tmp_dir, self.db_path = make_app_context()

    def tearDown(self) -> None:
        from tests.helpers import cleanup_app
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    def _seed(self):
        """Seed store with policy data matching SKILLS_JSON/PLUGINS_JSON fixtures.

        Fixture skills: github, weather.  Plugins: anthropic, memory-core.
        MCP: filesystem.
        """
        import uuid
        from datetime import datetime, timezone

        from defenseclaw.enforce import PolicyEngine
        pe = PolicyEngine(self.app.store)
        now = datetime.now(timezone.utc)

        pe.block("skill", "weather", "missing weather-cli binary")
        pe.allow("skill", "github", "security team approved")

        self.app.store.insert_scan_result(
            str(uuid.uuid4()), "plugin-scanner", "/plugins/anthropic",
            now, 100, 0, "INFO", "{}",
        )
        pe.block("plugin", "memory-core", "test block")

        pe.allow("mcp", "filesystem", "internal use")

    @patch("defenseclaw.inventory.claw_inventory.subprocess.run", side_effect=_mock_run)
    def test_json_output_includes_policy_verdicts(self, _):
        self._seed()
        from defenseclaw.commands.cmd_aibom import aibom
        runner = CliRunner()
        result = runner.invoke(aibom, ["scan", "--json"], obj=self.app)
        self.assertEqual(result.exit_code, 0, result.output)
        data = json.loads(result.stdout)

        for skill in data["skills"]:
            self.assertIn("policy_verdict", skill)

        by_id = {s["id"]: s for s in data["skills"]}
        self.assertEqual(by_id["github"]["policy_verdict"], "allowed")
        self.assertEqual(by_id["weather"]["policy_verdict"], "blocked")

    @patch("defenseclaw.inventory.claw_inventory.subprocess.run", side_effect=_mock_run)
    def test_json_plugins_have_verdicts(self, _):
        self._seed()
        from defenseclaw.commands.cmd_aibom import aibom
        runner = CliRunner()
        result = runner.invoke(aibom, ["scan", "--json"], obj=self.app)
        self.assertEqual(result.exit_code, 0, result.output)
        data = json.loads(result.stdout)

        by_id = {p["id"]: p for p in data["plugins"]}
        self.assertEqual(by_id["anthropic"]["policy_verdict"], "clean")
        self.assertEqual(by_id["memory-core"]["policy_verdict"], "blocked")

    @patch("defenseclaw.inventory.claw_inventory.subprocess.run", side_effect=_mock_run)
    def test_json_mcp_has_verdicts(self, _):
        self._seed()
        from defenseclaw.commands.cmd_aibom import aibom
        runner = CliRunner()
        result = runner.invoke(aibom, ["scan", "--json"], obj=self.app)
        self.assertEqual(result.exit_code, 0, result.output)
        data = json.loads(result.stdout)
        self.assertEqual(data["mcp"][0]["policy_verdict"], "allowed")

    @patch("defenseclaw.inventory.claw_inventory.subprocess.run", side_effect=_mock_run)
    def test_summary_has_policy_counts(self, _):
        self._seed()
        from defenseclaw.commands.cmd_aibom import aibom
        runner = CliRunner()
        result = runner.invoke(aibom, ["scan", "--json"], obj=self.app)
        self.assertEqual(result.exit_code, 0, result.output)
        data = json.loads(result.stdout)
        self.assertIn("policy_skills", data["summary"])
        self.assertIn("policy_plugins", data["summary"])
        self.assertIn("policy_mcp", data["summary"])

    @patch("defenseclaw.inventory.claw_inventory.subprocess.run", side_effect=_mock_run)
    def test_json_includes_scan_data(self, _):
        self._seed()
        from defenseclaw.commands.cmd_aibom import aibom
        runner = CliRunner()
        result = runner.invoke(aibom, ["scan", "--json"], obj=self.app)
        self.assertEqual(result.exit_code, 0, result.output)
        data = json.loads(result.stdout)

        by_id = {p["id"]: p for p in data["plugins"]}
        self.assertEqual(by_id["anthropic"]["scan_findings"], 0)
        self.assertEqual(by_id["anthropic"]["scan_severity"], "INFO")
        self.assertNotIn("scan_findings", by_id["memory-core"])

    @patch("defenseclaw.inventory.claw_inventory.subprocess.run", side_effect=_mock_run)
    def test_summary_has_scan_counts(self, _):
        self._seed()
        from defenseclaw.commands.cmd_aibom import aibom
        runner = CliRunner()
        result = runner.invoke(aibom, ["scan", "--json"], obj=self.app)
        self.assertEqual(result.exit_code, 0, result.output)
        data = json.loads(result.stdout)
        self.assertIn("scan_skills", data["summary"])
        self.assertIn("scan_plugins", data["summary"])
        self.assertIn("scan_mcp", data["summary"])

    @patch("defenseclaw.inventory.claw_inventory.subprocess.run", side_effect=_mock_run)
    def test_human_output_renders_policy_column(self, _):
        self._seed()
        from defenseclaw.commands.cmd_aibom import aibom
        runner = CliRunner()
        result = runner.invoke(aibom, ["scan"], obj=self.app)
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Policy", result.output)
        self.assertIn("blocked", result.output)
        self.assertIn("allowed", result.output)


# ---------------------------------------------------------------------------
# _run_openclaw — additional raw_decode edge cases
# ---------------------------------------------------------------------------


class TestRunOpenclawRawDecodeEdge(unittest.TestCase):

    @patch("defenseclaw.inventory.claw_inventory.subprocess.run")
    def test_stdout_with_leading_noise(self, mock_sub):
        """Leading noise on stdout (not just stderr) should still parse."""
        noise = "Some debug output\n"
        json_part = '{"agents": [{"id": "main"}]}'
        mock_sub.return_value = MagicMock(
            returncode=0,
            stdout=noise + json_part,
            stderr="",
        )
        result = _run_openclaw("agents", "list")
        self.assertIsNotNone(result.data)
        self.assertEqual(result.data["agents"][0]["id"], "main")

    @patch("defenseclaw.inventory.claw_inventory.subprocess.run")
    def test_array_root_json_in_noise(self, mock_sub):
        """Array-root JSON embedded in stderr noise should parse."""
        warning = "(node:123) Warning: something\n"
        json_part = '[{"name": "test-tool"}]'
        mock_sub.return_value = MagicMock(
            returncode=0,
            stdout="",
            stderr=warning + json_part,
        )
        result = _run_openclaw("tools", "list")
        self.assertIsNotNone(result.data)
        self.assertEqual(result.data[0]["name"], "test-tool")

    @patch("defenseclaw.inventory.claw_inventory.subprocess.run")
    def test_bracket_but_invalid_json(self, mock_sub):
        """A { character in non-JSON text shouldn't crash."""
        mock_sub.return_value = MagicMock(
            returncode=0,
            stdout="Error: something went wrong {see log}",
            stderr="",
        )
        result = _run_openclaw("agents", "list")
        self.assertIsNone(result.data)
        self.assertEqual(result.error, "no JSON in output")

    @patch("defenseclaw.inventory.claw_inventory.subprocess.run")
    def test_trailing_noise_on_stdout(self, mock_sub):
        """JSON followed by garbage on stdout should parse via raw_decode."""
        json_part = '{"models": []}'
        noise = "\n=== some debug footer ==="
        mock_sub.return_value = MagicMock(
            returncode=0,
            stdout=json_part + noise,
            stderr="",
        )
        result = _run_openclaw("models", "status")
        self.assertIsNotNone(result.data)
        self.assertEqual(result.data["models"], [])

    @patch("defenseclaw.inventory.claw_inventory.subprocess.run")
    def test_both_streams_have_noise_only(self, mock_sub):
        """When both stdout and stderr have non-JSON text, return error."""
        mock_sub.return_value = MagicMock(
            returncode=0,
            stdout="debug line 1\ndebug line 2",
            stderr="warning: something",
        )
        result = _run_openclaw("skills", "list")
        self.assertIsNone(result.data)
        self.assertEqual(result.error, "no JSON in output")

    @patch("defenseclaw.inventory.claw_inventory.subprocess.run")
    def test_noise_surrounding_json(self, mock_sub):
        """Leading AND trailing noise around JSON should parse."""
        text = '(node:1) Warning: x\n{"ok": true}\n(node:1) ExperimentalWarning: y'
        mock_sub.return_value = MagicMock(
            returncode=0,
            stdout="",
            stderr=text,
        )
        result = _run_openclaw("agents", "list")
        self.assertIsNotNone(result.data)
        self.assertTrue(result.data["ok"])


# ---------------------------------------------------------------------------
# S4.3 — Filesystem-adapter inventory for non-OpenClaw connectors
# ---------------------------------------------------------------------------


def _make_cfg_for_connector(tmp: str, connector: str) -> Config:
    """Build a Config with ``guardrail.connector`` set to *connector*.

    GuardrailConfig only lives on the FullConfig that the CLI builds at
    runtime; the unit-test Config doesn't carry it. We work around this
    by stubbing :meth:`Config.active_connector` on the instance below.
    """
    ddir = os.path.join(tmp, ".defenseclaw")
    os.makedirs(ddir, exist_ok=True)
    cfg = Config(
        data_dir=ddir,
        audit_db=os.path.join(ddir, "audit.db"),
        quarantine_dir=os.path.join(tmp, "q"),
        plugin_dir=os.path.join(tmp, "p"),
        policy_dir=os.path.join(tmp, "pol"),
        claw=ClawConfig(
            mode="openclaw",
            home_dir=os.path.join(tmp, "oc"),
            config_file=os.path.join(tmp, "oc", "openclaw.json"),
        ),
    )
    cfg.active_connector = lambda c=connector: c  # type: ignore[method-assign]
    return cfg


def _seed_skill(root: str, name: str, *, marker: str = "SKILL.md", body: str = "# A skill\n\nFirst paragraph.") -> str:
    """Create ``<root>/<name>/<marker>`` with *body* and return the dir."""
    path = os.path.join(root, name)
    os.makedirs(path, exist_ok=True)
    with open(os.path.join(path, marker), "w", encoding="utf-8") as f:
        f.write(body)
    return path


def _seed_plugin(root: str, name: str, *, manifest: str | None = "package.json") -> str:
    """Create ``<root>/<name>`` and optionally drop a manifest file."""
    path = os.path.join(root, name)
    os.makedirs(path, exist_ok=True)
    if manifest is None:
        return path
    rel_dir = os.path.dirname(manifest)
    if rel_dir:
        os.makedirs(os.path.join(path, rel_dir), exist_ok=True)
    with open(os.path.join(path, manifest), "w", encoding="utf-8") as f:
        f.write("{}")
    return path


class TestBuildAibomFromFilesystem(unittest.TestCase):
    """build_claw_aibom on non-OpenClaw connectors must walk the disk."""

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="dc-claw-fs-")

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _patch_skill_dirs(self, dirs):
        return patch(
            "defenseclaw.config.Config.skill_dirs",
            return_value=list(dirs),
        )

    def _patch_plugin_dirs(self, dirs):
        return patch(
            "defenseclaw.config.Config.plugin_dirs",
            return_value=list(dirs),
        )

    def _patch_mcp(self, entries):
        return patch(
            "defenseclaw.config.Config.mcp_servers",
            return_value=list(entries),
        )

    def test_codex_skips_subprocess_and_walks_disk(self):
        """For connector=codex, build_claw_aibom must NOT shell out."""
        cfg = _make_cfg_for_connector(self.tmp, "codex")
        skill_root = os.path.join(self.tmp, ".codex", "skills")
        os.makedirs(skill_root, exist_ok=True)
        _seed_skill(skill_root, "alpha")
        plugin_root = os.path.join(self.tmp, ".codex", "extensions")
        os.makedirs(plugin_root, exist_ok=True)
        _seed_plugin(plugin_root, "ext1", manifest=".codex-plugin/plugin.json")

        with self._patch_skill_dirs([skill_root]), \
             self._patch_plugin_dirs([plugin_root]), \
             self._patch_mcp([]), \
             patch("defenseclaw.inventory.claw_inventory.subprocess.run") as mock_sub:
            inv = build_claw_aibom(cfg, live=True)
            mock_sub.assert_not_called()

        self.assertEqual(inv["connector"], "codex")
        self.assertTrue(inv["live"])
        self.assertEqual(len(inv["skills"]), 1)
        self.assertEqual(inv["skills"][0]["id"], "alpha")
        self.assertTrue(inv["skills"][0]["eligible"])
        self.assertEqual(len(inv["plugins"]), 1)
        self.assertEqual(inv["plugins"][0]["id"], "ext1")
        self.assertEqual(inv["plugins"][0]["manifest"], ".codex-plugin/plugin.json")

    def test_codex_inventory_expands_system_skill_container(self):
        cfg = _make_cfg_for_connector(self.tmp, "codex")
        skill_root = os.path.join(self.tmp, ".codex", "skills")
        system_root = os.path.join(skill_root, ".system")
        _seed_skill(system_root, "skill-installer", body="# Built in")
        os.makedirs(os.path.join(system_root, "cache"), exist_ok=True)

        with self._patch_skill_dirs([skill_root]), \
             self._patch_plugin_dirs([]), \
             self._patch_mcp([]):
            inv = build_claw_aibom(cfg, live=True)

        by_id = {row["id"]: row for row in inv["skills"]}
        self.assertNotIn(".system", by_id)
        self.assertNotIn("cache", by_id)
        self.assertEqual(set(by_id), {"skill-installer"})
        self.assertTrue(by_id["skill-installer"]["bundled"])
        self.assertEqual(by_id["skill-installer"]["source"], system_root)
        self.assertTrue(by_id["skill-installer"]["eligible"])

    def test_codex_inventory_carries_connector_paths(self):
        """G3: non-OpenClaw inventories carry connector_home /
        connector_config_files / connector_skill_dirs / connector_plugin_dirs
        / connector_mcp_files alongside the legacy claw_home /
        openclaw_config keys, so the TUI renderer can show the right
        location to operators running against Codex / Claude Code etc.
        instead of a misleading "~/.openclaw" fallback.
        """
        cfg = _make_cfg_for_connector(self.tmp, "codex")
        skill_root = os.path.join(self.tmp, ".codex", "skills")
        plugin_root = os.path.join(self.tmp, ".codex", "extensions")
        with self._patch_skill_dirs([skill_root]), \
             self._patch_plugin_dirs([plugin_root]), \
             self._patch_mcp([]), \
             patch("defenseclaw.inventory.claw_inventory.subprocess.run"):
            inv = build_claw_aibom(cfg, live=True)
        self.assertEqual(inv["connector"], "codex")
        self.assertTrue(inv["connector_home"].endswith(".codex"))
        self.assertTrue(any(
            p.endswith("config.toml") for p in inv["connector_config_files"]
        ))
        self.assertEqual(inv["connector_skill_dirs"], [skill_root])
        self.assertEqual(inv["connector_plugin_dirs"], [plugin_root])
        self.assertEqual(inv["connector_config"], inv["connector_config_files"][0])
        self.assertNotIn("openclaw_config", inv)
        self.assertEqual(inv["claw_home"], inv["connector_home"])

    def test_codex_inventory_parses_project_and_user_agents_and_rules(self):
        cfg = _make_cfg_for_connector(self.tmp, "codex")
        repo = Path(self.tmp) / "repo"
        repo.mkdir()
        (repo / ".git").mkdir()
        cfg.claw.workspace_dir = str(repo)
        codex_home = Path(self.tmp) / "codex-home"

        project_agents = repo / ".codex" / "agents"
        project_agents.mkdir(parents=True)
        (project_agents / "reviewer.toml").write_text(
            'name = "reviewer"\n'
            'description = "Project reviewer"\n'
            'developer_instructions = "Do not expose this prompt."\n'
            'model = "gpt-test"\n'
        )
        user_agents = codex_home / "agents"
        user_agents.mkdir(parents=True)
        (user_agents / "reviewer.toml").write_text(
            'name = "reviewer"\n'
            'description = "User reviewer"\n'
            'developer_instructions = "Private instructions."\n'
        )
        project_rules = repo / ".codex" / "rules"
        project_rules.mkdir()
        (project_rules / "project.rules").write_text('prefix_rule(pattern=["git"], decision="prompt")\n')
        user_rules = codex_home / "rules"
        user_rules.mkdir()
        (user_rules / "user.rules").write_text('prefix_rule(pattern=["rm"], decision="forbidden")\n')

        with patch.dict(
            os.environ,
            {"CODEX_HOME": str(codex_home), "HOME": self.tmp, "USERPROFILE": self.tmp},
            clear=False,
        ), patch("defenseclaw.connector_paths.Path.home", return_value=Path(self.tmp)), \
             self._patch_skill_dirs([]), self._patch_plugin_dirs([]), self._patch_mcp([]):
            inv = build_claw_aibom(cfg, live=True)

        reviewers = [row for row in inv["agents"] if row["id"] == "reviewer"]
        self.assertEqual(len(reviewers), 2)
        self.assertEqual(reviewers[0]["scope"], "project")
        self.assertTrue(reviewers[0]["trust_required"])
        self.assertFalse(reviewers[0]["shadowed"])
        self.assertTrue(reviewers[0]["eligible"])
        self.assertEqual(reviewers[0]["model"], "gpt-test")
        self.assertNotIn("developer_instructions", reviewers[0])
        self.assertEqual(reviewers[1]["scope"], "user")
        self.assertTrue(reviewers[1]["shadowed"])
        self.assertEqual(
            {(rule["id"], rule["scope"]) for rule in inv["rules"]},
            {("project", "project"), ("user", "user")},
        )
        self.assertIn(str(project_agents), inv["connector_agent_dirs"])
        self.assertIn(str(project_rules), inv["connector_rule_dirs"])

    def test_codex_agents_and_rules_reject_reparse_ancestry(self):
        cfg = _make_cfg_for_connector(self.tmp, "codex")
        repo = Path(self.tmp) / "repo"
        repo.mkdir()
        (repo / ".git").mkdir()
        cfg.claw.workspace_dir = str(repo)
        codex_home = Path(self.tmp) / "codex-home"
        project_agents = repo / ".codex" / "agents"
        project_rules = repo / ".codex" / "rules"
        user_agents = codex_home / "agents"
        user_rules = codex_home / "rules"
        for directory in (project_agents, project_rules, user_agents, user_rules):
            directory.mkdir(parents=True)
        for path, name in (
            (project_agents / "project.toml", "project"),
            (user_agents / "user.toml", "user"),
        ):
            path.write_text(
                f'name = "{name}"\n'
                'description = "desc"\n'
                'developer_instructions = "private"\n'
            )
        (project_rules / "project.rules").write_text("prefix_rule(pattern=[\"pwsh\"])\n")
        (user_rules / "user.rules").write_text("prefix_rule(pattern=[\"git\"])\n")
        real_reject = connector_paths.reject_reparse_path
        unsafe_root = os.path.normcase(str(repo / ".codex"))

        def reject_project(path):
            if os.path.normcase(os.path.abspath(path)).startswith(unsafe_root):
                raise OSError("mocked Windows junction")
            return real_reject(path)

        with patch.dict(os.environ, {"CODEX_HOME": str(codex_home)}, clear=False), \
             patch.object(connector_paths, "reject_reparse_path", side_effect=reject_project):
            agents = _agents_from_codex_toml_dirs(
                [str(project_agents), str(user_agents)]
            )
            rules = _rules_for_connector("codex", cfg)

        self.assertEqual([row["id"] for row in agents], ["user"])
        self.assertEqual([row["id"] for row in rules], ["user"])

    def test_codex_agent_replaced_during_read_is_not_inventoried(self):
        agents_dir = Path(self.tmp) / "agents"
        agents_dir.mkdir()
        agent_file = agents_dir / "raced.toml"
        agent_file.write_text(
            'name = "raced"\n'
            'description = "desc"\n'
            'developer_instructions = "private"\n'
        )
        real_read = connector_paths._read_bounded_stable_file

        def reject_raced(path, *, max_bytes):
            if os.path.normcase(os.path.abspath(path)) == os.path.normcase(str(agent_file)):
                raise OSError("file was replaced while it was being inventoried")
            return real_read(path, max_bytes=max_bytes)

        with patch.object(
            connector_paths,
            "_read_bounded_stable_file",
            side_effect=reject_raced,
        ):
            agents = _agents_from_codex_toml_dirs([str(agents_dir)])

        self.assertEqual(agents, [])

    def test_codex_rule_reparse_file_is_not_inventoried(self):
        cfg = _make_cfg_for_connector(self.tmp, "codex")
        codex_home = Path(self.tmp) / "codex-home"
        rules_dir = codex_home / "rules"
        rules_dir.mkdir(parents=True)
        rule_file = rules_dir / "unsafe.rules"
        rule_file.write_text('prefix_rule(pattern=["pwsh"])\n')
        real_reject = connector_paths.reject_reparse_path

        def reject_rule(path):
            if os.path.normcase(os.path.abspath(path)) == os.path.normcase(str(rule_file)):
                raise OSError("mocked Windows reparse point")
            return real_reject(path)

        with patch.dict(os.environ, {"CODEX_HOME": str(codex_home)}, clear=False), \
             patch.object(connector_paths, "reject_reparse_path", side_effect=reject_rule):
            rules = _rules_for_connector("codex", cfg)

        self.assertEqual(rules, [])

    def test_codex_inventory_reads_exact_local_marketplace_plugin_root(self):
        cfg = _make_cfg_for_connector(self.tmp, "codex")
        repo = Path(self.tmp) / "repo"
        repo.mkdir()
        (repo / ".git").mkdir()
        cfg.claw.workspace_dir = str(repo)
        plugin = repo / "packages" / "declared-plugin"
        _seed_plugin(str(plugin.parent), plugin.name, manifest=".codex-plugin/plugin.json")
        legacy_plugin = repo / "packages" / "legacy-plugin"
        _seed_plugin(
            str(legacy_plugin.parent),
            legacy_plugin.name,
            manifest=".codex-plugin/plugin.json",
        )
        personal_plugin = Path(self.tmp) / "personal-plugins" / "personal-plugin"
        _seed_plugin(
            str(personal_plugin.parent),
            personal_plugin.name,
            manifest=".codex-plugin/plugin.json",
        )
        marketplace = repo / ".agents" / "plugins" / "marketplace.json"
        marketplace.parent.mkdir(parents=True)
        marketplace.write_text(
            json.dumps(
                {
                    "plugins": [
                        {
                            "name": "declared-plugin",
                            "source": {"source": "local", "path": "./packages/declared-plugin"},
                        }
                    ]
                }
            )
        )
        legacy_marketplace = repo / ".claude-plugin" / "marketplace.json"
        legacy_marketplace.parent.mkdir(parents=True)
        legacy_marketplace.write_text(
            json.dumps(
                {
                    "plugins": [
                        {
                            "name": "legacy-plugin",
                            "source": {
                                "source": "local",
                                "path": "./packages/legacy-plugin",
                            },
                        }
                    ]
                }
            )
        )
        personal_marketplace = Path(self.tmp) / ".agents" / "plugins" / "marketplace.json"
        personal_marketplace.parent.mkdir(parents=True)
        personal_marketplace.write_text(
            json.dumps(
                {
                    "plugins": [
                        {
                            "name": "personal-plugin",
                            "source": {
                                "source": "local",
                                "path": "./personal-plugins/personal-plugin",
                            },
                        }
                    ]
                }
            )
        )

        with patch.dict(
            os.environ,
            {"CODEX_HOME": str(Path(self.tmp) / "codex-home")},
            clear=False,
        ), patch("defenseclaw.connector_paths.Path.home", return_value=Path(self.tmp)), \
             self._patch_skill_dirs([]), self._patch_mcp([]):
            inv = build_claw_aibom(cfg, live=True)

        self.assertEqual(
            [row["id"] for row in inv["plugins"]],
            ["declared-plugin", "legacy-plugin", "personal-plugin"],
        )
        self.assertEqual(inv["plugins"][0]["path"], str(plugin))
        self.assertEqual(inv["plugins"][1]["path"], str(legacy_plugin))
        self.assertEqual(inv["plugins"][2]["path"], str(personal_plugin))

    def test_opencode_inventory_legacy_paths_are_connector_aware(self):
        cfg = _make_cfg_for_connector(self.tmp, "opencode")
        with self._patch_skill_dirs([]), \
             self._patch_plugin_dirs([]), \
             self._patch_mcp([]), \
             patch("defenseclaw.inventory.claw_inventory.subprocess.run"):
            inv = build_claw_aibom(cfg, live=True)

        self.assertEqual(inv["connector"], "opencode")
        self.assertTrue(inv["connector_home"].endswith(os.path.join(".config", "opencode")))
        self.assertTrue(inv["connector_config_files"][0].endswith(
            os.path.join(".config", "opencode", "plugins", "defenseclaw.js")
        ))
        self.assertEqual(inv["connector_config"], inv["connector_config_files"][0])
        self.assertNotIn("openclaw_config", inv)
        self.assertEqual(inv["claw_home"], inv["connector_home"])

        result = claw_aibom_to_scan_result(inv, cfg)
        self.assertEqual(result.target, inv["connector_config_files"][0])
        self.assertTrue(all(f.location == result.target for f in result.findings))

    def test_connector_inventory_mode_follows_scanned_connector(self):
        """The AIBOM ``Mode:`` line (inv['claw_mode']) must report the
        *scanned* connector, not the global cfg.claw.mode. In a
        multi-connector install cfg.claw.mode is a stale pointer to whichever
        connector was last activated, so a ``--connector codex`` scan would
        otherwise mislabel itself with e.g. ``antigravity``.
        """
        cfg = _make_cfg_for_connector(self.tmp, "codex")
        # Simulate the multi-connector reality: the global mode points at a
        # different (last-activated) connector than the one being scanned.
        cfg.claw.mode = "antigravity"
        skill_root = os.path.join(self.tmp, ".codex", "skills")
        with self._patch_skill_dirs([skill_root]), \
             self._patch_plugin_dirs([]), \
             self._patch_mcp([]):
            inv = build_claw_aibom(cfg, live=True)
        self.assertEqual(inv["connector"], "codex")
        self.assertEqual(inv["claw_mode"], "codex")

    def test_claudecode_walks_disk(self):
        cfg = _make_cfg_for_connector(self.tmp, "claudecode")
        skill_root = os.path.join(self.tmp, ".claude", "skills")
        os.makedirs(skill_root, exist_ok=True)
        _seed_skill(skill_root, "weather")
        with self._patch_skill_dirs([skill_root]), \
             self._patch_plugin_dirs([]), \
             self._patch_mcp([]):
            inv = build_claw_aibom(cfg, live=True)
        self.assertEqual(inv["connector"], "claudecode")
        ids = [s["id"] for s in inv["skills"]]
        self.assertIn("weather", ids)

    def test_cursor_inventory_reads_local_plugins_and_scoped_subagents(self):
        cfg = _make_cfg_for_connector(self.tmp, "cursor")
        home = os.path.join(self.tmp, "home")
        workspace = os.path.join(self.tmp, "workspace")
        os.makedirs(workspace)
        cfg.connector_workspace_dir = lambda: workspace  # type: ignore[method-assign]

        _seed_plugin(
            os.path.join(home, ".cursor", "plugins", "local"),
            "review-tools",
            manifest=".cursor-plugin/plugin.json",
        )
        user_agents = os.path.join(home, ".cursor", "agents")
        project_agents = os.path.join(workspace, ".cursor", "agents")
        os.makedirs(user_agents, exist_ok=True)
        os.makedirs(project_agents, exist_ok=True)
        with open(os.path.join(user_agents, "global-reviewer.md"), "w", encoding="utf-8") as handle:
            handle.write("---\nname: global-reviewer\n---\n")
        with open(os.path.join(project_agents, "project-reviewer.md"), "w", encoding="utf-8") as handle:
            handle.write("---\nname: project-reviewer\n---\n")

        with patch.dict(
            os.environ,
            {"HOME": home, "USERPROFILE": home},
            clear=False,
        ):
            inv = build_claw_aibom(cfg, live=True)

        self.assertEqual({row["id"] for row in inv["plugins"]}, {"review-tools"})
        self.assertEqual(inv["plugins"][0]["manifest"], ".cursor-plugin/plugin.json")
        self.assertEqual(
            {row["id"] for row in inv["agents"]},
            {"global-reviewer", "project-reviewer"},
        )
        self.assertEqual(
            inv["connector_plugin_dirs"],
            [os.path.join(home, ".cursor", "plugins", "local")],
        )
        self.assertEqual(cfg.plugin_dirs("cursor"), [])
        self.assertNotIn("agents", {row["category"] for row in inv["limitations"]})

    def test_cursor_inventory_does_not_infer_project_subagents_from_cwd(self):
        cfg = _make_cfg_for_connector(self.tmp, "cursor")
        home = os.path.join(self.tmp, "home")
        cwd = os.path.join(self.tmp, "unselected-workspace")
        os.makedirs(cwd)
        user_agents = os.path.join(home, ".cursor", "agents")
        project_agents = os.path.join(cwd, ".cursor", "agents")
        os.makedirs(user_agents, exist_ok=True)
        os.makedirs(project_agents, exist_ok=True)
        with open(os.path.join(user_agents, "global-reviewer.md"), "w", encoding="utf-8") as handle:
            handle.write("---\nname: global-reviewer\n---\n")
        with open(os.path.join(project_agents, "unselected.md"), "w", encoding="utf-8") as handle:
            handle.write("---\nname: unselected\n---\n")

        with patch.dict(
            os.environ,
            {"HOME": home, "USERPROFILE": home},
            clear=False,
        ), patch("os.getcwd", return_value=cwd):
            agents = _agents_for_connector("cursor", cfg)

        self.assertEqual({row["id"] for row in agents}, {"global-reviewer"})

    def test_claudecode_legacy_command_markdown_is_inventory_skill(self):
        cfg = _make_cfg_for_connector(self.tmp, "claudecode")
        commands = os.path.join(self.tmp, ".claude", "commands")
        os.makedirs(commands, exist_ok=True)
        command = os.path.join(commands, "deploy.md")
        with open(command, "w", encoding="utf-8") as handle:
            handle.write("# Deploy safely\n")
        with self._patch_skill_dirs([commands]), \
             self._patch_plugin_dirs([]), \
             self._patch_mcp([]):
            inv = build_claw_aibom(cfg, live=True)

        row = next(entry for entry in inv["skills"] if entry["id"] == "deploy")
        self.assertEqual(row["path"], command)
        self.assertTrue(row["eligible"])

    def test_claudecode_preserves_directory_qualified_nested_skill_variant(self):
        cfg = _make_cfg_for_connector(self.tmp, "claudecode")
        workspace = os.path.join(self.tmp, "repo")
        root_skills = os.path.join(workspace, ".claude", "skills")
        nested_skills = os.path.join(
            workspace,
            "apps",
            "web",
            ".claude",
            "skills",
        )
        _seed_skill(root_skills, "deploy")
        _seed_skill(nested_skills, "deploy")
        cfg.claw.workspace_dir = workspace
        with self._patch_skill_dirs([root_skills, nested_skills]), \
             self._patch_plugin_dirs([]), \
             self._patch_mcp([]):
            inv = build_claw_aibom(cfg, live=True)

        assert {entry["id"] for entry in inv["skills"]} == {
            "deploy",
            "apps/web:deploy",
        }
        root_row = next(entry for entry in inv["skills"] if entry["id"] == "deploy")
        nested_row = next(entry for entry in inv["skills"] if entry["id"] == "apps/web:deploy")
        assert root_row["enabled"] is True
        assert root_row["activation_verified"] is True
        assert nested_row["enabled"] is False
        assert nested_row["activation_verified"] is False
        assert nested_row["activation_state"] == "discoverable-unverified"

    def test_claudecode_skill_overrides_same_name_legacy_command(self):
        cfg = _make_cfg_for_connector(self.tmp, "claudecode")
        project_skills = os.path.join(self.tmp, "repo", ".claude", "skills")
        user_commands = os.path.join(self.tmp, ".claude", "commands")
        skill = _seed_skill(project_skills, "deploy")
        os.makedirs(user_commands, exist_ok=True)
        command = os.path.join(user_commands, "deploy.md")
        with open(command, "w", encoding="utf-8") as handle:
            handle.write("# Legacy deploy\n")

        with self._patch_skill_dirs([project_skills, user_commands]), \
             self._patch_plugin_dirs([]), \
             self._patch_mcp([]):
            inv = build_claw_aibom(cfg, live=True)

        rows = [entry for entry in inv["skills"] if entry["id"] == "deploy"]
        assert len(rows) == 1
        assert rows[0]["path"] == skill

    def test_claudecode_ancestor_and_nested_skills_plugins_are_inventory_plugins(self):
        cfg = _make_cfg_for_connector(self.tmp, "claudecode")
        repository = os.path.join(self.tmp, "repo")
        launch = os.path.join(repository, "apps", "web")
        roots = [
            os.path.join(repository, ".claude", "skills"),
            os.path.join(launch, "packages", "ui", ".claude", "skills"),
        ]
        for root, folder, identity in (
            (roots[0], "root-tools", "root-tools"),
            (roots[1], "ui-tools", "ui-tools"),
        ):
            manifest = os.path.join(root, folder, ".claude-plugin", "plugin.json")
            os.makedirs(os.path.dirname(manifest), exist_ok=True)
            with open(manifest, "w", encoding="utf-8") as handle:
                json.dump({"name": identity, "defaultEnabled": True}, handle)
        cfg.claw.workspace_dir = launch

        with self._patch_skill_dirs([]), \
             self._patch_plugin_dirs(roots), \
             self._patch_mcp([]):
            inv = build_claw_aibom(cfg, live=True)

        assert {entry["id"] for entry in inv["plugins"]} == {
            "root-tools@skills-dir",
            "ui-tools@skills-dir",
        }

    def test_claudecode_duplicate_skills_plugin_identity_is_ambiguous(self):
        cfg = _make_cfg_for_connector(self.tmp, "claudecode")
        repository = os.path.join(self.tmp, "repo")
        roots = [
            os.path.join(repository, ".claude", "skills"),
            os.path.join(repository, "apps", "web", ".claude", "skills"),
        ]
        for index, root in enumerate(roots):
            manifest = os.path.join(root, f"folder-{index}", ".claude-plugin", "plugin.json")
            os.makedirs(os.path.dirname(manifest), exist_ok=True)
            with open(manifest, "w", encoding="utf-8") as handle:
                json.dump({"name": "duplicate", "defaultEnabled": True}, handle)

        with self._patch_skill_dirs([]), \
             self._patch_plugin_dirs(roots), \
             self._patch_mcp([]):
            inv = build_claw_aibom(cfg, live=True)

        assert inv["plugins"] == []
        assert any("ambiguous plugin identity" in error["error"] for error in inv["errors"])

    def test_zeptoclaw_walks_disk(self):
        cfg = _make_cfg_for_connector(self.tmp, "zeptoclaw")
        skill_root = os.path.join(self.tmp, ".zeptoclaw", "skills")
        os.makedirs(skill_root, exist_ok=True)
        _seed_skill(skill_root, "alpha", marker="skill.json", body="{}")
        with self._patch_skill_dirs([skill_root]), \
             self._patch_plugin_dirs([]), \
             self._patch_mcp([]):
            inv = build_claw_aibom(cfg, live=True)
        self.assertEqual(inv["connector"], "zeptoclaw")
        self.assertEqual(len(inv["skills"]), 1)
        self.assertEqual(inv["skills"][0]["id"], "alpha")

    def test_copilot_agents_use_pinned_workspace_and_documented_ancestors(self):
        from defenseclaw.inventory.claw_inventory import _agents_for_connector

        cfg = _make_cfg_for_connector(self.tmp, "copilot")
        home = os.path.join(self.tmp, "home")
        copilot_home = os.path.join(home, "copilot")
        repo = os.path.join(self.tmp, "repo")
        package = os.path.join(repo, "packages", "service")
        os.makedirs(os.path.join(repo, ".git"), exist_ok=True)
        os.makedirs(package, exist_ok=True)
        cfg.claw.workspace_dir = package
        for root, name in (
            (os.path.join(package, ".claude", "agents"), "package-agent"),
            (os.path.join(repo, ".github", "agents"), "repo-agent"),
            (os.path.join(copilot_home, "agents"), "user-agent"),
        ):
            os.makedirs(root, exist_ok=True)
            with open(os.path.join(root, name + ".md"), "w", encoding="utf-8") as stream:
                stream.write(f"---\nname: {name}\n---\n")
        package_agents = os.path.join(package, ".github", "agents")
        repo_agents = os.path.join(repo, ".github", "agents")
        os.makedirs(package_agents, exist_ok=True)
        with open(
            os.path.join(package_agents, "reviewer.agent.md"),
            "w",
            encoding="utf-8",
        ) as stream:
            stream.write("---\ndescription: package reviewer\n---\n")
        with open(
            os.path.join(repo_agents, "reviewer.md"),
            "w",
            encoding="utf-8",
        ) as stream:
            stream.write("---\ndescription: lower-priority reviewer\n---\n")
        with open(
            os.path.join(package_agents, "ignored.json"),
            "w",
            encoding="utf-8",
        ) as stream:
            stream.write("{}")
        with open(
            os.path.join(package_agents, "code-review.md"),
            "w",
            encoding="utf-8",
        ) as stream:
            stream.write("---\ndescription: cannot shadow the built-in\n---\n")

        with patch.dict(
            os.environ,
            {"HOME": home, "USERPROFILE": home, "COPILOT_HOME": copilot_home},
            clear=False,
        ):
            rows = _agents_for_connector("copilot", cfg)

        self.assertEqual(
            {row["id"] for row in rows},
            {
                "code-review",
                "explore",
                "general-purpose",
                "research",
                "rubber-duck",
                "security-review",
                "task",
                "package-agent",
                "repo-agent",
                "user-agent",
                "reviewer",
            },
        )
        reviewer = [row for row in rows if row["id"] == "reviewer"]
        self.assertEqual(len(reviewer), 1)
        self.assertEqual(
            reviewer[0]["source"],
            os.path.join(package_agents, "reviewer.agent.md"),
        )
        self.assertFalse(any(row["id"] == "ignored" for row in rows))
        code_review = [row for row in rows if row["id"] == "code-review"]
        self.assertEqual(len(code_review), 1)
        self.assertEqual(code_review[0]["kind"], "built-in-agent")
        self.assertTrue(code_review[0]["immutable"])

        with patch.dict(
            os.environ,
            {"HOME": home, "USERPROFILE": home, "COPILOT_HOME": copilot_home},
            clear=False,
        ):
            inventory = build_claw_aibom(
                cfg,
                live=True,
                categories={"agents", "skills", "mcp"},
            )
        limitations = {row["category"]: row["reason"] for row in inventory["limitations"]}
        self.assertIn("plugin-contributed agents", limitations["agents"])
        self.assertIn("built-in agent set", limitations["agents"])
        self.assertIn("cannot be shadowed", limitations["agents"])
        self.assertIn("organization/enterprise", limitations["agents"])
        self.assertIn("folder trust", limitations["mcp"])
        self.assertIn("organization/remote skills", limitations["skills"])
        self.assertEqual(
            inventory["connector_mcp_files"],
            [
                os.path.join(package, ".mcp.json"),
                os.path.join(package, ".github", "mcp.json"),
                os.path.join(os.path.dirname(package), ".mcp.json"),
                os.path.join(os.path.dirname(package), ".github", "mcp.json"),
                os.path.join(repo, ".mcp.json"),
                os.path.join(repo, ".github", "mcp.json"),
                os.path.join(copilot_home, "mcp-config.json"),
            ],
        )
        self.assertFalse(
            any(
                os.path.basename(path) in {"config.json", "defenseclaw.json"}
                for path in inventory["connector_mcp_files"]
            )
        )

    def test_opencode_catalog_limits_unproven_asset_surfaces(self):
        cfg = _make_cfg_for_connector(self.tmp, "opencode")
        home = self.tmp
        root = os.path.join(home, ".config", "opencode")
        custom = os.path.join(home, "custom-opencode")
        _seed_skill(os.path.join(root, "skills"), "oc-skill")
        plugin_dir = os.path.join(root, "plugins")
        os.makedirs(plugin_dir, exist_ok=True)
        with open(os.path.join(plugin_dir, "oc-plugin.ts"), "w", encoding="utf-8") as f:
            f.write("export const OCPlugin = async () => ({})\n")
        tool_dir = os.path.join(root, "tools")
        os.makedirs(tool_dir, exist_ok=True)
        with open(os.path.join(tool_dir, "file-tool.ts"), "w", encoding="utf-8") as f:
            f.write("export default {}\n")
        command_dir = os.path.join(root, "commands")
        os.makedirs(command_dir, exist_ok=True)
        with open(os.path.join(command_dir, "review.md"), "w", encoding="utf-8") as f:
            f.write("---\ndescription: Review changes\n---\n")
        with open(os.path.join(root, "opencode.json"), "w", encoding="utf-8") as f:
            json.dump(
                {
                    "tools": {"bash": False},
                    "agent": {"reviewer": {"description": "Reviews code", "model": "openai/gpt-5"}},
                    "plugin": ["npm-plugin@1.0.0"],
                },
                f,
            )
        os.makedirs(custom)
        with open(os.path.join(custom, "opencode.json"), "w", encoding="utf-8") as f:
            json.dump(
                {"mcp": {"proven-mcp": {"type": "local", "command": ["mcp-demo"]}}},
                f,
            )

        with patch.dict(
            os.environ,
            {
                "HOME": home,
                "USERPROFILE": home,
                "OPENCODE_CONFIG_DIR": custom,
            },
            clear=False,
        ):
            inv = build_claw_aibom(cfg, live=True)

        self.assertEqual(inv["connector"], "opencode")
        if os.name == "nt":
            self.assertNotIn("oc-skill", {row["id"] for row in inv["skills"]})
            self.assertNotIn("oc-plugin", {row["id"] for row in inv["plugins"]})
            self.assertNotIn("file-tool", {row["id"] for row in inv["tools"]})
            self.assertNotIn("review", {row["id"] for row in inv["tools"]})
        else:
            self.assertIn("oc-skill", {row["id"] for row in inv["skills"]})
            self.assertIn("oc-plugin", {row["id"] for row in inv["plugins"]})
            self.assertIn("file-tool", {row["id"] for row in inv["tools"]})
            self.assertIn("review", {row["id"] for row in inv["tools"]})
        self.assertIn("npm-plugin@1.0.0", {row["id"] for row in inv["plugins"]})
        self.assertNotIn("bash", {row["id"] for row in inv["tools"]})
        self.assertIn("reviewer", {row["id"] for row in inv["agents"]})
        self.assertNotIn("opencode:tools", {e["command"] for e in inv["errors"]})
        self.assertEqual([row["id"] for row in inv["mcp"]], ["proven-mcp"])

    def test_antigravity_catalog_surfaces_skills_plugins_and_commands(self):
        cfg = _make_cfg_for_connector(self.tmp, "antigravity")
        home = self.tmp
        _seed_skill(
            os.path.join(home, ".gemini", "antigravity-cli", "skills"),
            "agy-direct",
        )
        plugin_root = _seed_plugin(
            os.path.join(home, ".gemini", "config", "plugins"),
            "agy-plugin",
            manifest="plugin.json",
        )
        _seed_skill(os.path.join(plugin_root, "skills"), "agy-plugin-skill")
        command_dir = os.path.join(plugin_root, "commands")
        os.makedirs(command_dir, exist_ok=True)
        with open(os.path.join(command_dir, "triage.md"), "w", encoding="utf-8") as f:
            f.write("---\ndescription: Triage issues\n---\n")

        with patch.dict(
            os.environ,
            {"HOME": home, "USERPROFILE": home},
            clear=False,
        ):
            inv = build_claw_aibom(cfg, live=True)

        self.assertEqual(inv["connector"], "antigravity")
        self.assertIn("agy-direct", {row["id"] for row in inv["skills"]})
        self.assertIn("agy-plugin-skill", {row["id"] for row in inv["skills"]})
        self.assertIn("agy-plugin", {row["id"] for row in inv["plugins"]})
        self.assertIn("triage", {row["id"] for row in inv["tools"]})
        self.assertNotIn("antigravity:tools", {e["command"] for e in inv["errors"]})

    def test_codex_expected_limitations_are_not_errors(self):
        cfg = _make_cfg_for_connector(self.tmp, "codex")
        with self._patch_skill_dirs([]), \
             self._patch_plugin_dirs([]), \
             self._patch_mcp([]), \
             patch("defenseclaw.inventory.claw_inventory._agents_for_connector", return_value=[]), \
             patch("defenseclaw.inventory.claw_inventory._tools_for_connector", return_value=[]), \
             patch("defenseclaw.inventory.claw_inventory._model_providers_for_connector", return_value=[]), \
             patch("defenseclaw.inventory.claw_inventory._memory_for_connector", return_value=[]):
            inv = build_claw_aibom(cfg, live=True)
        self.assertEqual(inv["agents"], [])
        self.assertEqual(inv["tools"], [])
        self.assertEqual(inv["model_providers"], [])
        self.assertEqual(inv["memory"], [])
        self.assertEqual(inv["errors"], [])
        self.assertEqual(inv["summary"]["errors"], 0)
        self.assertEqual(inv["summary"]["limitations"], 3)
        self.assertEqual(
            {item["category"] for item in inv["limitations"]},
            {"tools", "models", "memory"},
        )
        self.assertTrue(all(item["connector"] == "codex" for item in inv["limitations"]))
        self.assertTrue(all(item["status"] == "unsupported" for item in inv["limitations"]))

    def test_claudecode_expected_limitations_are_not_errors(self):
        cfg = _make_cfg_for_connector(self.tmp, "claudecode")
        with self._patch_skill_dirs([]), \
             self._patch_plugin_dirs([]), \
             self._patch_mcp([]), \
             patch("defenseclaw.inventory.claw_inventory._agents_for_connector", return_value=[]), \
             patch("defenseclaw.inventory.claw_inventory._tools_for_connector", return_value=[]), \
             patch("defenseclaw.inventory.claw_inventory._model_providers_for_connector", return_value=[]), \
             patch("defenseclaw.inventory.claw_inventory._memory_for_connector", return_value=[]):
            inv = build_claw_aibom(cfg, live=True)

        self.assertEqual(inv["errors"], [])
        self.assertEqual(len(inv["limitations"]), 4)
        self.assertTrue(all(item["connector"] == "claudecode" for item in inv["limitations"]))

    def test_real_collection_failure_stays_separate_from_limitations(self):
        cfg = _make_cfg_for_connector(self.tmp, "codex")
        with patch(
            "defenseclaw.inventory.claw_inventory._enumerate_skills_filesystem",
            side_effect=PermissionError("skills directory denied"),
        ), self._patch_plugin_dirs([]), self._patch_mcp([]), \
             patch("defenseclaw.inventory.claw_inventory._agents_for_connector", return_value=[]), \
             patch("defenseclaw.inventory.claw_inventory._tools_for_connector", return_value=[]), \
             patch("defenseclaw.inventory.claw_inventory._model_providers_for_connector", return_value=[]), \
             patch("defenseclaw.inventory.claw_inventory._memory_for_connector", return_value=[]):
            inv = build_claw_aibom(cfg, live=True)

        self.assertEqual(len(inv["errors"]), 1)
        self.assertEqual(inv["errors"][0]["command"], "codex:skills")
        self.assertIn("denied", inv["errors"][0]["error"])
        self.assertEqual(len(inv["limitations"]), 3)
        self.assertEqual(inv["summary"]["errors"], 1)
        self.assertEqual(inv["summary"]["limitations"], 3)

    def test_skill_eligibility_requires_marker(self):
        cfg = _make_cfg_for_connector(self.tmp, "codex")
        skill_root = os.path.join(self.tmp, "skills")
        os.makedirs(skill_root, exist_ok=True)
        empty_dir = os.path.join(skill_root, "empty")
        os.makedirs(empty_dir, exist_ok=True)
        _seed_skill(skill_root, "marked")
        with self._patch_skill_dirs([skill_root]), \
             self._patch_plugin_dirs([]), \
             self._patch_mcp([]):
            inv = build_claw_aibom(cfg, live=True)
        by_id = {s["id"]: s for s in inv["skills"]}
        self.assertTrue(by_id["marked"]["eligible"])
        self.assertFalse(by_id["empty"]["eligible"])

    def test_openhands_installed_container_is_not_a_skill(self):
        cfg = _make_cfg_for_connector(self.tmp, "openhands")
        openhands_skills = os.path.join(self.tmp, ".openhands", "skills")
        installed = os.path.join(openhands_skills, "installed")
        os.makedirs(installed, exist_ok=True)
        _seed_skill(installed, "real-installed")

        with self._patch_skill_dirs([openhands_skills, installed]), \
             self._patch_plugin_dirs([]), \
             self._patch_mcp([]):
            inv = build_claw_aibom(cfg, live=True)

        self.assertEqual([s["id"] for s in inv["skills"]], ["real-installed"])

    def test_skill_description_extracted_from_skill_md(self):
        cfg = _make_cfg_for_connector(self.tmp, "codex")
        skill_root = os.path.join(self.tmp, "skills")
        os.makedirs(skill_root, exist_ok=True)
        _seed_skill(
            skill_root,
            "described",
            body="# Skill Title\n\nA helpful skill that does X.\n",
        )
        with self._patch_skill_dirs([skill_root]), \
             self._patch_plugin_dirs([]), \
             self._patch_mcp([]):
            inv = build_claw_aibom(cfg, live=True)
        self.assertEqual(inv["skills"][0]["description"], "Skill Title")

    def test_skill_description_prefers_frontmatter(self):
        cfg = _make_cfg_for_connector(self.tmp, "openhands")
        skill_root = os.path.join(self.tmp, "skills")
        os.makedirs(skill_root, exist_ok=True)
        _seed_skill(
            skill_root,
            "frontmatter",
            body="---\nname: frontmatter\ndescription: Frontmatter description\n---\n\n# Fallback\n",
        )
        with self._patch_skill_dirs([skill_root]), \
             self._patch_plugin_dirs([]), \
             self._patch_mcp([]):
            inv = build_claw_aibom(cfg, live=True)
        self.assertEqual(inv["skills"][0]["description"], "Frontmatter description")

    def test_skill_description_rejects_linked_skill_ancestry(self):
        outside = Path(self.tmp) / "outside"
        outside.mkdir()
        secret = "outside-secret-must-not-be-disclosed"
        (outside / "SKILL.md").write_text(
            f"---\ndescription: {secret}\n---\n",
            encoding="utf-8",
        )
        linked = Path(self.tmp) / "linked-skill"
        try:
            linked.symlink_to(outside, target_is_directory=True)
        except OSError as exc:
            self.skipTest(f"filesystem does not permit test symlinks: {exc}")

        self.assertEqual(_read_skill_description(str(linked)), "")

    def test_plugin_status_no_manifest(self):
        cfg = _make_cfg_for_connector(self.tmp, "codex")
        plugin_root = os.path.join(self.tmp, "plugins")
        os.makedirs(plugin_root, exist_ok=True)
        _seed_plugin(plugin_root, "no-mf", manifest=None)
        _seed_plugin(plugin_root, "with-mf", manifest="plugin.json")
        with self._patch_skill_dirs([]), \
             self._patch_plugin_dirs([plugin_root]), \
             self._patch_mcp([]):
            inv = build_claw_aibom(cfg, live=True)
        by_id = {p["id"]: p for p in inv["plugins"]}
        self.assertEqual(by_id["no-mf"]["status"], "no-manifest")
        self.assertEqual(by_id["with-mf"]["status"], "loaded")

    def test_plugin_cache_dir_is_skipped(self):
        """The "cache" sibling under Codex/ZeptoClaw is not a plugin."""
        cfg = _make_cfg_for_connector(self.tmp, "codex")
        plugin_root = os.path.join(self.tmp, "plugins")
        os.makedirs(plugin_root, exist_ok=True)
        _seed_plugin(plugin_root, "cache", manifest=None)
        _seed_plugin(plugin_root, "real", manifest="plugin.json")
        with self._patch_skill_dirs([]), \
             self._patch_plugin_dirs([plugin_root]), \
             self._patch_mcp([]):
            inv = build_claw_aibom(cfg, live=True)
        ids = [p["id"] for p in inv["plugins"]]
        self.assertEqual(ids, ["real"])

    def test_codex_cache_inventory_uses_manifest_roots_and_active_metadata(self):
        cfg = _make_cfg_for_connector(self.tmp, "codex")
        codex_home = os.path.join(self.tmp, ".codex")
        plugin_root = os.path.join(codex_home, "plugins")
        cache = os.path.join(plugin_root, "cache")
        _seed_plugin(plugin_root, "clean-plugin", manifest="plugin.json")

        browser = seed_cached_plugin(
            cache, "openai-bundled", "browser", "2.0.0"
        )
        sites = seed_cached_plugin(
            cache, "openai-bundled", "sites", "1.2.0"
        )
        seed_cached_plugin(cache, "openai-curated-remote", "sites", "9.0.0")
        github = seed_cached_plugin(
            cache, "openai-curated-remote", "github", "0.2.0"
        )
        os.makedirs(codex_home, exist_ok=True)
        with open(
            os.path.join(codex_home, "config.toml"),
            "w",
            encoding="utf-8",
        ) as handle:
            handle.write(
                "[plugins.'browser@openai-bundled']\n"
                "enabled = true\n"
                "[plugins.'sites@openai-bundled']\n"
                "enabled = true\n"
            )

        with self._patch_skill_dirs([]), \
             self._patch_plugin_dirs([plugin_root, cache]), \
             self._patch_mcp([]):
            inv = build_claw_aibom(cfg, live=True)

        by_id = {plugin["id"]: plugin for plugin in inv["plugins"]}
        self.assertEqual(set(by_id), {"clean-plugin", "browser", "github", "sites"})
        self.assertNotIn("openai-bundled", by_id)
        self.assertNotIn("openai-curated-remote", by_id)
        self.assertEqual(by_id["browser"]["path"], browser)
        self.assertTrue(by_id["browser"]["enabled"])
        self.assertEqual(by_id["sites"]["path"], sites)
        self.assertTrue(by_id["sites"]["enabled"])
        self.assertEqual(by_id["github"]["path"], github)
        self.assertFalse(by_id["github"]["enabled"])
        self.assertEqual(inv["summary"]["plugins"]["count"], 4)
        self.assertEqual(inv["summary"]["plugins"]["disabled"], 1)

    def test_hidden_and_staging_plugin_dirs_are_skipped(self):
        """Hidden activation state must not surface as enabled plugins."""
        cfg = _make_cfg_for_connector(self.tmp, "codex")
        plugin_root = os.path.join(self.tmp, "plugins")
        os.makedirs(plugin_root, exist_ok=True)
        _seed_plugin(plugin_root, ".plugin-appserver", manifest="plugin.json")
        _seed_plugin(
            plugin_root,
            "..plugin-appserver.staging-123",
            manifest="plugin.json",
        )
        _seed_plugin(plugin_root, "real", manifest="plugin.json")
        with self._patch_skill_dirs([]), \
             self._patch_plugin_dirs([plugin_root]), \
             self._patch_mcp([]):
            inv = build_claw_aibom(cfg, live=True)
        self.assertEqual([p["id"] for p in inv["plugins"]], ["real"])

    def test_mcp_servers_passed_through(self):
        from defenseclaw.connector_paths import MCPServerEntry
        cfg = _make_cfg_for_connector(self.tmp, "codex")
        entries = [
            MCPServerEntry(
                name="filesystem",
                command="/usr/bin/mcp-fs",
                args=["--root", "/tmp"],
                env={"X_TOKEN": "redacted"},
            ),
            MCPServerEntry(name="http", url="https://example.com", transport="sse"),
        ]
        with self._patch_skill_dirs([]), \
             self._patch_plugin_dirs([]), \
             self._patch_mcp(entries):
            inv = build_claw_aibom(cfg, live=True)
        self.assertEqual(len(inv["mcp"]), 2)
        first = inv["mcp"][0]
        self.assertEqual(first["id"], "filesystem")
        self.assertEqual(first["command"], "/usr/bin/mcp-fs")
        self.assertEqual(first["args"], ["--root", "/tmp"])
        # env values must be redacted from the inventory snapshot —
        # only env_keys leak the *names* of env vars, never their values.
        self.assertNotIn("env", first)
        self.assertEqual(first["env_keys"], ["X_TOKEN"])
        second = inv["mcp"][1]
        self.assertEqual(second["url"], "https://example.com")
        self.assertEqual(second["transport"], "sse")

    def test_summary_total_matches_arrays_for_codex(self):
        cfg = _make_cfg_for_connector(self.tmp, "codex")
        skill_root = os.path.join(self.tmp, "skills")
        os.makedirs(skill_root, exist_ok=True)
        _seed_skill(skill_root, "a")
        _seed_skill(skill_root, "b")
        with self._patch_skill_dirs([skill_root]), \
             self._patch_plugin_dirs([]), \
             self._patch_mcp([]):
            inv = build_claw_aibom(cfg, live=True)
        self.assertEqual(inv["summary"]["total_items"], 2)
        self.assertEqual(inv["summary"]["skills"]["count"], 2)
        self.assertEqual(inv["summary"]["plugins"]["count"], 0)

    def test_categories_filter_skills_only_skips_others(self):
        cfg = _make_cfg_for_connector(self.tmp, "codex")
        skill_root = os.path.join(self.tmp, "skills")
        os.makedirs(skill_root, exist_ok=True)
        _seed_skill(skill_root, "a")
        plugin_root = os.path.join(self.tmp, "plugins")
        os.makedirs(plugin_root, exist_ok=True)
        _seed_plugin(plugin_root, "p1", manifest="plugin.json")
        with self._patch_skill_dirs([skill_root]), \
             self._patch_plugin_dirs([plugin_root]), \
             self._patch_mcp([]):
            inv = build_claw_aibom(cfg, live=True, categories={"skills"})
        self.assertEqual(len(inv["skills"]), 1)
        self.assertEqual(inv["plugins"], [])

    def test_live_false_returns_disk_shape(self):
        """``live=False`` keeps the legacy "no subprocess, no walk" path."""
        cfg = _make_cfg_for_connector(self.tmp, "codex")
        with patch("defenseclaw.inventory.claw_inventory.subprocess.run") as mock_sub:
            inv = build_claw_aibom(cfg, live=False)
            mock_sub.assert_not_called()
        # connector annotated even on the legacy path
        self.assertIn("connector", inv)
        self.assertEqual(inv["connector"], "codex")
        self.assertFalse(inv["live"])
        self.assertEqual(inv["skills"], [])
        self.assertEqual(inv["plugins"], [])

    def test_openclaw_default_unchanged(self):
        """Default connector "openclaw" must keep using subprocess."""
        cfg = _make_cfg_for_connector(self.tmp, "openclaw")
        with patch(
            "defenseclaw.inventory.claw_inventory.subprocess.run",
            side_effect=FileNotFoundError,
        ) as mock_sub:
            inv = build_claw_aibom(cfg, live=True)
            self.assertGreater(mock_sub.call_count, 0)
        self.assertEqual(inv["connector"], "openclaw")
        self.assertEqual(inv["connector_config"], inv["openclaw_config"])


class TestBuildAibomConnectorPathSkippedForOpenClaw(unittest.TestCase):
    """Ensure we keep dispatching via subprocess for OpenClaw."""

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="dc-claw-fs-oc-")
        self.cfg = _make_cfg(self.tmp)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    @patch("defenseclaw.inventory.claw_inventory.subprocess.run", side_effect=_mock_run)
    def test_openclaw_inventory_has_connector_field(self, _):
        inv = build_claw_aibom(self.cfg, live=True)
        self.assertEqual(inv["connector"], "openclaw")
        # The full set of legacy fields must still be populated.
        self.assertGreater(len(inv["skills"]), 0)
        self.assertGreater(len(inv["plugins"]), 0)


if __name__ == "__main__":
    unittest.main()
