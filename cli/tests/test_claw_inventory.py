"""Tests for OpenClaw AIBOM live inventory (defenseclaw aibom scan).

Covers: full build, category filter, summary, error reporting, partial
failure, timeout, human output modes, and CLI integration.
"""

from __future__ import annotations

import io
import json
import os
import subprocess
import tempfile
import shutil
import unittest
from unittest.mock import patch, MagicMock

from click.testing import CliRunner

from defenseclaw.config import ClawConfig, Config
from defenseclaw.inventory.claw_inventory import (
    ALL_CATEGORIES,
    _CmdResult,
    _build_summary,
    _fetch_all,
    _parse_skills,
    _parse_plugins,
    _parse_mcp,
    _parse_tools,
    _resolve_categories,
    _run_openclaw,
    build_claw_aibom,
    claw_aibom_to_scan_result,
    format_claw_aibom_human,
)


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
    def test_version_bumped_to_3(self, _):
        inv = build_claw_aibom(self.cfg, live=True)
        self.assertEqual(inv["version"], 3)

    @patch("defenseclaw.inventory.claw_inventory.subprocess.run", side_effect=_mock_run)
    def test_scan_result_has_seven_findings(self, _):
        inv = build_claw_aibom(self.cfg, live=True)
        result = claw_aibom_to_scan_result(inv, self.cfg)
        self.assertEqual(result.scanner, "aibom-claw")
        self.assertEqual(len(result.findings), 7)
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
        self.assertEqual(summary["tools"]["count"], len(inv["tools"]))
        self.assertEqual(summary["model_providers"]["count"], len(inv["model_providers"]))
        self.assertEqual(summary["memory"]["count"], len(inv["memory"]))

    @patch("defenseclaw.inventory.claw_inventory.subprocess.run", side_effect=_mock_run)
    def test_summary_total_is_sum(self, _):
        inv = build_claw_aibom(self.cfg, live=True)
        summary = inv["summary"]
        manual_total = sum(
            summary[c]["count"]
            for c in ("skills", "plugins", "mcp", "agents", "tools", "model_providers", "memory")
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
            "plugins": [{"enabled": True}, {"enabled": False}],
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
        self.assertIn("Warning", result.stderr)
        self.assertIn("failed", result.stderr)


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


if __name__ == "__main__":
    unittest.main()
