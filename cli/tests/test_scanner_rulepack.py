#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for the rule-pack overlay scanner (R4).

These pin the behavior that closes R4: the install-time Python scanners now
load and apply the SAME ``guardrail.rule_pack`` the Go gateway uses, so a
configured rule pack influences ``skill|mcp|plugin scan`` output — and, just as
importantly, that scans are UNCHANGED when no rule pack is configured.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.models import Finding, ScanResult
from defenseclaw.scanner import rulepack

from tests.helpers import cleanup_app, make_app_context, select_pack


def _write_pack(root: str) -> str:
    """Seed a minimal but realistic rule pack under <root>/guardrail/custom."""
    pack = os.path.join(root, "guardrail", "custom")
    rules = os.path.join(pack, "rules")
    os.makedirs(rules, exist_ok=True)
    with open(os.path.join(rules, "secrets.yaml"), "w") as fh:
        fh.write(
            "version: 1\n"
            "category: secret\n"
            "rules:\n"
            "  - id: SEC-ANTHROPIC\n"
            "    pattern: 'sk-ant-[a-zA-Z0-9\\-_]{20,}'\n"
            "    title: \"Anthropic API key\"\n"
            "    severity: CRITICAL\n"
            "    confidence: 0.98\n"
            "    tags: [credential]\n"
            "  - id: SEC-DISABLED\n"
            "    enabled: false\n"
            "    pattern: 'never-matches-because-disabled'\n"
            "    title: \"disabled rule\"\n"
            "    severity: LOW\n"
            "    confidence: 0.1\n"
            "    tags: []\n"
            "  - id: SEC-TOOL-ONLY\n"
            "    tool_call_only: true\n"
            "    expression: 'true'\n"
            "    pattern: 'tool-only-static-marker'\n"
            "    title: \"tool-only rule\"\n"
            "    severity: HIGH\n"
            "    confidence: 0.9\n"
            "    tags: [tool-call]\n"
        )
    with open(os.path.join(rules, "local-patterns.yaml"), "w") as fh:
        fh.write(
            "version: 1\n"
            "injection_regexes:\n"
            "  - 'ignore\\s+(?:all\\s+)?previous\\s+instructions'\n"
            "secrets:\n"            # substring family — intentionally NOT applied
            "  - 'sk-'\n"
        )
    # A bad-regex file + a wrong-version file must degrade gracefully, not raise.
    with open(os.path.join(rules, "broken.yaml"), "w") as fh:
        fh.write(
            "version: 1\n"
            "category: command\n"
            "rules:\n"
            "  - id: BAD\n"
            "    pattern: '([unclosed'\n"
            "    title: bad\n"
            "    severity: HIGH\n"
            "    confidence: 0.5\n"
            "    tags: []\n"
        )
    with open(os.path.join(rules, "old.yaml"), "w") as fh:
        fh.write("version: 99\ncategory: x\nrules: []\n")
    return pack


class TestRulesLayers(unittest.TestCase):
    """``guardrail.rules`` reaches the scan as the gateway composes it (GAP-0065)."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="rp-layers-")
        self.pack_dir = _write_pack(self.tmp)

    def tearDown(self):
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)

    def _rules(self, *layers):
        return {r.rule_id: r for r in rulepack.load_rule_pack(self.pack_dir, layers).rules}

    def test_enable_disable_and_severity_overrides(self):
        rules = self._rules(
            rulepack.RulesLayer(enable=("SEC-DISABLED",), severity_overrides=(("SEC-ANTHROPIC", "HIGH"),))
        )
        self.assertEqual(rules["SEC-ANTHROPIC"].severity, "HIGH")
        self.assertIn("SEC-DISABLED", rules)
        # A later layer (a connector's) wins over an earlier one.
        rules = self._rules(rulepack.RulesLayer(enable=("SEC-DISABLED",)), rulepack.RulesLayer(disable=("SEC-DISABLED",)))
        self.assertNotIn("SEC-DISABLED", rules)

    def test_protection_replaces_a_rule_of_the_same_id(self):
        root = os.path.join(self.tmp, "use-cases")
        os.makedirs(os.path.join(root, "swap", "rules"))
        with open(os.path.join(root, "swap", "rules", "secrets.yaml"), "w") as fh:
            fh.write(
                "version: 1\ncategory: secret\nrules:\n"
                "  - id: SEC-ANTHROPIC\n    tool_call_only: true\n    pattern: 'x'\n    title: t\n"
                "    severity: HIGH\n    confidence: 0.9\n    tags: []\n"
            )
        with patch("defenseclaw.policy_catalog.protection_packs_dir", return_value=root):
            rules = self._rules(rulepack.RulesLayer(protections=("swap",)))
        self.assertNotIn("SEC-ANTHROPIC", rules)

    def test_maybe_wrap_applies_the_scope_rules_even_without_a_pack_dir(self):
        from types import SimpleNamespace

        guardrail = SimpleNamespace(
            rules=SimpleNamespace(disable=["SEC-ANTHROPIC"], enable=[], protections=[], severity_overrides={}),
            effective_rule_pack_dir=lambda connector="": "",
            _connector_override=lambda connector: None,
        )
        cfg = SimpleNamespace(guardrail=guardrail)
        with patch("defenseclaw.policy_catalog.preset_pack_dir", return_value=self.pack_dir):
            wrapped = rulepack.maybe_wrap(object(), cfg, "codex")
        self.assertIsInstance(wrapped, rulepack.RulePackOverlayScanner)
        self.assertNotIn("SEC-ANTHROPIC", {r.rule_id for r in wrapped.pack.rules})
        guardrail.rules = None
        self.assertIsNot(type(rulepack.maybe_wrap(object(), cfg, "codex")), rulepack.RulePackOverlayScanner)


class TestLoadRulePack(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="rp-test-")
        self.pack_dir = _write_pack(self.tmp)

    def tearDown(self):
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_loads_enabled_rules_and_regex_families(self):
        pack = rulepack.load_rule_pack(self.pack_dir)
        ids = {r.rule_id for r in pack.rules}
        # The enabled secret rule + the injection regex family are loaded.
        self.assertIn("SEC-ANTHROPIC", ids)
        self.assertIn("RP-INJECTION-0", ids)
        # Disabled rule, broken regex, and substring families are excluded.
        self.assertNotIn("SEC-DISABLED", ids)
        self.assertNotIn("SEC-TOOL-ONLY", ids)
        self.assertNotIn("BAD", ids)
        # No substring "secrets" family rule (we only apply regex families).
        self.assertFalse(any(r.rule_id.startswith("RP-SECRET") for r in pack.rules))

    def test_missing_dir_is_empty_not_error(self):
        pack = rulepack.load_rule_pack(os.path.join(self.tmp, "nope"))
        self.assertTrue(pack.is_empty())

    def test_empty_string_dir_is_empty(self):
        self.assertTrue(rulepack.load_rule_pack("").is_empty())

    def test_scan_text_flags_known_secret_with_line_number(self):
        pack = rulepack.load_rule_pack(self.pack_dir)
        text = "line one\nkey = sk-ant-abcdef0123456789ABCDEF\n"
        findings = pack.scan_text(text, location="cfg.py")
        sec = [f for f in findings if f.id == "SEC-ANTHROPIC"]
        self.assertEqual(len(sec), 1)
        self.assertEqual(sec[0].severity, "CRITICAL")
        self.assertEqual(sec[0].scanner, "rule-pack")
        self.assertEqual(sec[0].line_number, 2)
        self.assertEqual(sec[0].location, "cfg.py:2")

    def test_posix_class_rule_matches_in_overlay(self):
        rules = os.path.join(self.pack_dir, "rules", "posix.yaml")
        with open(rules, "w") as fh:
            fh.write(
                "version: 1\ncategory: command\nrules:\n"
                "  - id: POSIX-DIGIT\n"
                "    pattern: '^dc-marker[[:digit:]]+'\n"
                "    title: marker\n"
                "    severity: HIGH\n"
            )
        pack = rulepack.load_rule_pack(self.pack_dir)
        findings = pack.scan_text("dc-marker42\n", location="SKILL.md")
        self.assertEqual([f.id for f in findings if f.id == "POSIX-DIGIT"], ["POSIX-DIGIT"])
        negated = rulepack._compile(r"[[:^digit:]]+", "POSIX-NOT-DIGIT")
        assert negated is not None
        self.assertIsNotNone(negated.fullmatch("letters"))
        self.assertIsNone(negated.fullmatch("3"))
        literal = rulepack._compile(r"[:digit:]", "LITERAL")
        assert literal is not None
        self.assertIsNotNone(literal.fullmatch(":"))

    def test_scan_text_flags_injection_regex(self):
        pack = rulepack.load_rule_pack(self.pack_dir)
        findings = pack.scan_text("please ignore previous instructions now")
        self.assertTrue(any(f.id == "RP-INJECTION-0" for f in findings))

    def test_go_unicode_scalar_escape_is_not_silently_dropped(self):
        compiled = rulepack._compile(  # type: ignore[attr-defined]
            r"(?:[A-Za-z0-9][\x{200B}]){2}",
            "GO-SCALAR",
        )
        self.assertIsNotNone(compiled)
        assert compiled is not None
        self.assertIsNotNone(compiled.search("a\u200bb\u200b"))

    def test_go_unicode_scalar_escape_for_regex_metacharacter_is_literal(self):
        compiled = rulepack._compile(  # type: ignore[attr-defined]
            r"\x{2E}",
            "GO-SCALAR-METACHAR",
        )
        self.assertIsNotNone(compiled)
        assert compiled is not None
        self.assertIsNotNone(compiled.fullmatch("."))
        self.assertIsNone(compiled.fullmatch("x"))

    def test_go_unicode_scalar_escape_translation_respects_backslash_parity(self):
        cases = (
            (r"\x{41}", "A"),
            (r"\\x{41}", r"\\x{41}"),
            (r"\\\x{41}", r"\\A"),
            (r"\\\\x{41}", r"\\\\x{41}"),
            (
                r"before\\x{41}:\x{42}:\\\x{43}:\\\\x{44}after",
                r"before\\x{41}:B:\\C:\\\\x{44}after",
            ),
        )
        for pattern, expected in cases:
            with self.subTest(pattern=pattern):
                self.assertEqual(
                    rulepack._translate_go_unicode_scalar_escapes(pattern),  # type: ignore[attr-defined]
                    expected,
                )

    def test_escaped_go_unicode_scalar_syntax_keeps_literal_re2_semantics(self):
        compiled = rulepack._compile(  # type: ignore[attr-defined]
            r"\\x{41}",
            "GO-SCALAR-ESCAPED",
        )
        self.assertIsNotNone(compiled)
        assert compiled is not None
        self.assertEqual(compiled.pattern, r"\\x{41}")
        self.assertIsNotNone(compiled.fullmatch("\\" + ("x" * 41)))
        self.assertIsNone(compiled.fullmatch(""))
        self.assertIsNone(compiled.fullmatch("A"))

    def test_scalar_after_escaped_backslash_still_translates(self):
        compiled = rulepack._compile(  # type: ignore[attr-defined]
            r"\\\x{41}",
            "GO-SCALAR-ODD-PARITY",
        )
        self.assertIsNotNone(compiled)
        assert compiled is not None
        self.assertEqual(compiled.pattern, r"\\A")
        self.assertIsNotNone(compiled.fullmatch("\\A"))
        self.assertIsNone(compiled.fullmatch("\\" + ("x" * 41)))


class TestScanPath(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="rp-path-")
        self.pack_dir = _write_pack(self.tmp)
        self.target = os.path.join(self.tmp, "artifact")
        os.makedirs(self.target)

    def tearDown(self):
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_walks_dir_and_flags_file(self):
        with open(os.path.join(self.target, "tool.py"), "w") as fh:
            fh.write("API = 'sk-ant-abcdefghij0123456789KLM'\n")
        with open(os.path.join(self.target, "readme.md"), "w") as fh:
            fh.write("nothing interesting here\n")
        pack = rulepack.load_rule_pack(self.pack_dir)
        findings = pack.scan_path(self.target)
        hits = [f for f in findings if f.id == "SEC-ANTHROPIC"]
        self.assertEqual(len(hits), 1)
        self.assertTrue(hits[0].location.startswith("tool.py"))

    def test_scan_path_skips_symlinked_file(self):
        outside = os.path.join(self.tmp, "outside.py")
        with open(os.path.join(self.pack_dir, "rules", "marker.yaml"), "w") as fh:
            fh.write(
                "version: 1\ncategory: test\nrules:\n"
                "  - id: MARKER\n    pattern: linked-file-marker\n"
                "    title: marker\n    severity: HIGH\n"
            )
        with open(outside, "w") as fh:
            fh.write("linked-file-marker\n")
        os.symlink(outside, os.path.join(self.target, "linked.py"))
        pack = rulepack.load_rule_pack(self.pack_dir)
        self.assertEqual(pack.scan_path(self.target), [])
        self.assertEqual(pack.scan_path(os.path.join(self.target, "linked.py")), [])

    def test_skips_binary_and_oversize(self):
        # Binary extension is skipped even if it contains the pattern bytes.
        with open(os.path.join(self.target, "blob.bin"), "w") as fh:
            fh.write("sk-ant-abcdefghij0123456789KLM")
        pack = rulepack.load_rule_pack(self.pack_dir)
        self.assertEqual(pack.scan_path(self.target), [])


class TestOverlayHonorsConfig(unittest.TestCase):
    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()
        self.pack_dir = _write_pack(os.path.join(self.tmp_dir, "policies"))

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    def test_no_pack_configured_returns_empty(self):
        # rule_pack unset -> honor-when-set means no overlay (R4 scope).
        self.assertEqual(self.app.cfg.guardrail.rule_pack, "")
        out = rulepack.overlay_findings(
            self.app.cfg, text="key sk-ant-abcdefghij0123456789KLM"
        )
        self.assertEqual(out, [])

    def test_configured_pack_overlays_text(self):
        select_pack(self.app.cfg, self.app.cfg.guardrail, self.pack_dir)
        out = rulepack.overlay_findings(
            self.app.cfg, text="key = sk-ant-abcdefghij0123456789KLM"
        )
        self.assertTrue(any(f.id == "SEC-ANTHROPIC" for f in out))

    def test_per_connector_pack_resolves(self):
        from defenseclaw.config import PerConnectorGuardrailConfig

        gc = self.app.cfg.guardrail
        gc.connectors = {"openclaw": PerConnectorGuardrailConfig()}
        select_pack(self.app.cfg, gc.connectors["openclaw"], self.pack_dir)
        out = rulepack.overlay_findings(
            self.app.cfg, "openclaw", text="sk-ant-abcdefghij0123456789KLM"
        )
        self.assertTrue(any(f.id == "SEC-ANTHROPIC" for f in out))


class _FakeScanner:
    """Minimal inner scanner: records calls, returns a fixed ScanResult."""

    def __init__(self):
        self.calls = []

    def name(self) -> str:
        return "fake"

    def scan(self, target, *args, **kwargs):
        self.calls.append((target, args, kwargs))
        return ScanResult(
            scanner="fake",
            target=str(target),
            timestamp=datetime.now(timezone.utc),
            findings=[Finding(id="EXISTING", severity="LOW", title="pre-existing")],
        )


class TestMaybeWrap(unittest.TestCase):
    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()
        self.pack_dir = _write_pack(os.path.join(self.tmp_dir, "policies"))

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    def test_no_pack_returns_inner_unchanged(self):
        inner = _FakeScanner()
        wrapped = rulepack.maybe_wrap(inner, self.app.cfg)
        self.assertIs(wrapped, inner)

    def test_a_skill_scan_acts_on_the_default_pack_when_nothing_is_selected(self):
        # The install watcher scans a skill with the default pack on a default
        # install, so the skill scan does too; MCP and plugin scans do not (GAP-0164).
        inner = _FakeScanner()
        with patch("defenseclaw.policy_catalog.preset_pack_dir", return_value=self.pack_dir):
            self.assertIs(rulepack.maybe_wrap(inner, self.app.cfg), inner)
            wrapped = rulepack.maybe_wrap(inner, self.app.cfg, default_pack=True)
        self.assertIsInstance(wrapped, rulepack.RulePackOverlayScanner)
        self.assertIn("SEC-ANTHROPIC", {r.rule_id for r in wrapped.pack.rules})

    def test_wrap_appends_findings_and_preserves_existing(self):
        select_pack(self.app.cfg, self.app.cfg.guardrail, self.pack_dir)
        inner = _FakeScanner()
        wrapped = rulepack.maybe_wrap(inner, self.app.cfg)
        self.assertIsNot(wrapped, inner)
        self.assertEqual(wrapped.name(), "fake")  # delegates

        artifact = os.path.join(self.tmp_dir, "art")
        os.makedirs(artifact)
        with open(os.path.join(artifact, "s.py"), "w") as fh:
            fh.write("tok = 'sk-ant-abcdefghij0123456789KLM'\n")

        result = wrapped.scan(artifact)
        ids = {f.id for f in result.findings}
        self.assertIn("EXISTING", ids)  # inner finding preserved
        self.assertIn("SEC-ANTHROPIC", ids)  # overlay finding added
        overlay = next(f for f in result.findings if f.id == "SEC-ANTHROPIC")
        self.assertEqual(overlay.scanner, result.scanner)
        self.assertIn("analyzer:rule-pack", overlay.tags)

    def test_wrap_overlays_mcp_server_text(self):
        select_pack(self.app.cfg, self.app.cfg.guardrail, self.pack_dir)
        inner = _FakeScanner()
        wrapped = rulepack.maybe_wrap(inner, self.app.cfg)

        class _Srv:
            name = "evil"
            command = "node"
            args = ["server.js"]
            env = {"TOKEN": "sk-ant-abcdefghij0123456789KLM"}
            url = ""

        result = wrapped.scan("evil", server_entry=_Srv())
        self.assertTrue(any(f.id == "SEC-ANTHROPIC" for f in result.findings))

    def test_overlay_failure_never_breaks_scan(self):
        select_pack(self.app.cfg, self.app.cfg.guardrail, self.pack_dir)
        inner = _FakeScanner()
        wrapped = rulepack.maybe_wrap(inner, self.app.cfg)
        # Sabotage the pack so the overlay raises internally; the inner result
        # must still come back intact.
        wrapped.pack = None  # type: ignore[assignment]
        result = wrapped.scan(os.path.join(self.tmp_dir, "art"))
        self.assertEqual({f.id for f in result.findings}, {"EXISTING"})

    def test_two_connector_packs_do_not_cross_contaminate(self):
        from defenseclaw.config import PerConnectorGuardrailConfig

        cursor_pack = os.path.join(self.tmp_dir, "policies", "cursor-only")
        os.makedirs(os.path.join(cursor_pack, "rules"))
        with open(
            os.path.join(cursor_pack, "rules", "custom.yaml"),
            "w",
            encoding="utf-8",
        ) as fh:
            fh.write(
                "version: 1\n"
                "category: custom\n"
                "rules:\n"
                "  - id: CURSOR-ONLY\n"
                "    pattern: 'cursor-exclusive-token'\n"
                "    title: cursor only\n"
                "    severity: HIGH\n"
                "    confidence: 1\n"
                "    tags: [custom]\n"
            )

        connectors = self.app.cfg.guardrail.connectors = {
            "codex": PerConnectorGuardrailConfig(),
            "cursor": PerConnectorGuardrailConfig(),
        }
        select_pack(self.app.cfg, connectors["codex"], self.pack_dir)
        select_pack(self.app.cfg, connectors["cursor"], cursor_pack)
        artifact = os.path.join(self.tmp_dir, "two-pack-artifact")
        os.makedirs(artifact)
        with open(os.path.join(artifact, "payload.txt"), "w", encoding="utf-8") as fh:
            fh.write(
                "sk-ant-abcdefghij0123456789KLM\n"
                "cursor-exclusive-token\n"
            )

        cache: dict[str, rulepack.RulePack] = {}
        codex = rulepack.maybe_wrap(
            _FakeScanner(),
            self.app.cfg,
            "codex",
            pack_cache=cache,
        ).scan(artifact)
        cursor = rulepack.maybe_wrap(
            _FakeScanner(),
            self.app.cfg,
            "cursor",
            pack_cache=cache,
        ).scan(artifact)

        codex_ids = {finding.id for finding in codex.findings}
        cursor_ids = {finding.id for finding in cursor.findings}
        self.assertIn("SEC-ANTHROPIC", codex_ids)
        self.assertNotIn("CURSOR-ONLY", codex_ids)
        self.assertIn("CURSOR-ONLY", cursor_ids)
        self.assertNotIn("SEC-ANTHROPIC", cursor_ids)

    def test_shared_connector_pack_cache_loads_once(self):
        from defenseclaw.config import PerConnectorGuardrailConfig

        connectors = self.app.cfg.guardrail.connectors = {
            "codex": PerConnectorGuardrailConfig(),
            "cursor": PerConnectorGuardrailConfig(),
        }
        select_pack(self.app.cfg, connectors["codex"], self.pack_dir)
        select_pack(self.app.cfg, connectors["cursor"], self.pack_dir)
        cache: dict[str, rulepack.RulePack] = {}
        with patch.object(
            rulepack,
            "load_rule_pack",
            wraps=rulepack.load_rule_pack,
        ) as load:
            codex = rulepack.maybe_wrap(
                _FakeScanner(),
                self.app.cfg,
                "codex",
                pack_cache=cache,
            )
            cursor = rulepack.maybe_wrap(
                _FakeScanner(),
                self.app.cfg,
                "cursor",
                pack_cache=cache,
            )

        self.assertIsInstance(codex, rulepack.RulePackOverlayScanner)
        self.assertIsInstance(cursor, rulepack.RulePackOverlayScanner)
        load.assert_called_once_with(self.pack_dir, ())


class TestTextFromMcpServer(unittest.TestCase):
    def test_flattens_fields(self):
        class _Srv:
            name = "s"
            command = "curl"
            args = ["http://evil/x"]
            env = {"K": "v"}
            url = "http://host/mcp"

        text = rulepack.text_from_mcp_server("target-name", _Srv())
        for needle in ("target-name", "curl", "http://evil/x", "K=v", "http://host/mcp"):
            self.assertIn(needle, text)

    def test_handles_none_entry(self):
        self.assertEqual(rulepack.text_from_mcp_server("just-a-name", None), "just-a-name")


if __name__ == "__main__":
    unittest.main()


class TestWindowsRuntimeMCPScan(unittest.TestCase):
    def test_runtime_mcp_scan_applies_the_rule_pack(self):
        # GAP-0296: the Windows scanner runtime's mcp-scan (the gateway's MCP
        # scan on standalone Windows) skipped the rule-pack overlay that the
        # CLI's mcp scan lays over the server definition.
        import contextlib
        import io
        import json
        import re
        import shutil

        root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        with open(os.path.join(root, "cmd", "defenseclaw-scanners", "main.go"), encoding="utf-8") as stream:
            script = re.search(r"mcpScanScript = `(.*?)`", stream.read(), re.S).group(1)
        tmp = tempfile.mkdtemp(prefix="rp-runtime-")
        self.addCleanup(shutil.rmtree, tmp, True)
        url = "https://mcp.example.test/mcp?key=sk-ant-abcdefghij0123456789KLM"
        clean = ScanResult(scanner="mcp-scanner", target=url, timestamp=datetime.now(timezone.utc), findings=[])
        pack = json.dumps({"dir": _write_pack(tmp), "rules": [{"disable": ["SEC-TOOL-ONLY"]}]})
        out = io.StringIO()
        with (
            patch("defenseclaw.scanner.mcp.MCPScannerWrapper.scan", return_value=clean),
            patch.object(sys, "argv", ["mcp-scan", "--settings", "{}", "--rule-pack", pack, url]),
            contextlib.redirect_stdout(out),
        ):
            exec(compile(script, "mcpScanScript", "exec"), {"__name__": "__main__"})
        findings = json.loads(out.getvalue())["findings"]
        self.assertIn("SEC-ANTHROPIC", [finding["id"] for finding in findings])
