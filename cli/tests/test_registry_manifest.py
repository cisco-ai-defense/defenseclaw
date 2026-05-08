# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for the registry manifest parser/validator.

These tests pin the *security-relevant* invariants — name / command
character classes, URL scheme allow-list, length caps, duplicate
rejection — so the ingest pipeline cannot silently accept a poisoned
catalog. They run without the optional ``jsonschema`` package, so the
hand-written validator is exercised end-to-end on every CI run.
"""

from __future__ import annotations

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.registries.manifest import (
    KNOWN_CONNECTORS,
    KNOWN_TRANSPORTS,
    KNOWN_TYPES,
    NAME_RE,
    ManifestError,
    parse_manifest,
)


def _wrap(*entries):
    return {"schema_version": 1, "entries": list(entries)}


class TestSchemaVersion(unittest.TestCase):
    def test_missing_schema_version_rejected(self):
        with self.assertRaises(ManifestError):
            parse_manifest(json.dumps({"entries": []}))

    def test_unsupported_schema_version_rejected(self):
        with self.assertRaises(ManifestError):
            parse_manifest(json.dumps({"schema_version": 2, "entries": []}))

    def test_v1_with_no_entries_ok(self):
        m = parse_manifest(json.dumps({"schema_version": 1, "entries": []}))
        self.assertEqual(m.schema_version, 1)
        self.assertEqual(m.entries, [])

    def test_top_level_must_be_mapping(self):
        with self.assertRaises(ManifestError):
            parse_manifest("[]")


class TestSkillEntries(unittest.TestCase):
    def test_minimal_skill_entry(self):
        m = parse_manifest(json.dumps(_wrap({
            "name": "demo-skill",
            "type": "skill",
            "source_url": "clawhub://demo-skill",
        })))
        self.assertEqual(len(m.entries), 1)
        self.assertTrue(m.entries[0].is_skill())

    def test_skill_requires_source_url(self):
        with self.assertRaises(ManifestError):
            parse_manifest(json.dumps(_wrap({
                "name": "demo-skill", "type": "skill",
            })))

    def test_skill_source_url_scheme_locked(self):
        for bad in ("file:///etc/passwd", "ftp://example.com", "ssh://x"):
            with self.subTest(url=bad):
                with self.assertRaises(ManifestError):
                    parse_manifest(json.dumps(_wrap({
                        "name": "demo", "type": "skill", "source_url": bad,
                    })))

    def test_skill_sha256_must_be_64_hex(self):
        with self.assertRaises(ManifestError):
            parse_manifest(json.dumps(_wrap({
                "name": "demo", "type": "skill",
                "source_url": "https://example.com/x.tgz",
                "sha256": "not-hex",
            })))

    def test_skill_sha256_accepted_when_valid(self):
        m = parse_manifest(json.dumps(_wrap({
            "name": "demo", "type": "skill",
            "source_url": "https://example.com/x.tgz",
            "sha256": "a" * 64,
        })))
        self.assertEqual(m.entries[0].sha256, "a" * 64)

    def test_skill_homepage_must_be_http(self):
        with self.assertRaises(ManifestError):
            parse_manifest(json.dumps(_wrap({
                "name": "demo", "type": "skill",
                "source_url": "https://x/y",
                "homepage": "javascript:alert(1)",
            })))


class TestMcpEntries(unittest.TestCase):
    def test_stdio_requires_command(self):
        with self.assertRaises(ManifestError):
            parse_manifest(json.dumps(_wrap({
                "name": "stdio-srv", "type": "mcp", "transport": "stdio",
            })))

    def test_command_character_class_locked(self):
        # The ; here would let a poisoned manifest smuggle a shell
        # metacharacter into the scanner subprocess if we ever invoked
        # via a shell. Refuse at parse time.
        with self.assertRaises(ManifestError):
            parse_manifest(json.dumps(_wrap({
                "name": "evil", "type": "mcp",
                "transport": "stdio",
                "command": "rm; sleep 5",
            })))

    def test_command_dot_slash_allowed(self):
        # Operators do legitimately point at ./bin/foo or relative
        # paths under repo roots — the allow-list covers that case.
        m = parse_manifest(json.dumps(_wrap({
            "name": "bin", "type": "mcp",
            "transport": "stdio",
            "command": "./bin/foo",
        })))
        self.assertEqual(m.entries[0].command, "./bin/foo")

    def test_env_required_must_be_uppercase(self):
        with self.assertRaises(ManifestError):
            parse_manifest(json.dumps(_wrap({
                "name": "srv", "type": "mcp",
                "transport": "stdio", "command": "x",
                "env_required": ["lowercase"],
            })))

    def test_remote_transport_requires_url(self):
        with self.assertRaises(ManifestError):
            parse_manifest(json.dumps(_wrap({
                "name": "srv", "type": "mcp",
                "transport": "streamable-http",
            })))

    def test_unknown_transport_rejected(self):
        with self.assertRaises(ManifestError):
            parse_manifest(json.dumps(_wrap({
                "name": "srv", "type": "mcp",
                "transport": "unicorn", "command": "x",
            })))

    def test_unknown_connector_rejected(self):
        with self.assertRaises(ManifestError):
            parse_manifest(json.dumps(_wrap({
                "name": "srv", "type": "mcp",
                "transport": "stdio", "command": "x",
                "connector": "fake",
            })))


class TestNamesAndDuplicates(unittest.TestCase):
    def test_name_must_match_regex(self):
        for bad in ("../escape", "with space", "$inject", ""):
            with self.subTest(name=bad):
                self.assertFalse(NAME_RE.match(bad))
                with self.assertRaises(ManifestError):
                    parse_manifest(json.dumps(_wrap({
                        "name": bad, "type": "skill",
                        "source_url": "https://x/y",
                    })))

    def test_duplicate_entry_rejected(self):
        with self.assertRaises(ManifestError):
            parse_manifest(json.dumps(_wrap(
                {"name": "dup", "type": "skill", "source_url": "https://x/y"},
                {"name": "dup", "type": "skill", "source_url": "https://x/y"},
            )))

    def test_duplicate_across_types_allowed(self):
        # A skill named "foo" and an MCP named "foo" are *different*
        # assets — both are allowed in the same manifest.
        m = parse_manifest(json.dumps(_wrap(
            {"name": "foo", "type": "skill", "source_url": "https://x/y"},
            {"name": "foo", "type": "mcp",
             "transport": "stdio", "command": "f"},
        )))
        self.assertEqual(len(m.entries), 2)


class TestParseFormats(unittest.TestCase):
    def test_yaml_accepted(self):
        body = (
            "schema_version: 1\n"
            "entries:\n"
            "  - name: yaml-demo\n"
            "    type: skill\n"
            "    source_url: clawhub://yaml-demo\n"
        )
        m = parse_manifest(body)
        self.assertEqual(m.entries[0].name, "yaml-demo")

    def test_bytes_accepted(self):
        m = parse_manifest(b'{"schema_version": 1, "entries": []}')
        self.assertEqual(m.entries, [])

    def test_invalid_utf8_rejected(self):
        with self.assertRaises(ManifestError):
            parse_manifest(b"\xff\xfe\xfc")

    def test_empty_payload_rejected(self):
        with self.assertRaises(ManifestError):
            parse_manifest("")


class TestFilterByContent(unittest.TestCase):
    def setUp(self):
        self.manifest = parse_manifest(json.dumps(_wrap(
            {"name": "s1", "type": "skill", "source_url": "https://x/1"},
            {"name": "m1", "type": "mcp",
             "transport": "stdio", "command": "x"},
        )))

    def test_skill_only(self):
        only = self.manifest.filter_by_content("skill")
        self.assertEqual([e.name for e in only], ["s1"])

    def test_mcp_only(self):
        only = self.manifest.filter_by_content("mcp")
        self.assertEqual([e.name for e in only], ["m1"])

    def test_both(self):
        both = self.manifest.filter_by_content("both")
        self.assertEqual({e.name for e in both}, {"s1", "m1"})


class TestKnownConstants(unittest.TestCase):
    """Regression: keep the KNOWN_* sets aligned with the schema."""

    def test_known_types_match_schema(self):
        self.assertEqual(KNOWN_TYPES, {"skill", "mcp"})

    def test_known_transports_match_schema(self):
        self.assertEqual(
            KNOWN_TRANSPORTS,
            {"stdio", "http", "sse", "streamable-http", "websocket"},
        )

    def test_known_connectors_match_schema(self):
        self.assertEqual(
            KNOWN_CONNECTORS,
            {"openclaw", "claudecode", "codex", "zeptoclaw"},
        )


if __name__ == "__main__":
    unittest.main()
