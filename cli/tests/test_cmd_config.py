# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for ``defenseclaw config``.

``validate`` is the most important surface — ``main.py`` runs it as a
pre-flight hook, so any regression here cascades into every command.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from click.testing import CliRunner

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.commands import cmd_config
from defenseclaw.config import default_config
from defenseclaw.config_inspect import ConfigInspectError


class _IsolatedHome:
    """Context manager that redirects ``DEFENSECLAW_HOME`` to a tmpdir.

    The config module caches paths at import time, so we also patch the
    resolved ``config_path()``/``load()`` helpers to pick up the new
    home. This keeps the tests hermetic even when the developer has a
    real config on disk.
    """

    def __init__(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.home = Path(self._tmp.name)
        self.config_path = self.home / "config.yaml"

    def __enter__(self):
        self._patches = [
            patch.dict(os.environ, {"DEFENSECLAW_HOME": str(self.home)}, clear=False),
            patch("defenseclaw.commands.cmd_config.config_module.config_path",
                  return_value=self.config_path),
        ]
        for p in self._patches:
            p.start()
        return self

    def __exit__(self, *exc):
        for p in reversed(self._patches):
            p.stop()
        self._tmp.cleanup()
        return False


class ValidateConfigTests(unittest.TestCase):
    def test_missing_config_is_ok(self):
        """No config yet → soft-pass so recovery/init commands can run."""
        with _IsolatedHome() as env:
            self.assertFalse(env.config_path.exists())
            res = cmd_config.validate_config()
            self.assertTrue(res.ok)
            self.assertFalse(res.exists)

    def test_invalid_yaml_reports_parse_error(self):
        with _IsolatedHome() as env:
            # Guaranteed YAML parse error (dangling unclosed bracket).
            env.config_path.write_text(
                "config_version: 8\nguardrail:\n  port: [oops\n",
                encoding="utf-8",
            )
            with patch.object(
                cmd_config,
                "inspect_v8_config",
                side_effect=ConfigInspectError("invalid YAML source"),
            ):
                res = cmd_config.validate_config()
            self.assertFalse(res.ok)
            self.assertTrue(any("invalid YAML" in error for error in res.errors))

    def test_out_of_range_port_is_error(self):
        with _IsolatedHome() as env:
            env.config_path.write_text(
                # Minimal, but enough to parse. Everything not listed
                # takes its dataclass default via the loader.
                "config_version: 8\n"
                "observability: {}\n"
                "guardrail:\n"
                "  port: 99999\n"
                "  mode: observe\n"
                "  scanner_mode: local\n",
                encoding="utf-8",
            )
            with patch.object(
                cmd_config,
                "inspect_v8_config",
                side_effect=ConfigInspectError("guardrail.port: must be between 1 and 65535"),
            ):
                res = cmd_config.validate_config()
            self.assertFalse(res.ok)
            self.assertTrue(any("guardrail.port" in e for e in res.errors),
                            msg=f"errors were: {res.errors}")

    def test_bad_scanner_mode_is_error(self):
        with _IsolatedHome() as env:
            env.config_path.write_text(
                "config_version: 8\n"
                "observability: {}\n"
                "guardrail:\n"
                "  mode: observe\n"
                "  port: 4000\n"
                "  scanner_mode: bogus\n",
                encoding="utf-8",
            )
            with patch.object(
                cmd_config,
                "inspect_v8_config",
                side_effect=ConfigInspectError("guardrail.scanner_mode: unsupported value"),
            ):
                res = cmd_config.validate_config()
            self.assertFalse(res.ok)
            self.assertTrue(any("scanner_mode" in e for e in res.errors))

    def test_unplaced_go_refusal_names_the_field(self):
        """Go's runtime-loader refusals reach the wire only at "$".

        The Go decision stands; the Python mirror of the openshell checks
        names the field and what it takes (the #1019 retest).
        """
        generic = ConfigInspectError(
            "candidate field=$; reason=configuration could not be compiled safely",
            field_path="$",
            reason="configuration could not be compiled safely",
        )
        with _IsolatedHome() as env:
            env.config_path.write_text("config_version: 8\nopenshell:\n  binary: bin/openshell\n", encoding="utf-8")
            with patch.object(cmd_config, "inspect_v8_config", side_effect=generic):
                res = cmd_config.validate_config()
            self.assertFalse(res.ok)
            self.assertEqual(
                res.errors,
                ["line 3: openshell.binary: use a command name on PATH or an absolute path."],
            )

            # Nothing the mirror finds: Go's own words.
            env.config_path.write_text("config_version: 8\n", encoding="utf-8")
            with patch.object(cmd_config, "inspect_v8_config", side_effect=generic):
                res = cmd_config.validate_config()
            self.assertEqual(res.errors, [str(generic)])

            # A refusal Go placed keeps its field and reason, in plain words.
            placed = ConfigInspectError(
                "candidate field=$.openshell.llm; reason=[config_schema_invalid] …",
                field_path="$.openshell.llm",
                reason="[config_schema_invalid] unknown field",
            )
            env.config_path.write_text("config_version: 8\nopenshell:\n  binary: bin/openshell\n", encoding="utf-8")
            with patch.object(cmd_config, "inspect_v8_config", side_effect=placed):
                res = cmd_config.validate_config()
            self.assertEqual(res.errors, ["openshell.llm: unknown field. All fields: defenseclaw config reference --format json-schema"])

    def test_enum_refusal_names_line_value_and_allowed_values(self):
        # GAP-1499: no "candidate field=$...; reason=[config_schema_invalid]" record.
        refusal = ConfigInspectError(
            "candidate field=$.guardrail.mode; reason=...",
            field_path="$.guardrail.mode",
            reason='[config_schema_invalid] configuration violates the enum constraint; expected one of '
            '["observe","action"]; inspect the canonical v8 schema or generated reference and correct this field',
        )
        with _IsolatedHome() as env:
            env.config_path.write_text(
                "config_version: 8\nguardrail:\n  mode: enforce-everything\n", encoding="utf-8"
            )
            with patch.object(cmd_config, "inspect_v8_config", side_effect=refusal):
                res = cmd_config.validate_config()
        self.assertEqual(
            res.errors,
            [
                'line 3: guardrail.mode is "enforce-everything"; allowed values: observe, action.'
            ],
        )

    def test_reference_yaml_drops_generator_header_and_help_names_json_schema(self):
        # GAP-1661: the YAML reference covers only observability; the help says
        # where every field is, and the output carries no repository paths.
        generated = (
            "# DEFENSECLAW CONFIGURATION v8 \u2014 OBSERVABILITY REFERENCE\n#\n"
            "# GENERATED FILE. DO NOT EDIT.\n"
            "# Canonical schema: schemas/config/v8/defenseclaw-config.schema.json\n"
            "# Generator: scripts/generate_observability_v8_reference.py\n#\n"
            "# This is the complete source-config surface.\nconfig_version: 8\n"
        )
        runner = CliRunner()
        with patch.object(cmd_config, "config_v8_reference", return_value=generated):
            res = runner.invoke(cmd_config.config_reference, [])
        self.assertEqual(res.exit_code, 0, res.output)
        self.assertNotIn("DO NOT EDIT", res.output)
        self.assertNotIn("schemas/config", res.output)
        self.assertNotIn("#\n#\n", res.output)
        self.assertIn("config_version: 8", res.output)
        help_text = runner.invoke(cmd_config.config_reference, ["--help"]).output
        self.assertIn("json-schema prints the schema of every", help_text)

    def test_yaml_syntax_refusal_names_the_bad_line_and_parser_reason(self):
        # GAP-1430: validate named line 119 and a generic list for a bad line 118.
        generic = ConfigInspectError(
            "candidate field=$; reason=[yaml_syntax_invalid] configuration source is not valid YAML",
            field_path="$",
            reason="[yaml_syntax_invalid] configuration source is not valid YAML",
        )
        with _IsolatedHome() as env:
            env.config_path.write_text("config_version: 8\na: 1\nguardrail: [unclosed\n", encoding="utf-8")
            with patch.object(cmd_config, "inspect_v8_config", side_effect=generic):
                res = cmd_config.validate_config()
        self.assertEqual(len(res.errors), 1)
        self.assertTrue(res.errors[0].startswith("line 3, column 12: invalid YAML (expected ',' or ']'"), res.errors)
        self.assertNotIn("candidate field", res.errors[0])

    def test_missing_secret_refusal_names_the_variable_and_keys_set(self):
        # GAP-1442: name the way out instead of "doctor --fix".
        refusal = ConfigInspectError(
            "candidate field=...",
            field_path='$.observability.destinations[0].headers["Galileo-API-Key"]',
            reason="[secret_reference_unresolved] required environment-backed secret is unavailable",
        )
        # setup galileo writes the {env: NAME} mapping form.
        for reference in ("${GALILEO_API_KEY}", "{env: GALILEO_API_KEY}"):
            with self.subTest(reference=reference), _IsolatedHome() as env:
                env.config_path.write_text(
                    "config_version: 8\nobservability:\n  destinations:\n    - name: galileo\n"
                    f"      headers:\n        Galileo-API-Key: {reference}\n",
                    encoding="utf-8",
                )
                with patch.object(cmd_config, "inspect_v8_config", side_effect=refusal):
                    res = cmd_config.validate_config()
                self.assertEqual(len(res.errors), 1)
                self.assertTrue(res.errors[0].startswith("line 6: "), res.errors)
                self.assertIn("needs GALILEO_API_KEY", res.errors[0])
                self.assertIn("defenseclaw keys set GALILEO_API_KEY", res.errors[0])
                self.assertNotIn("<NAME>", res.errors[0])

    def test_gateway_port_clash_is_warning_not_error(self):
        with _IsolatedHome() as env:
            env.config_path.write_text(
                "config_version: 8\n"
                "observability: {}\n"
                "guardrail:\n"
                "  mode: observe\n"
                "  port: 4000\n"
                "  scanner_mode: local\n"
                "gateway:\n"
                "  port: 7070\n"
                "  api_port: 7070\n",
                encoding="utf-8",
            )
            with patch.object(
                cmd_config,
                "inspect_v8_config",
                return_value=SimpleNamespace(valid=True),
            ):
                res = cmd_config.validate_config()
            # The canonical Go validator owns any advisory diagnostics. The
            # Python command must accept its valid decision without trying to
            # reimplement config semantics.
            self.assertTrue(res.ok, msg=f"errors: {res.errors}")


class ConfigShowTests(unittest.TestCase):
    def test_masked_dict_hides_internal_loader_snapshots(self):
        cfg = default_config()
        cfg._loaded_authoritative_dicts = {
            "guardrail.connectors": {
                "codex": {"mode": "observe", "rule_pack": ""}
            }
        }
        cfg._loaded_owned_nested_values = {
            "guardrail.connectors": {"codex": {"hilt": {"enabled": True}}}
        }

        rendered = cmd_config._config_to_masked_dict(cfg)
        blob = json.dumps(rendered)

        self.assertNotIn("_loaded_authoritative_dicts", rendered)
        self.assertNotIn("_loaded_owned_nested_values", rendered)
        self.assertNotIn("_loaded_authoritative_dicts", blob)
        self.assertNotIn("_loaded_owned_nested_values", blob)


class UndeclaredKeyWordingTests(unittest.TestCase):
    # GAP-2235: the gateway's words for an undeclared key, at the key's line.
    REASON = (
        "[config_schema_invalid] configuration violates the additionalProperties constraint; "
        "expected a declared field name; suggested field mode; "
        "inspect the canonical v8 schema or generated reference and correct this field"
    )

    def test_typo_reads_unknown_field_with_suggestion(self):
        raw = b"config_version: 8\nguardrail:\n  mdoe: observe\n"
        self.assertEqual(
            cmd_config._plain_v8_issue(raw, "$.guardrail.mdoe", self.REASON),
            'line 3: guardrail.mdoe: unknown field (did you mean "mode"?). '
            "All fields: defenseclaw config reference --format json-schema",
        )

    def test_unknown_section_names_its_own_line(self):
        raw = b"config_version: 8\ngateway2:\n  a: 1\n"
        reason = self.REASON.replace("suggested field mode; ", "")
        self.assertEqual(
            cmd_config._plain_v8_issue(raw, "$.gateway2", reason),
            "line 2: gateway2: unknown field. All fields: defenseclaw config reference --format json-schema",
        )

    def test_retired_key_names_its_replacement(self):
        v8 = b"config_version: 8\nskill_actions:\n  medium: {install: block}\n"
        self.assertEqual(
            cmd_config._plain_v8_issue(v8, "$.skill_actions", self.REASON),
            "line 2: skill_actions was replaced by admission.skill.actions in config_version 9; "
            "run: defenseclaw migrate",
        )
        v9 = v8.replace(b"8", b"9", 1)
        self.assertIn("move it to admission.skill.actions", cmd_config._plain_v8_issue(v9, "$.skill_actions", self.REASON))

    def test_config_get_and_set_send_a_retired_key_to_migrate(self):
        # A v8 file is migrated, not hand-edited: deleting the key loses its value.
        from defenseclaw import config_writer
        from defenseclaw.observability.v8_config import V8ConfigError, load_validate_v8

        raw = b"config_version: 8\nskill_actions:\n  medium: {install: block}\n"
        with self.assertRaises(V8ConfigError) as caught:
            load_validate_v8(raw, source_name="config.yaml")
        self.assertIn("run: defenseclaw migrate", str(caught.exception))
        self.assertEqual(
            config_writer.plain_error(_chained(caught.exception)),
            "skill_actions was replaced by admission.skill.actions in config_version 9; run: defenseclaw migrate",
        )

    def test_a_newer_config_version_is_not_sent_to_migrate(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "config.yaml")
            with open(path, "w", encoding="utf-8") as stream:
                stream.write("config_version: 10\n")
            self.assertIn("newer DefenseClaw (config_version 10)", cmd_config._not_current_message(path))
            with open(path, "w", encoding="utf-8") as stream:
                stream.write("config_version: 7\n")
            self.assertIn("run 'defenseclaw migrate'", cmd_config._not_current_message(path))


def _chained(cause: BaseException) -> BaseException:
    error = ValueError("refused")
    error.__cause__ = cause
    return error


if __name__ == "__main__":
    unittest.main()
