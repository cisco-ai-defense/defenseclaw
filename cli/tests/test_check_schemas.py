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

"""Regression tests for ``scripts/check_schemas.py``.

Pins two contracts that downstream consumers (Splunk APM, OTLP collector
validation, audit drill-down) silently depend on:

1. The recursive walk of ``schemas/`` covers ``schemas/otel/*.json``.
   A previous version of the script only globbed the top-level
   directory, so OTel schemas drifted unchecked for months.

2. ``schemas/otel/resource.schema.json``'s ``defenseclaw.claw.mode``
   enum stays aligned with every built-in connector name emitted by
   ``Connector.Name()`` in ``internal/gateway/connector``.
   Adding a connector and forgetting the schema means dashboards
   silently start dropping records — and the fresh-install empty
   placeholder ("") masks the failure on bench tests.

3. CLI schema mirrors are discovered from real ``//go:embed`` directives,
   remain byte-identical, and reject unexplained duplicate JSON files.

4. The management contract schemas under ``packaging/mdm/contract`` keep
   accepting their examples and keep the contract rules.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "check_schemas.py"
SCHEMA_DIR = ROOT / "schemas"
RESOURCE_SCHEMA = SCHEMA_DIR / "otel" / "resource.schema.json"
GALILEO_PROFILE_SCHEMA = SCHEMA_DIR / "otel" / "galileo-export-profile.schema.json"
UNICODE13_GENERATOR = ROOT / "scripts" / "generate_unicode13_repertoire.py"


class TestCheckSchemasResourceEnum(unittest.TestCase):
    def test_resource_schema_has_canonical_claw_mode_enum(self) -> None:
        """The released schema must list every connector emit() can produce."""
        doc = json.loads(RESOURCE_SCHEMA.read_text(encoding="utf-8"))
        enum = set(doc["properties"]["defenseclaw.claw.mode"].get("enum", []))
        # Connector names from internal/gateway/connector plus the empty placeholder
        # for fresh installs that haven't picked a connector yet.
        self.assertEqual(
            enum,
            {
                "openclaw",
                "zeptoclaw",
                "claudecode",
                "codex",
                "hermes",
                "cursor",
                "devin",
                "copilot",
        "antigravity",
        "opencode",
        "amp",
        "kiro",
                # Sentinel set by telemetry/resource.go when more than one
                # connector is active (multi-connector install). Not a
                # connector name — see buildResource / WU4.
                "multi",
                "",
            },
            "drift in defenseclaw.claw.mode enum — update Connector.Name() "
            "and the schema together; downstream APM dashboards pivot on this",
        )

    def test_legacy_modes_dropped(self) -> None:
        """Legacy placeholders that were never emitted must stay dropped.

        ``nemoclaw`` shipped in the schema before a connector by that name
        existed; allowing it back masks typos in operator config files and
        fails closed at the downstream consumer (silent drop of the resource
        record). OpenCode is now a real built-in connector.
        """
        doc = json.loads(RESOURCE_SCHEMA.read_text(encoding="utf-8"))
        enum = set(doc["properties"]["defenseclaw.claw.mode"].get("enum", []))
        self.assertNotIn("nemoclaw", enum)
        self.assertIn("opencode", enum)

    def test_claudecode_home_description_uses_official_config_override(self) -> None:
        """The resource contract must name Claude Code's documented override."""
        doc = json.loads(RESOURCE_SCHEMA.read_text(encoding="utf-8"))
        description = doc["properties"]["defenseclaw.claw.home_dir"]["description"]

        self.assertIn("$CLAUDE_CONFIG_DIR", description)
        self.assertNotIn("$CLAUDE_HOME", description)


class TestUnicode13RepertoireDrift(unittest.TestCase):
    def test_offline_generator_check_passes_and_detects_tampering(self) -> None:
        clean = subprocess.run(
            [sys.executable, str(UNICODE13_GENERATOR), "--check"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(clean.returncode, 0, clean.stdout + clean.stderr)

        with tempfile.TemporaryDirectory() as tmp:
            repository = Path(tmp)
            owned_paths = (
                Path("schemas/telemetry/v8/redaction/unicode-age-13.0.json"),
                Path("internal/observability/redaction/unicode13.go"),
                Path("cli/defenseclaw/observability/unicode13.py"),
            )
            for relative in owned_paths:
                destination = repository / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes((ROOT / relative).read_bytes())
            manifest = repository / owned_paths[0]
            document = json.loads(manifest.read_text(encoding="utf-8"))
            document["scalar_count"] += 1
            manifest.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")

            tampered = subprocess.run(
                [
                    sys.executable,
                    str(UNICODE13_GENERATOR),
                    "--check",
                    "--repository",
                    str(repository),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            self.assertNotEqual(tampered.returncode, 0)
            self.assertIn("generated file is stale", tampered.stderr + tampered.stdout)


class TestCheckSchemasDriftDetection(unittest.TestCase):
    """Run check_schemas.py against a tampered schema tree and assert it fails."""

    def _run_against(self, schema_dir: Path) -> subprocess.CompletedProcess[str]:
        # Re-execute the script with a swapped SCHEMA_DIR by injecting a
        # tiny shim that monkey-patches the path before main() runs.
        # This isolates the test from the real schemas/ tree.
        shim = (
            "import importlib.util, sys, pathlib\n"
            f"spec = importlib.util.spec_from_file_location('check_schemas', r'{SCRIPT}')\n"
            "mod = importlib.util.module_from_spec(spec)\n"
            "spec.loader.exec_module(mod)\n"
            f"mod.SCHEMA_DIR = pathlib.Path(r'{schema_dir}')\n"
            "sys.exit(mod.main())\n"
        )
        return subprocess.run(
            [sys.executable, "-c", shim],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

    def test_dropping_a_connector_mode_is_caught(self) -> None:
        # Mirror schemas/ into a tempdir, drop "claudecode" from the
        # resource schema's claw.mode enum, and assert the script
        # exits non-zero with a drift-shaped error message.
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            # rsync-equivalent copy preserving structure
            for src in SCHEMA_DIR.rglob("*.json"):
                rel = src.relative_to(SCHEMA_DIR)
                dst = tmp_path / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                dst.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")

            tampered = tmp_path / "otel" / "resource.schema.json"
            doc = json.loads(tampered.read_text(encoding="utf-8"))
            mode = doc["properties"]["defenseclaw.claw.mode"]
            mode["enum"] = [m for m in mode["enum"] if m != "claudecode"]
            tampered.write_text(json.dumps(doc, indent=2), encoding="utf-8")

            res = self._run_against(tmp_path)
            self.assertNotEqual(
                res.returncode,
                0,
                f"check_schemas should have flagged the dropped connector\nstdout={res.stdout}\nstderr={res.stderr}",
            )
            self.assertIn("defenseclaw.claw.mode", res.stderr)
            self.assertIn("claudecode", res.stderr)

    def test_adding_a_bogus_connector_mode_is_caught(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            for src in SCHEMA_DIR.rglob("*.json"):
                rel = src.relative_to(SCHEMA_DIR)
                dst = tmp_path / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                dst.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")

            tampered = tmp_path / "otel" / "resource.schema.json"
            doc = json.loads(tampered.read_text(encoding="utf-8"))
            doc["properties"]["defenseclaw.claw.mode"]["enum"].append("nemoclaw")
            tampered.write_text(json.dumps(doc, indent=2), encoding="utf-8")

            res = self._run_against(tmp_path)
            self.assertNotEqual(
                res.returncode,
                0,
                f"check_schemas should have flagged the legacy connector name\n"
                f"stdout={res.stdout}\nstderr={res.stderr}",
            )
            self.assertIn("nemoclaw", res.stderr)


class TestCheckSchemasCoversOtelTree(unittest.TestCase):
    def test_missing_directly_owned_public_schema_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            schema_dir = Path(tmp)
            for source in SCHEMA_DIR.rglob("*.json"):
                target = schema_dir / source.relative_to(SCHEMA_DIR)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(source.read_bytes())
            (schema_dir / "scan-result.json").unlink()

            shim = (
                "import importlib.util, pathlib, sys\n"
                f"spec = importlib.util.spec_from_file_location('check_schemas', r'{SCRIPT}')\n"
                "mod = importlib.util.module_from_spec(spec)\n"
                "spec.loader.exec_module(mod)\n"
                f"mod.SCHEMA_DIR = pathlib.Path(r'{schema_dir}')\n"
                "sys.exit(0 if mod.check_public_schema_inventory() else 1)\n"
            )
            result = subprocess.run(
                [sys.executable, "-c", shim],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("scan-result.json", result.stderr)

    def test_otel_subdir_is_walked(self) -> None:
        # Sanity: corrupt schemas/otel/metrics.schema.json and ensure
        # the script catches it (proves rglob covers the subtree).
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            for src in SCHEMA_DIR.rglob("*.json"):
                rel = src.relative_to(SCHEMA_DIR)
                dst = tmp_path / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                dst.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")

            corrupt = tmp_path / "otel" / "metrics.schema.json"
            corrupt.write_text("{not json", encoding="utf-8")

            shim = (
                "import importlib.util, sys, pathlib\n"
                f"spec = importlib.util.spec_from_file_location('check_schemas', r'{SCRIPT}')\n"
                "mod = importlib.util.module_from_spec(spec)\n"
                "spec.loader.exec_module(mod)\n"
                f"mod.SCHEMA_DIR = pathlib.Path(r'{tmp_path}')\n"
                "sys.exit(mod.main())\n"
            )
            res = subprocess.run(
                [sys.executable, "-c", shim],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            self.assertNotEqual(res.returncode, 0)
            self.assertIn(os.fspath(Path("otel") / "metrics.schema.json"), res.stderr)


class TestCliEmbedSchemaMirrors(unittest.TestCase):
    def test_unreferenced_duplicate_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            schema_dir = root / "schemas"
            cli_dir = root / "internal" / "cli"
            embed_dir = cli_dir / "embed"
            schema_dir.mkdir(parents=True)
            embed_dir.mkdir(parents=True)
            schema = '{"$schema":"https://json-schema.org/draft/2020-12/schema"}\n'
            (schema_dir / "scan-result.json").write_text(schema, encoding="utf-8")
            (embed_dir / "scan-result.json").write_text(schema, encoding="utf-8")
            (embed_dir / "orphan.json").write_text(schema, encoding="utf-8")
            (cli_dir / "scan.go").write_text(
                "//go:embed embed/scan-result.json\n", encoding="utf-8"
            )

            shim = (
                "import importlib.util, pathlib, sys\n"
                f"spec = importlib.util.spec_from_file_location('check_schemas', r'{SCRIPT}')\n"
                "mod = importlib.util.module_from_spec(spec)\n"
                "spec.loader.exec_module(mod)\n"
                f"mod.SCHEMA_DIR = pathlib.Path(r'{schema_dir}')\n"
                f"mod.CLI_GO_DIR = pathlib.Path(r'{cli_dir}')\n"
                f"mod.CLI_EMBED_SCHEMA_DIR = pathlib.Path(r'{embed_dir}')\n"
                "sys.exit(0 if mod.check_cli_embed_mirrors() else 1)\n"
            )
            res = subprocess.run(
                [sys.executable, "-c", shim],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("unreferenced CLI embed schema copies", res.stderr)
            self.assertIn("orphan.json", res.stderr)


MDM_CONTRACT_DIR = ROOT / "packaging" / "mdm" / "contract"


class TestManagementForwardSchemas(unittest.TestCase):
    """private #14 option A: the forward schemas are closed allowlists and no
    account name survives a projection of the fixtures."""

    def _check(self, contract_dir: Path) -> subprocess.CompletedProcess[str]:
        shim = (
            "import importlib.util, pathlib, sys\n"
            f"spec = importlib.util.spec_from_file_location('check_schemas', r'{SCRIPT}')\n"
            "mod = importlib.util.module_from_spec(spec)\n"
            "spec.loader.exec_module(mod)\n"
            f"mod.MDM_CONTRACT_DIR = pathlib.Path(r'{contract_dir}')\n"
            "sys.exit(0 if mod.check_forward_schemas() else 1)\n"
        )
        return subprocess.run([sys.executable, "-c", shim], capture_output=True, text=True, timeout=60, check=False)

    def _tampered(self, change) -> subprocess.CompletedProcess[str]:
        import shutil

        with tempfile.TemporaryDirectory() as tmp:
            contract_dir = Path(tmp) / "contract"
            shutil.copytree(MDM_CONTRACT_DIR, contract_dir)
            change(contract_dir / "forward")
            return self._check(contract_dir)

    @staticmethod
    def _edit(forward: Path, name: str, edit) -> None:
        path = forward / name
        document = json.loads(path.read_text(encoding="utf-8"))
        edit(document)
        path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")

    def test_repository_forward_schemas_pass(self) -> None:
        result = self._check(MDM_CONTRACT_DIR)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("management forward schemas OK", result.stdout)

    def test_a_member_that_names_an_account_is_caught(self) -> None:
        def add(document: dict) -> None:
            document["properties"]["enrollment"]["properties"]["accounts"] = {
                "type": "array", "items": {"type": "string", "pattern": ".*"}}

        result = self._tampered(lambda forward: self._edit(forward, "lifecycle-result-forward.schema.json", add))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("'accounts'", result.stderr)

    def test_a_loose_string_that_lets_a_name_through_is_caught(self) -> None:
        def loosen(document: dict) -> None:
            document["$defs"]["message"]["properties"]["code"] = {"type": "string", "pattern": ".*"}
            document["$defs"]["message"]["properties"]["detail_text"] = {"type": "string", "pattern": ".*"}

        def change(forward: Path) -> None:
            self._edit(forward, "lifecycle-result-forward.schema.json", loosen)
            fixture = forward / "fixtures" / "lifecycle-result.linux.status.json"
            document = json.loads(fixture.read_text(encoding="utf-8"))
            document["warnings"].append({"code": "x", "detail_text": "dcad-r102-eng1"})
            fixture.write_text(json.dumps(document), encoding="utf-8")

        result = self._tampered(change)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("leak=dcad-", result.stderr)

    def test_an_open_object_is_caught(self) -> None:
        def open_object(document: dict) -> None:
            document["properties"]["readiness"]["additionalProperties"] = True

        result = self._tampered(lambda forward: self._edit(forward, "lifecycle-result-forward.schema.json", open_object))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must be closed", result.stderr)


class TestManagementContractSchemas(unittest.TestCase):
    """The management contract check fails when a schema drifts from its
    examples, its rules or the guide (packaging/mdm/contract)."""

    def _check(self, contract_dir: Path) -> subprocess.CompletedProcess[str]:
        shim = (
            "import importlib.util, pathlib, sys\n"
            f"spec = importlib.util.spec_from_file_location('check_schemas', r'{SCRIPT}')\n"
            "mod = importlib.util.module_from_spec(spec)\n"
            "spec.loader.exec_module(mod)\n"
            f"mod.MDM_CONTRACT_DIR = pathlib.Path(r'{contract_dir}')\n"
            "sys.exit(0 if mod.check_management_contract() else 1)\n"
        )
        return subprocess.run(
            [sys.executable, "-c", shim],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )

    def _tampered(self, tmp: str, change) -> subprocess.CompletedProcess[str]:
        contract_dir = Path(tmp)
        for source in MDM_CONTRACT_DIR.iterdir():
            if source.is_file():
                (contract_dir / source.name).write_bytes(source.read_bytes())
        change(contract_dir)
        return self._check(contract_dir)

    @staticmethod
    def _edit_schema(contract_dir: Path, name: str, edit) -> None:
        path = contract_dir / name
        document = json.loads(path.read_text(encoding="utf-8"))
        edit(document)
        path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")

    def test_repository_contract_passes(self) -> None:
        result = self._check(MDM_CONTRACT_DIR)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("packaging/mdm/contract OK", result.stdout)

    def test_opened_schema_is_caught(self) -> None:
        # Dropping additionalProperties lets a features list back into the
        # version probe, which management_contract 1 replaced.
        with tempfile.TemporaryDirectory() as tmp:
            result = self._tampered(
                tmp,
                lambda d: self._edit_schema(d, "version.schema.json", lambda s: s.pop("additionalProperties")),
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must reject version with a features list", result.stderr)

    def test_windows_exit_5_must_stay_accepted(self) -> None:
        def drop_exit_5(schema: dict) -> None:
            for clause in schema["allOf"]:
                exit_code = clause.get("then", {}).get("properties", {}).get("exit_code", {})
                if 5 in exit_code.get("enum", []):
                    exit_code["enum"].remove(5)

        with tempfile.TemporaryDirectory() as tmp:
            result = self._tampered(
                tmp, lambda d: self._edit_schema(d, "lifecycle-result.schema.json", drop_exit_5)
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must accept Windows lifecycle result elevation_required with exit 5", result.stderr)

    def test_status_ref_without_delivery_id_is_caught(self) -> None:
        # bundle status prints the state records current and last_good with
        # the delivery_id that confirmed them (GAP-0001).
        def drop_delivery_id(schema: dict) -> None:
            # current (currentRef, from 1.0.6 with min_product_version) and
            # last_good (ref) both carry it.
            schema["$defs"]["ref"]["properties"].pop("delivery_id")
            schema["$defs"]["currentRef"]["properties"].pop("delivery_id")

        with tempfile.TemporaryDirectory() as tmp:
            result = self._tampered(
                tmp, lambda d: self._edit_schema(d, "bundle-status.schema.json", drop_delivery_id)
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("bundle-status.schema.json examples[0]", result.stderr)
        self.assertIn("must accept bundle status last_good with a delivery_id of 128 bytes", result.stderr)

    def test_example_that_no_longer_validates_is_caught(self) -> None:
        def break_example(schema: dict) -> None:
            schema["examples"][0]["schema_version"] = 2

        with tempfile.TemporaryDirectory() as tmp:
            result = self._tampered(
                tmp, lambda d: self._edit_schema(d, "bundle-verify.schema.json", break_example)
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("bundle-verify.schema.json examples[0]", result.stderr)

    def test_missing_example_is_drift_not_a_crash(self) -> None:
        # The rules build their documents from fixed examples. Removing one,
        # or emptying a nested list a rule edits, is reported for that rule,
        # and the other rules still run.
        def drop_examples(contract_dir: Path) -> None:
            self._edit_schema(
                contract_dir, "anchors-install.schema.json", lambda s: s.update(examples=s["examples"][:1])
            )
            self._edit_schema(
                contract_dir, "secret-result.schema.json", lambda s: s["examples"][2].update(secrets=[])
            )
            self._edit_schema(contract_dir, "version.schema.json", lambda s: s.pop("additionalProperties"))

        with tempfile.TemporaryDirectory() as tmp:
            result = self._tampered(tmp, drop_examples)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("Traceback", result.stderr)
        self.assertIn("anchors-install.schema.json rule 'anchors install", result.stderr)
        self.assertIn("secret-result.schema.json rule 'secret status that carries a value'", result.stderr)
        self.assertIn("must reject version with a features list", result.stderr)

    def test_unlisted_schema_and_undescribed_schema_are_caught(self) -> None:
        def add_and_hide(contract_dir: Path) -> None:
            (contract_dir / "extra.schema.json").write_text(
                '{"$schema":"https://json-schema.org/draft/2020-12/schema"}\n', encoding="utf-8"
            )
            guide = contract_dir / "management-agent.md"
            guide.write_text(
                guide.read_text(encoding="utf-8").replace("`secret-result.schema.json`", "the secret schema"),
                encoding="utf-8",
            )

        with tempfile.TemporaryDirectory() as tmp:
            result = self._tampered(tmp, add_and_hide)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unlisted=['extra.schema.json']", result.stderr)
        self.assertIn("does not describe secret-result.schema.json", result.stderr)


class TestGalileoExportProfileSchema(unittest.TestCase):
    def test_profile_signals_match_galileo_preset(self) -> None:
        from defenseclaw.observability.presets import PRESETS

        doc = json.loads(GALILEO_PROFILE_SCHEMA.read_text(encoding="utf-8"))
        preset = PRESETS["galileo"]
        schema_signals = tuple(doc["properties"]["signals"]["const"])
        self.assertEqual(schema_signals, preset.default_signals)
        self.assertEqual(
            [
                (item["name"], tuple(item["required_attributes"]))
                for item in doc["properties"]["operations"]["const"]
            ],
            list(preset.span_filter_operations),
        )

    def test_profile_operations_match_runtime_contracts(self) -> None:
        profile = json.loads(GALILEO_PROFILE_SCHEMA.read_text(encoding="utf-8"))
        operations = profile["properties"]["operations"]["const"]
        schemas = {
            "chat": "runtime-llm-span.schema.json",
            "invoke_agent": "runtime-agent-span.schema.json",
            "execute_tool": "runtime-tool-span.schema.json",
        }
        for operation in operations:
            contract = json.loads(
                (SCHEMA_DIR / "otel" / schemas[operation["name"]]).read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(
                operation["required_attributes"],
                contract["x-required-attribute-keys"],
            )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
