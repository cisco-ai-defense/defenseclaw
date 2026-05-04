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
   enum stays aligned with the four canonical connector names emitted
   by ``Connector.Name()`` in ``internal/gateway/connector``.
   Adding a connector and forgetting the schema means dashboards
   silently start dropping records — and the fresh-install empty
   placeholder ("") masks the failure on bench tests.
"""

from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "check_schemas.py"
SCHEMA_DIR = ROOT / "schemas"
RESOURCE_SCHEMA = SCHEMA_DIR / "otel" / "resource.schema.json"


class TestCheckSchemasResourceEnum(unittest.TestCase):
    def test_resource_schema_has_canonical_claw_mode_enum(self) -> None:
        """The released schema must list every connector emit() can produce."""
        doc = json.loads(RESOURCE_SCHEMA.read_text(encoding="utf-8"))
        enum = set(
            doc["properties"]["defenseclaw.claw.mode"].get("enum", [])
        )
        # Connector names from internal/gateway/connector/{openclaw,
        # zeptoclaw, claudecode, codex}.go plus the empty placeholder
        # for fresh installs that haven't picked a connector yet.
        self.assertEqual(
            enum,
            {"openclaw", "zeptoclaw", "claudecode", "codex", ""},
            "drift in defenseclaw.claw.mode enum — update Connector.Name() "
            "and the schema together; downstream APM dashboards pivot on this",
        )

    def test_legacy_modes_dropped(self) -> None:
        """Legacy placeholders that were never emitted must stay dropped.

        ``nemoclaw`` and ``opencode`` shipped in the schema before any
        connector by those names existed; allowing them back masks
        typos in operator config files and fails closed at the
        downstream consumer (silent drop of the resource record).
        """
        doc = json.loads(RESOURCE_SCHEMA.read_text(encoding="utf-8"))
        enum = set(
            doc["properties"]["defenseclaw.claw.mode"].get("enum", [])
        )
        self.assertNotIn("nemoclaw", enum)
        self.assertNotIn("opencode", enum)


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
                res.returncode, 0,
                f"check_schemas should have flagged the dropped connector\n"
                f"stdout={res.stdout}\nstderr={res.stderr}",
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
                res.returncode, 0,
                f"check_schemas should have flagged the legacy connector name\n"
                f"stdout={res.stdout}\nstderr={res.stderr}",
            )
            self.assertIn("nemoclaw", res.stderr)


class TestCheckSchemasCoversOtelTree(unittest.TestCase):
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
            self.assertIn("otel/metrics.schema.json", res.stderr)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
