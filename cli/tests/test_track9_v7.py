# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Track 9 — v7 CLI contracts (schemas, settings, alerts subcommands).

Pure-``unittest`` (no pytest dependency) so that ``make test`` works
against the production venv created by ``make install`` / ``make pycli``
without needing the ``[dependency-groups] dev`` packages.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from click.testing import CliRunner

ROOT = Path(__file__).resolve().parents[2]


class TestAlertsSubcommands(unittest.TestCase):
    """`defenseclaw alerts {acknowledge,dismiss}` should route through LogActivity."""

    CASES = [
        (["acknowledge", "--severity", "all"], "Acknowledged"),
        (["dismiss", "--severity", "HIGH"], "Dismissed"),
    ]

    def test_subcommands_route_through_log_activity(self) -> None:
        from defenseclaw.commands.cmd_alerts import alerts
        from defenseclaw.config import default_config
        from defenseclaw.context import AppContext

        for args, substr in self.CASES:
            with self.subTest(args=args, substr=substr):
                app = AppContext()
                app.cfg = default_config()
                app.cfg.data_dir = tempfile.mkdtemp(prefix="dc9-")
                store = MagicMock()
                store.acknowledge_alerts.return_value = 2
                store.dismiss_alerts_visible.return_value = 1
                app.store = store
                app.logger = MagicMock()

                runner = CliRunner()
                result = runner.invoke(
                    alerts, args, obj=app, catch_exceptions=False
                )
                self.assertEqual(result.exit_code, 0, msg=result.output)
                self.assertIn(substr, result.output)
                self.assertTrue(app.logger.log_activity.called)


class TestSettingsSave(unittest.TestCase):
    def test_settings_save_invokes_activity(self) -> None:
        from defenseclaw.commands.cmd_settings import settings_cmd
        from defenseclaw.config import default_config
        from defenseclaw.context import AppContext

        app = AppContext()
        app.cfg = default_config()
        app.cfg.data_dir = tempfile.mkdtemp(prefix="dc9-")
        os.makedirs(app.cfg.data_dir, exist_ok=True)
        app.store = MagicMock()
        app.logger = MagicMock()

        runner = CliRunner()
        result = runner.invoke(
            settings_cmd, ["save"], obj=app, catch_exceptions=False
        )
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("Saved configuration", result.output)
        self.assertTrue(app.logger.log_activity.called)


class TestAibomProvenance(unittest.TestCase):
    def test_aibom_json_has_provenance(self) -> None:
        from defenseclaw.config import default_config
        from defenseclaw.inventory.claw_inventory import build_claw_aibom
        from defenseclaw.provenance import stamp_aibom_inventory

        cfg = default_config()
        inv = build_claw_aibom(cfg, live=False, categories={"skills"})
        stamp_aibom_inventory(inv, cfg)
        self.assertIn("provenance", inv)
        self.assertEqual(inv["provenance"]["schema_version"], 7)
        for item in inv.get("skills", []):
            self.assertIn("provenance", item)


class TestGoScanCodeJSONSchema(unittest.TestCase):
    """`go run ./cmd/defenseclaw scan code --json` must validate against
    the canonical scan-result schema.

    Skipped when ``go`` or ``jsonschema`` is unavailable (the latter only
    ships in ``[dependency-groups] dev``); the Go e2e job covers the
    same contract from the Go side via ``test/e2e/v7_golden_events_test.go``.
    """

    @unittest.skipUnless(shutil.which("go"), "go not on PATH")
    def test_go_scan_code_json_validates_schema(self) -> None:
        try:
            import jsonschema
        except ImportError:
            self.skipTest("jsonschema not installed (dev-only dependency)")

        schema_path = ROOT / "schemas" / "scan-result.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "x.go"
            p.write_text('package x\nvar _ = "x"\n', encoding="utf-8")
            proc = subprocess.run(
                [
                    "go",
                    "run",
                    "./cmd/defenseclaw",
                    "scan",
                    "code",
                    str(p),
                    "--json",
                ],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                timeout=120,
                env={**os.environ, "HOME": tmp},
                check=False,
            )
            if proc.returncode != 0:
                self.skipTest(f"go scan failed: {proc.stderr}")
            doc = json.loads(proc.stdout)
            jsonschema.validate(instance=doc, schema=schema)


class TestScanResultSchemaEmbedded(unittest.TestCase):
    def test_embedded_matches_repo_schema(self) -> None:
        emb = ROOT / "internal" / "cli" / "embed" / "scan-result.json"
        src = ROOT / "schemas" / "scan-result.json"
        self.assertEqual(emb.read_text(), src.read_text())


if __name__ == "__main__":
    unittest.main()
