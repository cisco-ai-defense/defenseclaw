# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Track 9 — CLI contracts for schemas, settings, and alert review.

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
    """Alert review must use the canonical v8 protected-state API."""

    CASES = [
        (["acknowledge", "--severity", "all", "--yes"], "acknowledged", "Acknowledged"),
        (["dismiss", "--severity", "HIGH", "--yes"], "dismissed", "Dismissed"),
    ]

    def test_subcommands_route_through_protected_state_api(self) -> None:
        from defenseclaw.commands.cmd_alerts import alerts
        from defenseclaw.config import default_config, prepare_fresh_v8_config
        from defenseclaw.context import AppContext

        for args, disposition, substr in self.CASES:
            with self.subTest(args=args, disposition=disposition, substr=substr):
                app = AppContext()
                app.cfg = prepare_fresh_v8_config(default_config())
                app.cfg.audit_db = str(Path(tempfile.mkdtemp(prefix="dc-alert-db-")) / "audit.db")
                app.cfg.gateway.token = "test-alert-review-token"
                client = MagicMock()
                client.set_alert_disposition.side_effect = [
                    {
                        "_http_status": 200,
                        "matched": 3,
                        "selection_digest": "sha256:v1:" + "1" * 64,
                        "targets": [
                            {"id": "alert-a", "projection_version": 0},
                            {"id": "alert-b", "projection_version": 1},
                            {"id": "alert-c", "projection_version": 0},
                        ],
                    },
                    {
                        "_http_status": 200,
                        "matched": 3,
                        "applied": 2,
                        "no_change": 1,
                        "rejected": 0,
                        "failed": 0,
                    },
                ]

                runner = CliRunner()
                with unittest.mock.patch(
                    "defenseclaw.gateway.OrchestratorClient",
                    return_value=client,
                ):
                    result = runner.invoke(
                        alerts, args, obj=app, catch_exceptions=False
                    )
                self.assertEqual(result.exit_code, 0, msg=result.output)
                self.assertIn(substr, result.output)
                self.assertIn("Preview: 3 alert(s)", result.output)
                self.assertEqual(client.set_alert_disposition.call_count, 2)
                self.assertEqual(
                    client.set_alert_disposition.call_args_list[1].kwargs["disposition"],
                    disposition,
                )
                self.assertTrue(client.set_alert_disposition.call_args_list[0].kwargs["preview"])
                self.assertFalse(client.set_alert_disposition.call_args_list[1].kwargs["preview"])
                client.close.assert_called_once_with()

    def test_exact_id_dry_run_and_partial_failure_contracts(self) -> None:
        from defenseclaw.commands.cmd_alerts import alerts
        from defenseclaw.config import default_config, prepare_fresh_v8_config
        from defenseclaw.context import AppContext

        app = AppContext()
        app.cfg = prepare_fresh_v8_config(default_config())
        app.cfg.audit_db = str(Path(tempfile.mkdtemp(prefix="dc-alert-exact-")) / "audit.db")
        app.cfg.gateway.token = "test-alert-review-token"
        preview = {
            "_http_status": 200,
            "matched": 1,
            "selection_digest": "sha256:v1:" + "2" * 64,
            "targets": [{"id": "alert-a", "projection_version": 4}],
        }

        dry_client = MagicMock()
        dry_client.set_alert_disposition.return_value = preview
        with unittest.mock.patch("defenseclaw.gateway.OrchestratorClient", return_value=dry_client):
            result = CliRunner().invoke(
                alerts,
                ["dismiss", "--id", "alert-a", "--dry-run"],
                obj=app,
                catch_exceptions=False,
            )
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Dry run complete", result.output)
        dry_client.set_alert_disposition.assert_called_once()

        partial_client = MagicMock()
        partial_client.set_alert_disposition.side_effect = [
            preview,
            {
                "_http_status": 409,
                "matched": 1,
                "applied": 0,
                "no_change": 0,
                "rejected": 1,
                "failed": 0,
                "error": "one or more alert dispositions were rejected",
                "failures": [{"id": "alert-a", "code": "stale_projection_version"}],
            },
        ]
        with unittest.mock.patch("defenseclaw.gateway.OrchestratorClient", return_value=partial_client):
            result = CliRunner().invoke(
                alerts,
                ["acknowledge", "--id", "alert-a"],
                obj=app,
                catch_exceptions=False,
            )
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("matched=1 applied=0 no_change=0 rejected=1 failed=0", result.output)
        self.assertIn("stale_projection_version", result.output)

    def test_broad_mutation_requires_confirmation(self) -> None:
        from defenseclaw.commands.cmd_alerts import alerts
        from defenseclaw.config import default_config, prepare_fresh_v8_config
        from defenseclaw.context import AppContext

        app = AppContext()
        app.cfg = prepare_fresh_v8_config(default_config())
        app.cfg.audit_db = str(Path(tempfile.mkdtemp(prefix="dc-alert-confirm-")) / "audit.db")
        app.cfg.gateway.token = "test-alert-review-token"
        client = MagicMock()
        client.set_alert_disposition.return_value = {
            "_http_status": 200,
            "matched": 2,
            "selection_digest": "sha256:v1:" + "3" * 64,
            "targets": [],
        }
        with unittest.mock.patch("defenseclaw.gateway.OrchestratorClient", return_value=client):
            result = CliRunner().invoke(
                alerts,
                ["dismiss", "--connector", "codex"],
                input="n\n",
                obj=app,
                catch_exceptions=False,
            )
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("Apply dismissed to 2 matched alert(s)?", result.output)
        client.set_alert_disposition.assert_called_once()

    def test_audit_database_identity_distinguishes_disposable_homes(self) -> None:
        from defenseclaw.commands.cmd_alerts import _alert_audit_db_identity

        with tempfile.TemporaryDirectory(prefix="dc-home-a-") as home_a, tempfile.TemporaryDirectory(
            prefix="dc-home-b-"
        ) as home_b:
            first = _alert_audit_db_identity(str(Path(home_a) / "audit.db"))
            second = _alert_audit_db_identity(str(Path(home_b) / "audit.db"))
        self.assertNotEqual(first, second)
        self.assertTrue(first.startswith("sha256:v1:"))
        if os.name == "nt":
            vector_path = r"D:\__defenseclaw_identity_vector__\audit.db"
            expected = "sha256:v1:1991f13803f4111a45620ecb5426c7c2363444d9b961a312eacc86d851aed03f"
        else:
            vector_path = "/__defenseclaw_identity_vector__/audit.db"
            expected = "sha256:v1:edf22eb16e6d1bf09331b1581c9a33b4694ced26bf3f6c6085a7b06f83291c60"
        self.assertEqual(_alert_audit_db_identity(vector_path), expected)


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

    def test_settings_save_reports_managed_permission_error_without_traceback(self) -> None:
        from defenseclaw.commands.cmd_settings import settings_cmd
        from defenseclaw.config import default_config
        from defenseclaw.context import AppContext

        app = AppContext()
        app.cfg = default_config()
        app.cfg.data_dir = tempfile.mkdtemp(prefix="dc9-")
        app.cfg.save = MagicMock(
            side_effect=PermissionError(
                "managed_enterprise config changes require operating-system "
                "administrator privileges"
            )
        )
        app.logger = MagicMock()

        result = CliRunner().invoke(
            settings_cmd,
            ["save"],
            obj=app,
            catch_exceptions=False,
        )

        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("Failed to save config", result.output)
        self.assertIn("administrator privileges", result.output)
        self.assertNotIn("Traceback", result.output)
        app.logger.log_activity.assert_not_called()


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
        go_paths = subprocess.run(
            ["go", "env", "-json", "GOCACHE", "GOMODCACHE"],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            # Hosted Windows runners execute the Python and Go matrices in
            # parallel and can take more than 30 seconds merely to schedule a
            # new Go process. Keep a firm bound, but allow the same headroom as
            # other metadata/bootstrap subprocesses before declaring a hang.
            timeout=90,
            check=True,
        )
        go_cache = json.loads(go_paths.stdout)
        with tempfile.TemporaryDirectory() as tmp:
            isolated_home = Path(tmp) / "home"
            data_dir = isolated_home / ".defenseclaw"
            data_dir.mkdir(parents=True)
            config_path = data_dir / "config.yaml"
            config_path.write_text(
                "config_version: 8\n"
                f"data_dir: {json.dumps(str(data_dir))}\n"
                "observability: {}\n",
                encoding="utf-8",
            )
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
                timeout=180,
                env={
                    **os.environ,
                    "HOME": str(isolated_home),
                    "DEFENSECLAW_HOME": str(data_dir),
                    "DEFENSECLAW_CONFIG": str(config_path),
                    "GOCACHE": go_cache["GOCACHE"],
                    "GOMODCACHE": go_cache["GOMODCACHE"],
                },
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            doc = json.loads(proc.stdout)
            jsonschema.validate(instance=doc, schema=schema)


class TestScanResultSchemaEmbedded(unittest.TestCase):
    def test_embedded_matches_repo_schema(self) -> None:
        emb = ROOT / "internal" / "cli" / "embed" / "scan-result.json"
        src = ROOT / "schemas" / "scan-result.json"
        self.assertEqual(emb.read_text(), src.read_text())


if __name__ == "__main__":
    unittest.main()
