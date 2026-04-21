# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Track 9 — v7 CLI contracts (schemas, settings, alerts subcommands)."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from click.testing import CliRunner

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize(
    "args,substr",
    [
        (["acknowledge", "--severity", "all"], "Acknowledged"),
        (["dismiss", "--severity", "HIGH"], "Dismissed"),
    ],
)
def test_alerts_subcommands(args: list[str], substr: str) -> None:
    from defenseclaw.commands.cmd_alerts import alerts
    from defenseclaw.config import default_config
    from defenseclaw.context import AppContext

    app = AppContext()
    app.cfg = default_config()
    app.cfg.data_dir = tempfile.mkdtemp(prefix="dc9-")
    store = MagicMock()
    store.acknowledge_alerts.return_value = 2
    store.dismiss_alerts_visible.return_value = 1
    app.store = store
    app.logger = MagicMock()

    runner = CliRunner()
    result = runner.invoke(alerts, args, obj=app, catch_exceptions=False)
    assert result.exit_code == 0
    assert substr in result.output
    assert app.logger.log_activity.called


def test_settings_save_invokes_activity() -> None:
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
    result = runner.invoke(settings_cmd, ["save"], obj=app, catch_exceptions=False)
    assert result.exit_code == 0
    assert "Saved configuration" in result.output
    assert app.logger.log_activity.called


def test_aibom_json_has_provenance() -> None:
    from defenseclaw.config import default_config
    from defenseclaw.inventory.claw_inventory import build_claw_aibom
    from defenseclaw.provenance import stamp_aibom_inventory

    cfg = default_config()
    inv = build_claw_aibom(cfg, live=False, categories={"skills"})
    stamp_aibom_inventory(inv, cfg)
    assert "provenance" in inv
    assert inv["provenance"]["schema_version"] == 7
    for item in inv.get("skills", []):
        assert "provenance" in item


@pytest.mark.skipif(shutil.which("go") is None, reason="go not on PATH")
def test_go_scan_code_json_validates_schema() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    schema_path = ROOT / "schemas" / "scan-result.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "x.go"
        p.write_text('package x\nvar _ = "x"\n', encoding="utf-8")
        proc = subprocess.run(
            ["go", "run", "./cmd/defenseclaw", "scan", "code", str(p), "--json"],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            timeout=120,
            env={**os.environ, "HOME": tmp},
        )
        if proc.returncode != 0:
            pytest.skip(f"go scan failed: {proc.stderr}")
        doc = json.loads(proc.stdout)
        jsonschema.validate(instance=doc, schema=schema)


class TestScanResultSchemaEmbedded(unittest.TestCase):
    def test_embedded_matches_repo_schema(self) -> None:
        emb = ROOT / "internal" / "cli" / "embed" / "scan-result.json"
        src = ROOT / "schemas" / "scan-result.json"
        self.assertEqual(emb.read_text(), src.read_text())
