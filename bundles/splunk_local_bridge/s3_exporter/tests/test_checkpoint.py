import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import export_splunk_to_s3 as exporter


def test_missing_checkpoint_returns_none(tmp_path):
    assert exporter.load_checkpoint(tmp_path / "checkpoint.json") is None


def test_saved_checkpoint_is_read_back(tmp_path):
    path = tmp_path / "state" / "checkpoint.json"

    exporter.save_checkpoint(path, "2026-05-06T12:00:00Z")

    assert exporter.load_checkpoint(path) == "2026-05-06T12:00:00Z"


def test_save_checkpoint_uses_temp_then_replace(tmp_path):
    path = tmp_path / "checkpoint.json"
    exporter.save_checkpoint(path, "2026-05-06T12:00:00Z")
    exporter.save_checkpoint(path, "2026-05-06T12:05:00Z")

    assert json.loads(path.read_text()) == {"latest": "2026-05-06T12:05:00Z"}
    assert not list(tmp_path.glob("*.tmp"))
