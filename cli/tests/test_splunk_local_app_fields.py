"""Splunk local-mode app: each field is extracted once, not twice (GAP-0039)."""

from __future__ import annotations

import configparser
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
APP = ROOT / "bundles/splunk_local_bridge/splunk/apps/defenseclaw_local_mode/default"
EXPORTER = ROOT / "bundles/splunk_local_bridge/s3_exporter/export_splunk_to_s3.py"


def _conf(name: str) -> configparser.RawConfigParser:
    parser = configparser.RawConfigParser(strict=True, interpolation=None)
    parser.optionxform = str
    parser.read(APP / name, encoding="utf-8")
    return parser


def test_macros_do_not_run_spath_on_top_of_kv_mode_json() -> None:
    # KV_MODE=json already extracts every field at search time; spath extracts it
    # again, so every multivalue field doubles and so does every count by it.
    macros = _conf("macros.conf")
    assert len(macros.sections()) > 20
    for name in macros.sections():
        assert not re.search(r"\bspath\b", macros[name]["definition"]), name
    assert not re.search(r"^\s*\|\s*spath\s*$", EXPORTER.read_text(encoding="utf-8"), re.MULTILINE)


def test_every_sourcetype_the_macros_search_extracts_json_once() -> None:
    props = _conf("props.conf")
    macros = _conf("macros.conf")
    searched = set()
    for name in macros.sections():
        searched.update(re.findall(r'sourcetype\s*=\s*"([^"]+)"', macros[name]["definition"]))
    assert searched
    for sourcetype in sorted(searched):
        assert props[sourcetype]["KV_MODE"] == "json", sourcetype
