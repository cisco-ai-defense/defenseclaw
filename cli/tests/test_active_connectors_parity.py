"""Go and Python resolve the same connector set for the same config (GAP-0707).

The cases live in test/testdata/active-connectors.json; the Go side is
internal/config TestActiveConnectorsParityFixture.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from defenseclaw import config as dcconfig

_FIXTURE = Path(__file__).resolve().parents[2] / "test" / "testdata" / "active-connectors.json"
_CASES = json.loads(_FIXTURE.read_text(encoding="utf-8"))["cases"]


@pytest.mark.parametrize("case", _CASES, ids=[case["name"] for case in _CASES])
def test_python_resolves_what_the_shared_fixture_says(case: dict, tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("USERPROFILE", str(tmp_path / "home"))
    monkeypatch.delenv("DEFENSECLAW_CONFIG", raising=False)
    (tmp_path / "config.yaml").write_text(
        f"config_version: 9\ndata_dir: {json.dumps(str(tmp_path))}\n" + case["config"], encoding="utf-8"
    )
    cfg = dcconfig.load(data_dir=tmp_path)
    assert cfg.active_connector() == case["primary"]
    assert cfg.active_connectors() == case["roster"]
    assert cfg.policy_connectors() == case["policy"]
    for connector, pack in case.get("rule_pack", {}).items():
        assert cfg.guardrail.effective_rule_pack(connector) == pack
