"""Final-cert TUI fixes, batch 31 (GAP-2508, GAP-2509)."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from defenseclaw.tui.app import DefenseClawTUI, _config_label_cells
from defenseclaw.tui.panels.setup import admission_action_fields


@pytest.mark.parametrize("asset_type", ["skill", "mcp", "plugin"])
@pytest.mark.parametrize("room", [20, 30, 34])
def test_admission_header_reads_whole(asset_type: str, room: int) -> None:
    header = admission_action_fields(asset_type, {})[0]

    label, value = _config_label_cells(header, room, room)

    assert "…" not in label + value
    assert label.startswith(".. ") and label.endswith(" ..")
    assert asset_type.upper() in label
    assert len(label) <= room and len(value) <= 12


def test_overview_signature_changes_with_width(monkeypatch: pytest.MonkeyPatch) -> None:
    app = DefenseClawTUI()
    app.body_text = "Agents 9 configured"
    size = SimpleNamespace(width=80, height=60)
    monkeypatch.setattr(DefenseClawTUI, "size", property(lambda _self: size))

    narrow = app._overview_body_signature()
    size.width = 140

    assert app._overview_body_signature() != narrow
