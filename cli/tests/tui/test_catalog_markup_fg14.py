"""Catalog body markup stays valid when an empty source has brackets."""

from __future__ import annotations

import io
import sys
from pathlib import Path

from defenseclaw.tui.panels.mcps import MCPsPanelModel
from rich.console import Console

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fixtures import snapshot_app  # noqa: E402


def test_empty_mcps_panel_renders_bracketed_source_at_80x24(tmp_path) -> None:
    app = snapshot_app(tmp_path)
    app.mcps_model = MCPsPanelModel(connector="codex")
    app.catalog_models["mcps"] = app.mcps_model
    app.mcps_model.apply_loaded(())
    app.active_panel = "mcps"

    body = app._body_text()
    rendered = app._safe_body_renderable(body)
    console = Console(file=io.StringIO(), width=80, height=24, record=True)
    console.print(rendered)
    plain = console.export_text(styles=False)

    assert plain.startswith("MCPs")
    assert "[mcp_servers]" in plain
    assert "[bold" not in plain and "#22D3EE]" not in plain
