# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Final-cert TUI fixes, batch 9: tab strip, Overview with the gateway down, uninstall chooser."""

from __future__ import annotations

import io
import re
import sys
from pathlib import Path

from defenseclaw.tui.app import PANELS
from defenseclaw.tui.screens.uninstall import build_uninstall_model
from defenseclaw.tui.services.overview_state import HealthSnapshot
from defenseclaw.tui.services.runtime_state import RuntimeSnapshot
from defenseclaw.tui.widgets import tab_fit
from defenseclaw.tui.widgets.tab_fit import fit_tab_labels, strip_width
from rich.console import Console

sys.path.insert(0, str(Path(__file__).parent))

from fixtures import snapshot_app  # noqa: E402

_COUNT = re.compile(r"(\([0-9+]+\)|[⁰¹²³⁴⁵⁶⁷⁸⁹⁺]+)$")


def _plain(renderable: object) -> str:
    console = Console(file=io.StringIO(), width=160, color_system=None)
    console.print(renderable)
    return console.file.getvalue()


def test_badges_never_blank_or_rename_tabs_at_160_columns(monkeypatch) -> None:
    # GAP-2301: at 160 columns (a 146-cell strip) Logs/Activity badges left
    # "5" bare and turned "4 MCP" into "4 MCPs"; one Activity badge turned
    # "3 Skills" into "3 Skill".
    monkeypatch.setattr(tab_fit, "_PLAIN_BADGE", False)
    names = {name: _COUNT.sub("", label) for name, label in fit_tab_labels(PANELS, "overview", {}, 146).items()}
    assert all(" " in label for label in names.values()), names
    for unread in ({"alerts": 22}, {"alerts": 22, "activity": 1}, {"alerts": 22, "logs": 37, "activity": 5, "ai": 1}):
        fits = {name: fit_tab_labels(PANELS, name, {**unread, name: 0}, 146) for name, _key, _title in PANELS}
        for active, labels in fits.items():
            assert strip_width(tuple(labels.values())) <= 146
            for name, label in labels.items():
                if name != active:
                    # A Logs backlog may leave the least important tab a bare
                    # key so the open tab reads in full (GAP-2460); a tab is
                    # never renamed.
                    bare = "logs" in unread and _COUNT.sub("", label) == label.split(" ")[0]
                    assert bare or _COUNT.sub("", label) == names[name], (unread, active, label)
        assert fits["overview"]["alerts"] == "2 Alerts²²"
    assert fits["overview"]["logs"] == "8 Log³⁷"


def test_bare_alerts_key_reads_the_same_on_every_panel_at_80_columns(monkeypatch) -> None:
    # GAP-2301: at 80x24 Overview read "2(22)" but Setup "2²²".
    monkeypatch.setattr(tab_fit, "_PLAIN_BADGE", False)
    for active, _key, _title in PANELS:
        if active != "alerts":
            labels = fit_tab_labels(PANELS, active, {"alerts": 22}, 66)
            assert strip_width(tuple(labels.values())) <= 66
            assert labels["alerts"].endswith("(22)"), (active, labels)


def test_overview_with_the_gateway_down_drops_uptime_and_dates_the_last_sample(tmp_path) -> None:
    # GAP-2302: "uptime=91s" and "Last sample 34s ago" froze while the
    # gateway stayed down.
    app = snapshot_app(tmp_path)
    app.overview_model.set_health(HealthSnapshot(uptime_ms=91_000))
    app.runtime_model.snapshot = RuntimeSnapshot(scanned_at="2026-10-03T06:00:05Z")
    app.overview_model.set_gateway_probe("running")
    assert "up 1m" in _plain(app._overview_renderable())  # noqa: SLF001
    app.overview_model.set_gateway_probe("stopped")
    assert "up 1m" not in _plain(app._overview_renderable())  # noqa: SLF001
    runtime = _plain(app._overview_runtime_panel())  # noqa: SLF001
    assert re.search(r"Last sample at (\d\d:\d\d:\d\d|Oct 0[23] \d\d:\d\d); it", runtime), runtime
    assert " ago" not in runtime


def test_uninstall_chooser_hint_says_which_keys_run_and_which_select() -> None:
    # GAP-2303: "press a row's key" while [u] only selects and [p] runs.
    hint = build_uninstall_model().default_hint
    assert hint.startswith("p runs now") and "u/a/e select, then enter twice runs" in hint
    assert "row's key" not in hint and hint.endswith("esc cancel")
