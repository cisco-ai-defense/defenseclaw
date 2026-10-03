# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Final-cert UX batch 17 (ux2): failed doctor names the failure first; the
open tab keeps its full name beside Alerts, Logs and Audit backlogs."""

from __future__ import annotations

import itertools
import sys
from pathlib import Path

import pytest
from defenseclaw.tui.app import PANELS
from defenseclaw.tui.command_line import command_result_summary, failure_result_summary
from defenseclaw.tui.widgets import tab_fit
from defenseclaw.tui.widgets.tab_fit import fit_tab_labels, strip_width

sys.path.insert(0, str(Path(__file__).resolve().parent))

import fixtures  # noqa: E402

DOCTOR_FAILED = [
    "[WARN] Connector compatibility: claudecode  -  hook version is older",
    "[PASS] Gateway",
    "[WARN] Connector hooks: codex  -  not installed",
    "[FAIL] Destination: u2t16-dead  -  connection failed",
    "[WARN] Connector OTLP: codex  -  partial drop-only evidence",
    "Health: 41 passed, 1 failed, 3 warnings, 13 skipped",
    "⚠ Fix the failures above, then re-run: defenseclaw doctor",
]


def test_failed_doctor_names_the_failing_check_first() -> None:
    # GAP-2419: two warnings ahead of the failure hid it behind "and N more".
    assert failure_result_summary("doctor", DOCTOR_FAILED) == (
        "Health: 41 passed, 1 failed, 3 warnings, 13 skipped · check: failed Destination: u2t16-dead, "
        "warning Connector compatibility: claudecode and 2 more"
    )
    # One kind only keeps the plain labels.
    warned = [line for line in DOCTOR_FAILED if not line.startswith("[FAIL]")]
    assert command_result_summary("doctor", warned).endswith(
        "check: Connector compatibility: claudecode, Connector hooks: codex and 1 more"
    )


@pytest.mark.parametrize("width", range(160, 181))
def test_open_tab_keeps_its_full_name_beside_alerts_logs_audit(monkeypatch, width) -> None:
    # GAP-2420: "V AI Discove…" at 172-180 with Alerts, Logs 999+ and Audit counts.
    monkeypatch.setattr(tab_fit, "_PLAIN_BADGE", False)
    for alerts, logs, audit in itertools.product((0, 22, 171, 1000), (0, 48, 1000), (0, 579, 1000)):
        unread = {k: v for k, v in (("alerts", alerts), ("logs", logs), ("audit", audit)) if v}
        for name, key, title in PANELS:
            labels = fit_tab_labels(PANELS, name, unread, width)
            assert labels[name].startswith(f"{key} {title}"), (width, unread, labels)
            assert strip_width(tuple(labels.values())) <= width


async def test_failed_doctor_drawer_at_80x24(tmp_path) -> None:
    app = fixtures.snapshot_app(tmp_path)
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        app._strip_running("doctor")  # noqa: SLF001
        for line in DOCTOR_FAILED:
            app._strip_output(line)  # noqa: SLF001
        app._strip_finished(exit_code=1, duration=0.1)  # noqa: SLF001
        await pilot.pause()
        assert "check: failed Destination: u2t16-dead" in app._strip_summary  # noqa: SLF001
