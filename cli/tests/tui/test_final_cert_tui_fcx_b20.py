# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Config editor Lenient hint and notifications modal state labels (final-cert batch 20)."""

from __future__ import annotations

from defenseclaw.tui.panels.setup import _scanners_section
from defenseclaw.tui.screens.notifications import build_notifications_model


def test_lenient_hint_describes_malformed_skill_tolerance() -> None:
    # GAP-2573: the hint said "Downgrade findings by one severity.", but
    # lenient only decides whether malformed skills are scanned or failed.
    field = next(f for f in _scanners_section(None).fields if f.key == "scanners.skill_scanner.lenient")
    assert "malformed skills" in field.hint
    assert "severity" not in field.hint.lower()


def test_notifications_modal_uses_one_label_per_state() -> None:
    # GAP-2574: ON and OFF were worded differently as the current state and
    # as the target, so the OFF->ON modal did not mirror the ON->OFF one.
    to_off = build_notifications_model(True, "Linux").summary.splitlines()
    to_on = build_notifications_model(False, "Linux").summary.splitlines()
    on, off = to_off[0].split(": ", 1)[1], to_off[1].split(":", 1)[1].strip()
    assert on.startswith("ON (") and off.startswith("OFF (")
    assert to_on == [f"Current state: {off}", f"Will become:   {on}"]
