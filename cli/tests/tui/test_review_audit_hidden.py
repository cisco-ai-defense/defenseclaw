# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""An Audit view that hides routine events says so and how to show them."""

from __future__ import annotations

from defenseclaw.models import Event
from defenseclaw.tui.panels.audit import AuditPanelModel


def _routine(index: int) -> Event:
    return Event(action="gateway-start", target=f"gateway-{index}", severity="INFO", details="started")


def test_hidden_routine_events_are_counted_and_explained() -> None:
    model = AuditPanelModel()
    model.set_events([_routine(1), _routine(2)])

    assert model.filtered == []
    assert model.hidden_routine_count() == 2
    assert "2 routine hidden, 1 shows all" in model.toolbar_state().summary_label
    assert "Press 1 to show all events" in model.render_text()

    model.handle_key("1")
    assert len(model.filtered) == 2
    assert model.hidden_routine_count() == 0
    assert "routine hidden" not in model.toolbar_state().summary_label
