# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""GAP-1126: routing denials have routing.* audit actions and are not guardrail blocks."""

from __future__ import annotations

from datetime import datetime, timezone

from defenseclaw import audit_actions
from defenseclaw.db import Store
from defenseclaw.models import Event
from defenseclaw.tui.panels.audit import audit_action_display


def test_routing_denial_actions_are_registered() -> None:
    assert audit_actions.ACTION_ROUTING_ADMIN_DENIED == "routing.admin_denied"
    assert audit_actions.ACTION_ROUTING_SENSITIVE_REFUSED == "routing.sensitive_refused"
    for action in (audit_actions.ACTION_ROUTING_ADMIN_DENIED, audit_actions.ACTION_ROUTING_SENSITIVE_REFUSED):
        assert action in audit_actions.ALL_ACTIONS


def test_routing_denials_are_not_counted_as_blocks(tmp_path) -> None:
    store = Store(str(tmp_path / "audit.db"))
    store.init()
    now = datetime.now(timezone.utc)
    try:
        for index, (action, target) in enumerate(
            (
                ("routing.admin_denied", "routing.admin"),
                ("routing.sensitive_refused", "routing.sensitive"),
                ("inspect-request-block", "pre-request"),
            )
        ):
            store.log_event(
                Event(
                    id=f"r-{index}",
                    timestamp=now,
                    action=action,
                    target=target,
                    severity="MEDIUM",
                    details="routing refused the model request: routing_admin_denied path=/v1/messages",
                )
            )
        blocks = store.list_block_event_summaries()
    finally:
        store.close()
    assert [event.action for event in blocks] == ["inspect-request-block"]
    # The Audit panel labels any "*block*" action BLOCK; routing rows are not.
    for action in ("routing.admin_denied", "routing.sensitive_refused"):
        assert audit_action_display(action)[0] != "BLOCK"
    assert audit_action_display("inspect-request-block")[0] == "BLOCK"
