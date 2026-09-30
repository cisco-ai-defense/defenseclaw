# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Sandboxes says what to do when the daemon is down and hides dead keys."""

from __future__ import annotations

from defenseclaw.tui.services.sandbox_state import SandboxesPanelModel, sandbox_keys_hint


def test_unreachable_daemon_gets_a_next_step() -> None:
    model = SandboxesPanelModel()
    model.set_error("no gateway API port is configured")

    assert model.state() == "unreachable"
    assert "defenseclaw doctor" in model.empty_state()


def test_empty_sandbox_list_does_not_advertise_row_keys() -> None:
    empty = sandbox_keys_hint("sandboxes", has_rows=False)

    assert "connect" not in empty and "delete" not in empty
    assert "connect" in sandbox_keys_hint("sandboxes")
