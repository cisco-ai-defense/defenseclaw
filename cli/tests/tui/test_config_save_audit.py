# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""GAP-2121: a TUI config-editor save records a config-update audit event."""

from __future__ import annotations

from defenseclaw.tui.services.config_audit import TUI_ACTOR, record_config_save
from defenseclaw.tui.services.setup_state import ConfigDiffEntry


class _Recorder:
    def __init__(self, fail: bool = False) -> None:
        self.calls: list[dict] = []
        self.fail = fail

    def log_activity(self, **kwargs) -> None:
        if self.fail:
            raise RuntimeError("gateway not running")
        self.calls.append(kwargs)


def test_save_records_each_changed_key_before_and_after() -> None:
    rec = _Recorder()
    entries = (
        ConfigDiffEntry("asset_policy.enabled", "false", "true"),
        ConfigDiffEntry("asset_policy.mode", "observe", "action"),
        ConfigDiffEntry("llm.api_key", "********", "********", secret=True),
    )

    assert record_config_save(object(), entries, logger_factory=lambda _cfg: rec)

    (call,) = rec.calls
    assert call["actor"] == TUI_ACTOR
    assert call["action"] == "config-update"
    assert call["target_type"] == "config"
    assert call["before"]["asset_policy.mode"] == "observe"
    assert call["after"]["asset_policy.enabled"] == "true"
    assert {"path": "asset_policy.mode", "op": "replace", "before": "observe", "after": "action"} in call["diff"]
    assert call["after"]["llm.api_key"] == "********"


def test_delivery_failure_never_fails_the_save() -> None:
    entries = (ConfigDiffEntry("asset_policy.enabled", "true", "false"),)
    assert record_config_save(object(), entries, logger_factory=lambda _cfg: _Recorder(fail=True)) is False
    assert record_config_save(object(), (), logger_factory=lambda _cfg: _Recorder()) is False
