# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Audit event for a config save in the TUI config editor (GAP-2121).

The CLI records every setting change (``settings save``, ``guardrail mode``,
``registry`` edits), but a save in the TUI config editor wrote nothing, so
switching ``asset_policy.enabled`` / ``asset_policy.mode`` (which CLI
admission honours at once) left no trail. The save now records one
``config-update`` activity with each changed key's before/after. Values are
the editor's already-masked diff, so secrets never reach the event.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any

from defenseclaw.audit_actions import ACTION_CONFIG_UPDATE


def record_config_save(
    cfg: Any,
    entries: Sequence[Any],
    *,
    logger_factory: Callable[[Any], Any] | None = None,
) -> bool:
    """Record the saved *entries* (ConfigDiffEntry) as one activity event.

    Returns True when the gateway accepted the event. A stopped gateway or
    any other delivery failure returns False: the config is already saved,
    so the save itself must not fail on the audit hand-off.
    """

    if not entries:
        return False
    if logger_factory is None:
        from defenseclaw.logger import Logger

        logger_factory = Logger.from_config
    before = {str(e.key): str(e.before) for e in entries}
    after = {str(e.key): str(e.after) for e in entries}
    diff = [
        {"path": str(e.key), "op": "replace", "before": str(e.before), "after": str(e.after)}
        for e in entries
    ]
    try:
        from defenseclaw.config_writer import ACTOR_PREFIX_TUI, current_actor

        logger_factory(cfg).log_activity(
            actor=current_actor(ACTOR_PREFIX_TUI),
            action=ACTION_CONFIG_UPDATE,
            target_type="config",
            target_id="config.yaml",
            before=before,
            after=after,
            diff=diff,
        )
    except Exception:  # noqa: BLE001 - the save already happened; never fail it here.
        return False
    return True
