# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Audit events of changes a command has already applied.

``skill block``, ``plugin block``/``install``, ``mcp set`` and ``guardrail judge add``
save the change first and record its audit event afterwards. With the
gateway stopped (or never started), the event used to end the command with
"Error: ... then run the command again", rc 1, after the change was already
applied (GAP-1811, GAP-1823). A stopped gateway now skips only the event,
with one warning per command run, like ``acp setup`` and ``registry add``.
A gateway that refuses the event still fails the command.
"""

from __future__ import annotations

from typing import Any

from defenseclaw import ux

_NOTED = False

GATEWAY_START_HINT = "start it with: defenseclaw-gateway start"


def not_recorded_warning(what: str = "the audit event") -> str:
    """The one wording for "the gateway is stopped, so *what* was skipped" (GAP-2267)."""
    return f"  ⚠ The gateway isn't running, so {what} was not recorded ({GATEWAY_START_HINT})."


NOT_RECORDED_WARNING = not_recorded_warning()


class _SavedChangeAudit:
    def __init__(self, logger: Any) -> None:
        self._logger = logger

    def _record(self, method: str, *args: Any, **kwargs: Any) -> None:
        from defenseclaw.logger import CanonicalObservabilityUnavailableError

        global _NOTED
        try:
            getattr(self._logger, method)(*args, **kwargs)
        except CanonicalObservabilityUnavailableError:
            if not _NOTED:
                _NOTED = True
                ux.echo(NOT_RECORDED_WARNING, err=True)

    def log_action(self, *args: Any, **kwargs: Any) -> None:
        self._record("log_action", *args, **kwargs)

    def log_config_change(self, *args: Any, **kwargs: Any) -> None:
        self._record("log_config_change", *args, **kwargs)

    def log_scan(self, *args: Any, **kwargs: Any) -> None:
        self._record("log_scan", *args, **kwargs)


def saved_change_audit(logger: Any) -> _SavedChangeAudit:
    """Wrap *logger* for the audit event of an already applied change."""
    return _SavedChangeAudit(logger)


def note_asset_policy_observed(
    logger: Any, decision: Any, *, target_type: str, name: str, connector: str = "",
) -> None:
    """Warn and audit an asset-policy would-block in observe mode (GAP-2390).

    Observe mode admits the asset, but operators must still see what action
    mode would refuse, both on screen and in the audit trail.
    """
    reason = getattr(decision, "observed_reason", "")
    if not reason:
        return
    source = getattr(decision, "observed_source", "")
    where = f" [{connector}]" if connector else ""
    ux.secho(
        ux.console_text(
            f"  ⚠ asset policy (observe){where}: {reason}; allowed now, "
            "action mode would block it."
        ),
        fg="yellow",
    )
    if logger:
        saved_change_audit(logger).log_action(
            "install-warning", name,
            f"type={target_type} connector={connector} mode=observe would-block "
            f"source={source} reason={reason}",
        )
