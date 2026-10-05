# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Alerts, Audit and Activity display fixes (final-cert UX batch 5)."""

from __future__ import annotations

import sys
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from defenseclaw.commands import cmd_alerts, cmd_judge
from defenseclaw.hook_metrics import detection_only_hook_label
from defenseclaw.models import Event
from defenseclaw.tui.app import DefenseClawTUI
from defenseclaw.tui.panels import alerts as alerts_panel
from defenseclaw.tui.panels.alerts import alerts_from_v8_history
from defenseclaw.tui.panels.audit import AuditPanelModel, _row_details_label, _row_target_label
from defenseclaw.tui.services import read_repository
from defenseclaw.tui.services.v8_event_history import V8EventHistoryRow

from scripts.benchmark_tui_refresh import create_synthetic_v8_database

AT = datetime(2026, 10, 2, 11, 19, 54, tzinfo=timezone.utc)


def _row(row_id: str, payload: dict[str, object], *, action: str = "scan-finding") -> V8EventHistoryRow:
    return V8EventHistoryRow(
        id=row_id,
        timestamp=AT,
        bucket="security.finding",
        event_name="finding.observed",
        source="gateway",
        severity="HIGH",
        action=action,
        actor="gateway",
        details="",
        connector="claudecode",
        redaction_profile="sensitive",
        payload=payload,
    )


def test_message_display_finding_cannot_block_in_cli_and_tui() -> None:
    """GAP-1531: MessageDisplay runs async; its finding is never "observe mode"."""
    observed = ["connector=claudecode action=allow raw_action=block mode=action would_block=true"]
    label = "detected in the displayed reply (cannot block)"
    assert detection_only_hook_label("claudecode:MessageDisplay") == label
    assert cmd_alerts._hook_decision(observed, "claudecode:MessageDisplay") == label  # noqa: SLF001
    assert alerts_panel._hook_decision_from_rows(observed, "claudecode:MessageDisplay") == label  # noqa: SLF001
    # A pre-call event keeps the CLI's wording in the TUI too (GAP-1560).
    assert alerts_panel._hook_decision_from_rows(observed, "claudecode:UserPromptSubmit") == (  # noqa: SLF001
        "would block (observe mode)"
    )


async def test_shared_snapshot_alerts_get_the_hook_decision(tmp_path, monkeypatch) -> None:
    """GAP-1456/GAP-1560: background refreshes no longer reset the decision to "allow"."""
    path = tmp_path / "audit.db"
    create_synthetic_v8_database(path, 8)
    seen: list[object] = []

    def spy(store, events):
        seen.append(store)
        return [replace(event, facts=(("Decision", "would block (observe mode)"),)) for event in events]

    monkeypatch.setattr(read_repository, "with_hook_decisions", spy)
    repository = read_repository.TUIReadRepository(path)
    try:
        result = await repository.refresh()
    finally:
        repository.close()
    assert seen and seen[0] is not None
    assert result.snapshot is not None and result.snapshot.alert_events
    assert all(("Decision", "would block (observe mode)") in e.facts for e in result.snapshot.alert_events)


def test_sandbox_finding_detail_has_the_openshell_decision() -> None:
    """GAP-1532: the TUI shows decision=blocked like ``defenseclaw alerts``."""
    (alert,) = alerts_from_v8_history(
        (
            _row(
                "sb-1",
                {
                    "defenseclaw.finding.rule_id": "SANDBOX-OCSF-FINDING",
                    "defenseclaw.finding.title": "Provider credential used at an unauthorized endpoint",
                    "defenseclaw.guardrail.evidence_summary": 'FINDING:BLOCKED [HIGH] "Provider credential"',
                    "defenseclaw.sandbox.name": "rhs2-sb",
                },
                action="sandbox-finding",
            ),
        )
    )
    assert ("Decision", "blocked") in alert.facts
    assert alert.target == "rhs2-sb"


def _audit(action: str, structured: dict[str, object], *, details: str, at: datetime = AT, **kw) -> Event:
    return Event(
        id=f"{action}-{at.timestamp()}",
        timestamp=at,
        action=action,
        details=details,
        structured=structured,
        severity=kw.pop("severity", "CRITICAL"),
        connector=kw.pop("connector", "claudecode"),
        **kw,
    )


def test_audit_rows_name_the_call_and_blocks_lists_each_block_once() -> None:
    """GAP-1510: verdict and judge rows read like hook rows; Blocks is honest."""
    verdict = _audit(
        "guardrail-verdict",
        {
            "defenseclaw.acp.method": "session/prompt",
            "defenseclaw.guardrail.effective_action": "block",
            "defenseclaw.guardrail.rule_ids": ["SEC-AWS-KEY"],
        },
        details="guardrail.evaluation.completed",
        connector="opencode",
    )
    judge = _audit(
        "llm-judge-response",
        {"defenseclaw.judge.action": "block", "defenseclaw.judge.kind": "pii"},
        details="guardrail.judge.completed",
        severity="HIGH",
        enforced=True,
    )
    hook = _audit(
        "connector-hook",
        {},
        details="connector=claudecode action=block severity=CRITICAL mode=action",
        target="PreToolUse",
        at=AT + timedelta(milliseconds=16),
    )
    decision = _audit(
        "hook_decision",
        {"defenseclaw.guardrail.effective_action": "block", "defenseclaw.hook.event": "PreToolUse"},
        details="hook_decision",
    )
    assert _row_target_label(verdict) == "ACP session/prompt"
    assert _row_details_label(verdict) == "block · SEC-AWS-KEY"
    assert _row_target_label(judge) == "pii judge"
    assert _row_details_label(judge) == "judge: block"
    assert _row_target_label(decision) == "PreToolUse"

    model = AuditPanelModel()
    model.set_events([verdict, judge, hook, decision])
    model.set_common_filter("blocks")
    assert [event.action for event in model.filtered] == ["guardrail-verdict", "connector-hook"]


def test_audit_export_writes_a_new_file_each_time(tmp_path) -> None:
    """GAP-1533: a second export never replaces the first one."""
    model = AuditPanelModel()
    model.set_events([_audit("guardrail-verdict", {}, details="x")])
    app = DefenseClawTUI(data_dir=tmp_path, audit_model=model)
    first = app._export_audit(None)  # noqa: SLF001 - direct sync export
    second = app._export_audit(None)  # noqa: SLF001
    assert first != second and first.exists() and second.exists()
    assert first.name.startswith("defenseclaw-audit-export-") and first.suffix == ".json"


def test_alerts_hook_target_drops_the_connector_prefix() -> None:
    """GAP-1535: "UserPromptSubmit", not "...ptSubmit"; the connector is in Details."""
    assert cmd_alerts._short_hook_target("claudecode:UserPromptSubmit", "claudecode") == "UserPromptSubmit"  # noqa: SLF001
    assert cmd_alerts._short_hook_target("rhs2-sb", "claudecode") == "rhs2-sb"  # noqa: SLF001


def test_activity_mutations_name_what_changed(monkeypatch) -> None:
    """GAP-1511: webhook, judge and use-pack changes carry before -> after."""
    from defenseclaw.commands import cmd_setup_webhook

    app = SimpleNamespace(logger=MagicMock())
    cmd_setup_webhook._record_webhook_change(app, "Webhook disabled", "sf2r2-cap", "", "disabled", "enabled")  # noqa: SLF001
    assert app.logger.log_config_change.call_args.args == (
        "webhook",
        "scope=sf2r2-cap webhook=disabled previous=enabled",
    )

    gc = SimpleNamespace(enabled=False, judge=SimpleNamespace(hook_connectors=["claudecode"]))
    judge_app = SimpleNamespace(cfg=MagicMock(), logger=MagicMock())
    monkeypatch.setattr(cmd_judge, "_warn_if_inert", lambda *a: None)
    cmd_judge._save_and_restart(judge_app, gc, restart=False, action="add claudecode", previous="")  # noqa: SLF001
    assert judge_app.logger.log_config_change.call_args.args[1] == "hook_connectors=claudecode previous=(none)"
