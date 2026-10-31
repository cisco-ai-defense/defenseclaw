"""The Guardrail row leads with the judge state (GAP-0180)."""

from __future__ import annotations

from defenseclaw.tui.services.overview_state import (
    HealthSnapshot,
    OverviewConfig,
    OverviewPanelModel,
    SubsystemHealth,
)


def test_judge_fallbacks_come_before_the_port_and_pack() -> None:
    cfg = OverviewConfig(guardrail_enabled=True, guardrail_mode="action", guardrail_connector="claudecode")
    model = OverviewPanelModel(cfg, version="test")
    model.set_health(
        HealthSnapshot(
            guardrail=SubsystemHealth(
                state="running",
                details={
                    "judge_state": "degraded",
                    "judge_failed_calls": 9,
                    "judge_recent_calls": 20,
                    "judge_fallbacks": 6,
                },
            )
        )
    )
    detail = model.guardrail_detail()
    assert model.judge_fallbacks() == 6
    assert detail.startswith("action, judge degraded: 9/20 calls failed, judge fallbacks: 6")
