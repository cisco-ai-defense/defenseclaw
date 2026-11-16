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
    assert detail.startswith("action, fallbacks 6, judge degraded: 9/20 calls failed")


async def test_fallbacks_count_is_on_screen_at_80x24_and_120x40(tmp_path) -> None:
    # rc18 (TST-4746): 160x45 showed "judge fallbacks: 44"; 120x40 cut the
    # wrapped SERVICES row before it and 80x24 showed only "action …".
    import re
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).parent))
    from fixtures import screen_text, settle_panel, snapshot_app

    details = {"judge_state": "failing", "judge_failed_calls": 20, "judge_recent_calls": 20, "judge_fallbacks": 44}
    for size in ((80, 24), (120, 40)):
        (tmp_path / f"{size[0]}x{size[1]}").mkdir()
        app = snapshot_app(tmp_path / f"{size[0]}x{size[1]}")
        health = app.overview_model.health
        health.guardrail.details.update(details)
        async with app.run_test(size=size) as pilot:
            await settle_panel(app, pilot)
            app._render_chrome()  # noqa: SLF001
            await pilot.pause()
            screen = screen_text(app)
        # The old long form counts too: the bar is that the number is on screen.
        assert re.search(r"fallbacks:? 44\b", screen), (size, screen)
