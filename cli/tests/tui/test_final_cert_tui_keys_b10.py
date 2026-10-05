"""GAP-2254: the TUI keys-remove confirm names the feature a REQUIRED key breaks."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from defenseclaw.config import Config, GuardrailConfig  # noqa: E402
from defenseclaw.tui.command_line import ParsedCommand  # noqa: E402
from defenseclaw.tui.panels.setup import SetupPanelModel, SetupWizard, wizard_goals  # noqa: E402
from defenseclaw.tui.screens.command_preview import build_command_preview  # noqa: E402


def _remove_intent(cfg, env_name):
    model = SetupPanelModel(cfg)
    goal = next(goal for goal in wizard_goals(SetupWizard.CREDENTIALS, {}) if goal.id == "remove")
    model.open_wizard_form(SetupWizard.CREDENTIALS, goal=goal)
    model.form_fields = [
        field.with_value(env_name) if field.label == "Env Name" else field for field in model.form_fields
    ]
    action = model.submit_wizard_form()
    assert action.intent is not None and action.intent.label == "keys remove"
    return action.intent


def test_remove_confirm_names_the_feature_a_required_key_breaks(tmp_path, monkeypatch) -> None:
    (tmp_path / ".env").write_text("CISCO_AI_DEFENSE_API_KEY=c1\nOLD_TYPO_KEY=x\n")
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path))
    monkeypatch.delenv("CISCO_AI_DEFENSE_API_KEY", raising=False)
    cfg = Config(data_dir=str(tmp_path), guardrail=GuardrailConfig(enabled=True, scanner_mode="remote"))
    intent = _remove_intent(cfg, "CISCO_AI_DEFENSE_API_KEY")
    assert "REQUIRED by guardrail.remote" in intent.consequence
    parsed = ParsedCommand(
        binary=intent.binary,
        args=intent.args,
        display_name=intent.label,
        category=intent.category,
        consequence=intent.consequence,
    )
    assert "guardrail.remote stops working" in build_command_preview(parsed).consequence
    assert _remove_intent(cfg, "OLD_TYPO_KEY").consequence == ""
