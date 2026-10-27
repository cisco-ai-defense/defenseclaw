"""A per-user outage follows an explicit choice, then its policy tier."""

import pytest
import yaml
from defenseclaw.bootstrap import FirstRunOptions, _apply_first_run_choices, pin_cursor_posture
from defenseclaw.commands import cmd_init
from defenseclaw.config import (
    GuardrailConfig,
    PerConnectorGuardrailConfig,
    default_config,
    prepare_fresh_v8_config,
)


def test_per_user_hook_outage_mode_follows_the_policy_tier_for_every_connector() -> None:
    for connector in ("codex", "claudecode", "cursor", "copilot", "hermes", "amp", "opencode"):
        for saved, expected in (("open", "open"), ("closed", "closed"), ("", None)):
            for mode in ("observe", "action"):
                for tier in ("default", "strict", "permissive"):
                    gc = GuardrailConfig(mode=mode, rule_pack=tier)
                    gc.connectors[connector] = PerConnectorGuardrailConfig(hook_fail_mode=saved)
                    assert gc.effective_hook_fail_mode(connector) == (expected or ("closed" if tier == "strict" else "open"))


def test_first_run_cursor_does_not_save_a_tier_overriding_fail_mode() -> None:
    for mode, tier, expected in (("observe", "strict", "closed"), ("action", "default", "open")):
        gc = GuardrailConfig(connector="cursor", mode=mode, rule_pack=tier)
        pin_cursor_posture(gc, "cursor")
        assert gc.hook_fail_mode == "closed"
        assert gc.effective_hook_fail_mode("cursor") == expected
        assert gc.effective_hook_fail_mode("claudecode") == expected


@pytest.mark.parametrize(
    "mode,tier,expected", [("observe", "strict", "closed"), ("action", "default", "open")]
)
def test_init_cursor_writes_no_automatic_fail_mode(tmp_path, monkeypatch, mode, tier, expected) -> None:
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path))
    cfg = prepare_fresh_v8_config(default_config())
    cfg.guardrail.rule_pack = tier
    fail_mode = None
    if mode == "action":
        fail_mode, _, _ = cmd_init._prompt_action_policy(
            fail_mode=None, human_approval=False, hilt_min_severity=None
        )
    options = FirstRunOptions(connector="cursor", profile=mode, hook_fail_mode=fail_mode or "")
    _apply_first_run_choices(cfg, options, "cursor", mode, "both")
    cfg.save()
    saved = yaml.safe_load((tmp_path / "config.yaml").read_text(encoding="utf-8"))
    assert "hook_fail_mode" not in saved["guardrail"]
    assert cfg.guardrail.effective_hook_fail_mode("cursor") == expected
    assert cfg.guardrail.effective_hook_fail_mode("claudecode") == expected


def test_unloaded_default_config_uses_the_tier_outage_mode() -> None:
    gc = default_config().guardrail
    assert gc.effective_hook_fail_mode("claudecode") == "open"
    gc.rule_pack = "strict"
    assert gc.effective_hook_fail_mode("claudecode") == "closed"


def test_first_run_does_not_offer_a_per_user_open_choice(monkeypatch) -> None:
    def no_prompt(*_args, **_kwargs):
        raise AssertionError("first run offered an outage-open choice")

    monkeypatch.setattr(cmd_init.click, "prompt", no_prompt)
    mode, approval, severity = cmd_init._prompt_action_policy(
        fail_mode=None, human_approval=False, hilt_min_severity=None
    )
    assert (mode, approval, severity) == (None, False, None)
