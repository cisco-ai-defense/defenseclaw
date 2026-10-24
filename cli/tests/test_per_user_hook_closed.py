"""A per-user hook's outage mode follows its policy tier, never a saved fail mode."""

from defenseclaw.commands import cmd_init
from defenseclaw.config import GuardrailConfig, PerConnectorGuardrailConfig


def test_per_user_hook_outage_mode_follows_the_policy_tier_for_every_connector() -> None:
    for connector in ("codex", "claudecode", "cursor", "copilot", "hermes", "amp", "opencode"):
        for saved in ("open", "closed", ""):
            for mode in ("observe", "action"):
                default = GuardrailConfig(hook_fail_mode=saved, mode=mode)
                default.connectors[connector] = PerConnectorGuardrailConfig(hook_fail_mode=saved)
                assert default.effective_hook_fail_mode(connector) == "open"
                strict = GuardrailConfig(hook_fail_mode=saved, mode=mode, rule_pack="strict")
                strict.connectors[connector] = PerConnectorGuardrailConfig(hook_fail_mode=saved)
                assert strict.effective_hook_fail_mode(connector) == "closed"


def test_first_run_does_not_offer_a_per_user_open_choice(monkeypatch) -> None:
    def no_prompt(*_args, **_kwargs):
        raise AssertionError("first run offered an outage-open choice")

    monkeypatch.setattr(cmd_init.click, "prompt", no_prompt)
    mode, approval, severity = cmd_init._prompt_action_policy(
        fail_mode=None, human_approval=False, hilt_min_severity=None
    )
    assert (mode, approval, severity) == ("closed", False, None)
