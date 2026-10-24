"""Per-user hooks cannot inherit an old outage-open configuration."""

from defenseclaw.commands import cmd_init
from defenseclaw.config import GuardrailConfig, PerConnectorGuardrailConfig


def test_per_user_hook_fail_mode_is_closed_for_every_connector() -> None:
    guardrail = GuardrailConfig(hook_fail_mode="open")
    for connector in ("codex", "claudecode", "cursor", "amp", "opencode"):
        guardrail.connectors[connector] = PerConnectorGuardrailConfig(hook_fail_mode="open")
        for mode in ("observe", "action"):
            guardrail.mode = mode
            assert guardrail.effective_hook_fail_mode(connector) == "closed"


def test_first_run_does_not_offer_a_per_user_open_choice(monkeypatch) -> None:
    def no_prompt(*_args, **_kwargs):
        raise AssertionError("first run offered an outage-open choice")

    monkeypatch.setattr(cmd_init.click, "prompt", no_prompt)
    mode, approval, severity = cmd_init._prompt_action_policy(
        fail_mode=None, human_approval=False, hilt_min_severity=None
    )
    assert (mode, approval, severity) == ("closed", False, None)
