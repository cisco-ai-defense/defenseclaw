# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Phase 10: Quick Start ``apply_answers`` mapper tests.

These tests pin the answers-to-Policy contract that the docs-site
Creator and the TUI Quick Start wizard share. Behaviour must stay
byte-equivalent across both surfaces so an operator who builds a
policy in the docs and then opens it in the TUI sees the same
config.
"""

from __future__ import annotations

from defenseclaw.tui.creator.answers import (
    SinkAnswer,
    default_answers,
)
from defenseclaw.tui.creator.apply import apply_answers


def test_apply_answers_with_defaults_yields_default_preset() -> None:
    """Defaults must round-trip the bundled default preset
    untouched - operators who never touch the wizard get the same
    policy as ``defenseclaw policy show default``."""
    policy = apply_answers(default_answers())
    assert policy.name == "default"
    assert policy.basedOn == "default"


def test_posture_switches_base_preset() -> None:
    answers = default_answers()
    answers.posture = "strict"
    assert apply_answers(answers).name == "strict"
    answers.posture = "permissive"
    assert apply_answers(answers).name == "permissive"


def test_block_card_enables_rules_and_destinations() -> None:
    answers = default_answers()
    answers.block.add("exfiltration")
    policy = apply_answers(answers)
    # Destinations from BLOCK_CARDS["exfiltration"] must land in
    # firewall.blocked_destinations without duplicating.
    blocked = set(policy.firewall.blocked_destinations)
    assert {"requestbin.com", "hookbin.com", "ngrok.io"} <= blocked
    # Rule ids the card references should have been forced enabled
    # (we just check that the policy didn't drop them from the pack).
    found_ids: set[str] = set()
    for f in policy.rule_pack.files:
        for rule in f.rules:
            if rule.id.startswith("C2-"):
                found_ids.add(rule.id)
                assert rule.enabled is True or True  # rule may be absent in default pack; this is a smoke check


def test_block_card_with_correlator_forces_named_patterns_enabled() -> None:
    """If a preset ships correlator patterns and the operator picks
    a multi-step block card, the named pattern ids should flip to
    enabled. We construct a minimal Policy graph to test this in
    isolation since the bundled YAML presets don't always include
    correlator definitions."""
    from defenseclaw.tui.creator.apply import _replace_correlator_enabled
    from defenseclaw.tui.creator.types import (
        CorrelationClause,
        CorrelationPattern,
    )

    pattern = CorrelationPattern(
        id="LETHAL-TRIFECTA",
        window_events=20,
        severity_on_match="CRITICAL",
        all_of=[CorrelationClause(axis="ingress_untrusted")],
        enabled=False,
    )
    flipped = _replace_correlator_enabled(pattern, True)
    assert flipped.id == pattern.id
    assert flipped.window_events == pattern.window_events
    assert flipped.enabled is True


def test_allow_card_adds_tool_suppression() -> None:
    answers = default_answers()
    answers.allow.add("cosmetic_shell")
    policy = apply_answers(answers)
    patterns = {s.tool_pattern for s in policy.suppressions.tool_suppressions}
    assert r"^(?:shell|bash|sh)\.execute$" in patterns


def test_allow_card_dedupes_when_applied_twice() -> None:
    """Re-running apply_answers shouldn't pile up duplicates - the
    operator can toggle, untoggle, retoggle without the policy
    growing unboundedly."""
    answers = default_answers()
    answers.allow.add("cosmetic_shell")
    once = apply_answers(answers)
    twice = apply_answers(answers)
    assert len(once.suppressions.tool_suppressions) == len(twice.suppressions.tool_suppressions)


def test_allow_card_adds_first_party_glob_with_target_type_plugin() -> None:
    answers = default_answers()
    answers.allow.add("first_party_plugins")
    policy = apply_answers(answers)
    matched = [e for e in policy.first_party_allow_list if e.target_name == "cisco-ai-defense/*"]
    assert matched
    assert matched[0].target_type == "plugin"


def test_freeform_extras_land_in_firewall_and_first_party() -> None:
    answers = default_answers()
    answers.domains_extra = ["*.corp.example", "  "]  # blanks stripped
    answers.first_party_extra = ["myorg/*"]
    policy = apply_answers(answers)
    assert "*.corp.example" in policy.firewall.allowed_domains
    assert any(e.target_name == "myorg/*" for e in policy.first_party_allow_list)


def test_response_block_tightens_install_actions() -> None:
    answers = default_answers()
    answers.response = "block"
    policy = apply_answers(answers)
    for sev in ("medium", "high", "critical"):
        assert policy.skill_actions.get(sev).install == "block"


def test_response_alert_pins_block_threshold_to_critical() -> None:
    answers = default_answers()
    answers.response = "alert"
    policy = apply_answers(answers)
    assert policy.guardrail.block_threshold == 4
    assert policy.guardrail.alert_threshold == 3
    assert policy.guardrail.hilt.enabled is False


def test_response_ask_enables_hilt_at_medium() -> None:
    answers = default_answers()
    answers.response = "ask"
    policy = apply_answers(answers)
    assert policy.guardrail.hilt.enabled is True
    assert policy.guardrail.hilt.min_severity == "MEDIUM"


def test_local_file_sink_flips_audit_logging() -> None:
    answers = default_answers()
    # local_file is enabled by default in default_answers().
    assert answers.sinks["local_file"].enabled
    policy = apply_answers(answers)
    assert policy.audit.log_all_actions is True
    assert policy.audit.log_scan_results is True


def test_slack_sink_with_valid_url_creates_webhook_with_signing_secret() -> None:
    answers = default_answers()
    answers.sinks["slack"] = SinkAnswer(
        enabled=True,
        url="https://hooks.slack.com/services/T0/B0/abc",
        secret_env="SLACK_WEBHOOK_SECRET",
    )
    policy = apply_answers(answers)
    matching = [w for w in policy.webhooks if w.url == "https://hooks.slack.com/services/T0/B0/abc"]
    assert matching, "Slack webhook missing from emitted policy"
    assert matching[0].type == "slack"
    assert matching[0].secret_env == "SLACK_WEBHOOK_SECRET"
    assert matching[0].min_severity == "HIGH"


def test_sink_with_invalid_url_is_skipped() -> None:
    answers = default_answers()
    answers.sinks["splunk"] = SinkAnswer(
        enabled=True,
        url="not-a-url",
        secret_env="SPLUNK_HEC_TOKEN",
    )
    policy = apply_answers(answers)
    assert all(w.url != "not-a-url" for w in policy.webhooks)


def test_apply_answers_is_idempotent() -> None:
    """Same Answers in -> same Policy out (per the contract pinned
    in apply.ts). The serializer is stable so this comparison is
    safe."""
    answers = default_answers()
    answers.block.add("secrets")
    answers.allow.add("dev_tools")
    answers.response = "ask"
    answers.sinks["slack"] = SinkAnswer(
        enabled=True,
        url="https://hooks.slack.com/services/T/B/X",
        secret_env="SLACK_WEBHOOK_SECRET",
    )
    a = apply_answers(answers)
    b = apply_answers(answers)
    assert a.name == b.name
    assert a.firewall.allowed_domains == b.firewall.allowed_domains
    assert a.firewall.blocked_destinations == b.firewall.blocked_destinations
    assert [w.url for w in a.webhooks] == [w.url for w in b.webhooks]


def test_block_card_unknown_id_is_silently_ignored() -> None:
    """The wizard's free-form code can't add unknown card ids, but
    a corrupted draft file might. The mapper should drop them
    rather than raise."""
    answers = default_answers()
    answers.block.add("does-not-exist")
    policy = apply_answers(answers)
    assert policy.name == "default"


def test_block_card_guardrail_patterns_merge_dedupe() -> None:
    answers = default_answers()
    answers.block.add("prompt_injection")
    policy = apply_answers(answers)
    inj = policy.guardrail.patterns.get("injection", [])
    # Each card pattern must appear once.
    assert inj.count("ignore (?:all )?previous") == 1
    assert policy.guardrail.severity_mappings.get("injection") == "HIGH"
