# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Phase 8: Policy validator tests.

Each test pins one rule from ``validators.py``. The behaviour
contract is: every public-facing knob the operator is likely to
mis-configure surfaces as a typed ``ValidationFinding`` so the
Playground header and the issues tray can render exactly the same
codes as the docs-site Creator.
"""

from __future__ import annotations

from typing import cast

from defenseclaw.tui.creator import types, validators


# --- Secret heuristics ----------------------------------------------------


def test_looks_like_env_var_name_accepts_upper_snake_and_rejects_paste() -> None:
    assert validators.looks_like_env_var_name("CISCO_AI_DEFENSE_API_KEY")
    assert validators.looks_like_env_var_name("FOO_BAR")
    assert not validators.looks_like_env_var_name("lowercase_name")
    assert not validators.looks_like_env_var_name("AB")  # too short
    assert not validators.looks_like_env_var_name("FOO BAR")
    assert not validators.looks_like_env_var_name("ghp_AAAA...")


def test_scan_for_inline_secret_detects_each_supported_shape() -> None:
    """Pinned: each supported shape labels itself in the message."""
    cases = {
        "leading text sk-AAAAAAAAAAAAAAAAAAAA more": "OpenAI/Anthropic-style API key",
        "ghp_" + "A" * 36: "GitHub PAT",
        "gho_" + "B" * 36: "GitHub OAuth token",
        "ghs_" + "C" * 36: "GitHub server token",
        "AKIA" + "Z" * 16: "AWS access key id",
        "-----BEGIN PRIVATE KEY-----": "PEM-encoded private key",
        "eyJaaaaaaaaaa.bbbbbbbbbb.cccccccccc": "JWT-shaped token",
    }
    for source, expected in cases.items():
        assert validators.scan_for_inline_secret(source) == expected, source


def test_scan_for_inline_secret_returns_none_for_clean_text() -> None:
    assert validators.scan_for_inline_secret("ENV_VAR_NAME") is None
    assert validators.scan_for_inline_secret("") is None


def test_redact_for_ui_keeps_short_strings_fully_masked() -> None:
    assert validators.redact_for_ui("ab") == "\u2022\u2022\u2022\u2022"
    assert validators.redact_for_ui("abcdef") == "\u2022\u2022\u2022\u2022"  # exactly 6


def test_redact_for_ui_preserves_recognizable_shape_for_long_strings() -> None:
    """Operators identify the field by prefix + suffix; the middle
    must be opaque to keep the secret out of screenshots."""
    masked = validators.redact_for_ui("ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    assert masked.startswith("ghp")
    assert masked.endswith("AA")
    assert "\u2022" in masked
    # Middle bullets capped at 8.
    assert masked.count("\u2022") == 8


# --- lint_regex -----------------------------------------------------------


def test_lint_regex_empty_pattern_returns_invalid_only() -> None:
    result = validators.lint_regex("")
    assert result.compiled is False
    assert result.error == "pattern is empty"
    assert {f.code for f in result.findings} == {"REGEX_INVALID"}


def test_lint_regex_clean_anchored_pattern_lints_clean() -> None:
    result = validators.lint_regex(r"^AKIA[0-9A-Z]{16}$")
    assert result.compiled is True
    assert result.error is None
    assert result.findings == ()


def test_lint_regex_flags_each_re2_incompatibility() -> None:
    """Each RE2-banned construct must surface as REGEX_RE2_INCOMPAT
    even when Python's re accepts the source."""
    cases: dict[str, str] = {
        r"foo(?=bar)": "lookaround",
        r"(\w+)\1": "backreferences",
        r"foo*+": "possessive quantifiers",
        # ``(?>foo)`` and ``\\k<x>`` are syntax errors in Python's
        # ``re`` so we only assert the lint message; compile failure
        # is expected.
    }
    for pattern, expected_substring in cases.items():
        codes = {f.code for f in validators.lint_regex(pattern).findings}
        assert "REGEX_RE2_INCOMPAT" in codes, pattern
        msgs = " ".join(
            f.message
            for f in validators.lint_regex(pattern).findings
            if f.code == "REGEX_RE2_INCOMPAT"
        )
        assert expected_substring in msgs


def test_lint_regex_flags_atomic_group_and_named_backref() -> None:
    """Atomic groups + named backrefs are RE2-incompatible. Python's
    ``re`` accepts atomic groups since 3.11 (so the lint must still
    fire even when compile succeeds), and rejects ``\\k<...>`` named
    backref syntax (Python uses ``(?P=name)`` instead)."""
    for pattern in (r"(?>foo)", r"(?P<x>foo)\k<x>"):
        codes = [f.code for f in validators.lint_regex(pattern).findings]
        assert "REGEX_RE2_INCOMPAT" in codes, pattern


def test_lint_regex_flags_redos_antipatterns() -> None:
    nested = validators.lint_regex(r"^(a+)+$")
    assert "REGEX_REDOS" in {f.code for f in nested.findings}

    overlap = validators.lint_regex(r"(a|aa|aaa)+")
    assert "REGEX_REDOS" in {f.code for f in overlap.findings}


def test_lint_regex_flags_missing_anchor_as_info() -> None:
    """Patterns without anchors are info-level, not error - matching
    everywhere is sometimes intentional but it's still worth
    flagging because the false-positive rate climbs fast."""
    findings = validators.lint_regex(r"AKIA[0-9A-Z]{16}").findings
    info = [f for f in findings if f.code == "REGEX_ANCHOR_MISSING"]
    assert len(info) == 1
    assert info[0].level == "info"


# --- test_regex -----------------------------------------------------------


def test_test_regex_classifies_examples_correctly() -> None:
    rows = validators.test_regex(
        r"^AKIA[0-9A-Z]{16}$",
        examples=[f"AKIA{'Z' * 16}"],
        counterexamples=["not-a-key"],
    )
    by_text = {r.text: r for r in rows}
    assert by_text[f"AKIA{'Z' * 16}"].actual == "match"
    assert by_text["not-a-key"].actual == "no-match"


def test_test_regex_returns_error_rows_when_pattern_invalid() -> None:
    """Unbalanced parens fail to compile in every Python version, so
    we use that as the canonical "invalid pattern" fixture rather
    than RE2-only constructs (which Python 3.11+ accepts)."""
    rows = validators.test_regex(r"(unclosed", examples=["foo"], counterexamples=["bar"])
    assert all(r.actual == "error" for r in rows)
    assert all(r.detail for r in rows)


# --- validate_policy: name + rule packs -----------------------------------


def _policy_with_name(name: str = "valid-name") -> types.Policy:
    return types.Policy(name=name, basedOn="default")


def test_validate_policy_flags_invalid_name() -> None:
    findings = validators.validate_policy(types.Policy(name="Bad Name"))
    assert any(f.code == "NAME_INVALID" for f in findings)
    assert all(f.code != "NAME_INVALID" for f in validators.validate_policy(_policy_with_name()))


def test_validate_policy_dedupes_rule_ids_and_lints_format() -> None:
    pol = _policy_with_name()
    pol.rule_pack = types.RulePackBundle(
        name="x",
        files=[
            types.RulesFile(
                filename="aws",
                category="secrets",
                rules=[
                    types.RuleDef(id="AKID", pattern=r"^A$"),
                    types.RuleDef(id="AKID", pattern=r"^B$"),  # duplicate
                    types.RuleDef(id="lowercase", pattern=r"^C$"),  # bad shape
                ],
            )
        ],
    )
    findings = validators.validate_policy(pol)
    codes = [f.code for f in findings]
    assert codes.count("ID_DUPLICATE") == 1
    # AKID once (warn for length<3 prefix shape) plus lowercase warn.
    id_format_warnings = [
        f for f in findings if f.code == "ID_FORMAT" and f.level == "warning"
    ]
    assert any("lowercase" in f.message for f in id_format_warnings)


def test_validate_policy_flags_missing_rule_id_as_id_format_error() -> None:
    pol = _policy_with_name()
    pol.rule_pack = types.RulePackBundle(
        name="x",
        files=[
            types.RulesFile(
                filename="empty-id",
                rules=[types.RuleDef(id="", pattern=r"^A$")],
            )
        ],
    )
    errors = [
        f
        for f in validators.validate_policy(pol)
        if f.code == "ID_FORMAT" and f.level == "error"
    ]
    assert any("missing an id" in f.message for f in errors)


# --- Suppressions --------------------------------------------------------


def test_validate_policy_flags_broad_suppressions() -> None:
    pol = _policy_with_name()
    pol.suppressions = types.SuppressionsBundle(
        finding_suppressions=[
            types.FindingSuppressionDef(id="all", finding_pattern=".*", reason="lazy")
        ],
        tool_suppressions=[
            types.ToolSuppressionDef(tool_pattern=".*", reason="lazy"),
        ],
    )
    findings = validators.validate_policy(pol)
    codes = [f.code for f in findings]
    assert codes.count("SUPP_OVER_BROAD") == 2


# --- Firewall -----------------------------------------------------------


def test_validate_policy_warns_on_default_deny_with_no_allow() -> None:
    pol = _policy_with_name()
    pol.firewall = types.FirewallConfig(default_action="deny", allowed_domains=[])
    codes = {f.code for f in validators.validate_policy(pol)}
    assert "FIREWALL_DEFAULT_DENY_NO_ALLOW" in codes


def test_validate_policy_warns_on_default_allow_no_blocklist() -> None:
    pol = _policy_with_name()
    pol.firewall = types.FirewallConfig(
        default_action="allow", blocked_destinations=[], allowed_domains=[]
    )
    codes = {f.code for f in validators.validate_policy(pol)}
    assert "RISKY_FIREWALL_DEFAULT_ALLOW" in codes


# --- Scanner overrides --------------------------------------------------


def test_validate_policy_warns_when_scanner_override_loosens_base() -> None:
    pol = _policy_with_name()
    pol.skill_actions.set(
        "high",
        types.SeverityActionTriple(runtime="disable", file="quarantine", install="block"),
    )
    pol.scanner_overrides = cast(
        "dict[types.ScannerType, dict[types.Severity, types.SeverityActionTriple]]",
        {
            "skill": {
                "high": types.SeverityActionTriple(
                    runtime="enable", file="none", install="none"
                )
            }
        },
    )
    findings = validators.validate_policy(pol)
    codes = [f.code for f in findings]
    assert codes.count("SCANNER_OVERRIDE_LOOSER") == 2  # install + runtime


# --- Webhooks -----------------------------------------------------------


def test_validate_policy_flags_webhook_secret_paste() -> None:
    pol = _policy_with_name()
    pol.webhooks = [
        types.WebhookEntry(url="https://hooks.example/abc", secret_env="ghp_" + "A" * 36)
    ]
    findings = validators.validate_policy(pol)
    env_findings = [f for f in findings if f.code == "ENV_NAME_LIKELY_SECRET"]
    assert env_findings
    # Redaction must NOT echo the full token back into the message.
    assert all("ghp_" + "A" * 36 not in f.message for f in env_findings)


def test_validate_policy_warns_when_enabled_webhook_has_no_secret() -> None:
    pol = _policy_with_name()
    pol.webhooks = [types.WebhookEntry(url="https://hooks.example/abc", enabled=True)]
    codes = {f.code for f in validators.validate_policy(pol)}
    assert "WEBHOOK_SECRET_MISSING" in codes


# --- Custom Rego --------------------------------------------------------


def test_validate_policy_requires_package_in_custom_rego() -> None:
    pol = _policy_with_name()
    pol.custom_rego = [
        types.CustomRegoSnippet(name="x", source="deny[msg] { msg := \"x\" }")
    ]
    codes = {f.code for f in validators.validate_policy(pol)}
    assert "CUSTOM_REGO_MISSING_PACKAGE" in codes


def test_validate_policy_flags_inline_secret_in_custom_rego() -> None:
    pol = _policy_with_name()
    pol.custom_rego = [
        types.CustomRegoSnippet(
            name="x",
            source=(
                "package defenseclaw.custom.x\n"
                f"# example: AKIA{'Z' * 16}\n"
            ),
        )
    ]
    codes = {f.code for f in validators.validate_policy(pol)}
    assert "CUSTOM_REGO_LIKELY_SECRET" in codes


def test_validate_policy_flags_identity_allow_rego() -> None:
    pol = _policy_with_name()
    pol.custom_rego = [
        types.CustomRegoSnippet(
            name="open-the-door",
            source="package defenseclaw.custom.open\ndefault allow := true\n",
        )
    ]
    codes = {f.code for f in validators.validate_policy(pol)}
    assert "RISKY_CUSTOM_REGO_IDENTITY_ALLOW" in codes


def test_validate_policy_does_not_flag_canary_identity_allow() -> None:
    """The verify-canary fixture must not trip the lint, otherwise
    the install script's canary check spams the issues tray."""
    pol = _policy_with_name()
    pol.custom_rego = [
        types.CustomRegoSnippet(
            name="verify-canary",
            source="package defenseclaw.custom.verify_canary\ndefault allow := true\n",
        )
    ]
    codes = {f.code for f in validators.validate_policy(pol)}
    assert "RISKY_CUSTOM_REGO_IDENTITY_ALLOW" not in codes


# --- Correlator --------------------------------------------------------


def test_validate_policy_flags_empty_correlator_pattern_and_invalid_window() -> None:
    pol = _policy_with_name()
    pol.correlator = [
        types.CorrelationPattern(id="empty", window_events=10, severity_on_match="HIGH"),
        types.CorrelationPattern(
            id="zero-window",
            window_events=0,
            severity_on_match="HIGH",
            all_of=[types.CorrelationClause(axis="ingress_untrusted")],
        ),
        types.CorrelationPattern(
            id="huge-window",
            window_events=5000,
            severity_on_match="HIGH",
            all_of=[types.CorrelationClause(axis="ingress_untrusted")],
        ),
    ]
    codes = [f.code for f in validators.validate_policy(pol)]
    assert "CORRELATOR_PATTERN_EMPTY" in codes
    assert codes.count("CORRELATOR_WINDOW_INVALID") == 2  # zero + huge


def test_validate_policy_flags_correlator_id_duplication_when_enabled() -> None:
    pol = _policy_with_name()
    pol.correlator = [
        types.CorrelationPattern(
            id="dup",
            window_events=10,
            severity_on_match="HIGH",
            all_of=[types.CorrelationClause(axis="ingress_untrusted")],
        ),
        types.CorrelationPattern(
            id="dup",
            window_events=10,
            severity_on_match="HIGH",
            all_of=[types.CorrelationClause(axis="ingress_untrusted")],
        ),
    ]
    codes = [f.code for f in validators.validate_policy(pol)]
    assert codes.count("ID_DUPLICATE") == 1


def test_validate_policy_warns_when_all_correlator_patterns_disabled() -> None:
    pol = _policy_with_name()
    pol.correlator = [
        types.CorrelationPattern(
            id="x",
            window_events=10,
            severity_on_match="HIGH",
            enabled=False,
            all_of=[types.CorrelationClause(axis="ingress_untrusted")],
        )
    ]
    codes = {f.code for f in validators.validate_policy(pol)}
    assert "RISKY_CORRELATOR_ALL_DISABLED" in codes


# --- Cisco AI Defense ---------------------------------------------------


def test_validate_policy_warns_when_aid_block_present_without_key_env() -> None:
    pol = _policy_with_name()
    pol.cisco_ai_defense = types.CiscoAIDefenseConfig(enabled=True)
    codes = {f.code for f in validators.validate_policy(pol)}
    assert "CISCO_AID_KEY_ENV_MISSING" in codes


def test_validate_policy_flags_aid_inline_secret_paste() -> None:
    pol = _policy_with_name()
    pol.cisco_ai_defense = types.CiscoAIDefenseConfig(
        enabled=True, api_key_env="sk-" + "A" * 25
    )
    findings = validators.validate_policy(pol)
    secret_findings = [f for f in findings if f.code == "ENV_NAME_LIKELY_SECRET"]
    assert secret_findings
    assert "sk-" + "A" * 25 not in secret_findings[0].message


def test_validate_policy_flags_aid_invalid_env_name_without_secret_shape() -> None:
    pol = _policy_with_name()
    pol.cisco_ai_defense = types.CiscoAIDefenseConfig(
        enabled=True, api_key_env="lower_snake"
    )
    codes = {f.code for f in validators.validate_policy(pol)}
    assert "CISCO_AID_KEY_ENV_MISSING" in codes


# --- Risky-config codes ------------------------------------------------


def test_validate_policy_warns_when_all_actions_allow() -> None:
    pol = _policy_with_name()
    # All defaults are runtime=enable, install=none -> trips lint.
    codes = {f.code for f in validators.validate_policy(pol)}
    assert "RISKY_ALL_ACTIONS_ALLOW" in codes


def test_validate_policy_warns_on_judge_threshold_mismatch() -> None:
    pol = _policy_with_name()
    pol.judges = [
        types.JudgeConfig(name="injection", enabled=False, system_prompt="x"),
    ]
    pol.guardrail = types.GuardrailConfig(block_threshold=4)
    codes = {f.code for f in validators.validate_policy(pol)}
    assert "RISKY_JUDGE_THRESHOLD_MISMATCH" in codes


# --- Summary + helpers --------------------------------------------------


def test_summarize_counts_levels() -> None:
    findings = (
        types.ValidationFinding(level="error", code="NAME_INVALID", message=""),
        types.ValidationFinding(level="warning", code="SUPP_OVER_BROAD", message=""),
        types.ValidationFinding(level="warning", code="SUPP_OVER_BROAD", message=""),
        types.ValidationFinding(level="info", code="REGEX_ANCHOR_MISSING", message=""),
    )
    summary = validators.summarize(findings)
    assert summary.errors == 1
    assert summary.warnings == 2
    assert summary.info == 1


def test_unique_rule_id_increments_until_unused() -> None:
    taken: set[str] = {"AKID", "AKID-2", "AKID-3"}
    assert validators.unique_rule_id("AKID", taken) == "AKID-4"
    assert validators.unique_rule_id("FRESH", taken) == "FRESH"


def test_risky_config_codes_membership() -> None:
    """Pin the public set so the Playground header doesn't drift
    from the docs Creator's banner contract."""
    assert validators.RISKY_CONFIG_CODES == frozenset(
        {
            "RISKY_FIREWALL_DEFAULT_ALLOW",
            "RISKY_ALL_ACTIONS_ALLOW",
            "RISKY_CUSTOM_REGO_IDENTITY_ALLOW",
            "RISKY_JUDGE_THRESHOLD_MISMATCH",
            "RISKY_CORRELATOR_ALL_DISABLED",
        }
    )
