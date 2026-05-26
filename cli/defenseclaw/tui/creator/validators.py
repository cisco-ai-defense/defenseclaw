# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Regex + ``Policy`` validators for the TUI Policy Creator.

Python port of ``docs-site/components/policy-creator/lib/validators.ts``.

Two layers, mirroring the web Creator:

1. ``lint_regex`` - compile a pattern with Python's ``re`` and run a
   set of static lints for RE2 incompatibilities (Go's ``regexp`` is
   RE2 - no lookaround, no backreferences, no possessive quantifiers,
   no atomic groups), a cheap catastrophic-backtracking heuristic,
   and an anchor sanity check.
2. ``validate_policy`` - whole-``Policy`` lint that rolls up regex
   findings plus structural checks (duplicate ids, broad
   suppressions, scanner overrides looser than the base, webhook
   secrets pasted into the form, identity-allow custom Rego, etc.).

We intentionally do **not** ship a full RE2 round-trip: the static
RE2 incompatibility list catches every feature gap we have actually
seen in production rule packs. Operators who want the full RE2
verdict get it the moment they hit Live Test (which shells out to
``opa eval`` in Phase 9).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from defenseclaw.tui.creator.types import (
    Policy,
    ValidationCode,
    ValidationFinding,
)

# --- Anti-secret-paste heuristics ------------------------------------------
#
# Operators routinely paste literal secrets into env-name fields like
# ``secret_env`` or ``api_key_env`` because the form labels them
# generically. The heuristics below catch the most common shapes: API
# key prefixes we recognize, JWTs, and PEM blocks. They are
# intentionally conservative (false-negative-biased) because a
# warning on a real env-var name is more annoying than a missed
# warning on a paste.

_ENV_VAR_NAME_RE = re.compile(r"^[A-Z_][A-Z0-9_]{2,63}$")


def looks_like_env_var_name(value: str) -> bool:
    """True iff ``value`` matches ``[A-Z_][A-Z0-9_]{2,63}``.

    Used by the wizard to flag fields that should hold the *name* of
    an env var, not the value inside it.
    """
    return bool(_ENV_VAR_NAME_RE.match(value))


_INLINE_SECRET_PROBES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\bsk-[A-Za-z0-9]{20,}"), "OpenAI/Anthropic-style API key"),
    (re.compile(r"\bghp_[A-Za-z0-9]{36}\b"), "GitHub PAT"),
    (re.compile(r"\bgho_[A-Za-z0-9]{36}\b"), "GitHub OAuth token"),
    (re.compile(r"\bghs_[A-Za-z0-9]{36}\b"), "GitHub server token"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key id"),
    (re.compile(r"-----BEGIN[A-Z ]*PRIVATE KEY-----"), "PEM-encoded private key"),
    (
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        "JWT-shaped token",
    ),
)


def scan_for_inline_secret(text: str) -> str | None:
    """Return the *kind* of inline secret detected in ``text``, or ``None``.

    Cross-reference: codeguard-1-hardcoded-credentials. Operators
    should never store secrets in policy YAML; the gateway reads them
    from env vars via ``os.Getenv()`` so they never reach disk in the
    rule pack.
    """
    for probe, label in _INLINE_SECRET_PROBES:
        if probe.search(text):
            return label
    return None


def redact_for_ui(value: str) -> str:
    """Mask ``value`` for UI display.

    Keep the first 3 / last 2 characters, replace the middle with
    bullet glyphs. Long enough strings still produce a recognizable
    shape so the operator can confirm we caught the right field
    without echoing the whole secret back into the DOM.
    """
    if len(value) <= 6:
        return "\u2022\u2022\u2022\u2022"
    middle = "\u2022" * min(8, len(value) - 5)
    return f"{value[:3]}{middle}{value[-2:]}"


# --- Regex linting ---------------------------------------------------------


@dataclass(frozen=True)
class RegexLintResult:
    """Outcome of a single ``lint_regex`` call.

    ``compiled`` mirrors Python's compile success - not RE2's.
    ``findings`` may contain ``REGEX_RE2_INCOMPAT`` errors even when
    ``compiled`` is True, because Python accepts patterns Go's
    ``regexp`` rejects.
    """

    compiled: bool
    error: str | None
    findings: tuple[ValidationFinding, ...]


# RE2 explicitly rejects these constructs. Order is most-likely-
# encountered-first so we surface the actionable label early.
# Reference: https://github.com/google/re2/wiki/Syntax
_RE2_INCOMPAT: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"\(\?=|\(\?!|\(\?<=|\(\?<!"),
        "lookaround (?=, ?!, ?<=, ?<!) is not supported by RE2",
    ),
    (re.compile(r"\\[1-9]"), "backreferences (\\1, \\2 ...) are not supported by RE2"),
    (re.compile(r"\(\?>"), "atomic groups (?>) are not supported by RE2"),
    (
        re.compile(r"[*+?]\+"),
        "possessive quantifiers (*+, ++, ?+) are not supported by RE2",
    ),
    (re.compile(r"\\k<"), "named backreferences (\\k<...>) are not supported by RE2"),
)

_REDOS_ANTIPATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"\([^()]*[+*]\)[+*]"),
        "nested quantifier shape ((..+)+) is prone to catastrophic backtracking",
    ),
    (
        re.compile(r"\(([^()|]+\|){2,}[^()]*\)[+*]"),
        "overlapping alternation under a quantifier may explode on adversarial input",
    ),
)

_ANCHOR_PROBE = re.compile(r"[\^$]|\\b|\\A|\\z")


def lint_regex(pattern: str) -> RegexLintResult:
    """Static-lint ``pattern`` against the engine's RE2 expectations."""
    findings: list[ValidationFinding] = []

    if not pattern:
        return RegexLintResult(
            compiled=False,
            error="pattern is empty",
            findings=(
                ValidationFinding(
                    level="error",
                    code="REGEX_INVALID",
                    message="Pattern cannot be empty.",
                    location="pattern",
                ),
            ),
        )

    compiled = False
    error: str | None = None
    try:
        re.compile(pattern)
        compiled = True
    except re.error as exc:
        error = str(exc)
        findings.append(
            ValidationFinding(
                level="error",
                code="REGEX_INVALID",
                message=error,
                location="pattern",
            )
        )

    for probe, label in _RE2_INCOMPAT:
        if probe.search(pattern):
            findings.append(
                ValidationFinding(
                    level="error",
                    code="REGEX_RE2_INCOMPAT",
                    message=label,
                    location="pattern",
                    fix=(
                        "Re-author without that feature; the engine compiles "
                        "patterns with Go's regexp (RE2)."
                    ),
                )
            )

    for probe, label in _REDOS_ANTIPATTERNS:
        if probe.search(pattern):
            findings.append(
                ValidationFinding(
                    level="warning",
                    code="REGEX_REDOS",
                    message=label,
                    location="pattern",
                    fix=(
                        "Tighten the inner quantifier so each character is "
                        "consumed by exactly one alternative."
                    ),
                )
            )

    if not _ANCHOR_PROBE.search(pattern):
        findings.append(
            ValidationFinding(
                level="info",
                code="REGEX_ANCHOR_MISSING",
                message=(
                    "Pattern has no anchors (^, $, \\b). It will match "
                    "anywhere in the input."
                ),
                location="pattern",
                fix=(
                    "If the secret/identifier has a known prefix, anchor "
                    "with ^ or \\b to reduce false positives."
                ),
            )
        )

    return RegexLintResult(compiled=compiled, error=error, findings=tuple(findings))


@dataclass(frozen=True)
class RegexTestResult:
    """One row of the wizard's "Run examples" panel.

    ``actual`` is "error" when the pattern itself failed to compile.
    """

    text: str
    expected: str
    actual: str
    detail: str | None = None


def test_regex(
    pattern: str,
    examples: tuple[str, ...] | list[str],
    counterexamples: tuple[str, ...] | list[str],
    *,
    flags: int = 0,
) -> tuple[RegexTestResult, ...]:
    """Run ``pattern`` against ``examples`` and ``counterexamples``.

    Inline flag groups like ``(?i)foo`` are accepted natively by
    Python's ``re``, so we don't need a separate translator the way
    the JS implementation does.
    """
    out: list[RegexTestResult] = []
    try:
        compiled = re.compile(pattern, flags)
    except re.error as exc:
        detail = str(exc)
        for text in [*examples, *counterexamples]:
            out.append(
                RegexTestResult(
                    text=text,
                    expected="match" if text in examples else "no-match",
                    actual="error",
                    detail=detail,
                )
            )
        return tuple(out)

    for text in examples:
        out.append(
            RegexTestResult(
                text=text,
                expected="match",
                actual="match" if compiled.search(text) else "no-match",
            )
        )
    for text in counterexamples:
        out.append(
            RegexTestResult(
                text=text,
                expected="no-match",
                actual="match" if compiled.search(text) else "no-match",
            )
        )
    return tuple(out)


# --- Whole-policy validation -----------------------------------------------

_POLICY_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
_RULE_ID_RE = re.compile(r"^[A-Z][A-Z0-9_-]{2,63}$")
_REGO_DEFAULT_ALLOW_RE = re.compile(r"\bdefault\s+allow\s*:?=\s*true\b")
_REGO_ALLOW_IF_RE = re.compile(r"allow\s+(?:if|=)\s*\{")

_BROAD_PATTERNS: frozenset[str] = frozenset({"", ".*", ".+", "^.*$"})


def validate_policy(policy: Policy) -> tuple[ValidationFinding, ...]:
    """Run every lint over ``policy`` and return the aggregated findings.

    The order matters: callers iterate the returned tuple to compute
    section status badges, so keep the rule-pack lints contiguous,
    correlator lints last among the structural checks, and ``RISKY_*``
    codes after everything else.
    """
    findings: list[ValidationFinding] = []

    if not policy.name or not _POLICY_NAME_RE.match(policy.name):
        findings.append(
            ValidationFinding(
                level="error",
                code="NAME_INVALID",
                message="Policy name must match [a-z0-9][a-z0-9-]{0,63}.",
                location="basics.name",
            )
        )

    seen_ids: set[str] = set()
    for rules_file in policy.rule_pack.files:
        for rule in rules_file.rules:
            if not rule.id:
                findings.append(
                    ValidationFinding(
                        level="error",
                        code="ID_FORMAT",
                        message=f"Rule in {rules_file.filename}.yaml is missing an id.",
                        location=f"rules.{rules_file.filename}",
                    )
                )
                continue
            if rule.id in seen_ids:
                findings.append(
                    ValidationFinding(
                        level="error",
                        code="ID_DUPLICATE",
                        message=f'Duplicate rule id "{rule.id}".',
                        location=f"rules.{rules_file.filename}.{rule.id}",
                        fix="Each rule id must be unique across every rule pack file.",
                    )
                )
            else:
                seen_ids.add(rule.id)
            if not _RULE_ID_RE.match(rule.id):
                findings.append(
                    ValidationFinding(
                        level="warning",
                        code="ID_FORMAT",
                        message=(
                            f'Rule id "{rule.id}" should be UPPER_SNAKE_OR_DASH '
                            f"(e.g. SEC-AWS-KEY)."
                        ),
                        location=f"rules.{rules_file.filename}.{rule.id}",
                    )
                )
            lint = lint_regex(rule.pattern)
            for f in lint.findings:
                findings.append(
                    ValidationFinding(
                        level=f.level,
                        code=f.code,
                        message=f.message,
                        location=f"rules.{rules_file.filename}.{rule.id}",
                        fix=f.fix,
                    )
                )

    for supp in policy.suppressions.finding_suppressions:
        if supp.finding_pattern in _BROAD_PATTERNS:
            label = supp.id or "(unnamed)"
            findings.append(
                ValidationFinding(
                    level="warning",
                    code="SUPP_OVER_BROAD",
                    message=(
                        f'Suppression "{label}" matches every finding. '
                        f"This will silence real signals."
                    ),
                    location=f"suppressions.finding.{supp.id}",
                    fix=(
                        "Scope the pattern to a finding ID prefix "
                        "(e.g. ^SEC-AWS-) or specific judge category."
                    ),
                )
            )
    for tool in policy.suppressions.tool_suppressions:
        if tool.tool_pattern in _BROAD_PATTERNS:
            findings.append(
                ValidationFinding(
                    level="warning",
                    code="SUPP_OVER_BROAD",
                    message=(
                        "Tool suppression matches every tool. This will "
                        "silence every finding on every tool."
                    ),
                    location="suppressions.tool",
                    fix=r"Scope the regex (e.g. ^(shell|bash)\.execute$).",
                )
            )

    if (
        policy.firewall.default_action == "deny"
        and not policy.firewall.allowed_domains
    ):
        findings.append(
            ValidationFinding(
                level="warning",
                code="FIREWALL_DEFAULT_DENY_NO_ALLOW",
                message=(
                    'Firewall default is "deny" but no allowed_domains are '
                    "configured. Every outbound call from a sandboxed plugin will fail."
                ),
                location="firewall.default_action",
                fix=(
                    'Either flip default_action to "allow" with an explicit '
                    "blocked_destinations list, or add the domains your "
                    "sandboxed code legitimately needs."
                ),
            )
        )

    for scanner, overrides in policy.scanner_overrides.items():
        if not overrides:
            continue
        for sev, triple in overrides.items():
            base = policy.skill_actions.get(sev)
            if triple is None or base is None:
                continue
            if base.install == "block" and triple.install != "block":
                findings.append(
                    ValidationFinding(
                        level="warning",
                        code="SCANNER_OVERRIDE_LOOSER",
                        message=(
                            f'Scanner "{scanner}" allows install at '
                            f"{sev.upper()} even though base policy blocks it."
                        ),
                        location=f"severity-matrix.{scanner}.{sev}.install",
                    )
                )
            if base.runtime == "disable" and triple.runtime != "disable":
                findings.append(
                    ValidationFinding(
                        level="warning",
                        code="SCANNER_OVERRIDE_LOOSER",
                        message=(
                            f'Scanner "{scanner}" leaves runtime enabled at '
                            f"{sev.upper()} even though base policy disables it."
                        ),
                        location=f"severity-matrix.{scanner}.{sev}.runtime",
                    )
                )

    for wh in policy.webhooks:
        if wh.enabled and not wh.secret_env:
            findings.append(
                ValidationFinding(
                    level="warning",
                    code="WEBHOOK_SECRET_MISSING",
                    message=(
                        f"Webhook {wh.url} is enabled but has no secret_env. "
                        f"Inbound deliveries can't be verified."
                    ),
                    location="webhooks",
                    fix=(
                        "Add the env-var name (e.g. SLACK_WEBHOOK_SECRET) so "
                        "the dispatcher can sign requests."
                    ),
                )
            )
        if wh.secret_env and not looks_like_env_var_name(wh.secret_env):
            redacted = redact_for_ui(wh.secret_env)
            findings.append(
                ValidationFinding(
                    level="error",
                    code="ENV_NAME_LIKELY_SECRET",
                    message=(
                        f"Webhook {wh.url}: secret_env value "
                        f'"{redacted}" doesn\'t look like an env-var name. '
                        f"It looks like a literal secret pasted into the wrong field."
                    ),
                    location="webhooks",
                    fix=(
                        "Use UPPER_SNAKE_CASE matching [A-Z_][A-Z0-9_]+ - "
                        "the dispatcher reads the actual secret from "
                        "os.Getenv() at gateway boot."
                    ),
                )
            )

    for snippet in policy.custom_rego:
        if "package " not in snippet.source:
            findings.append(
                ValidationFinding(
                    level="error",
                    code="CUSTOM_REGO_MISSING_PACKAGE",
                    message=(
                        f'Custom Rego snippet "{snippet.name}" must declare a '
                        f'"package defenseclaw.custom.<name>" line.'
                    ),
                    location=f"custom_rego.{snippet.name}",
                )
            )
        secret_kind = scan_for_inline_secret(snippet.source)
        if secret_kind:
            findings.append(
                ValidationFinding(
                    level="warning",
                    code="CUSTOM_REGO_LIKELY_SECRET",
                    message=(
                        f'Custom Rego snippet "{snippet.name}" contains text '
                        f"that looks like an inline secret ({secret_kind}). "
                        f"Inline secrets land in YAML and get printed by "
                        f'"defenseclaw policy show".'
                    ),
                    location=f"custom_rego.{snippet.name}",
                    fix=(
                        "Replace the literal with a data-driven check (e.g. "
                        "compare input.token_prefix against a server-side "
                        "allowlist) and never store the secret in the policy itself."
                    ),
                )
            )

    seen_pattern_ids: set[str] = set()
    for pattern in policy.correlator:
        if not pattern.enabled:
            continue
        if pattern.id in seen_pattern_ids:
            findings.append(
                ValidationFinding(
                    level="error",
                    code="ID_DUPLICATE",
                    message=(
                        f'Correlator pattern id "{pattern.id}" appears more '
                        f"than once. IDs are the join key for promoted CORR-* "
                        f"findings; duplicates collide in audit logs."
                    ),
                    location=f"correlator.{pattern.id}",
                )
            )
        else:
            seen_pattern_ids.add(pattern.id)
        clause_count = (
            len(pattern.all_of) + len(pattern.sequence) + len(pattern.fingerprint_chain)
        )
        if clause_count == 0:
            findings.append(
                ValidationFinding(
                    level="error",
                    code="CORRELATOR_PATTERN_EMPTY",
                    message=(
                        f'Correlator pattern "{pattern.id}" has no clauses on '
                        f"any match mode. It will never fire."
                    ),
                    location=f"correlator.{pattern.id}",
                    fix=(
                        "Add at least one clause under all_of, sequence, or "
                        "fingerprint_chain - or disable the pattern."
                    ),
                )
            )
        if not isinstance(pattern.window_events, int) or pattern.window_events <= 0:
            findings.append(
                ValidationFinding(
                    level="error",
                    code="CORRELATOR_WINDOW_INVALID",
                    message=(
                        f'Correlator pattern "{pattern.id}" has '
                        f"window_events={pattern.window_events}. Must be a "
                        f"positive integer."
                    ),
                    location=f"correlator.{pattern.id}.window_events",
                )
            )
        elif pattern.window_events > 1000:
            findings.append(
                ValidationFinding(
                    level="warning",
                    code="CORRELATOR_WINDOW_INVALID",
                    message=(
                        f'Correlator pattern "{pattern.id}" '
                        f"window_events={pattern.window_events} is very large. "
                        f"The session buffer caps at a few hundred findings; "
                        f'values above that effectively mean "the whole session".'
                    ),
                    location=f"correlator.{pattern.id}.window_events",
                )
            )

    aid = policy.cisco_ai_defense
    if aid.enabled or aid.api_key_env or aid.endpoint:
        if not aid.api_key_env:
            findings.append(
                ValidationFinding(
                    level="warning",
                    code="CISCO_AID_KEY_ENV_MISSING",
                    message=(
                        "Cisco AI Defense block is populated but api_key_env "
                        "is empty. The gateway will skip the AID lane silently "
                        "until an env-var name is supplied."
                    ),
                    location="cisco_ai_defense.api_key_env",
                    fix=(
                        "Set api_key_env to the env var the gateway should "
                        "read (e.g. CISCO_AI_DEFENSE_API_KEY)."
                    ),
                )
            )
        elif not looks_like_env_var_name(aid.api_key_env):
            secret_kind = scan_for_inline_secret(aid.api_key_env)
            if secret_kind:
                findings.append(
                    ValidationFinding(
                        level="error",
                        code="ENV_NAME_LIKELY_SECRET",
                        message=(
                            f"Cisco AI Defense api_key_env looks like an "
                            f"inline secret ({secret_kind}, masked as "
                            f'"{redact_for_ui(aid.api_key_env)}"). The wizard '
                            f"expects the NAME of the env var, not the value."
                        ),
                        location="cisco_ai_defense.api_key_env",
                        fix=(
                            "Use UPPER_SNAKE_CASE matching "
                            "[A-Z_][A-Z0-9_]+ - the gateway reads the actual "
                            "secret via os.Getenv() at boot."
                        ),
                    )
                )
            else:
                findings.append(
                    ValidationFinding(
                        level="error",
                        code="CISCO_AID_KEY_ENV_MISSING",
                        message=(
                            f'Cisco AI Defense api_key_env "{aid.api_key_env}" '
                            f"is not a valid env-var name. The wizard expects "
                            f"the NAME of the env var (e.g. "
                            f"CISCO_AI_DEFENSE_API_KEY), not the key value."
                        ),
                        location="cisco_ai_defense.api_key_env",
                        fix=(
                            "Use UPPER_SNAKE_CASE matching "
                            "[A-Z_][A-Z0-9_]+ - the gateway looks up the "
                            "actual secret via os.Getenv() at boot."
                        ),
                    )
                )

    # --- Risky-config (D5) -------------------------------------------------

    if (
        policy.firewall.default_action == "allow"
        and not policy.firewall.blocked_destinations
    ):
        findings.append(
            ValidationFinding(
                level="warning",
                code="RISKY_FIREWALL_DEFAULT_ALLOW",
                message=(
                    "Firewall is in default-allow mode with no explicit "
                    "blocked_destinations. This means the firewall layer "
                    "enforces nothing - every outbound destination is allowed. "
                    "Most production deployments want default-deny with an "
                    "explicit allow_list."
                ),
                location="firewall.default_action",
                fix=(
                    "Switch to default_action: 'deny' and list the "
                    "destinations you actually want to allow under "
                    "allowed_domains, or document why default-allow is intended."
                ),
            )
        )

    severities = ("critical", "high", "medium", "low", "info")
    all_runtime_enable = all(
        policy.skill_actions.get(s).runtime == "enable" for s in severities
    )
    all_install_none = all(
        policy.skill_actions.get(s).install == "none" for s in severities
    )
    if all_runtime_enable and all_install_none:
        findings.append(
            ValidationFinding(
                level="warning",
                code="RISKY_ALL_ACTIONS_ALLOW",
                message=(
                    "Every severity tier in skill_actions allows runtime AND "
                    "install with no quarantine. This effectively disables "
                    "enforcement across the matrix - the gateway will scan but "
                    "never block."
                ),
                location="skill_actions",
                fix=(
                    "Pick at least one (severity, surface) where action != "
                    'allow/none. The "default" preset blocks runtime + '
                    "install at HIGH and CRITICAL; that's a reasonable floor."
                ),
            )
        )

    for snippet in policy.custom_rego:
        # Identity-allow Rego (``default allow := true`` with no
        # overriding rules) is a footgun. Exempt the canary fixture
        # name we ship in the install script so internal tests don't
        # flap.
        if (
            _REGO_DEFAULT_ALLOW_RE.search(snippet.source)
            and not _REGO_ALLOW_IF_RE.search(snippet.source)
            and snippet.name != "verify-canary"
        ):
            findings.append(
                ValidationFinding(
                    level="warning",
                    code="RISKY_CUSTOM_REGO_IDENTITY_ALLOW",
                    message=(
                        f'Custom Rego snippet "{snippet.name}" sets '
                        f"default allow := true with no overriding rules. "
                        f"It always allows. If you intended a no-op, "
                        f"document that - if you intended to gate something, "
                        f"add at least one allow-if rule."
                    ),
                    location=f"custom_rego.{snippet.name}",
                )
            )

    if (
        policy.guardrail.block_threshold > 0
        and policy.judges
        and all(not j.enabled for j in policy.judges)
    ):
        findings.append(
            ValidationFinding(
                level="warning",
                code="RISKY_JUDGE_THRESHOLD_MISMATCH",
                message=(
                    f"guardrail.block_threshold={policy.guardrail.block_threshold} "
                    f"expects the LLM judges to contribute verdicts, but every "
                    f"judge in policy.judges is disabled. The threshold will "
                    f"only ever be reached by deterministic scanners."
                ),
                location="guardrail.block_threshold",
                fix=(
                    "Either enable at least one judge or document that the "
                    "threshold is set assuming deterministic-scanner verdicts only."
                ),
            )
        )

    if policy.correlator and not any(p.enabled for p in policy.correlator):
        count = len(policy.correlator)
        plural = "is" if count == 1 else "are"
        findings.append(
            ValidationFinding(
                level="warning",
                code="RISKY_CORRELATOR_ALL_DISABLED",
                message=(
                    f"{count} session-correlator pattern{'' if count == 1 else 's'} "
                    f"{plural} configured but every one is disabled. Layer 5 "
                    f"(session correlator) will not fire on this policy."
                ),
                location="correlator",
                fix=(
                    "Enable at least one pattern or remove the disabled set "
                    "to keep the policy minimal."
                ),
            )
        )

    return tuple(findings)


# --- Convenience helpers ---------------------------------------------------

RISKY_CONFIG_CODES: frozenset[ValidationCode] = frozenset(
    {
        "RISKY_FIREWALL_DEFAULT_ALLOW",
        "RISKY_ALL_ACTIONS_ALLOW",
        "RISKY_CUSTOM_REGO_IDENTITY_ALLOW",
        "RISKY_JUDGE_THRESHOLD_MISMATCH",
        "RISKY_CORRELATOR_ALL_DISABLED",
    }
)


@dataclass(frozen=True)
class ValidationSummary:
    """Counts by level for the issue-tray badge in the Playground."""

    errors: int
    warnings: int
    info: int


def summarize(
    findings: tuple[ValidationFinding, ...] | list[ValidationFinding],
) -> ValidationSummary:
    """Roll up ``findings`` into per-level counts for the issues tray."""
    errors = warnings = info = 0
    for f in findings:
        if f.level == "error":
            errors += 1
        elif f.level == "warning":
            warnings += 1
        else:
            info += 1
    return ValidationSummary(errors=errors, warnings=warnings, info=info)


def unique_rule_id(base: str, taken: set[str] | frozenset[str]) -> str:
    """Suggest the next-available rule id with a numeric suffix.

    Mirrors the JS helper used by the wizard's "Add rule" button: if
    ``base`` is unused, return it; otherwise append ``-2``, ``-3``, ...
    until we land on something free.
    """
    if base not in taken:
        return base
    i = 2
    while f"{base}-{i}" in taken:
        i += 1
    return f"{base}-{i}"
