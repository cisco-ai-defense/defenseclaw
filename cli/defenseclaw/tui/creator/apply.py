# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Quick Start answers -> ``Policy`` mapper.

Python port of ``docs-site/components/policy-creator/quick-start/apply.ts``.

Pure function: same answers in -> same Policy out. We always start
from a clean preset (per the operator's posture choice) and apply
mutations on top, so unchecking a previously-applied answer
naturally undoes it.

Mirrors the TS ordering: BLOCK -> ALLOW -> RESPONSE -> SINKS so any
behaviour bug surfaces as a one-line diff against ``apply.ts``.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from typing import TypeVar

from defenseclaw.tui.creator.answers import (
    ALLOW_CARDS,
    BLOCK_CARDS,
    POSTURE_TO_PRESET,
    RESPONSES,
    SINK_CARDS,
    Answers,
    BlockCard,
    SinkAnswer,
)
from defenseclaw.tui.creator.presets import load_preset_with_pack
from defenseclaw.tui.creator.types import (
    FirstPartyEntry,
    Policy,
    RuleDef,
    RulesFile,
    SeverityActionTriple,
    ToolSuppressionDef,
    WebhookEntry,
)

T = TypeVar("T")

_HTTP_URL_RE = re.compile(r"^https?://", re.IGNORECASE)


def apply_answers(answers: Answers) -> Policy:
    """Apply ``answers`` on top of the chosen posture preset.

    Idempotent. ``answers`` defaults always produce a valid preset
    even if the user never advances past the first step.
    """
    preset = POSTURE_TO_PRESET.get(answers.posture, "default")
    policy, rules_files = load_preset_with_pack(preset)
    policy.rule_pack.files = list(rules_files)

    # --- Q2: BLOCK ----------------------------------------------------------

    enabled_rule_ids: set[str] = set()
    new_destinations: set[str] = set()
    forced_correlator_ids: set[str] = set()

    for card_id in answers.block:
        card = _find_block_card(card_id)
        if card is None:
            continue
        enabled_rule_ids.update(card.rule_ids)
        new_destinations.update(card.destinations)
        for bundle in card.guardrail_patterns:
            existing = list(policy.guardrail.patterns.get(bundle.category, []))
            seen: set[str] = set(existing)
            for pat in bundle.patterns:
                if pat not in seen:
                    existing.append(pat)
                    seen.add(pat)
            policy.guardrail.patterns[bundle.category] = existing
            policy.guardrail.severity_mappings[bundle.category] = bundle.severity
        forced_correlator_ids.update(card.correlator_pattern_ids)

    if forced_correlator_ids:
        policy.correlator = [
            _replace_correlator_enabled(p, True)
            if p.id in forced_correlator_ids
            else p
            for p in policy.correlator
        ]

    if enabled_rule_ids:
        policy.rule_pack.files = [
            _force_rule_ids_enabled(file, enabled_rule_ids)
            for file in policy.rule_pack.files
        ]

    if new_destinations:
        merged = list(policy.firewall.blocked_destinations)
        seen_d: set[str] = set(merged)
        for dest in new_destinations:
            if dest not in seen_d:
                merged.append(dest)
                seen_d.add(dest)
        policy.firewall.blocked_destinations = merged

    # --- Q3: ALLOW ----------------------------------------------------------

    new_tool_supps: list[ToolSuppressionDef] = []
    new_domains: set[str] = {
        d.strip() for d in answers.domains_extra if d.strip()
    }
    new_first_party: set[str] = {
        d.strip() for d in answers.first_party_extra if d.strip()
    }

    for card_id in answers.allow:
        allow_card = next((c for c in ALLOW_CARDS if c.id == card_id), None)
        if allow_card is None:
            continue
        if allow_card.tool_pattern and allow_card.suppress_findings:
            new_tool_supps.append(
                ToolSuppressionDef(
                    tool_pattern=allow_card.tool_pattern,
                    suppress_findings=list(allow_card.suppress_findings),
                    reason=allow_card.title,
                )
            )
        new_domains.update(allow_card.domains)
        new_first_party.update(allow_card.first_party)

    policy.suppressions.tool_suppressions = _dedupe_by(
        [*policy.suppressions.tool_suppressions, *new_tool_supps],
        key=lambda s: s.tool_pattern,
    )

    merged_domains = list(policy.firewall.allowed_domains)
    seen_dom: set[str] = set(merged_domains)
    for dom in sorted(new_domains):
        if dom not in seen_dom:
            merged_domains.append(dom)
            seen_dom.add(dom)
    policy.firewall.allowed_domains = merged_domains

    existing_first_party_names = {e.target_name for e in policy.first_party_allow_list}
    for glob in sorted(new_first_party):
        if glob in existing_first_party_names:
            continue
        policy.first_party_allow_list.append(
            FirstPartyEntry(
                target_type="plugin",
                target_name=glob,
                reason="Added via Quick Start",
                source_path_contains=[],
            )
        )
        existing_first_party_names.add(glob)

    # --- Q4: response posture ----------------------------------------------

    response = next(
        (r for r in RESPONSES if r.id == answers.response),
        RESPONSES[1],  # "alert" default if id is unknown
    )
    policy.guardrail.block_threshold = response.block_threshold
    policy.guardrail.alert_threshold = response.alert_threshold
    policy.guardrail.hilt.enabled = response.hilt_enabled
    policy.guardrail.hilt.min_severity = response.hilt_min

    if response.id == "block":
        # Tighten install column at MEDIUM/HIGH/CRITICAL. Mirrors
        # the TS ``apply.ts`` "block" branch exactly so a TUI-built
        # "block" policy emits the same install actions as the docs
        # one.
        for sev in ("medium", "high", "critical"):
            triple = policy.skill_actions.get(sev)
            policy.skill_actions.set(
                sev,
                SeverityActionTriple(
                    runtime=triple.runtime,
                    file=triple.file,
                    install="block",
                ),
            )

    # --- Q5: sinks ----------------------------------------------------------

    new_webhooks: list[WebhookEntry] = []
    for card_id, ans in answers.sinks.items():
        if not ans.enabled:
            continue
        sink_card = next((c for c in SINK_CARDS if c.id == card_id), None)
        if sink_card is None:
            continue
        if card_id == "local_file":
            policy.audit.log_all_actions = True
            policy.audit.log_scan_results = True
            continue
        if card_id == "stdout":
            policy.audit.log_all_actions = True
            continue
        if not sink_card.type:
            continue
        if not _is_valid_sink(ans):
            continue
        new_webhooks.append(
            WebhookEntry(
                url=ans.url.strip(),
                type=sink_card.type,  # type: ignore[arg-type]
                secret_env=ans.secret_env.strip(),
                min_severity="HIGH",
                events=["block", "guardrail"],
                enabled=True,
            )
        )

    policy.webhooks = _dedupe_by(
        [*policy.webhooks, *new_webhooks],
        key=lambda w: w.url,
    )

    return policy


# --- helpers -------------------------------------------------------------


def _find_block_card(card_id: str) -> BlockCard | None:
    return next((c for c in BLOCK_CARDS if c.id == card_id), None)


def _force_rule_ids_enabled(file: RulesFile, enabled_ids: set[str]) -> RulesFile:
    """Return a new ``RulesFile`` whose rules in ``enabled_ids`` are
    forced to ``enabled=True`` and the rest are passed through.
    """
    new_rules: list[RuleDef] = []
    for rule in file.rules:
        if rule.id in enabled_ids:
            new_rules.append(
                RuleDef(
                    id=rule.id,
                    pattern=rule.pattern,
                    title=rule.title,
                    severity=rule.severity,
                    confidence=rule.confidence,
                    tags=list(rule.tags),
                    enabled=True,
                )
            )
        else:
            new_rules.append(rule)
    return RulesFile(filename=file.filename, category=file.category, rules=new_rules)


def _replace_correlator_enabled(pattern, enabled: bool):  # type: ignore[no-untyped-def]
    """Return a copy of ``pattern`` with ``enabled`` overridden.

    We mutate-by-copy rather than in-place so the test suite's
    "same Answers in -> same Policy out" property holds even when
    the caller reuses an Answers object across calls.
    """
    from defenseclaw.tui.creator.types import CorrelationPattern

    return CorrelationPattern(
        id=pattern.id,
        description=pattern.description,
        window_events=pattern.window_events,
        severity_on_match=pattern.severity_on_match,
        all_of=list(pattern.all_of),
        sequence=list(pattern.sequence),
        fingerprint_chain=list(pattern.fingerprint_chain),
        enabled=enabled,
    )


def _is_valid_sink(answer: SinkAnswer) -> bool:
    """True iff the sink has a usable HTTP(S) URL."""
    if not answer.enabled:
        return False
    if not answer.url:
        return False
    return bool(_HTTP_URL_RE.match(answer.url.strip()))


def _dedupe_by(items: Iterable[T], *, key: Callable[[T], str]) -> list[T]:
    seen: set[str] = set()
    out: list[T] = []
    for item in items:
        k = key(item)
        if k in seen:
            continue
        seen.add(k)
        out.append(item)
    return out
