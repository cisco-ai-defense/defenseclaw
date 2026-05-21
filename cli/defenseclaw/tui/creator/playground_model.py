# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Phase 11: Playground modal model.

Mirrors ``docs-site/components/policy-creator/playground.tsx`` plus
the per-section files under ``sections/``. Owns:

* The active section pointer and 14-section navigation.
* All key-driven edit handlers per section so the modal screen stays
  a thin Rich/Textual renderer.
* Status badges (``untouched`` / ``customized`` / ``warning``) and
  per-section subtitle strings used by the left-rail nav.
* Validation summary, diff-vs-preset, and a save predicate that the
  modal queries before stamping the policy through ``emit()``.

Following the same model-vs-screen split as
``QuickStartWizardModel`` keeps every interaction unit-testable
without spinning up a Textual ``App`` for every micro-edit.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Literal, Sequence

from defenseclaw.tui.creator.diff import DiffEntry, diff_against_base
from defenseclaw.tui.creator.types import (
    SCANNER_TYPES,
    SEVERITIES,
    AdmissionConfig,
    AuditConfig,
    CiscoAIDefenseConfig,
    EnforcementConfig,
    FirewallConfig,
    FirstPartyEntry,
    GuardrailConfig,
    JudgeConfig,
    Policy,
    SensitiveTool,
    Severity,
    SeverityActionMatrix,
    SeverityActionTriple,
    SeverityUpper,
    WatchConfig,
    WebhookEntry,
)
from defenseclaw.tui.creator.validators import (
    ValidationFinding,
    ValidationSummary,
    summarize,
    validate_policy,
)


SectionStatus = Literal["untouched", "customized", "warning"]


@dataclass(frozen=True, slots=True)
class SectionDef:
    """Static metadata about one Playground section.

    ``id`` powers section navigation and the Ctrl+K palette index.
    ``title`` shows in the left rail. The runtime-computed
    ``subtitle`` and ``status`` callbacks read the live ``Policy``
    so the rail re-renders after every edit without forcing each
    caller to repeat the comprehension.
    """

    id: str
    title: str
    subtitle: Callable[[Policy], str]
    status: Callable[[Policy], SectionStatus]


# --- helpers ----------------------------------------------------------------


def _customized_if_nonempty(values: Sequence[object]) -> SectionStatus:
    """Return ``customized`` when any of the inputs is a non-empty
    list/dict/truthy primitive.

    Matches the React helper ``customizedIfNonEmpty`` so the section
    badges match what the docs-site Creator paints in the same state.
    """

    for value in values:
        if value is None:
            continue
        if isinstance(value, (list, tuple)):
            if value:
                return "customized"
            continue
        if isinstance(value, dict):
            if value:
                return "customized"
            continue
        if value:
            return "customized"
    return "untouched"


_NAME_RE = __import__("re").compile(r"^[a-z0-9][a-z0-9-]{0,63}$")


def _basics_status(policy: Policy) -> SectionStatus:
    if not policy.name or policy.name == "my-policy" or not _NAME_RE.match(policy.name):
        return "warning"
    return "customized"


def _severity_subtitle(policy: Policy) -> str:
    overrides = len(policy.scanner_overrides)
    if overrides:
        suffix = "" if overrides == 1 else "s"
        return f"5 severities | {overrides} scanner override{suffix}"
    return "5 severities"


def _admission_subtitle(policy: Policy) -> str:
    n = len(policy.first_party_allow_list)
    word = "entry" if n == 1 else "entries"
    return f"{n} allow-list {word}"


def _guardrail_subtitle(policy: Policy) -> str:
    cats = len(policy.guardrail.patterns)
    word = "category" if cats == 1 else "categories"
    return (
        f"block>={policy.guardrail.block_threshold} | "
        f"alert>={policy.guardrail.alert_threshold} | "
        f"{cats} pattern {word}"
    )


def _guardrail_status(policy: Policy) -> SectionStatus:
    if policy.guardrail.patterns or policy.guardrail.hilt.enabled:
        return "customized"
    return "untouched"


def _rules_subtitle(policy: Policy) -> str:
    files = len(policy.rule_pack.files)
    total = sum(len(f.rules) for f in policy.rule_pack.files)
    f_word = "" if files == 1 else "s"
    r_word = "" if total == 1 else "s"
    return f"{files} file{f_word} | {total} rule{r_word}"


def _rules_status(policy: Policy) -> SectionStatus:
    return (
        "customized"
        if any(f.rules for f in policy.rule_pack.files)
        else "untouched"
    )


def _suppressions_subtitle(policy: Policy) -> str:
    return (
        f"{len(policy.suppressions.pre_judge_strips)} pre-judge | "
        f"{len(policy.suppressions.finding_suppressions)} finding | "
        f"{len(policy.suppressions.tool_suppressions)} tool"
    )


def _judges_subtitle(policy: Policy) -> str:
    if not policy.judges:
        return "no judges configured"
    return ", ".join(j.name for j in policy.judges)


def _correlator_subtitle(policy: Policy) -> str:
    enabled = sum(1 for c in policy.correlator if c.enabled)
    if not policy.correlator:
        return "not loaded - pick a preset to seed defaults"
    if enabled == len(policy.correlator):
        word = "" if enabled == 1 else "s"
        return f"{enabled} pattern{word} enabled"
    return f"{enabled} of {len(policy.correlator)} patterns enabled"


def _correlator_status(policy: Policy) -> SectionStatus:
    if not policy.correlator:
        return "untouched"
    disabled = sum(1 for c in policy.correlator if not c.enabled)
    if disabled:
        return "warning"
    return "customized"


def _firewall_subtitle(policy: Policy) -> str:
    return (
        f"{policy.firewall.default_action} | "
        f"{len(policy.firewall.allowed_domains)} allow | "
        f"{len(policy.firewall.blocked_destinations)} block"
    )


def _firewall_status(policy: Policy) -> SectionStatus:
    # Default preset ships ~2 IMDS-style block entries; show
    # ``customized`` when the operator added more or any allow domains.
    if policy.firewall.allowed_domains:
        return "customized"
    if len(policy.firewall.blocked_destinations) > 2:
        return "customized"
    return "untouched"


def _webhooks_subtitle(policy: Policy) -> str:
    if not policy.webhooks:
        return "no destinations configured"
    word = "" if len(policy.webhooks) == 1 else "s"
    return f"{len(policy.webhooks)} destination{word}"


def _watch_subtitle(policy: Policy) -> str:
    if policy.watch.rescan_enabled:
        return f"enabled | every {policy.watch.rescan_interval_min} min"
    return "disabled"


def _enforcement_subtitle(policy: Policy) -> str:
    return f"max delay {policy.enforcement.max_enforcement_delay_seconds}s"


def _audit_subtitle(policy: Policy) -> str:
    return f"{policy.audit.retention_days} day retention"


def _scanners_subtitle(policy: Policy) -> str:
    overrides = sum(
        1
        for axis in ("codeguard", "plugin_scanner", "skill_scanner")
        if getattr(policy.scanners, axis)
    )
    if overrides:
        word = "" if overrides == 1 else "s"
        return f"{overrides} scanner profile{word} overridden"
    return "inherit base"


def _scanners_status(policy: Policy) -> SectionStatus:
    if any(
        getattr(policy.scanners, axis)
        for axis in ("codeguard", "plugin_scanner", "skill_scanner")
    ):
        return "customized"
    return "untouched"


def _aid_subtitle(policy: Policy) -> str:
    aid = policy.cisco_ai_defense
    if not aid.enabled and not aid.api_key_env and not aid.endpoint:
        return "off"
    parts = [
        "enabled" if aid.enabled else "disabled",
        f"key={aid.api_key_env}" if aid.api_key_env else "no key",
        f"hook surface {'on' if aid.scan_hook_surface else 'off'}",
    ]
    return " | ".join(parts)


def _aid_status(policy: Policy) -> SectionStatus:
    aid = policy.cisco_ai_defense
    if aid.enabled and not aid.api_key_env:
        return "warning"
    if aid.enabled or aid.api_key_env:
        return "customized"
    return "untouched"


def _custom_rego_subtitle(policy: Policy) -> str:
    if not policy.custom_rego:
        return "no snippets"
    word = "" if len(policy.custom_rego) == 1 else "s"
    return f"{len(policy.custom_rego)} snippet{word}"


# --- the section catalogue --------------------------------------------------

SECTION_DEFS: tuple[SectionDef, ...] = (
    SectionDef(
        id="basics",
        title="Basics",
        subtitle=lambda p: f"name={p.name or '(unset)'} | base={p.basedOn}",
        status=_basics_status,
    ),
    SectionDef(
        id="severity-matrix",
        title="Severity matrix",
        subtitle=_severity_subtitle,
        status=lambda p: "customized" if p.scanner_overrides else "untouched",
    ),
    SectionDef(
        id="admission",
        title="Admission",
        subtitle=_admission_subtitle,
        status=lambda p: _customized_if_nonempty([p.first_party_allow_list]),
    ),
    SectionDef(
        id="guardrail",
        title="Guardrail",
        subtitle=_guardrail_subtitle,
        status=_guardrail_status,
    ),
    SectionDef(
        id="rules",
        title="Rule pack",
        subtitle=_rules_subtitle,
        status=_rules_status,
    ),
    SectionDef(
        id="suppressions",
        title="Suppressions",
        subtitle=_suppressions_subtitle,
        status=lambda p: _customized_if_nonempty(
            [
                p.suppressions.pre_judge_strips,
                p.suppressions.finding_suppressions,
                p.suppressions.tool_suppressions,
            ]
        ),
    ),
    SectionDef(
        id="sensitive-tools",
        title="Sensitive tools",
        subtitle=lambda p: (
            f"{len(p.sensitive_tools)} tool"
            f"{'' if len(p.sensitive_tools) == 1 else 's'}"
        ),
        status=lambda p: _customized_if_nonempty([p.sensitive_tools]),
    ),
    SectionDef(
        id="judges",
        title="LLM judges",
        subtitle=_judges_subtitle,
        status=lambda p: _customized_if_nonempty([p.judges]),
    ),
    SectionDef(
        id="correlator",
        title="Session correlator",
        subtitle=_correlator_subtitle,
        status=_correlator_status,
    ),
    SectionDef(
        id="firewall",
        title="Firewall",
        subtitle=_firewall_subtitle,
        status=_firewall_status,
    ),
    SectionDef(
        id="webhooks",
        title="Webhooks",
        subtitle=_webhooks_subtitle,
        status=lambda p: _customized_if_nonempty([p.webhooks]),
    ),
    SectionDef(
        id="watch",
        title="Watch (rescan)",
        subtitle=_watch_subtitle,
        status=lambda _p: "untouched",
    ),
    SectionDef(
        id="enforcement",
        title="Enforcement",
        subtitle=_enforcement_subtitle,
        status=lambda _p: "untouched",
    ),
    SectionDef(
        id="audit",
        title="Audit",
        subtitle=_audit_subtitle,
        status=lambda _p: "untouched",
    ),
    SectionDef(
        id="scanners",
        title="Scanner profiles",
        subtitle=_scanners_subtitle,
        status=_scanners_status,
    ),
    SectionDef(
        id="cisco-ai-defense",
        title="Cisco AI Defense",
        subtitle=_aid_subtitle,
        status=_aid_status,
    ),
    SectionDef(
        id="custom-rego",
        title="Custom Rego",
        subtitle=_custom_rego_subtitle,
        status=lambda p: _customized_if_nonempty([p.custom_rego]),
    ),
    SectionDef(
        id="review",
        title="Review & save",
        subtitle=lambda _p: "Generated YAML + data.json",
        status=lambda _p: "untouched",
    ),
)


# --- key-driven edit actions ------------------------------------------------


# Severities cycled by the matrix editor.
_RUNTIME_AXIS_VALUES: tuple[str, ...] = ("enable", "disable")
_FILE_AXIS_VALUES: tuple[str, ...] = ("none", "quarantine")
_INSTALL_AXIS_VALUES: tuple[str, ...] = ("none", "allow", "block")
_SEV_UPPER: tuple[SeverityUpper, ...] = (
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
    "INFO",
)
_FIREWALL_DEFAULT_VALUES: tuple[str, ...] = ("allow", "deny")
_TRUST_LEVEL_VALUES: tuple[str, ...] = ("full", "advisory", "none")


def _cycle(values: Sequence[str], current: str) -> str:
    """Cycle through ``values`` returning the value after ``current``.
    If ``current`` isn't in the sequence we return the first entry so
    a stale value gets normalized on the next keystroke instead of
    silently jamming the cycler."""

    try:
        idx = values.index(current)
    except ValueError:
        return values[0]
    return values[(idx + 1) % len(values)]


@dataclass
class PlaygroundModel:
    """Playground state machine.

    ``policy`` is mutated in place so every section editor can rely
    on a stable reference. ``section_idx`` tracks the active section;
    ``severity_cursor`` tracks which row of the severity matrix is
    selected (0..4); ``scanner_axis`` cycles through the four target
    columns of the matrix (``skill_actions``, ``skill``, ``mcp``,
    ``plugin``); ``webhook_cursor`` / ``allowlist_cursor`` mark the
    selected row inside the firewall and admission lists.

    ``dirty`` flips on the first mutation so the close-confirm path
    can prompt only when there's something to lose.
    """

    policy: Policy
    section_idx: int = 0
    severity_cursor: int = 0
    scanner_axis: int = 0  # 0 = skill_actions, 1+2+3 = scanner overrides
    allowlist_cursor: int = 0
    webhook_cursor: int = 0
    test_pane_open: bool = False
    diff_open: bool = False
    dirty: bool = False
    last_message: str = ""

    @property
    def section(self) -> SectionDef:
        return SECTION_DEFS[self.section_idx]

    def section_by_id(self, section_id: str) -> int | None:
        for i, sec in enumerate(SECTION_DEFS):
            if sec.id == section_id:
                return i
        return None

    def jump_to_section(self, section_id: str) -> bool:
        idx = self.section_by_id(section_id)
        if idx is None:
            return False
        self.section_idx = idx
        return True

    # --- validation / diff / status ---------------------------------------

    def validate(self) -> tuple[ValidationFinding, ...]:
        return tuple(validate_policy(self.policy))

    def summary(self) -> ValidationSummary:
        return summarize(self.validate())

    def diff(self) -> list[DiffEntry]:
        return diff_against_base(self.policy)

    def is_savable(self) -> bool:
        """Mirror ``QuickStartWizardModel.is_savable``: block save
        when there are blocking validation errors. Warnings are
        operator-facing only and don't gate save."""
        return self.summary().errors == 0

    def status_for(self, idx: int) -> SectionStatus:
        return SECTION_DEFS[idx].status(self.policy)

    def subtitle_for(self, idx: int) -> str:
        return SECTION_DEFS[idx].subtitle(self.policy)

    # --- section navigation -----------------------------------------------

    def next_section(self) -> None:
        self.section_idx = (self.section_idx + 1) % len(SECTION_DEFS)
        self.severity_cursor = 0
        self.scanner_axis = 0

    def prev_section(self) -> None:
        self.section_idx = (self.section_idx - 1) % len(SECTION_DEFS)
        self.severity_cursor = 0
        self.scanner_axis = 0

    # --- top-level dispatcher --------------------------------------------

    def handle_key(self, key: str) -> str:
        """Route a keystroke to the active section's editor.

        Returns a short human-readable message describing what
        changed (or ``""`` for navigation-only). The modal screen
        echos the message into the validation strip so the operator
        gets immediate feedback.
        """

        # Modal-wide bindings.
        if key == "p":
            self.test_pane_open = not self.test_pane_open
            return f"live test {'on' if self.test_pane_open else 'off'}"
        if key == "d":
            self.diff_open = not self.diff_open
            return f"diff {'shown' if self.diff_open else 'hidden'}"
        if key in ("[", "shift+tab"):
            self.prev_section()
            return ""
        if key in ("]", "tab"):
            self.next_section()
            return ""
        # Section-specific.
        section_id = self.section.id
        method_name = f"_handle_{section_id.replace('-', '_')}"
        handler = getattr(self, method_name, None)
        if handler is None:
            return ""
        message = handler(key)
        if message:
            self.dirty = True
            self.last_message = message
        return message

    # --- per-section handlers --------------------------------------------

    def _handle_basics(self, key: str) -> str:
        if key == "+":
            cycle = ("default", "strict", "permissive")
            self.policy.basedOn = _cycle(cycle, self.policy.basedOn)  # type: ignore[arg-type]
            return f"basedOn -> {self.policy.basedOn}"
        return ""

    def _handle_severity_matrix(self, key: str) -> str:
        # j/k cycle severity rows; h/l cycle scanner axis (0=base,
        # 1=skill, 2=mcp, 3=plugin); space cycles the runtime verdict
        # of the active cell; f cycles file axis; i cycles install axis.
        if key in ("j", "down"):
            self.severity_cursor = (self.severity_cursor + 1) % len(SEVERITIES)
            return ""
        if key in ("k", "up"):
            self.severity_cursor = (self.severity_cursor - 1) % len(SEVERITIES)
            return ""
        if key in ("h", "left"):
            self.scanner_axis = (self.scanner_axis - 1) % 4
            return ""
        if key in ("l", "right"):
            self.scanner_axis = (self.scanner_axis + 1) % 4
            return ""
        if key not in ("space", "f", "i"):
            return ""

        sev: Severity = SEVERITIES[self.severity_cursor]  # type: ignore[assignment]
        triple = self._matrix_cell(sev)
        if key == "space":
            triple.runtime = _cycle(_RUNTIME_AXIS_VALUES, triple.runtime)  # type: ignore[assignment]
            self._matrix_assign(sev, triple)
            return f"{self._axis_label()}.{sev}.runtime -> {triple.runtime}"
        if key == "f":
            triple.file = _cycle(_FILE_AXIS_VALUES, triple.file)  # type: ignore[assignment]
            self._matrix_assign(sev, triple)
            return f"{self._axis_label()}.{sev}.file -> {triple.file}"
        if key == "i":
            triple.install = _cycle(_INSTALL_AXIS_VALUES, triple.install)  # type: ignore[assignment]
            self._matrix_assign(sev, triple)
            return f"{self._axis_label()}.{sev}.install -> {triple.install}"
        return ""

    def _axis_label(self) -> str:
        if self.scanner_axis == 0:
            return "skill_actions"
        return f"scanner_overrides.{SCANNER_TYPES[self.scanner_axis - 1]}"

    def _matrix_cell(self, sev: Severity) -> SeverityActionTriple:
        if self.scanner_axis == 0:
            return SeverityActionTriple(**vars(self.policy.skill_actions.get(sev)))
        scanner = SCANNER_TYPES[self.scanner_axis - 1]
        ovr = self.policy.scanner_overrides.get(scanner, {})
        triple = ovr.get(sev) if isinstance(ovr, dict) else None
        if triple is None:
            return SeverityActionTriple(**vars(self.policy.skill_actions.get(sev)))
        return SeverityActionTriple(**vars(triple))

    def _matrix_assign(self, sev: Severity, triple: SeverityActionTriple) -> None:
        if self.scanner_axis == 0:
            self.policy.skill_actions.set(sev, triple)
            return
        scanner = SCANNER_TYPES[self.scanner_axis - 1]
        ovr = self.policy.scanner_overrides.setdefault(scanner, {})
        if isinstance(ovr, dict):
            ovr[sev] = triple

    def _handle_admission(self, key: str) -> str:
        if key == "s":
            self.policy.admission.scan_on_install = not self.policy.admission.scan_on_install
            return f"scan_on_install -> {self.policy.admission.scan_on_install}"
        if key == "b":
            self.policy.admission.allow_list_bypass_scan = (
                not self.policy.admission.allow_list_bypass_scan
            )
            return (
                "allow_list_bypass_scan -> "
                f"{self.policy.admission.allow_list_bypass_scan}"
            )
        if key == "x" and self.policy.first_party_allow_list:
            removed = self.policy.first_party_allow_list.pop(self.allowlist_cursor)
            self.allowlist_cursor = max(
                0, min(self.allowlist_cursor, len(self.policy.first_party_allow_list) - 1)
            )
            return f"removed first_party allow-list entry: {removed.target_name or '<unnamed>'}"
        if key in ("j", "down"):
            if self.policy.first_party_allow_list:
                self.allowlist_cursor = (self.allowlist_cursor + 1) % len(
                    self.policy.first_party_allow_list
                )
            return ""
        if key in ("k", "up"):
            if self.policy.first_party_allow_list:
                self.allowlist_cursor = (self.allowlist_cursor - 1) % len(
                    self.policy.first_party_allow_list
                )
            return ""
        return ""

    def _handle_guardrail(self, key: str) -> str:
        g = self.policy.guardrail
        if key == "+" and g.block_threshold < 4:
            g.block_threshold += 1
            return f"block_threshold -> {g.block_threshold}"
        if key == "-" and g.block_threshold > 1:
            g.block_threshold -= 1
            return f"block_threshold -> {g.block_threshold}"
        if key == "shift+up" and g.alert_threshold < 4:
            g.alert_threshold += 1
            return f"alert_threshold -> {g.alert_threshold}"
        if key == "shift+down" and g.alert_threshold > 1:
            g.alert_threshold -= 1
            return f"alert_threshold -> {g.alert_threshold}"
        if key == "h":
            g.hilt.enabled = not g.hilt.enabled
            return f"hilt.enabled -> {g.hilt.enabled}"
        if key == "t":
            g.cisco_trust_level = _cycle(_TRUST_LEVEL_VALUES, g.cisco_trust_level)  # type: ignore[assignment]
            return f"cisco_trust_level -> {g.cisco_trust_level}"
        return ""

    def _handle_firewall(self, key: str) -> str:
        f = self.policy.firewall
        if key == "space":
            f.default_action = _cycle(_FIREWALL_DEFAULT_VALUES, f.default_action)  # type: ignore[assignment]
            return f"default_action -> {f.default_action}"
        return ""

    def _handle_webhooks(self, key: str) -> str:
        if key == "x" and self.policy.webhooks:
            removed = self.policy.webhooks.pop(self.webhook_cursor)
            self.webhook_cursor = max(
                0, min(self.webhook_cursor, len(self.policy.webhooks) - 1)
            )
            return f"removed webhook: {removed.url or '<no-url>'}"
        if key in ("j", "down") and self.policy.webhooks:
            self.webhook_cursor = (self.webhook_cursor + 1) % len(
                self.policy.webhooks
            )
            return ""
        if key in ("k", "up") and self.policy.webhooks:
            self.webhook_cursor = (self.webhook_cursor - 1) % len(
                self.policy.webhooks
            )
            return ""
        return ""

    def _handle_watch(self, key: str) -> str:
        w = self.policy.watch
        if key == "space":
            w.rescan_enabled = not w.rescan_enabled
            return f"rescan_enabled -> {w.rescan_enabled}"
        if key == "+":
            w.rescan_interval_min = min(1440, w.rescan_interval_min + 5)
            return f"rescan_interval_min -> {w.rescan_interval_min}"
        if key == "-":
            w.rescan_interval_min = max(5, w.rescan_interval_min - 5)
            return f"rescan_interval_min -> {w.rescan_interval_min}"
        return ""

    def _handle_enforcement(self, key: str) -> str:
        e = self.policy.enforcement
        if key == "+":
            e.max_enforcement_delay_seconds += 1
            return f"max_enforcement_delay_seconds -> {e.max_enforcement_delay_seconds}"
        if key == "-" and e.max_enforcement_delay_seconds > 0:
            e.max_enforcement_delay_seconds -= 1
            return f"max_enforcement_delay_seconds -> {e.max_enforcement_delay_seconds}"
        return ""

    def _handle_audit(self, key: str) -> str:
        a = self.policy.audit
        if key == "a":
            a.log_all_actions = not a.log_all_actions
            return f"log_all_actions -> {a.log_all_actions}"
        if key == "s":
            a.log_scan_results = not a.log_scan_results
            return f"log_scan_results -> {a.log_scan_results}"
        if key == "+":
            a.retention_days = min(365, a.retention_days + 7)
            return f"retention_days -> {a.retention_days}"
        if key == "-":
            a.retention_days = max(1, a.retention_days - 7)
            return f"retention_days -> {a.retention_days}"
        return ""

    def _handle_cisco_ai_defense(self, key: str) -> str:
        aid = self.policy.cisco_ai_defense
        if key == "space":
            aid.enabled = not aid.enabled
            return f"cisco_ai_defense.enabled -> {aid.enabled}"
        if key == "h":
            aid.scan_hook_surface = not aid.scan_hook_surface
            return f"scan_hook_surface -> {aid.scan_hook_surface}"
        return ""

    def _handle_correlator(self, key: str) -> str:
        if key == "space" and self.policy.correlator:
            pat = self.policy.correlator[0]
            pat.enabled = not pat.enabled
            # Use ``correlator.<id>`` rather than the dotted-array
            # ``correlator[<id>]`` form because the latter is parsed
            # as a Rich style tag the moment a renderer pipes the
            # message into a ``Static.update``.
            return f"correlator.{pat.id}.enabled -> {pat.enabled}"
        return ""

    # Sections that are read-only in this build (reserved for the
    # full per-section editors planned in the design doc but not in
    # this commit's scope). They acknowledge the keystroke without
    # mutating state so the operator can still navigate freely.
    def _handle_rules(self, key: str) -> str:
        return ""

    def _handle_suppressions(self, key: str) -> str:
        return ""

    def _handle_sensitive_tools(self, key: str) -> str:
        return ""

    def _handle_judges(self, key: str) -> str:
        return ""

    def _handle_scanners(self, key: str) -> str:
        return ""

    def _handle_custom_rego(self, key: str) -> str:
        return ""

    def _handle_review(self, key: str) -> str:
        # Review section is renderer-only; save is wired through
        # ctrl+s at the screen level, not here.
        return ""

    # --- save outcome ----------------------------------------------------

    def save_payload(self) -> Policy:
        """Return the live ``Policy`` for the modal to persist.

        We hand back the same reference (not a copy) because the
        screen passes it straight to ``emit()`` and discards the
        modal afterwards. If a later phase needs to keep the modal
        open after save (e.g. continuous edit), this is the seam to
        switch to ``dataclasses.replace`` for a snapshot.
        """

        return self.policy
