# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Python port of ``docs-site/components/policy-creator/types.ts``.

Each dataclass mirrors a TypeScript ``interface`` 1:1 so the wizard,
the validator pipeline, the YAML emitter, and the OPA-eval lane can
share a single, strongly-typed schema. Field names match what
``defenseclaw policy activate`` writes to ``~/.defenseclaw/policies/``
- changing one means changing all six consumers in lock-step.

We use ``dataclass(frozen=False)`` so the wizard can mutate live state
with simple attribute assignment (the model produces a new ``Policy``
on every keystroke and the panel diffs against the preset). Frozen
records would force ``replace()`` on every keystroke, which is a real
allocation tax in a TUI. Hashing isn't needed because nothing keys a
``dict`` by ``Policy``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

# Severity levels — lowercase variants used throughout the YAML schema
# (skill_actions keys, finding severities). Mirrors ``SEVERITIES``
# in the TS module.
SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low", "info")
Severity = Literal["critical", "high", "medium", "low", "info"]

# Uppercase variants used by guardrail / judge / firewall / webhook
# blocks because the gateway preserves the legacy operator-facing
# casing in those configs.
SEVERITIES_UPPER: tuple[str, ...] = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
SeverityUpper = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

SCANNER_TYPES: tuple[str, ...] = ("skill", "mcp", "plugin")
ScannerType = Literal["skill", "mcp", "plugin"]

RuntimeAction = Literal["enable", "disable"]
FileAction = Literal["none", "quarantine"]
InstallAction = Literal["none", "allow", "block"]

PresetName = Literal["default", "strict", "permissive"]


# --- Severity action matrix --------------------------------------------------


@dataclass
class SeverityActionTriple:
    """Triple of (runtime, file, install) action verdicts for one severity."""

    runtime: RuntimeAction = "enable"
    file: FileAction = "none"
    install: InstallAction = "none"


@dataclass
class SeverityActionMatrix:
    """One ``SeverityActionTriple`` per severity. Matches the TS
    ``Record<Severity, SeverityActionTriple>`` and the YAML
    ``skill_actions`` block."""

    critical: SeverityActionTriple = field(default_factory=SeverityActionTriple)
    high: SeverityActionTriple = field(default_factory=SeverityActionTriple)
    medium: SeverityActionTriple = field(default_factory=SeverityActionTriple)
    low: SeverityActionTriple = field(default_factory=SeverityActionTriple)
    info: SeverityActionTriple = field(default_factory=SeverityActionTriple)

    def get(self, severity: str) -> SeverityActionTriple:
        return getattr(self, severity)

    def set(self, severity: str, triple: SeverityActionTriple) -> None:
        setattr(self, severity, triple)

    def items(self) -> list[tuple[str, SeverityActionTriple]]:
        return [(severity, getattr(self, severity)) for severity in SEVERITIES]


# --- Admission --------------------------------------------------------------


@dataclass
class AdmissionConfig:
    scan_on_install: bool = True
    allow_list_bypass_scan: bool = True


# --- First-party allow list -------------------------------------------------


@dataclass
class FirstPartyEntry:
    target_type: ScannerType = "skill"
    target_name: str = ""
    reason: str = ""
    source_path_contains: list[str] = field(default_factory=list)


# --- Guardrail --------------------------------------------------------------


@dataclass
class GuardrailHilt:
    enabled: bool = False
    min_severity: SeverityUpper = "MEDIUM"


@dataclass
class GuardrailConfig:
    block_threshold: int = 4  # 1..4 in TS; we rely on the validator to enforce
    alert_threshold: int = 2
    cisco_trust_level: Literal["full", "advisory", "none"] = "full"
    hilt: GuardrailHilt = field(default_factory=GuardrailHilt)
    # Free-form keyed by category. The default catalogue ships with
    # injection / secrets / exfiltration; the operator can add new
    # categories from the Playground "Patterns" section.
    patterns: dict[str, list[str]] = field(default_factory=dict)
    severity_mappings: dict[str, SeverityUpper] = field(default_factory=dict)


# --- Rule packs -------------------------------------------------------------


@dataclass
class RuleDef:
    """One regex rule inside a guardrail rule pack file."""

    id: str = ""
    pattern: str = ""
    title: str = ""
    severity: SeverityUpper = "MEDIUM"
    confidence: float = 0.5
    tags: list[str] = field(default_factory=list)
    enabled: bool | None = None


@dataclass
class RulesFile:
    """One ``guardrail/<pack>/rules/<filename>.yaml`` file."""

    filename: str = ""
    category: str = ""
    rules: list[RuleDef] = field(default_factory=list)


@dataclass
class RulePackBundle:
    name: str = ""
    files: list[RulesFile] = field(default_factory=list)


# --- Suppressions -----------------------------------------------------------


@dataclass
class PreJudgeStripDef:
    id: str = ""
    pattern: str = ""
    context: str = ""
    applies_to: list[Literal["pii", "injection", "tool-injection", "exfil"]] = field(
        default_factory=list
    )


@dataclass
class FindingSuppressionDef:
    id: str = ""
    finding_pattern: str = ""
    entity_pattern: str = ""
    condition: Literal["", "is_epoch", "is_platform_id"] = ""
    reason: str = ""


@dataclass
class ToolSuppressionDef:
    tool_pattern: str = ""
    suppress_findings: list[str] = field(default_factory=list)
    reason: str = ""


@dataclass
class SuppressionsBundle:
    pre_judge_strips: list[PreJudgeStripDef] = field(default_factory=list)
    finding_suppressions: list[FindingSuppressionDef] = field(default_factory=list)
    tool_suppressions: list[ToolSuppressionDef] = field(default_factory=list)


# --- Sensitive tools --------------------------------------------------------


@dataclass
class SensitiveTool:
    name: str = ""
    result_inspection: bool = False
    judge_result: bool = False
    min_entities_for_alert: int | None = None


# --- Judges -----------------------------------------------------------------


@dataclass
class JudgeCategoryDef:
    finding_id: str = ""
    severity: SeverityUpper | None = None
    severity_default: SeverityUpper | None = None
    severity_prompt: SeverityUpper | None = None
    severity_completion: SeverityUpper | None = None
    enabled: bool = True


@dataclass
class JudgeConfig:
    name: Literal["pii", "injection", "tool-injection", "exfil"] = "injection"
    enabled: bool = False
    system_prompt: str = ""
    adjudication_prompt: str = ""
    min_categories_for_high: int | None = None
    # The bundled injection judge ships with min_categories_for_critical=2
    # so two independent category hits escalate to CRITICAL. Modeling
    # this explicitly avoids silently dropping the field on emit and
    # lowering the operator's effective severity ceiling.
    min_categories_for_critical: int | None = None
    single_category_max_severity: SeverityUpper | None = None
    categories: dict[str, JudgeCategoryDef] = field(default_factory=dict)


# --- Firewall ---------------------------------------------------------------


@dataclass
class FirewallConfig:
    default_action: Literal["allow", "deny"] = "allow"
    blocked_destinations: list[str] = field(default_factory=list)
    allowed_domains: list[str] = field(default_factory=list)
    allowed_ports: list[int] = field(default_factory=list)


# --- Webhooks ---------------------------------------------------------------


@dataclass
class WebhookEntry:
    url: str = ""
    type: Literal["slack", "webex", "pagerduty", "generic"] = "slack"
    secret_env: str = ""
    room_id: str = ""
    min_severity: SeverityUpper = "HIGH"
    events: list[Literal["block", "drift", "guardrail"]] = field(default_factory=list)
    enabled: bool = True


# --- Watch / enforcement / audit -------------------------------------------


@dataclass
class WatchConfig:
    rescan_enabled: bool = False
    rescan_interval_min: int = 60


@dataclass
class EnforcementConfig:
    max_enforcement_delay_seconds: int = 5


@dataclass
class AuditConfig:
    log_all_actions: bool = True
    log_scan_results: bool = True
    retention_days: int = 30


# --- Per-scanner profiles ---------------------------------------------------


@dataclass
class ScannerProfileSelection:
    """Profile-name selection per scanner. Keys match the YAML
    ``scanners.<name>.profile`` field. Empty string == use bundled
    default."""

    codeguard: str = ""
    plugin_scanner: str = ""
    skill_scanner: str = ""

    def to_yaml_keys(self) -> dict[str, str]:
        """Map snake_case Python attrs back to the YAML's
        ``codeguard`` / ``plugin-scanner`` / ``skill-scanner`` keys."""
        return {
            "codeguard": self.codeguard,
            "plugin-scanner": self.plugin_scanner,
            "skill-scanner": self.skill_scanner,
        }


# --- Custom Rego ------------------------------------------------------------


@dataclass
class CustomRegoSnippet:
    """Custom Rego that appends to the bundled rule pack at install
    time. MUST declare ``package defenseclaw.custom.<name>`` so the
    bundled modules can reference it via ``data.defenseclaw.custom``.
    """

    name: str = ""
    package: str = ""
    source: str = ""
    description: str = ""


# --- Layer-5 correlator -----------------------------------------------------

DATA_AXES: tuple[str, ...] = (
    "ingress_untrusted",
    "sensitive_access",
    "egress_external",
)
DataAxis = Literal["ingress_untrusted", "sensitive_access", "egress_external"]

TOOL_CAPABILITY_CLASSES: tuple[str, ...] = (
    "read_fs",
    "write_fs",
    "exec_shell",
    "network_fetch",
    "send_message",
)
ToolCapabilityClass = Literal[
    "read_fs", "write_fs", "exec_shell", "network_fetch", "send_message"
]


@dataclass
class CorrelationClause:
    """Single predicate inside a correlation pattern.

    Empty fields are "don't care"; the clause fires when ALL set
    predicates hold on the finding under inspection.
    """

    axis: DataAxis | None = None
    tool_capability_class: ToolCapabilityClass | None = None
    with_rule_match: list[str] = field(default_factory=list)
    min_severity: SeverityUpper | None = None


@dataclass
class CorrelationSequenceStep:
    severity: SeverityUpper = "MEDIUM"


@dataclass
class CorrelationPattern:
    id: str = ""
    description: str = ""
    window_events: int = 100
    severity_on_match: SeverityUpper = "HIGH"
    all_of: list[CorrelationClause] = field(default_factory=list)
    sequence: list[CorrelationSequenceStep] = field(default_factory=list)
    fingerprint_chain: list[CorrelationClause] = field(default_factory=list)
    enabled: bool = True


# --- Cisco AI Defense ------------------------------------------------------


@dataclass
class CiscoAIDefenseConfig:
    """Top-level config.yaml block for the AID gateway lane.

    Mirrors ``internal/config/config.go`` ``CiscoAIDefenseConfig``.
    ``scan_hook_surface`` defaults to True so the hook lane is
    enabled when an API key resolves at runtime.
    """

    enabled: bool = False
    endpoint: str = ""
    api_key_env: str = ""
    scan_hook_surface: bool = True


# --- The aggregate Policy ---------------------------------------------------


@dataclass
class Policy:
    """Aggregate of every knob the engine consumes.

    ``basedOn`` (note the camelCase mirroring the TS field) records
    which preset the operator started from. The diff renderer in
    Phase 8 uses this to highlight overrides.

    All sub-blocks default to a no-op posture matching the CLI's
    ``policy create`` defaults so a brand-new ``Policy()`` is itself
    a valid (if permissive) configuration.
    """

    name: str = ""
    description: str = ""
    basedOn: PresetName = "default"
    admission: AdmissionConfig = field(default_factory=AdmissionConfig)
    skill_actions: SeverityActionMatrix = field(default_factory=SeverityActionMatrix)
    # Partial overrides: ``{scanner_type: {severity: triple}}``.
    # Empty dict means "fall through to skill_actions".
    scanner_overrides: dict[ScannerType, dict[Severity, SeverityActionTriple]] = field(
        default_factory=dict
    )
    first_party_allow_list: list[FirstPartyEntry] = field(default_factory=list)
    guardrail: GuardrailConfig = field(default_factory=GuardrailConfig)
    rule_pack: RulePackBundle = field(default_factory=RulePackBundle)
    suppressions: SuppressionsBundle = field(default_factory=SuppressionsBundle)
    sensitive_tools: list[SensitiveTool] = field(default_factory=list)
    judges: list[JudgeConfig] = field(default_factory=list)
    firewall: FirewallConfig = field(default_factory=FirewallConfig)
    webhooks: list[WebhookEntry] = field(default_factory=list)
    watch: WatchConfig = field(default_factory=WatchConfig)
    enforcement: EnforcementConfig = field(default_factory=EnforcementConfig)
    audit: AuditConfig = field(default_factory=AuditConfig)
    scanners: ScannerProfileSelection = field(default_factory=ScannerProfileSelection)
    custom_rego: list[CustomRegoSnippet] = field(default_factory=list)
    correlator: list[CorrelationPattern] = field(default_factory=list)
    cisco_ai_defense: CiscoAIDefenseConfig = field(default_factory=CiscoAIDefenseConfig)


# --- Validation findings ----------------------------------------------------

ValidationLevel = Literal["error", "warning", "info"]

# Codes mirror the TS ``ValidationCode`` union. Pinning each code as
# a string constant lets tests assert on individual rules without
# having to import the ``Literal`` type.
VALIDATION_CODES: tuple[str, ...] = (
    "REGEX_INVALID",
    "REGEX_RE2_INCOMPAT",
    "REGEX_REDOS",
    "REGEX_ANCHOR_MISSING",
    "ID_DUPLICATE",
    "ID_FORMAT",
    "SEVERITY_OUT_OF_RANGE",
    "SUPP_OVER_BROAD",
    "RULE_OVERLAP",
    "WEBHOOK_SECRET_MISSING",
    "FIREWALL_DEFAULT_DENY_NO_ALLOW",
    "SCANNER_OVERRIDE_LOOSER",
    "OPA_VERDICT_UNEXPECTED",
    "NAME_INVALID",
    "CUSTOM_REGO_MISSING_PACKAGE",
    "CORRELATOR_PATTERN_EMPTY",
    "CORRELATOR_WINDOW_INVALID",
    "CISCO_AID_KEY_ENV_MISSING",
    "ENV_NAME_LIKELY_SECRET",
    "CUSTOM_REGO_LIKELY_SECRET",
    "RISKY_FIREWALL_DEFAULT_ALLOW",
    "RISKY_ALL_ACTIONS_ALLOW",
    "RISKY_CUSTOM_REGO_IDENTITY_ALLOW",
    "RISKY_JUDGE_THRESHOLD_MISMATCH",
    "RISKY_CORRELATOR_ALL_DISABLED",
)
ValidationCode = Literal[
    "REGEX_INVALID",
    "REGEX_RE2_INCOMPAT",
    "REGEX_REDOS",
    "REGEX_ANCHOR_MISSING",
    "ID_DUPLICATE",
    "ID_FORMAT",
    "SEVERITY_OUT_OF_RANGE",
    "SUPP_OVER_BROAD",
    "RULE_OVERLAP",
    "WEBHOOK_SECRET_MISSING",
    "FIREWALL_DEFAULT_DENY_NO_ALLOW",
    "SCANNER_OVERRIDE_LOOSER",
    "OPA_VERDICT_UNEXPECTED",
    "NAME_INVALID",
    "CUSTOM_REGO_MISSING_PACKAGE",
    "CORRELATOR_PATTERN_EMPTY",
    "CORRELATOR_WINDOW_INVALID",
    "CISCO_AID_KEY_ENV_MISSING",
    "ENV_NAME_LIKELY_SECRET",
    "CUSTOM_REGO_LIKELY_SECRET",
    "RISKY_FIREWALL_DEFAULT_ALLOW",
    "RISKY_ALL_ACTIONS_ALLOW",
    "RISKY_CUSTOM_REGO_IDENTITY_ALLOW",
    "RISKY_JUDGE_THRESHOLD_MISMATCH",
    "RISKY_CORRELATOR_ALL_DISABLED",
]


@dataclass(frozen=True)
class ValidationFinding:
    """One lint result against a ``Policy``.

    Frozen so the validator can return tuples that the UI dedupes by
    ``(code, location)`` without surprising mutation.
    """

    level: ValidationLevel
    code: ValidationCode
    message: str
    # Dotted JSON path or section name where the issue lives. The
    # wizard uses this to scroll the user to the right control.
    location: str = ""
    fix: str = ""


# --- Generated build-time types --------------------------------------------


@dataclass
class PresetGuardrailBundle:
    rules: dict[str, Any] = field(default_factory=dict)
    judge: dict[str, Any] = field(default_factory=dict)
    suppressions: dict[str, Any] | None = None
    sensitiveTools: dict[str, Any] | None = None
    correlator: dict[str, Any] | None = None


@dataclass
class PresetInnerBundle:
    name: str = ""
    description: str = ""
    policy: dict[str, Any] = field(default_factory=dict)
    guardrail: PresetGuardrailBundle = field(default_factory=PresetGuardrailBundle)
    scanners: dict[str, dict[str, dict[str, Any]]] = field(default_factory=dict)


@dataclass
class PresetBundle:
    """Top-level preset shape — name + description + the inner bundle."""

    name: PresetName = "default"
    description: str = ""
    bundle: PresetInnerBundle = field(default_factory=PresetInnerBundle)


# --- OPA result -------------------------------------------------------------


@dataclass
class OpaResult:
    """Outcome of one ``opa eval`` call against the Live-Test pane."""

    verdict: str = ""
    reason: str = ""
    raw: Any = None
