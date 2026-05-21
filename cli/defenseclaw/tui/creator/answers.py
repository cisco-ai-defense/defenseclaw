# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Quick Start question catalogues.

Python port of ``docs-site/components/policy-creator/quick-start/questions.ts``.

Pure data + simple types so the TUI Quick Start screen and the
``apply.py`` mapper can both import this without dragging Textual
into the latter. Mirrors every constant in the TS module 1:1 so a
docs-site policy and a TUI-built policy with the same answers
produce byte-identical YAML.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from defenseclaw.tui.creator.types import PresetName, SeverityUpper

PostureId = Literal["permissive", "default", "strict"]
ResponseId = Literal["log_only", "alert", "ask", "block"]
BlockCategory = Literal["data", "network", "code", "llm", "multi_step"]
SinkConfigKey = Literal["url", "secret_env"]


@dataclass(frozen=True)
class PostureCard:
    id: PostureId
    title: str
    description: str


# Q1: posture (single select). Mirrors the ``POSTURES`` array in the
# TS module - same ids, same titles, same description copy.
POSTURES: tuple[PostureCard, ...] = (
    PostureCard(
        id="permissive",
        title="Permissive",
        description=(
            "Log everything; only CRITICAL findings block installs. Best for "
            "the first week of a pilot or a SOC team that wants visibility "
            "without operational risk."
        ),
    ),
    PostureCard(
        id="default",
        title="Balanced",
        description=(
            "Block CRITICAL findings, alert on HIGH, log MEDIUM. Sensible "
            "production default for most teams."
        ),
    ),
    PostureCard(
        id="strict",
        title="Strict",
        description=(
            "Block at MEDIUM+, ask before any sandboxed install, hold HIGH+ "
            "verdicts for human approval. Pick this for regulated workloads."
        ),
    ),
)

POSTURE_TO_PRESET: dict[PostureId, PresetName] = {
    "permissive": "permissive",
    "default": "default",
    "strict": "strict",
}


# Q2: what to block ----------------------------------------------------------


@dataclass(frozen=True)
class BlockCategoryCard:
    id: BlockCategory
    title: str
    blurb: str


BLOCK_CATEGORIES: tuple[BlockCategoryCard, ...] = (
    BlockCategoryCard(
        id="data",
        title="Data leaks",
        blurb=(
            "Credentials, PII, and sensitive paths the agent should never "
            "read or send."
        ),
    ),
    BlockCategoryCard(
        id="network",
        title="Network exfiltration",
        blurb=(
            "Outbound destinations commonly used to siphon data out of a sandbox."
        ),
    ),
    BlockCategoryCard(
        id="code",
        title="Code execution",
        blurb="Shell commands and tool calls that can hose the box.",
    ),
    BlockCategoryCard(
        id="llm",
        title="LLM-layer attacks",
        blurb="Prompt-shape patterns aimed at the model itself.",
    ),
    BlockCategoryCard(
        id="multi_step",
        title="Multi-step attack patterns",
        blurb=(
            "Session-level patterns where each step looks benign but the "
            "sequence does not. Powered by the Layer-5 correlator."
        ),
    ),
)


@dataclass(frozen=True)
class GuardrailPatternBundle:
    category: str
    patterns: tuple[str, ...]
    severity: SeverityUpper


@dataclass(frozen=True)
class BlockCard:
    """One toggle on the "What should we block?" step.

    Attributes mirror the TS ``BlockCard`` interface. Mutable
    sequences are exposed as tuples to keep the catalog
    immutable - the apply mapper copies them when building the
    Policy graph.
    """

    id: str
    category: BlockCategory
    title: str
    description: str
    rule_ids: tuple[str, ...] = ()
    destinations: tuple[str, ...] = ()
    guardrail_patterns: tuple[GuardrailPatternBundle, ...] = ()
    correlator_pattern_ids: tuple[str, ...] = ()
    cookbook_href: str = ""


def _build_block_display_order(
    categories: tuple["BlockCategoryCard", ...],
    cards: tuple["BlockCard", ...],
) -> tuple[int, ...]:
    """Return ``BLOCK_CARDS`` indices in *render* order.

    The Block step renders cards grouped by category (Data leaks ->
    Network -> Code -> LLM -> Multi-step), but ``BLOCK_CARDS`` is in
    declaration order, so up/down navigation has to walk this derived
    order or the cursor visibly jumps between sections instead of
    moving smoothly down the list.

    Categories are walked in ``BLOCK_CATEGORIES`` order; within a
    category, cards keep their declaration order. Any card whose
    category is not in ``BLOCK_CATEGORIES`` is appended at the end so
    nothing gets dropped silently.
    """

    seen_indices: set[int] = set()
    display: list[int] = []
    for cat in categories:
        for i, card in enumerate(cards):
            if card.category == cat.id:
                display.append(i)
                seen_indices.add(i)
    for i in range(len(cards)):
        if i not in seen_indices:
            display.append(i)
    return tuple(display)


BLOCK_CARDS: tuple[BlockCard, ...] = (
    BlockCard(
        id="secrets",
        category="data",
        title="Hardcoded secrets in prompts",
        description=(
            "AWS access keys, OpenAI keys, GitHub tokens, JWTs, private keys, "
            "Slack webhooks. Catches credentials accidentally pasted into "
            "prompts before they reach an LLM provider."
        ),
        rule_ids=(
            "SEC-AWS-KEY",
            "SEC-OPENAI-V2",
            "SEC-GITHUB-TOKEN",
            "SEC-PRIVKEY",
            "SEC-JWT",
            "SEC-SLACK-WEBHOOK",
            "SEC-STRIPE",
            "SEC-GCP",
        ),
        cookbook_href="/docs/policies/regex-cookbook",
    ),
    BlockCard(
        id="prompt_injection",
        category="llm",
        title="Prompt injection",
        description=(
            "System-prompt overrides, role overrides, jailbreak chains. "
            "Detects user input attempting to bypass guardrails or escalate "
            "the agent's capabilities."
        ),
        rule_ids=(
            "INJ-SYS-OVERRIDE",
            "INJ-ROLE-OVERRIDE",
            "INJ-IGNORE-PREV",
            "INJ-JAILBREAK",
        ),
        guardrail_patterns=(
            GuardrailPatternBundle(
                category="injection",
                patterns=(
                    "ignore (?:all )?previous",
                    "system prompt:",
                    "you are (?:now )?(?:a |an )?",
                ),
                severity="HIGH",
            ),
        ),
        cookbook_href="/docs/policies/regex-cookbook",
    ),
    BlockCard(
        id="exfiltration",
        category="network",
        title="Exfiltration to known leak sinks",
        description=(
            "RequestBin, HookBin, Burp Collaborator, ngrok, webhook.site. "
            "The most common destinations for exfiltrated data when an "
            "attacker doesn't bother hiding."
        ),
        rule_ids=("C2-REQUESTBIN", "C2-HOOKBIN", "C2-BURP", "C2-NGROK", "C2-WEBHOOKSITE"),
        destinations=(
            "requestbin.com",
            "hookbin.com",
            "burpcollaborator.net",
            "ngrok.io",
            "webhook.site",
        ),
        cookbook_href="/docs/policies/regex-cookbook",
    ),
    BlockCard(
        id="cloud_metadata",
        category="network",
        title="Cloud metadata access (IMDS)",
        description=(
            "AWS IMDS at 169.254.169.254, GCP metadata at "
            "metadata.google.internal, Azure IMDS. Exposing these from a "
            "sandboxed agent leaks credentials with one curl."
        ),
        destinations=(
            "169.254.169.254",
            "fd00:ec2::254",
            "metadata.google.internal",
            "metadata.azure.com",
        ),
    ),
    BlockCard(
        id="destructive_shell",
        category="code",
        title="Destructive shell commands",
        description=(
            "rm -rf /, dd if=, mkfs, fdisk, shred, :(){:|:&};:. Catches the "
            'canonical "make the disk dance" patterns before they hit a '
            "sandbox."
        ),
        rule_ids=("CMD-RM-RF", "CMD-DD", "CMD-MKFS", "CMD-FORK-BOMB", "CMD-SHRED"),
        cookbook_href="/docs/policies/regex-cookbook",
    ),
    BlockCard(
        id="sensitive_paths",
        category="data",
        title="Sensitive file paths",
        description=(
            "~/.ssh, ~/.aws, ~/.kube, /etc/shadow, .env files, gh-cli config. "
            "Prevents the agent from reading or writing config that leaks "
            "long-lived credentials."
        ),
        rule_ids=("PATH-SSH", "PATH-AWS", "PATH-KUBE", "PATH-SHADOW", "PATH-DOTENV"),
        cookbook_href="/docs/policies/regex-cookbook",
    ),
    BlockCard(
        id="pii_enterprise",
        category="data",
        title="PII / enterprise data leakage",
        description=(
            "SSN, internal hostnames, employee IDs, financial routing numbers. "
            "Most useful when the agent talks to public LLM providers."
        ),
        rule_ids=("PII-SSN", "ENT-INTERNAL-HOST", "ENT-EMP-ID", "PII-ROUTING"),
        cookbook_href="/docs/policies/regex-cookbook",
    ),
    BlockCard(
        id="trust_exploit",
        category="llm",
        title="Trust / impersonation exploits",
        description=(
            "Role overrides, fake function-call results, "
            '"you are an admin" prompts. Catches the social-engineering '
            "vector against agents."
        ),
        rule_ids=("TRUST-ROLE-OVERRIDE", "TRUST-FAKE-RESULT", "TRUST-ADMIN-CLAIM"),
        cookbook_href="/docs/policies/regex-cookbook",
    ),
    BlockCard(
        id="cognitive",
        category="llm",
        title="Cognitive / manipulation patterns",
        description=(
            "Authority-claim, urgency, fake citations, false consensus. "
            "Lower-confidence patterns that flag suspicious narrative shape "
            "rather than concrete payloads."
        ),
        rule_ids=("COG-AUTHORITY", "COG-URGENCY", "COG-FAKE-CITE"),
        cookbook_href="/docs/policies/regex-cookbook",
    ),
    BlockCard(
        id="lethal_trifecta",
        category="multi_step",
        title="Lethal trifecta (Willison)",
        description=(
            "Session combines untrusted ingress + sensitive data access + "
            "external egress. The three ingredients of indirect-prompt-"
            "injection exfil. Catches sessions where each step looked "
            "HIGH/MEDIUM individually but the combination is CRITICAL."
        ),
        correlator_pattern_ids=("LETHAL-TRIFECTA", "TRIFECTA-WITH-FINGERPRINT-MATCH"),
        cookbook_href="/docs/policies#layer-5--session-correlator",
    ),
    BlockCard(
        id="escalation_chain",
        category="multi_step",
        title="Escalation chain across turns",
        description=(
            "MEDIUM -> HIGH -> HIGH severity progression inside the same "
            "session - attacker iterating on a prompt to get past a "
            "guardrail. Promoted to CRITICAL when the chain completes."
        ),
        correlator_pattern_ids=("ESCALATION-CHAIN",),
        cookbook_href="/docs/policies#layer-5--session-correlator",
    ),
    BlockCard(
        id="destructive_flow",
        category="multi_step",
        title="Destructive shell after sensitive read",
        description=(
            "rm -rf / mkfs / dd-if invoked in the same session as a prior "
            "sensitive-access finding (~/.ssh, ~/.aws, /etc/shadow). "
            "Indicates active exploitation rather than reconnaissance."
        ),
        correlator_pattern_ids=("DESTRUCTIVE-FLOW",),
        cookbook_href="/docs/policies#layer-5--session-correlator",
    ),
)


# Order ``BLOCK_CARDS`` indices appear in the Quick-Start render. The
# Block step iterates ``BLOCK_CATEGORIES`` first and emits each card
# whose ``category`` matches; up/down navigation walks this list so
# the cursor matches what the operator sees on screen.
BLOCK_DISPLAY_ORDER: tuple[int, ...] = _build_block_display_order(
    BLOCK_CATEGORIES, BLOCK_CARDS
)


# Q3: what to allow -----------------------------------------------------------


@dataclass(frozen=True)
class AllowCard:
    id: str
    title: str
    description: str
    tool_pattern: str = ""
    suppress_findings: tuple[str, ...] = ()
    domains: tuple[str, ...] = ()
    first_party: tuple[str, ...] = ()
    cookbook_href: str = ""


ALLOW_CARDS: tuple[AllowCard, ...] = (
    AllowCard(
        id="cosmetic_shell",
        title="Cosmetic shell commands (git status, ls, pwd)",
        description=(
            "These are read-only, always safe, and the noisiest source of "
            "false-positive injection findings. Suppress them and your alert "
            "volume drops by ~60%."
        ),
        tool_pattern=r"^(?:shell|bash|sh)\.execute$",
        suppress_findings=("JUDGE-INJ-COSMETIC", "CMD-LS", "CMD-PWD"),
        cookbook_href="/docs/policies/suppression-cookbook",
    ),
    AllowCard(
        id="first_party_plugins",
        title="First-party plugins (your org's code)",
        description=(
            "Skills and MCP servers shipped by your organization should "
            "never get blocked. Add the org/* glob below; matches bypass "
            "admission scans."
        ),
        first_party=("cisco-ai-defense/*",),
    ),
    AllowCard(
        id="internal_domains",
        title="Internal domains (corp network)",
        description=(
            "Sandboxed agents that legitimately fetch from internal APIs "
            "need their domains whitelisted in the firewall."
        ),
        domains=("*.corp.internal", "*.internal.example.com"),
    ),
    AllowCard(
        id="dev_tools",
        title="Known dev tools (Cursor / Claude Code / Codex)",
        description=(
            "IDE assistants generate noisy traffic that's usually fine. "
            "Suppress the standard noise without disabling the rule packs."
        ),
        tool_pattern=r"^(?:cursor|claude-code|codex|aider)\.[a-z_]+$",
        suppress_findings=("JUDGE-INJ-COSMETIC",),
        cookbook_href="/docs/policies/suppression-cookbook",
    ),
)


# Q4: response posture --------------------------------------------------------


@dataclass(frozen=True)
class ResponseCard:
    id: ResponseId
    title: str
    description: str
    block_threshold: int
    alert_threshold: int
    hilt_enabled: bool
    hilt_min: SeverityUpper


RESPONSES: tuple[ResponseCard, ...] = (
    ResponseCard(
        id="log_only",
        title="Log silently",
        description=(
            "Record everything to the audit log; never block, never prompt. "
            "Best for shadow-mode evaluation."
        ),
        block_threshold=4,
        alert_threshold=1,
        hilt_enabled=False,
        hilt_min="CRITICAL",
    ),
    ResponseCard(
        id="alert",
        title="Alert me on high+",
        description=(
            "Send guardrail/firewall alerts to your sinks for HIGH and "
            "CRITICAL. Does not pause the agent. Recommended starting point."
        ),
        block_threshold=4,
        alert_threshold=3,
        hilt_enabled=False,
        hilt_min="HIGH",
    ),
    ResponseCard(
        id="ask",
        title="Ask first (HILT) on medium+",
        description=(
            "Pause the agent at MEDIUM and HIGH and wait for a human to "
            "approve / deny. CRITICAL still hard-blocks."
        ),
        block_threshold=4,
        alert_threshold=2,
        hilt_enabled=True,
        hilt_min="MEDIUM",
    ),
    ResponseCard(
        id="block",
        title="Hard block on medium+",
        description=(
            "Block MEDIUM, HIGH, and CRITICAL. Use this when false positives "
            "are an acceptable cost (regulated workloads, restricted data)."
        ),
        block_threshold=2,
        alert_threshold=1,
        hilt_enabled=False,
        hilt_min="CRITICAL",
    ),
)


# Q5: where events go ---------------------------------------------------------


@dataclass(frozen=True)
class SinkConfigField:
    key: SinkConfigKey
    label: str
    placeholder: str


@dataclass(frozen=True)
class SinkCard:
    id: str
    title: str
    description: str
    type: Literal["", "slack", "webex", "pagerduty", "generic"] = ""
    config_fields: tuple[SinkConfigField, ...] = ()


SINK_CARDS: tuple[SinkCard, ...] = (
    SinkCard(
        id="local_file",
        title="Local audit log",
        description=(
            "Append every event to ~/.defenseclaw/audit.jsonl. Always-on "
            "default; recommended even when you also wire a remote sink."
        ),
    ),
    SinkCard(
        id="stdout",
        title="stdout / journald",
        description=(
            "Write structured JSON events to stdout. Useful for container "
            "deployments where journald or a log shipper picks them up."
        ),
    ),
    SinkCard(
        id="splunk",
        title="Splunk HEC",
        description=(
            "Forward block/alert events to Splunk's HTTP Event Collector. "
            "Token is read from the env var you provide - never hardcoded."
        ),
        type="generic",
        config_fields=(
            SinkConfigField(
                key="url",
                label="HEC URL",
                placeholder="https://splunk.example.com:8088/services/collector/event",
            ),
            SinkConfigField(
                key="secret_env",
                label="Token env var",
                placeholder="SPLUNK_HEC_TOKEN",
            ),
        ),
    ),
    SinkCard(
        id="slack",
        title="Slack webhook",
        description=(
            "Post HIGH/CRITICAL events into a Slack channel via "
            "incoming-webhook. Signing secret is read from the env var "
            "you provide."
        ),
        type="slack",
        config_fields=(
            SinkConfigField(
                key="url",
                label="Webhook URL",
                placeholder="https://hooks.slack.com/services/T0000/B0000/abcdef",
            ),
            SinkConfigField(
                key="secret_env",
                label="Signing-secret env var",
                placeholder="SLACK_WEBHOOK_SECRET",
            ),
        ),
    ),
    SinkCard(
        id="generic_webhook",
        title="Generic webhook",
        description=(
            "POST events to any HTTP endpoint that accepts JSON. Use this "
            "for SOAR platforms, custom collectors, or PagerDuty."
        ),
        type="generic",
        config_fields=(
            SinkConfigField(
                key="url",
                label="Webhook URL",
                placeholder="https://soar.example.com/defenseclaw",
            ),
            SinkConfigField(
                key="secret_env",
                label="HMAC env var (optional)",
                placeholder="WEBHOOK_HMAC_SECRET",
            ),
        ),
    ),
)


# --- Aggregate answers -------------------------------------------------------


@dataclass
class SinkAnswer:
    """One row of state for the Sinks step.

    Mutable so the wizard can flip ``enabled`` and edit the URL /
    env-var via the keyboard without re-allocating the row.
    """

    enabled: bool = False
    url: str = ""
    secret_env: str = ""


@dataclass
class Answers:
    """Aggregate Quick Start state.

    Mirrors the TS ``Answers`` interface. ``block`` and ``allow`` are
    Python ``set``s so toggling is O(1). ``sinks`` keys mirror the
    ``SinkCard.id`` so the apply mapper can look up the matching card
    metadata by ``answers.sinks[card.id]``.
    """

    posture: PostureId = "default"
    block: set[str] = field(default_factory=set)
    allow: set[str] = field(default_factory=set)
    first_party_extra: list[str] = field(default_factory=list)
    domains_extra: list[str] = field(default_factory=list)
    response: ResponseId = "alert"
    sinks: dict[str, SinkAnswer] = field(default_factory=dict)


def default_answers() -> Answers:
    """Return a fresh ``Answers`` matching the TS ``defaultAnswers``."""
    sinks: dict[str, SinkAnswer] = {}
    for card in SINK_CARDS:
        sinks[card.id] = SinkAnswer(enabled=card.id == "local_file")
    return Answers(sinks=sinks)


def serialize_answers(answers: Answers) -> dict[str, Any]:
    """Convert ``Answers`` into a plain dict suitable for ``json.dumps``.

    Mirrors the TS ``serializeAnswers``. ``set``s become sorted
    lists so two equivalent ``Answers`` produce byte-identical
    serializations (handy for diffing test fixtures).
    """
    return {
        "posture": answers.posture,
        "block": sorted(answers.block),
        "allow": sorted(answers.allow),
        "first_party_extra": list(answers.first_party_extra),
        "domains_extra": list(answers.domains_extra),
        "response": answers.response,
        "sinks": {
            sid: {
                "enabled": s.enabled,
                "url": s.url,
                "secret_env": s.secret_env,
            }
            for sid, s in answers.sinks.items()
        },
    }


def deserialize_answers(raw: Any) -> Answers:
    """Inverse of ``serialize_answers``.

    Robust to malformed input (e.g. a corrupted draft file): unknown
    fields fall back to defaults rather than raising.
    """
    base = default_answers()
    if not isinstance(raw, dict):
        return base
    posture = raw.get("posture")
    if posture not in {"permissive", "default", "strict"}:
        posture = base.posture
    response = raw.get("response")
    if response not in {"log_only", "alert", "ask", "block"}:
        response = base.response

    raw_block = raw.get("block")
    block = set(raw_block) if isinstance(raw_block, list) else set()
    raw_allow = raw.get("allow")
    allow = set(raw_allow) if isinstance(raw_allow, list) else set()
    raw_fp = raw.get("first_party_extra")
    first_party_extra = list(raw_fp) if isinstance(raw_fp, list) else []
    raw_dom = raw.get("domains_extra")
    domains_extra = list(raw_dom) if isinstance(raw_dom, list) else []

    raw_sinks = raw.get("sinks")
    sinks = {sid: SinkAnswer(**vars(s)) for sid, s in base.sinks.items()}
    if isinstance(raw_sinks, dict):
        for sid, body in raw_sinks.items():
            if sid not in sinks or not isinstance(body, dict):
                continue
            sinks[sid] = SinkAnswer(
                enabled=bool(body.get("enabled", False)),
                url=str(body.get("url", "")),
                secret_env=str(body.get("secret_env", "")),
            )

    return Answers(
        posture=posture,  # type: ignore[arg-type]
        block=block,
        allow=allow,
        first_party_extra=first_party_extra,
        domains_extra=domains_extra,
        response=response,  # type: ignore[arg-type]
        sinks=sinks,
    )
