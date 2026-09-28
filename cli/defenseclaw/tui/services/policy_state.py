# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Pure model for the Policies panel (key ``P``), the protection center.

Seven views, in navigation order (keys ``1``-``7``):

1. **Posture**: one row per scope (global, then each active connector) with
   its guardrail mode, the levels its tool calls are blocked and alerted at,
   human approval, rule pack and opt-in packs. ``m`` ``b`` ``a`` ``h`` ``p``
   change them.
2. **Opt-in packs**: the deterministic protection packs for one scope (``s``
   cycles the scope); Space or Enter turns one on or off.
3. **Chains**: the bounded tool-call chains, grouped by domain (read-only).
4. **Rule families**: the rule files of the scope's effective pack.
5. **Policies**: the named security policies (``policy activate``); ``b`` /
   ``a`` change the highlighted policy's levels for LLM traffic.
6. **Rule packs**: the guardrail rule pack per scope (``guardrail use-pack``).
7. **Sandbox packs**: the sandbox policy packs, read-only.

A tool call's block and alert levels come from ``guardrail.block_at`` /
``alert_at`` (the connector's own value, else the global one), else from the
name of the scope's rule-pack folder (``internal/gateway/decision.go``:
``strict`` blocks MEDIUM+, ``permissive`` and everything else CRITICAL); the
alert level never sits above the block level. The posture rows show them and
``b`` / ``a`` there run ``guardrail block-at`` / ``alert-at``. The named
policy's thresholds apply to LLM traffic through the guardrail proxy only;
the Policies view shows and changes those (``policy edit guardrail``).

No I/O happens here. The app reads :mod:`defenseclaw.policy_catalog` in a
thread and feeds the results in; the model answers what to render and which
action a key asked for. Mutations leave as command intents.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from defenseclaw.policy_catalog import ScopeLevels, level_value, resolve_levels

POLICY_VIEWS: tuple[str, ...] = (
    "posture",
    "optin",
    "chains",
    "families",
    "policies",
    "packs",
    "sandbox_packs",
)
VIEW_TITLES = {
    "posture": "Posture",
    "optin": "Opt-in packs",
    "chains": "Chains",
    "families": "Rule families",
    "policies": "Policies",
    "packs": "Rule packs",
    "sandbox_packs": "Sandbox packs",
}
# The one-line view switcher under 100 columns uses these.
VIEW_SHORT_TITLES = {
    "posture": "Posture",
    "optin": "Opt-in",
    "chains": "Chains",
    "families": "Families",
    "policies": "Policies",
    "packs": "Packs",
    "sandbox_packs": "Sandbox",
}
VIEW_KEYS = {str(index): view for index, view in enumerate(POLICY_VIEWS, start=1)}

# Sandbox packs: the gateway's packs.DefaultPack.
DEFAULT_SANDBOX_PACK = "open"

# Rule-pack presets, strictest last (cmd_guardrail / policy_catalog.RULE_PACK_PRESETS).
PACK_STRICTNESS = {"permissive": 1, "default": 2, "strict": 3}

# policy_catalog threshold labels -> how much they block (lower = stricter).
# "none" blocks nothing, so it is the weakest.
_THRESHOLD_RANK = {"LOW+": 1, "MEDIUM+": 2, "HIGH+": 3, "CRITICAL": 4, "NONE": 5}

# guardrail.rego ``severity_rank``; ``policy edit guardrail --block-threshold N``.
SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
LEVEL_FOR_RANK = {4: "CRITICAL", 3: "HIGH+", 2: "MEDIUM+", 1: "LOW+"}

# The levels the policy's block-at and alert-at pickers offer (LLM traffic).
BLOCK_LEVELS = ("CRITICAL", "HIGH+", "MEDIUM+")
ALERT_LEVELS = ("HIGH+", "MEDIUM+", "LOW+")
# The tool-call level pickers (``guardrail block-at`` / ``alert-at``), plus
# INHERIT: clear the scope's own value and follow the global or pack level.
TOOL_BLOCK_LEVELS = ("CRITICAL", "HIGH+", "MEDIUM+")
TOOL_ALERT_LEVELS = ("CRITICAL", "HIGH+", "MEDIUM+", "LOW+")
INHERIT = "inherit"
# Human approval (``guardrail hilt``): off, or the lowest severity that asks.
HILT_LEVELS = ("off", "CRITICAL", "HIGH+", "MEDIUM+", "LOW+")

# Tool-call block/alert levels per rule-pack profile (decision.go
# ``guardrailThresholdsForConnector``).
PROFILE_LEVELS = {
    "strict": ("MEDIUM+", "LOW+"),
    "permissive": ("CRITICAL", "HIGH+"),
    "default": ("CRITICAL", "MEDIUM+"),
}

# What a finding at a severity turns into, strongest first.
ACTION_STRENGTH = {"block": 3, "ask": 2, "alert": 1, "allow": 0}
ACTION_WORDS = {"block": "block", "ask": "ask a human", "alert": "alert", "allow": "allow"}

# Chain domains in display order (tool-chains.json ``domain``).
CHAIN_DOMAINS: tuple[tuple[str, str], ...] = (
    ("sql", "SQL"),
    ("kubernetes", "Kubernetes"),
    ("cloud", "Cloud"),
    ("host", "Host"),
    ("credentials", "Credentials"),
    ("data-egress", "Data egress"),
    ("network", "Network"),
    ("security-controls", "Security controls"),
)

# The composed pack folder ``guardrail protection enable`` writes per scope.
PROTECTED_PACK_PREFIX = "protected-"


def threshold_rank(label: str) -> int | None:
    """How little a threshold label catches (1 = LOW+ … 5 = none); None if unknown."""
    return _THRESHOLD_RANK.get((label or "").strip().upper())


def level_rank(label: str) -> int | None:
    """``CRITICAL`` → 4, ``HIGH+`` → 3, ``MEDIUM+`` → 2, ``LOW+`` → 1 (None otherwise)."""
    text = (label or "").strip().upper()
    for rank, level in LEVEL_FOR_RANK.items():
        if level == text:
            return rank
    return None


def hilt_rank(label: str) -> int:
    """How little approval asks for (1 = LOW+ … 4 = CRITICAL, 5 = off)."""
    rank = level_rank(label)
    return rank if rank is not None else 5


def fit(text: str, width: int) -> str:
    """``text`` cut to ``width`` characters with an ellipsis (0 keeps it whole)."""
    if width <= 0 or len(text) <= width:
        return text
    return text[: max(0, width - 1)].rstrip() + "…"


def _attr(obj: object, name: str, default: Any = "") -> Any:
    value = getattr(obj, name, default)
    return default if value is None else value


def _hilt_label(value: object) -> str:
    if value is True:
        return "on"
    if value is False:
        return "off"
    return "inherit"


def pack_profile(path: str) -> str:
    """The posture profile the gateway derives from a rule-pack folder.

    Mirrors ``guardrailProfileForDir``: the folder's base name, lowercased;
    ``strict`` and ``permissive`` keep their posture, ``balanced`` and every
    other custom name read as ``default``. A composed pack
    (``protected-<scope>/<profile>``) ends in its base pack's profile.
    """
    raw = (path or "").strip().rstrip("/\\")
    if not raw:
        return "default"
    base = os.path.basename(os.path.normpath(raw)).lower()
    return base if base in {"strict", "permissive"} else "default"


def profile_levels(path: str) -> tuple[str, str]:
    """``(blocks at, alerts at)`` for tool calls under the pack at ``path``."""
    return PROFILE_LEVELS[pack_profile(path)]


def severity_actions(block_at: str, alert_at: str, hilt: str) -> tuple[tuple[str, str], ...]:
    """``(severity, action)`` from CRITICAL to LOW, in the gateway's order.

    The block level wins first, then human approval, then the alert level
    (``guardrailRuntimeActionForConnector``). This is the action-mode answer;
    observe mode only logs what it would do.
    """
    block = level_rank(block_at) or 5
    alert = level_rank(alert_at) or 5
    ask = hilt_rank(hilt)
    rows = []
    for severity in SEVERITY_ORDER:
        rank = SEVERITY_RANK[severity]
        if rank >= block:
            action = "block"
        elif rank >= ask:
            action = "ask"
        elif rank >= alert:
            action = "alert"
        else:
            action = "allow"
        rows.append((severity, action))
    return tuple(rows)


def _severity_span(severities: list[str]) -> str:
    """The level label of a group's lowest severity (``HIGH`` → ``HIGH+``)."""
    return LEVEL_FOR_RANK[SEVERITY_RANK[severities[-1]]] if severities else ""


def posture_summary(scope: str, mode: str, block_at: str, alert_at: str, hilt: str) -> str:
    """One plain sentence: what ``scope``'s tool calls get at each severity."""
    groups: dict[str, list[str]] = {"block": [], "ask": [], "alert": [], "allow": []}
    for severity, action in severity_actions(block_at, alert_at, hilt):
        groups[action].append(severity)
    observe = mode != "action"
    verbs = (
        {"block": "block", "ask": "ask a human for", "alert": "alert on"}
        if observe
        else {"block": "blocks", "ask": "asks a human for", "alert": "alerts on"}
    )
    parts = [
        f"{verbs[action]} {_severity_span(groups[action])}" for action in ("block", "ask", "alert") if groups[action]
    ]
    if not parts:
        parts = ["allow every severity" if observe else "allows every severity"]
    clause = parts[0] if len(parts) == 1 else ", ".join(parts[:-1]) + " and " + parts[-1]
    subject = "The global default" if scope in {"", "global"} else scope
    if observe:
        return f"{subject} logs only; in action mode it would {clause}."
    return f"{subject} {clause}."


def matrix_lines(mode: str, block_at: str, alert_at: str, hilt: str) -> tuple[str, ...]:
    """The severity → action matrix, one line per severity."""
    observe = mode != "action"
    lines = []
    for severity, action in severity_actions(block_at, alert_at, hilt):
        word = ACTION_WORDS[action]
        if observe and action in {"block", "ask"}:
            word = f"log (would {word})"
        lines.append(f"  {severity:<9} {word}")
    return tuple(lines)


def actions_weaken(before: tuple[tuple[str, str], ...], after: tuple[tuple[str, str], ...]) -> tuple[str, ...]:
    """Severities whose action gets weaker (block → ask → alert → allow)."""
    old = dict(before)
    return tuple(
        severity
        for severity, action in after
        if ACTION_STRENGTH.get(action, 0) < ACTION_STRENGTH.get(old.get(severity, "allow"), 0)
    )


def mode_weakens(old: str, new: str) -> bool:
    """Action → observe stops every block."""
    return (old or "observe") == "action" and new != "action"


def threshold_weakens(old: str, new: str) -> bool:
    """Raising a block or alert level catches fewer severities."""
    old_rank, new_rank = threshold_rank(old), threshold_rank(new)
    return old_rank is not None and new_rank is not None and new_rank > old_rank


def hilt_weakens(old: str, new: str) -> bool:
    """Turning approval off, or asking for fewer severities."""
    return hilt_rank(new) > hilt_rank(old)


# ---------------------------------------------------------------------------
# Intents
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PolicyCommandIntent:
    """A CLI command the app previews and runs."""

    label: str
    args: tuple[str, ...]
    binary: str = "defenseclaw"
    category: str = "policy"
    risk: str = "mutation"
    hint: str = ""

    @property
    def argv(self) -> tuple[str, ...]:
        return (self.binary, *self.args)


def activate_intent(name: str) -> PolicyCommandIntent:
    return PolicyCommandIntent(
        label=f"policy activate {name}",
        args=("policy", "activate", name),
        hint=f"Activate the {name} policy and reload the gateway.",
    )


def use_pack_intent(pack: str, connector: str = "") -> PolicyCommandIntent:
    args: tuple[str, ...] = ("guardrail", "use-pack", pack)
    if connector:
        args = (*args, "--connector", connector)
    scope = f" for {connector}" if connector else ""
    return PolicyCommandIntent(
        label=f"guardrail use-pack {pack}{scope}",
        args=args,
        hint=f"Switch the guardrail rule pack{scope or ' for every connector'} to {pack}.",
    )


def mode_intent(mode: str, connector: str = "") -> PolicyCommandIntent:
    """``guardrail mode observe|action [--connector C]`` (only the mode changes)."""
    args: tuple[str, ...] = ("guardrail", "mode", mode)
    if connector:
        args = (*args, "--connector", connector)
    scope = f" for {connector}" if connector else ""
    return PolicyCommandIntent(
        label=f"guardrail mode {mode}{scope}",
        args=args,
        hint=f"Set the guardrail mode{scope or ''} to {mode}.",
    )


def threshold_intent(kind: str, level: str, policy: str = "") -> PolicyCommandIntent:
    """``policy edit guardrail --block-threshold N [-p NAME]`` (or ``--alert-threshold``).

    The named policy's level for LLM traffic through the guardrail proxy:
    ``policy`` names it ("" = the active one); a built-in one is copied to the
    policy folder first. ``level`` is a threshold label (``HIGH+``).
    """
    rank = level_rank(level)
    if rank is None:
        raise ValueError(f"unknown level {level!r}")
    flag = "--block-threshold" if kind == "block" else "--alert-threshold"
    what = "block" if kind == "block" else "alert"
    args: tuple[str, ...] = ("policy", "edit", "guardrail", flag, str(rank))
    if policy:
        args = (*args, "-p", policy)
    return PolicyCommandIntent(
        label=f"policy edit guardrail {flag} {rank}" + (f" -p {policy}" if policy else ""),
        args=args,
        hint=f"Make the {policy or 'active'} policy {what} LLM traffic at {level}.",
    )


def level_intent(kind: str, level: str, connector: str = "") -> PolicyCommandIntent:
    """``guardrail block-at|alert-at LEVEL [--connector C]``: a scope's tool-call level.

    ``level`` is a picker value (``CRITICAL``, ``HIGH+``, ``MEDIUM+``,
    ``LOW+``) or :data:`INHERIT`, which clears the scope's own value.
    """
    if level == INHERIT:
        name = INHERIT
    else:
        name = (level or "").strip().rstrip("+").upper()
        if name not in SEVERITY_RANK:
            raise ValueError(f"unknown level {level!r}")
    # Literal argv per setting, so scripts/gap_audit.py sees both commands.
    if kind == "block":
        args: tuple[str, ...] = ("guardrail", "block-at", name)
    else:
        args = ("guardrail", "alert-at", name)
    if connector:
        args = (*args, "--connector", connector)
    scope = f" for {connector}" if connector else ""
    what = "block" if kind == "block" else "alert"
    return PolicyCommandIntent(
        label=f"guardrail {args[1]} {name}{scope}",
        args=args,
        hint=f"Set the tool-call {what} level{scope} to {name}.",
    )


def hilt_intent(level: str, connector: str = "") -> PolicyCommandIntent:
    """``guardrail hilt on --min-severity SEV|off [--connector C] --yes``.

    ``--yes`` skips the CLI's own prompt: the TUI already confirmed it.
    """
    if level == "off":
        args: tuple[str, ...] = ("guardrail", "hilt", "off")
    else:
        severity = level.rstrip("+").upper()
        if severity not in SEVERITY_RANK:
            raise ValueError(f"unknown approval level {level!r}")
        args = ("guardrail", "hilt", "on", "--min-severity", severity)
    if connector:
        args = (*args, "--connector", connector)
    args = (*args, "--yes")
    scope = f" for {connector}" if connector else ""
    return PolicyCommandIntent(
        label=f"guardrail hilt {'off' if level == 'off' else 'on ' + level}{scope}",
        args=args,
        hint=f"Set human approval{scope} to {level}.",
    )


def protection_intent(name: str, *, enable: bool, connector: str = "") -> PolicyCommandIntent:
    """``guardrail protection enable|disable NAME [--connector C]``."""
    verb = "enable" if enable else "disable"
    # Literal argv per verb, so scripts/gap_audit.py sees both commands.
    if enable:
        args: tuple[str, ...] = ("guardrail", "protection", "enable", name)
    else:
        args = ("guardrail", "protection", "disable", name)
    if connector:
        args = (*args, "--connector", connector)
    scope = f" for {connector}" if connector else ""
    return PolicyCommandIntent(
        label=f"guardrail protection {verb} {name}{scope}",
        args=args,
        hint=f"Turn {'on' if enable else 'off'} {name}{scope or ' for every connector'}.",
    )


# ---------------------------------------------------------------------------
# Tool-call levels (guardrail.block_at / alert_at)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LevelEffect:
    """One scope's tool-call levels before and after a block-at / alert-at change."""

    scope: str
    before: ScopeLevels
    after: ScopeLevels

    @property
    def weaker(self) -> bool:
        """It blocks or alerts on fewer severities (the alert level can follow the block level)."""
        return self.after.block_rank > self.before.block_rank or self.after.alert_rank > self.before.alert_rank

    @property
    def subject(self) -> str:
        return "the global default" if self.scope in {"", "global"} else self.scope

    def loosening(self) -> str:
        """``blocks HIGH+ instead of MEDIUM+`` ("" when nothing got weaker)."""
        parts = []
        if self.after.block_rank > self.before.block_rank:
            parts.append(f"blocks {self.after.block_at} instead of {self.before.block_at}")
        if self.after.alert_rank > self.before.alert_rank:
            parts.append(f"alerts on {self.after.alert_at} instead of {self.before.alert_at}")
        return " and ".join(parts)


def _and_join(items: list[str]) -> str:
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " and " + items[-1]


def loosened_text(effects: Iterable[LevelEffect]) -> str:
    """``blocks CRITICAL instead of HIGH+ for the global default, codex and hermes``.

    Scopes that lose the same way share one phrase ("" when none loosens).
    """
    groups: dict[str, list[str]] = {}
    for effect in effects:
        phrase = effect.loosening()
        if phrase:
            groups.setdefault(phrase, []).append(effect.subject)
    return "; ".join(f"{phrase} for {_and_join(subjects)}" for phrase, subjects in groups.items())


@dataclass(frozen=True)
class LevelChange:
    """What ``guardrail block-at|alert-at`` would do, from the posture rows.

    ``connector`` is the ``--connector`` value ("" = the global value, which
    every connector without its own follows); ``value`` the stored level
    after it (``CRITICAL`` … ``LOW``, "" = inherit). ``effects`` lists every
    scope it reaches; ``keep_own`` the connectors a global change can't reach
    because they set their own.
    """

    kind: str
    connector: str
    value: str
    effects: tuple[LevelEffect, ...]
    keep_own: tuple[str, ...] = ()

    def effect_for(self, scope: str) -> LevelEffect | None:
        want = scope or "global"
        return next((effect for effect in self.effects if effect.scope == want), None)

    def weakened(self) -> tuple[LevelEffect, ...]:
        return tuple(effect for effect in self.effects if effect.weaker)


def levels_setting(levels: ScopeLevels, kind: str) -> tuple[str, str]:
    """``(label, source)`` of the block (``kind="block"``) or alert level."""
    if kind == "block":
        return levels.block_at, levels.block_source
    return levels.alert_at, levels.alert_source


def level_origin(source: str, scope: str, pack: str, profile: str) -> str:
    """``set for codex`` / ``set globally`` / ``from the strict pack``."""
    if source == "override":
        return f"set for {scope}"
    if source == "global":
        return "set globally"
    pack = pack or profile
    return f"from the {pack} pack" if pack == profile else f"from the {pack} pack ({profile} levels)"


def picker_level(stored: str) -> str:
    """A stored level (``HIGH``) as a picker value (``HIGH+``); "" → :data:`INHERIT`."""
    rank = SEVERITY_RANK.get((stored or "").strip().upper())
    return LEVEL_FOR_RANK[rank] if rank else INHERIT


# ---------------------------------------------------------------------------
# Comparing policies and packs
# ---------------------------------------------------------------------------


def policy_weakenings(old: object | None, new: object | None) -> tuple[str, ...]:
    """Ways ``new`` protects less than ``old`` (empty when it does not).

    A threshold that catches fewer severities, a firewall that goes from deny
    to allow by default, or human approval switched off.
    """
    if old is None or new is None:
        return ()
    reasons: list[str] = []
    for field, label in (
        ("block_at", "blocks"),
        ("alert_at", "alerts on"),
        ("install_block_at", "blocks installs of"),
    ):
        before, after = str(_attr(old, field)), str(_attr(new, field))
        if threshold_weakens(before, after):
            reasons.append(f"{label} {after} instead of {before}")
    if _attr(old, "firewall_default") == "deny" and _attr(new, "firewall_default") == "allow":
        reasons.append("the firewall allows by default instead of denying")
    if _attr(old, "hilt", None) is True and _attr(new, "hilt", None) is False:
        reasons.append("human approval is turned off")
    return tuple(reasons)


def policy_comparison(old: object | None, new: object) -> tuple[tuple[str, str, str], ...]:
    """``(label, active value, new value)`` rows for the picker preview."""

    def values(policy: object | None) -> dict[str, str]:
        if policy is None:
            return {}
        firewall = str(_attr(policy, "firewall_default")) or "unchanged"
        return {
            "Block at": str(_attr(policy, "block_at")) or "-",
            "Alert at": str(_attr(policy, "alert_at")) or "-",
            "Install block at": str(_attr(policy, "install_block_at")) or "-",
            "Firewall default": firewall,
            "Human approval": _hilt_label(_attr(policy, "hilt", None)),
        }

    before, after = values(old), values(new)
    return tuple((label, before.get(label, "-"), value) for label, value in after.items())


def policy_side_effects(new: object) -> tuple[str, ...]:
    """What activating ``new`` changes besides the thresholds."""
    effects: list[str] = []
    if _attr(new, "replaces_webhooks", False):
        effects.append("replaces your webhooks")
    if _attr(new, "sets_cisco", False):
        effects.append("changes Cisco AI Defense settings")
    overrides = int(_attr(new, "scanner_overrides", 0) or 0)
    if overrides:
        effects.append(f"{overrides} scanner override{'s' if overrides != 1 else ''}")
    return tuple(effects)


def pack_weakens(old_packs: tuple[str, ...] | list[str], new_pack: str) -> bool:
    """Whether switching any of ``old_packs`` to ``new_pack`` moves to a looser preset."""
    new_rank = PACK_STRICTNESS.get(new_pack)
    if new_rank is None:
        return False
    return any(PACK_STRICTNESS.get(old, 0) > new_rank for old in old_packs)


def policy_posture_text(active: object | None) -> str:
    """``strict · block MEDIUM+ · alert LOW+`` for the active policy ("" if unknown)."""
    if active is None:
        return ""
    name = str(_attr(active, "name")) or "?"
    return f"{name} · block {_attr(active, 'block_at') or '?'} · alert {_attr(active, 'alert_at') or '?'}"


# ---------------------------------------------------------------------------
# Rule-pack validation (``guardrail validate-pack PATH --json``)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PackValidation:
    """The validator's answer: ``valid``, ``invalid`` or ``unavailable``."""

    state: str
    message: str = ""
    rule_count: int = 0
    enabled_rule_count: int = 0
    rule_file_count: int = 0
    digest: str = ""

    @property
    def summary(self) -> str:
        if self.state == "valid":
            digest = f" · digest {self.digest[:12]}" if self.digest else ""
            return (
                f"valid: {self.enabled_rule_count}/{self.rule_count} rules enabled "
                f"across {self.rule_file_count} files{digest}"
            )
        if self.state == "invalid":
            return f"invalid: {self.message or 'the pack did not load'}"
        return f"validator unavailable: {self.message or 'defenseclaw-gateway could not check it'}"


def parse_validation(returncode: int, stdout: str) -> PackValidation:
    """Decode ``validate-pack --json`` (exit 0 valid, 1 invalid, 2 unavailable)."""
    try:
        payload = json.loads(stdout or "{}")
    except ValueError:
        payload = {}
    if not isinstance(payload, dict):
        payload = {}
    error = payload.get("error") if isinstance(payload.get("error"), dict) else {}
    reason = str(error.get("reason", "") or "").strip()
    where = str(error.get("path", "") or "").strip()
    if where and where != "$":
        reason = f"{reason} (at {where})" if reason else where
    if returncode == 2:
        return PackValidation("unavailable", reason)
    if returncode == 0 and payload.get("valid") is True:
        summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}

        def count(key: str) -> int:
            try:
                return int(summary.get(key, 0) or 0)
            except (TypeError, ValueError):
                return 0

        return PackValidation(
            "valid",
            rule_count=count("rule_count"),
            enabled_rule_count=count("enabled_rule_count"),
            rule_file_count=count("rule_file_count"),
            digest=str(summary.get("digest", "") or ""),
        )
    return PackValidation("invalid", reason or f"exit {returncode}")


# ---------------------------------------------------------------------------
# Sandbox packs (``defenseclaw sandbox pack list -o json``)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SandboxPackRow:
    name: str
    builtin: bool = False
    source: str = ""
    description: str = ""
    profile: str = ""
    digest: str = ""
    error: str = ""


def decode_sandbox_packs(text: str) -> list[SandboxPackRow]:
    """Rows from ``{"packs": [...]}``; raises ValueError on malformed JSON."""
    payload = json.loads(text or "{}")
    items = payload.get("packs") if isinstance(payload, dict) else None
    if not isinstance(items, list):
        raise ValueError("sandbox pack list returned no packs array")
    rows: list[SandboxPackRow] = []
    for item in items:
        if not isinstance(item, dict) or not str(item.get("name", "") or "").strip():
            continue
        rows.append(
            SandboxPackRow(
                name=str(item.get("name")),
                builtin=bool(item.get("builtin")),
                source=str(item.get("source", "") or ""),
                description=str(item.get("description", "") or ""),
                profile=str(item.get("profile", "") or ""),
                digest=str(item.get("digest", "") or ""),
                error=str(item.get("error", "") or ""),
            )
        )
    return rows


# ---------------------------------------------------------------------------
# Protection center inputs
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PackRule:
    """One rule of an opt-in protection pack, for its detail."""

    id: str
    severity: str = ""
    title: str = ""


# What turning a production-protection pack on asserts about the scope
# (deterministic-detection docs: assigning one asserts the context is protected).
PROTECTED_CONTEXT = {
    "database-destruction-protection": "a protected database",
    "kubernetes-production-protection": "a protected production Kubernetes cluster",
    "cloud-production-protection": "protected production cloud accounts",
    "infrastructure-destruction-protection": "protected production hosts and infrastructure",
    "privacy-high-assurance": "high-assurance personal data",
}


def protection_claim(name: str, scope: str) -> str:
    """The sentence a scope's user agrees to by turning pack ``name`` on."""
    context = PROTECTED_CONTEXT.get(name, "a protected environment")
    if scope in {"", "global"}:
        return f"Turning it on tells DefenseClaw that every connector using the global pack works with {context}."
    return f"Turning it on tells DefenseClaw that {scope} works with {context}."


def pack_short_title(title: str) -> str:
    """``Database destruction protection`` → ``Database destruction`` for a table cell."""
    short = title[: -len(" protection")] if title.lower().endswith(" protection") else title
    return short or title


def chain_domain_label(domain: str) -> str:
    return dict(CHAIN_DOMAINS).get(domain, "Other")


def chain_display_rows(chains: Iterable[Any]) -> tuple[tuple[str, Any | None], ...]:
    """``(group label, None)`` header rows, each followed by its chains.

    Domains follow :data:`CHAIN_DOMAINS`; chains keep catalog order inside a
    domain, and unknown domains are grouped last under "Other".
    """
    order = {key: index for index, (key, _label) in enumerate(CHAIN_DOMAINS)}
    grouped: dict[str, list[Any]] = {}
    for chain in chains:
        domain = str(_attr(chain, "domain")).strip().lower()
        grouped.setdefault(domain if domain in order else "", []).append(chain)
    rows: list[tuple[str, Any | None]] = []
    for domain in sorted(grouped, key=lambda key: order.get(key, len(order))):
        label = chain_domain_label(domain)
        rows.append((label, None))
        rows.extend((label, chain) for chain in grouped[domain])
    return tuple(rows)


def _window_text(chain: object) -> str:
    events = int(_attr(chain, "event_window", 0) or 0)
    seconds = int(_attr(chain, "time_window_seconds", 0) or 0)
    parts = []
    if events:
        parts.append(f"the last {events} tool calls")
    if seconds:
        parts.append(f"{seconds // 60} minutes" if seconds >= 60 else f"{seconds} seconds")
    return " within ".join(parts) if parts else "-"


# ---------------------------------------------------------------------------
# The panel
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PolicyPanelAction:
    """What a key asked for.

    ``kind``: ``none`` (not handled), ``render``, ``hint``, ``refresh``,
    ``load_sandbox_packs``, ``pick_policy`` (``policy`` = the highlighted
    one), ``pick_pack`` (``connector`` = the scope, "" = global),
    ``toggle_mode``, ``pick_block``, ``pick_alert`` (tool-call levels),
    ``pick_hilt`` (``connector`` = the scope), ``pick_policy_block`` /
    ``pick_policy_alert`` (``policy`` = the highlighted policy's LLM-traffic
    level) or ``toggle_protection`` (``pack`` and ``enable``, ``connector`` =
    the scope).
    """

    kind: str
    hint: str = ""
    policy: str = ""
    connector: str = ""
    intent: PolicyCommandIntent | None = None
    pack: str = ""
    enable: bool = False

    @property
    def handled(self) -> bool:
        return self.kind != "none"


# Every key the panel handles, for the ``?`` sheet: (keys, what, views).
POLICY_KEYMAP: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("1 … 7", "Posture · Opt-in packs · Chains · Rule families · Policies · Rule packs · Sandbox packs", POLICY_VIEWS),
    ("j/k or Up/Down", "Move in the view", POLICY_VIEWS),
    ("m", "Posture: switch the highlighted scope between observe and action", ("posture",)),
    ("b / a", "Posture: the scope's tool-call block at / alert at level", ("posture",)),
    ("b / a", "Policies: the policy's block / alert level for LLM traffic (guardrail proxy)", ("policies",)),
    ("h", "Posture: human approval for the highlighted scope", ("posture",)),
    ("p", "Posture: switch the highlighted scope's rule pack", ("posture",)),
    ("Space / Enter", "Opt-in packs: turn the pack on or off for the scope", ("optin",)),
    ("s", "Opt-in packs, Rule families: next scope (global, then each connector)", ("optin", "families")),
    ("Enter", "Policies: pick and activate a policy · Rule packs: switch a pack", ("policies", "packs")),
    ("i / Enter", "Details of the highlighted row (Enter on Posture, Chains, Families)", POLICY_VIEWS),
    ("Esc / q", "Close the details", POLICY_VIEWS),
    ("r", "Refresh", POLICY_VIEWS),
)


def policy_keymap_rows(sandbox_supported: bool = True) -> tuple[tuple[str, str, tuple[str, ...]], ...]:
    """:data:`POLICY_KEYMAP` for this platform (no sandbox view where it is unsupported)."""
    views = POLICY_VIEWS if sandbox_supported else POLICY_VIEWS[:-1]
    rows = []
    for keys, what, key_views in POLICY_KEYMAP:
        if not sandbox_supported and keys.startswith("1 "):
            keys, what = "1 … 6", what.replace(" · Sandbox packs", "")
        rows.append((keys, what, tuple(view for view in key_views if view in views)))
    return tuple(rows)


def policies_keys_hint(view: str, *, sandbox_supported: bool = True) -> str:
    """The hint bar's keys for a Policies view (one line at 80 columns)."""
    views = "1-7 view" if sandbox_supported else "1-6 view"
    if view == "posture":
        return f"KEYS  m mode | b block at | a alert at | h approval | p rule pack | {views}"
    if view == "optin":
        return f"KEYS  Space turn on/off | s scope | i details | r refresh | {views}"
    if view == "chains":
        return f"KEYS  j/k move | i details | r refresh | {views} | read-only"
    if view == "families":
        return f"KEYS  s scope | i details | r refresh | {views}"
    if view == "packs":
        return f"KEYS  {views} | Enter change pack | i details | r refresh"
    if view == "sandbox_packs":
        return f"KEYS  {views} | Enter details | r refresh | read-only: sandbox pack set"
    return f"KEYS  {views} | Enter activate | b/a LLM block/alert | i details | r refresh"


class PoliciesPanelModel:
    """State for the Policies panel."""

    def __init__(self, *, sandbox_supported: bool = True) -> None:
        self.sandbox_supported = sandbox_supported
        self.view = "posture"
        self.cursors = {view: 0 for view in POLICY_VIEWS}
        # The posture row and the opt-in/families scope chip are one choice.
        self.scope_index = 0
        self.detail_open = False
        self.loaded = False
        self.loading = False
        self.error = ""
        self.policies: tuple[Any, ...] = ()
        self.global_pack: Any | None = None
        self.connector_packs: tuple[Any, ...] = ()
        self.packs: tuple[Any, ...] = ()
        self.pack_error = ""
        self.sandbox_loaded = False
        self.sandbox_error = ""
        self.sandbox_packs: tuple[SandboxPackRow, ...] = ()
        self.sandbox_active = DEFAULT_SANDBOX_PACK
        # Protection center.
        self.postures: tuple[Any, ...] = ()
        self.posture_error = ""
        self.protection: tuple[Any, ...] = ()
        self.pack_rules: dict[str, tuple[PackRule, ...]] = {}
        self.families: dict[str, tuple[Any, ...]] = {}
        self.chains: tuple[Any, ...] = ()
        self.pack_bases: dict[str, str] = {}
        self.multi_connector = False
        self.policy_dir = ""

    # ---- inputs -----------------------------------------------------------

    def set_config(self, config: object | None) -> None:
        openshell = getattr(config, "openshell", None)
        pack = str(getattr(openshell, "pack", "") or "").strip()
        self.sandbox_active = pack or DEFAULT_SANDBOX_PACK
        guardrail = getattr(config, "guardrail", None)
        connectors = getattr(guardrail, "connectors", None)
        # ``guardrail hilt --connector`` needs the per-connector map; a
        # single-connector install changes the global block instead.
        self.multi_connector = isinstance(connectors, Mapping) and bool(connectors)
        self.policy_dir = str(getattr(config, "policy_dir", "") or "")

    def apply_policies(self, policies: list[Any] | tuple[Any, ...]) -> None:
        self.policies = tuple(policies)
        self.loaded = True
        self.error = ""
        self._clamp()

    def apply_packs(
        self, global_pack: Any | None, connectors: list[Any] | tuple[Any, ...], packs: list[Any] | tuple[Any, ...]
    ) -> None:
        self.global_pack = global_pack
        self.connector_packs = tuple(connectors)
        self.packs = tuple(packs)
        self.pack_error = ""
        self._clamp()

    def apply_protection(
        self,
        postures: Iterable[Any],
        packs: Iterable[Any] = (),
        *,
        pack_rules: Mapping[str, Iterable[PackRule]] | None = None,
        families: Mapping[str, Iterable[Any]] | None = None,
        chains: Iterable[Any] = (),
        pack_bases: Mapping[str, str] | None = None,
    ) -> None:
        """Scopes, opt-in packs (selectable first), their rules, families per pack path, chains.

        ``pack_bases`` maps a composed pack's folder to the pack it was built on.
        """
        self.postures = tuple(postures)
        listed = tuple(packs)
        self.protection = tuple(p for p in listed if _attr(p, "status") != "staged") + tuple(
            p for p in listed if _attr(p, "status") == "staged"
        )
        self.pack_rules = {name: tuple(rules) for name, rules in (pack_rules or {}).items()}
        self.families = {path: tuple(rows) for path, rows in (families or {}).items()}
        self.chains = tuple(chains)
        self.pack_bases = dict(pack_bases or {})
        self.posture_error = ""
        self._clamp()

    def apply_sandbox_packs(self, rows: list[SandboxPackRow] | tuple[SandboxPackRow, ...]) -> None:
        self.sandbox_packs = tuple(rows)
        self.sandbox_loaded = True
        self.sandbox_error = ""
        self._clamp()

    def apply_sandbox_json(self, text: str) -> None:
        try:
            self.apply_sandbox_packs(decode_sandbox_packs(text))
        except ValueError as exc:
            self.set_sandbox_error(str(exc))

    def set_error(self, message: str) -> None:
        """A failed read keeps the last good rows."""
        self.error = message
        self.loaded = True

    def set_pack_error(self, message: str) -> None:
        self.pack_error = message

    def set_posture_error(self, message: str) -> None:
        self.posture_error = message

    def set_sandbox_error(self, message: str) -> None:
        self.sandbox_error = message
        self.sandbox_loaded = True

    # ---- queries ----------------------------------------------------------

    def views(self) -> tuple[str, ...]:
        return POLICY_VIEWS if self.sandbox_supported else POLICY_VIEWS[:-1]

    @property
    def cursor(self) -> int:
        if self.view == "posture":
            return self.scope_index
        return self.cursors[self.view]

    @cursor.setter
    def cursor(self, value: int) -> None:
        if self.view == "posture":
            self.scope_index = value
        elif self.view == "chains":
            rows = self.chain_rows()
            before = self.cursors["chains"]
            self.cursors["chains"] = value
            if 0 <= value < len(rows) and rows[value][1] is None:
                # A header row: carry on in the direction of travel.
                self.cursors["chains"] = self._next_chain(value, 1 if value >= before else -1)
        else:
            self.cursors[self.view] = value
        self._clamp()

    def active_policy(self) -> Any | None:
        return next((policy for policy in self.policies if getattr(policy, "active", False)), None)

    def policy_named(self, name: str) -> Any | None:
        return next((policy for policy in self.policies if getattr(policy, "name", "") == name), None)

    def pack_rows(self) -> tuple[Any, ...]:
        """The global row first, then one per active connector."""
        rows = (self.global_pack,) if self.global_pack is not None else ()
        return (*rows, *self.connector_packs)

    def override_connectors(self) -> tuple[str, ...]:
        """Connectors whose own pack a global switch would clear."""
        return tuple(row.connector for row in self.connector_packs if getattr(row, "source", "") == "override")

    def packs_for_scope(self, connector: str) -> tuple[str, ...]:
        """The pack names a switch at this scope replaces."""
        if connector:
            row = next((r for r in self.connector_packs if r.connector == connector), None)
            return (row.pack,) if row is not None else ()
        names = [self.global_pack.pack] if self.global_pack is not None else []
        names.extend(row.pack for row in self.connector_packs if getattr(row, "source", "") == "override")
        return tuple(names)

    def current_pack(self, connector: str) -> str:
        if connector:
            row = next((r for r in self.connector_packs if r.connector == connector), None)
            return row.pack if row is not None else ""
        return self.global_pack.pack if self.global_pack is not None else ""

    # Scopes -----------------------------------------------------------------

    def selected_scope(self) -> Any | None:
        """The posture row that is highlighted (also the opt-in/families scope)."""
        if not self.postures:
            return None
        return self.postures[max(0, min(self.scope_index, len(self.postures) - 1))]

    def scope_name(self) -> str:
        row = self.selected_scope()
        return str(_attr(row, "scope")) if row is not None else ""

    def scope_row(self, connector: str) -> Any | None:
        """The posture row for ``connector`` ("" or "global" = the global row)."""
        want = connector or "global"
        return next((row for row in self.postures if _attr(row, "scope") == want), None)

    def own_setting(self, field: str) -> tuple[str, ...]:
        """Connectors whose ``mode``/``pack`` is their own, not the global one."""
        source = f"{field}_source"
        return tuple(
            str(_attr(row, "scope"))
            for row in self.postures
            if self.connector_of(row) and _attr(row, source) == "override"
        )

    @staticmethod
    def connector_of(row: object | None) -> str:
        """The ``--connector`` value for a scope row ("" for global)."""
        scope = str(_attr(row, "scope")) if row is not None else ""
        return "" if scope in {"", "global"} else scope

    def command_connector(self, row: object | None) -> str:
        """``--connector`` for mode and approval: "" on a single-connector install."""
        connector = self.connector_of(row)
        return connector if connector and self.multi_connector else ""

    def scope_levels(self, row: object | None) -> tuple[str, str]:
        """``(blocks at, alerts at)`` for the scope's tool calls.

        The catalog's ``block_at`` / ``alert_at`` (``guardrail.block_at`` /
        ``alert_at`` applied); a row without them resolves the same way.
        """
        if row is None:
            return profile_levels("")
        block, alert = str(_attr(row, "block_at")), str(_attr(row, "alert_at"))
        if level_rank(block) and level_rank(alert):
            return block, alert
        levels = self.row_levels(row)
        return levels.block_at, levels.alert_at

    @staticmethod
    def own_levels(row: object | None) -> tuple[str, str]:
        """The ``(block_at, alert_at)`` a scope sets itself ("" = inherits)."""
        if row is None:
            return "", ""
        return level_value(_attr(row, "own_block_at")), level_value(_attr(row, "own_alert_at"))

    def row_levels(
        self,
        row: object,
        *,
        global_own: tuple[str, str] | None = None,
        own: tuple[str, str] | None = None,
    ) -> ScopeLevels:
        """How the gateway resolves ``row``'s levels, optionally with changed values.

        ``global_own`` replaces the global row's values, ``own`` the row's own
        (ignored for the global row, whose own values are the global ones).
        """
        shared = global_own if global_own is not None else self.own_levels(self.scope_row(""))
        path = str(_attr(row, "pack_path"))
        if not self.connector_of(row):
            return resolve_levels(path, shared)
        return resolve_levels(path, shared, own if own is not None else self.own_levels(row))

    def level_change(self, kind: str, row: object, choice: str) -> LevelChange:
        """What picking ``choice`` (a picker value or :data:`INHERIT`) on ``row`` changes.

        On a single-connector install the change goes to the global value
        (:meth:`command_connector`), as ``m`` and ``h`` do.
        """
        index = 0 if kind == "block" else 1
        value = "" if choice == INHERIT else (choice or "").strip().rstrip("+").upper()
        target = self.command_connector(row)
        if target:
            own = list(self.own_levels(row))
            own[index] = value
            scope = str(_attr(row, "scope"))
            effect = LevelEffect(scope, self.row_levels(row), self.row_levels(row, own=(own[0], own[1])))
            return LevelChange(kind, target, value, (effect,))
        shared = list(self.own_levels(self.scope_row("")))
        shared[index] = value
        effects: list[LevelEffect] = []
        keep_own: list[str] = []
        for scope_row in self.postures:
            scope = str(_attr(scope_row, "scope"))
            if self.connector_of(scope_row) and self.own_levels(scope_row)[index]:
                keep_own.append(scope)
                continue
            after = self.row_levels(scope_row, global_own=(shared[0], shared[1]))
            effects.append(LevelEffect(scope, self.row_levels(scope_row), after))
        return LevelChange(kind, "", value, tuple(effects), tuple(keep_own))

    def level_current(self, kind: str, row: object) -> str:
        """The picker value the change's scope stores now (:data:`INHERIT` if none)."""
        index = 0 if kind == "block" else 1
        holder = row if self.command_connector(row) else self.scope_row("")
        return picker_level(self.own_levels(holder)[index])

    def level_inherit_text(self, kind: str, row: object) -> str:
        """``Use the pack's level (CRITICAL)`` or ``Use the global level (HIGH+)``."""
        change = self.level_change(kind, row, INHERIT)
        effect = change.effect_for(str(_attr(row, "scope")))
        if effect is None:
            return "Use the pack's level"
        label, source = levels_setting(effect.after, kind)
        where = "the global level" if source == "global" else "the pack's level"
        return f"Use {where} ({label})"

    def levels_line(self, row: object) -> str:
        """Where a scope's tool-call levels come from, for its detail."""
        levels = self.row_levels(row)
        scope = str(_attr(row, "scope")) or "global"
        pack = str(_attr(row, "pack"))
        profile = pack_profile(str(_attr(row, "pack_path")))
        block, alert = levels.block_source, levels.alert_source
        if block == alert:
            line = f"Levels {level_origin(block, scope, pack, profile)}."
        else:
            line = (
                f"Block level {level_origin(block, scope, pack, profile)}; "
                f"alert level {level_origin(alert, scope, pack, profile)}."
            )
        if levels.alert_clamped:
            line += f" Alerts start at {levels.alert_at}: anything that blocks also alerts."
        return line

    def scope_pack_label(self, row: object) -> str:
        """``strict``, or ``strict+1`` for a pack composed from strict and one opt-in pack."""
        pack = str(_attr(row, "pack")) or "-"
        base = self.pack_bases.get(str(_attr(row, "pack_path")))
        if base:
            return f"{base}+{len(self.scope_protection(row))}"
        return pack

    def scope_protection(self, row: object | None = None) -> tuple[str, ...]:
        row = row if row is not None else self.selected_scope()
        return tuple(_attr(row, "protection", ()) or ()) if row is not None else ()

    def scope_actions(self, row: object | None) -> tuple[tuple[str, str], ...]:
        block, alert = self.scope_levels(row)
        return severity_actions(block, alert, str(_attr(row, "hilt")) or "off")

    def protection_total(self) -> int:
        return sum(1 for pack in self.protection if _attr(pack, "status") != "staged")

    def protection_in_use(self) -> tuple[str, ...]:
        """Opt-in packs turned on for any scope, in pack order."""
        used = {name for row in self.postures for name in self.scope_protection(row)}
        return tuple(str(_attr(p, "name")) for p in self.protection if _attr(p, "name") in used)

    def protection_pack(self, name: str) -> Any | None:
        return next((p for p in self.protection if _attr(p, "name") == name), None)

    def selected_protection(self) -> Any | None:
        if self.view != "optin" or not self.protection:
            return None
        return self.protection[self.cursors["optin"]]

    def scope_families(self, row: object | None = None) -> tuple[Any, ...]:
        row = row if row is not None else self.selected_scope()
        if row is None:
            return ()
        return self.families.get(str(_attr(row, "pack_path")), ())

    def selected_family(self) -> Any | None:
        rows = self.scope_families()
        if self.view != "families" or not rows:
            return None
        return rows[self.cursors["families"]]

    def chain_rows(self) -> tuple[tuple[str, Any | None], ...]:
        return chain_display_rows(self.chains)

    def blocking_chains(self) -> int:
        return sum(1 for chain in self.chains if _attr(chain, "can_block", False))

    def selected_chain(self) -> Any | None:
        rows = self.chain_rows()
        if self.view != "chains" or not rows:
            return None
        return rows[self.cursors["chains"]][1]

    def row_count(self, view: str | None = None) -> int:
        view = view or self.view
        if view == "posture":
            return len(self.postures)
        if view == "optin":
            return len(self.protection)
        if view == "chains":
            return len(self.chain_rows())
        if view == "families":
            return len(self.scope_families())
        if view == "packs":
            return len(self.pack_rows())
        if view == "sandbox_packs":
            return len(self.sandbox_packs)
        return len(self.policies)

    def selected_policy(self) -> Any | None:
        if self.view != "policies" or not self.policies:
            return None
        return self.policies[self.cursor]

    def selected_pack_row(self) -> Any | None:
        rows = self.pack_rows()
        if self.view != "packs" or not rows:
            return None
        return rows[self.cursor]

    def selected_sandbox_pack(self) -> SandboxPackRow | None:
        if self.view != "sandbox_packs" or not self.sandbox_packs:
            return None
        return self.sandbox_packs[self.cursor]

    # ---- keys -------------------------------------------------------------

    def set_view(self, view: str) -> None:
        if view not in self.views():
            return
        if view != self.view:
            self.detail_open = False
        self.view = view
        if view == "chains":
            rows = self.chain_rows()
            current = self.cursors["chains"]
            if 0 <= current < len(rows) and rows[current][1] is None:
                self.cursors["chains"] = self._next_chain(current, 1)
        self._clamp()

    def handle_key(self, key: str) -> PolicyPanelAction:
        if key in VIEW_KEYS:
            view = VIEW_KEYS[key]
            if view not in self.views():
                return PolicyPanelAction("hint", hint="Sandbox packs are available on Linux and macOS only.")
            self.set_view(view)
            if view == "sandbox_packs" and not self.sandbox_loaded:
                return PolicyPanelAction("load_sandbox_packs")
            return PolicyPanelAction("render")
        if key in {"escape", "esc", "q"}:
            if self.detail_open:
                self.detail_open = False
                return PolicyPanelAction("render")
            return PolicyPanelAction("none")
        if key in {"down", "j"}:
            self._move(1)
            return PolicyPanelAction("render")
        if key in {"up", "k"}:
            self._move(-1)
            return PolicyPanelAction("render")
        if key == "r":
            return PolicyPanelAction("refresh", hint="Refreshing policies...")
        if key == "i":
            return self._toggle_detail()
        view = self.view
        if view == "posture":
            return self._posture_key(key)
        if view == "optin":
            if key in {"space", "enter"}:
                return self._toggle_protection()
            if key == "s":
                return self._next_scope()
            return PolicyPanelAction("none")
        if view == "families":
            if key == "s":
                return self._next_scope()
            if key == "enter":
                return self._toggle_detail()
            return PolicyPanelAction("none")
        if view == "chains":
            if key == "enter":
                return self._toggle_detail()
            return PolicyPanelAction("none")
        if view == "policies" and key in {"b", "a"}:
            policy = self.selected_policy()
            if policy is None:
                return PolicyPanelAction("hint", hint="No named policies were found.")
            return PolicyPanelAction("pick_policy_block" if key == "b" else "pick_policy_alert", policy=policy.name)
        if key != "enter":
            return PolicyPanelAction("none")
        if view == "policies":
            policy = self.selected_policy()
            if policy is None:
                return PolicyPanelAction("hint", hint="No named policies were found.")
            return PolicyPanelAction("pick_policy", policy=policy.name)
        if view == "packs":
            row = self.selected_pack_row()
            connector = "" if row is None or row.connector == "global" else row.connector
            return PolicyPanelAction("pick_pack", connector=connector)
        if not self.row_count():
            return PolicyPanelAction("hint", hint="No sandbox packs are loaded.")
        self.detail_open = not self.detail_open
        return PolicyPanelAction("render")

    def _posture_key(self, key: str) -> PolicyPanelAction:
        if key == "enter":
            return self._toggle_detail()
        if key not in {"m", "b", "a", "h", "p"}:
            return PolicyPanelAction("none")
        row = self.selected_scope()
        if row is None:
            return PolicyPanelAction("hint", hint="The scopes have not loaded yet; press r to refresh.")
        connector = self.connector_of(row)
        if key == "m":
            return PolicyPanelAction("toggle_mode", connector=connector)
        if key == "h":
            return PolicyPanelAction("pick_hilt", connector=connector)
        if key == "p":
            return PolicyPanelAction("pick_pack", connector=connector)
        return PolicyPanelAction("pick_block" if key == "b" else "pick_alert", connector=connector)

    def _toggle_protection(self) -> PolicyPanelAction:
        pack = self.selected_protection()
        if pack is None:
            return PolicyPanelAction("hint", hint="No opt-in packs were found.")
        title = str(_attr(pack, "title")) or str(_attr(pack, "name"))
        if _attr(pack, "status") == "staged":
            return PolicyPanelAction("hint", hint=f"{title} is staged and can't be turned on yet.")
        row = self.selected_scope()
        if row is None:
            return PolicyPanelAction("hint", hint="The scopes have not loaded yet; press r to refresh.")
        name = str(_attr(pack, "name"))
        return PolicyPanelAction(
            "toggle_protection",
            connector=self.connector_of(row),
            pack=name,
            enable=name not in self.scope_protection(row),
        )

    def _next_scope(self) -> PolicyPanelAction:
        if len(self.postures) < 2:
            return PolicyPanelAction("hint", hint="There is only one scope.")
        self.scope_index = (self.scope_index + 1) % len(self.postures)
        self.detail_open = False
        self._clamp()
        return PolicyPanelAction("render")

    def _toggle_detail(self) -> PolicyPanelAction:
        if not self.row_count():
            return PolicyPanelAction("hint", hint="Nothing is selected.")
        self.detail_open = not self.detail_open
        return PolicyPanelAction("render")

    def keys_hint(self, view: str | None = None) -> str:
        return policies_keys_hint(view or self.view, sandbox_supported=self.sandbox_supported)

    # ---- rendering --------------------------------------------------------

    def header(self, width: int = 0) -> str:
        """``● default policy · default pack · 1 of 5 opt-in packs · 26 chains (4 can block)``."""
        if self.loading and not self.loaded:
            return "Loading policies…"
        active = self.active_policy()
        policy = active.name if active is not None else "no"
        pack = self.global_pack.pack if self.global_pack is not None else "?"
        used, total = len(self.protection_in_use()), self.protection_total()
        chains, blocking = len(self.chains), self.blocking_chains()
        wide = [f"● {policy} policy", f"{pack} pack"]
        short = [f"● {policy} policy", f"{pack} pack"]
        if total:
            wide.append(f"{used} of {total} opt-in packs")
            short.append(f"{used}/{total} opt-in")
        if chains:
            wide.append(f"{chains} chains ({blocking} can block)")
            short.append(f"{chains} chains")
        text = " · ".join(wide)
        if width and len(text) > width:
            text = " · ".join(short)
        return fit(text, width)

    def headline(self, width: int = 0) -> str:
        """The view's status line: errors, loading, or what the view is about."""
        if self.loading and not self.loaded:
            return "Loading policies…"
        view = self.view
        if view == "sandbox_packs":
            if self.sandbox_error:
                return f"Could not list sandbox packs: {self.sandbox_error}"
            if not self.sandbox_loaded:
                return "Loading sandbox packs…"
            return f"New sandboxes use the {self.sandbox_active} pack (openshell.pack); change it in Setup."
        if self.error:
            return f"Could not read policies: {self.error}"
        if view in {"posture", "optin", "families", "chains"} and self.posture_error:
            return f"Could not read the protection settings: {self.posture_error}"
        if view == "packs" and self.pack_error:
            return f"Could not read rule packs: {self.pack_error}"
        if view == "posture":
            active = self.active_policy()
            if active is None:
                return "Tool-call levels are set per scope below · no policy is active for LLM traffic"
            text = (
                f"LLM traffic ({active.name} policy): blocks {active.block_at or '?'}, alerts {active.alert_at or '?'}"
            )
            wide = f"{text} · tool calls: per scope below"
            return wide if not width or len(wide) <= width else text
        if view in {"optin", "families"}:
            scope = self.scope_name() or "-"
            if view == "optin":
                on = len(self.scope_protection())
                return f"Scope: {scope} ▾  ·  {on} of {self.protection_total()} on"
            row = self.selected_scope()
            pack = str(_attr(row, "pack")) if row is not None else "-"
            return f"Scope: {scope} ▾  ·  {pack} pack"
        if view == "chains":
            blocking = self.blocking_chains()
            return (
                f"{len(self.chains)} bounded chains · ✓ {blocking} can block · "
                f"◐ {len(self.chains) - blocking} alert only · built in, read-only"
            )
        active = self.active_policy()
        policy = f"active policy {active.name}" if active is not None else "no policy activated yet"
        pack = self.global_pack.pack if self.global_pack is not None else "?"
        overrides = len(self.override_connectors())
        own = f" · {overrides} connector{'s' if overrides != 1 else ''} with their own" if overrides else ""
        return f"{policy} · rule pack {pack}{own}"

    def empty_state(self) -> str:
        if self.row_count():
            return ""
        view = self.view
        if view == "packs":
            return "" if self.pack_error else "No rule packs found."
        if view == "sandbox_packs":
            return "" if not self.sandbox_loaded or self.sandbox_error else "No sandbox packs found."
        if self.loading or not self.loaded or self.error:
            return ""
        if view in {"posture", "optin", "families", "chains"} and self.posture_error:
            return ""
        if view == "posture":
            return "No scopes found. Set up the guardrail first: defenseclaw setup guardrail"
        if view == "optin":
            return "No opt-in protection packs were found in this install."
        if view == "families":
            return "The scope's rule pack has no rule files."
        if view == "chains":
            return "The chain catalog was not found in this install."
        return "No named policies found. Create one with: defenseclaw policy create NAME"

    def view_switcher(self) -> tuple[tuple[str, str, bool], ...]:
        """``(key, short title, active)`` for the one-line switcher."""
        return tuple(
            (str(index), VIEW_SHORT_TITLES[view], view == self.view) for index, view in enumerate(self.views(), start=1)
        )

    def nav_entries(self) -> tuple[tuple[str, str, str, bool], ...]:
        """``(view, title, badge, active)`` for the navigation list."""
        badges = {
            "posture": str(len(self.postures)) if self.postures else "",
            "optin": f"{len(self.protection_in_use())}/{self.protection_total()}" if self.protection_total() else "",
            "chains": str(len(self.chains)) if self.chains else "",
            "families": str(len(self.scope_families())) if self.scope_families() else "",
            "policies": str(len(self.policies)) if self.policies else "",
            "packs": str(len(self.pack_rows())) if self.pack_rows() else "",
            "sandbox_packs": str(len(self.sandbox_packs)) if self.sandbox_packs else "",
        }
        return tuple((view, VIEW_TITLES[view], badges[view], view == self.view) for view in self.views())

    def data_table_columns(self, width: int = 0) -> tuple[str, ...]:
        """Column titles for a table ``width`` characters wide (0 = unknown, narrow)."""
        return self.table(width)[0]

    def data_table_rows(self, width: int = 0) -> tuple[tuple[str, ...], ...]:
        return self.table(width)[1]

    def table(self, width: int = 0) -> tuple[tuple[str, ...], tuple[tuple[str, ...], ...]]:
        """``(columns, rows)`` that fit a table ``width`` characters wide.

        ``width`` is the table's own width: beside a navigation list and an
        aside it is much narrower than the terminal, so each view drops the
        columns the aside (or ``i``) shows for the highlighted row.
        """
        view = self.view
        if view == "posture":
            return self._posture_table(width)
        if view == "optin":
            return self._protection_table(width)
        if view == "chains":
            return self._chain_table(width)
        if view == "families":
            return self._family_table(width)
        if view == "packs":
            return self._pack_table(width)
        if view == "sandbox_packs":
            return self._sandbox_table(width)
        return self._policy_table(width)

    def _posture_table(self, width: int) -> tuple[tuple[str, ...], tuple[tuple[str, ...], ...]]:
        total = self.protection_total()
        rows = []
        for row in self.postures:
            block, alert = self.scope_levels(row)
            own = bool(self.connector_of(row))
            mode = str(_attr(row, "mode")) or "observe"
            pack = self.scope_pack_label(row)
            on = len(self.scope_protection(row))
            scope = str(_attr(row, "scope"))
            hilt = str(_attr(row, "hilt")) or "off"
            if width >= 90:
                if own and _attr(row, "mode_source") == "override":
                    mode += " (own)"
                if own and _attr(row, "pack_source") == "override":
                    pack += " (own)"
                optin = f"{on} of {total}" if total else str(on)
                rows.append((fit(scope, 16), mode, block, alert, hilt, fit(pack, 22), optin))
            elif width >= 69:
                optin = f"{on}/{total}" if total else str(on)
                rows.append((fit(scope, 11), mode, block, alert, hilt, fit(pack, 11), optin))
            elif width >= 55:
                optin = f"{on}/{total}" if total else str(on)
                rows.append((fit(scope, 11), mode, block, alert, hilt, optin))
            elif width >= 47:
                optin = f"{on}/{total}" if total else str(on)
                rows.append((fit(scope, 11), mode, block, hilt, optin))
            else:
                rows.append((fit(scope, 11), mode, block))
        if width >= 90:
            columns = ("Scope", "Mode", "Blocks at", "Alerts at", "Approval", "Rule pack", "Opt-in")
        elif width >= 69:
            columns = ("Scope", "Mode", "Blocks", "Alerts", "Approval", "Pack", "Opt-in")
        elif width >= 55:
            columns = ("Scope", "Mode", "Blocks", "Alerts", "Approval", "Opt-in")
        elif width >= 47:
            columns = ("Scope", "Mode", "Blocks", "Approval", "Opt-in")
        else:
            columns = ("Scope", "Mode", "Blocks")
        return columns, tuple(rows)

    def _protection_table(self, width: int) -> tuple[tuple[str, ...], tuple[tuple[str, ...], ...]]:
        rows = []
        for pack in self.protection:
            name = str(_attr(pack, "name"))
            title = pack_short_title(str(_attr(pack, "title")) or name)
            staged = _attr(pack, "status") == "staged"
            if staged:
                state, rules = "─ staged", "-"
            else:
                state = "● on" if name in self.scope_protection() else "○ off"
                rules = str(_attr(pack, "rule_count", 0))
            covers = "staged, not available yet" if staged else str(_attr(pack, "covers")) or "-"
            if width >= 66:
                rows.append((fit(title, 26), fit(covers, width - 26 - 5 - 8 - 8), rules, state))
            elif width >= 44:
                rows.append((fit(title, 26), rules, state))
            else:
                rows.append((fit(title, max(8, width - 12)), state))
        if width >= 66:
            columns: tuple[str, ...] = ("Pack", "Covers", "Rules", "State")
        elif width >= 44:
            columns = ("Pack", "Rules", "State")
        else:
            columns = ("Pack", "State")
        return columns, tuple(rows)

    def _chain_table(self, width: int) -> tuple[tuple[str, ...], tuple[tuple[str, ...], ...]]:
        full = width >= 60
        severity_width = 8 if full else 4
        title_width = max(12, width - 1 - severity_width - 6)
        rows = []
        for label, chain in self.chain_rows():
            if chain is None:
                rows.append(("", f"── {label}", ""))
                continue
            marker = "✓" if _attr(chain, "can_block", False) else "◐"
            severity = str(_attr(chain, "severity")) or "-"
            rows.append((marker, fit(str(_attr(chain, "title")), title_width), severity[:severity_width]))
        return ("", "Chain", "Severity" if full else "Sev"), tuple(rows)

    def _family_table(self, width: int) -> tuple[tuple[str, ...], tuple[tuple[str, ...], ...]]:
        rows = []
        for family in self.scope_families():
            name = fit(str(_attr(family, "name")), 15)
            counts = (str(_attr(family, "rules", 0)), str(_attr(family, "enabled", 0)))
            if width >= 60:
                what = fit(str(_attr(family, "description")) or "-", width - 15 - 5 - 7 - 8)
                rows.append((name, *counts, what))
            elif width >= 34:
                rows.append((name, *counts))
            else:
                rows.append((name, counts[0]))
        if width >= 60:
            columns: tuple[str, ...] = ("Family", "Rules", "Enabled", "What it catches")
        elif width >= 34:
            columns = ("Family", "Rules", "On")
        else:
            columns = ("Family", "Rules")
        return columns, tuple(rows)

    def _pack_table(self, width: int) -> tuple[tuple[str, ...], tuple[tuple[str, ...], ...]]:
        rows = []
        for row in self.pack_rows():
            scope = "global" if row.connector == "global" else row.connector
            source = {"global": "uses global", "override": "own pack", "default": "built-in default"}.get(
                row.source, row.source
            )
            if row.connector == "global":
                source = "configured" if row.source == "global" else "built-in default"
            if width >= 100:
                rows.append((scope, row.pack or "-", source, fit(row.path or "-", 48)))
            elif width >= 44:
                rows.append((scope, row.pack or "-", source))
            else:
                rows.append((fit(scope, 12), fit(row.pack or "-", max(8, width - 18))))
        if width >= 100:
            columns: tuple[str, ...] = ("Scope", "Pack", "Source", "Folder")
        elif width >= 44:
            columns = ("Scope", "Pack", "Source")
        else:
            columns = ("Scope", "Pack")
        return columns, tuple(rows)

    def _sandbox_table(self, width: int) -> tuple[tuple[str, ...], tuple[tuple[str, ...], ...]]:
        rows = []
        for pack in self.sandbox_packs:
            marker = "●" if pack.name == self.sandbox_active else ""
            digest = "invalid" if pack.error else (pack.digest[:12] or "-")
            kind = "built-in" if pack.builtin else "custom"
            if width >= 100:
                rows.append((marker, pack.name, kind, pack.profile or "-", digest, fit(pack.description or "-", 40)))
            elif width >= 56:
                rows.append((marker, pack.name, kind, pack.profile or "-", digest))
            else:
                rows.append((marker, fit(pack.name, max(8, width - 16)), kind))
        if width >= 100:
            columns: tuple[str, ...] = ("", "Pack", "Kind", "Profile", "Digest", "Description")
        elif width >= 56:
            columns = ("", "Pack", "Kind", "Profile", "Digest")
        else:
            columns = ("", "Pack", "Kind")
        return columns, tuple(rows)

    def _policy_table(self, width: int) -> tuple[tuple[str, ...], tuple[tuple[str, ...], ...]]:
        rows = []
        for policy in self.policies:
            active = "●" if policy.active else ""
            kind = "built-in" if policy.builtin else "custom"
            if width >= 100:
                rows.append(
                    (
                        active,
                        fit(policy.name, 24),
                        kind,
                        policy.block_at or "-",
                        policy.alert_at or "-",
                        policy.install_block_at or "-",
                        policy.firewall_default or "-",
                        fit(policy.description or "-", 40),
                    )
                )
            elif width >= 62:
                rows.append(
                    (
                        active,
                        fit(policy.name, 14),
                        kind,
                        policy.block_at or "-",
                        policy.alert_at or "-",
                        policy.install_block_at or "-",
                    )
                )
            else:
                rows.append(
                    (active, fit(policy.name, max(8, width - 30)), policy.block_at or "-", policy.alert_at or "-")
                )
        # Block / alert here are the policy's levels for LLM traffic through the
        # guardrail proxy; the Posture view shows the tool-call levels.
        if width >= 100:
            columns: tuple[str, ...] = (
                "",
                "Policy",
                "Kind",
                "LLM block",
                "LLM alert",
                "Install block",
                "Firewall",
                "Description",
            )
        elif width >= 62:
            columns = ("", "Policy", "Kind", "LLM block", "LLM alert", "Install block")
        else:
            columns = ("", "Policy", "LLM block", "LLM alert")
        return columns, tuple(rows)

    def aside(self) -> tuple[str, tuple[str, ...]]:
        """``(title, lines)`` describing the highlighted row ("" title when nothing)."""
        view = self.view
        if view == "posture":
            return self._posture_aside()
        if view == "optin":
            return self._protection_aside()
        if view == "chains":
            return self._chain_aside()
        if view == "families":
            return self._family_aside()
        if view == "packs":
            return self._pack_aside()
        if view == "sandbox_packs":
            return self._sandbox_aside()
        return self._policy_aside()

    def detail_text(self) -> str:
        """The aside as plain lines, for the detail pane (only when opened)."""
        if not self.detail_open:
            return ""
        title, lines = self.aside()
        if not title:
            return ""
        return "\n".join((title, *lines))

    def _posture_aside(self) -> tuple[str, tuple[str, ...]]:
        row = self.selected_scope()
        if row is None:
            return "", ()
        scope = str(_attr(row, "scope"))
        mode = str(_attr(row, "mode")) or "observe"
        hilt = str(_attr(row, "hilt")) or "off"
        block, alert = self.scope_levels(row)
        # Where the mode comes from; levels_line says where the levels do.
        if self.connector_of(row) and _attr(row, "mode_source") == "override":
            source = "its own mode"
        else:
            source = "global mode"
        lines = [
            posture_summary(scope, mode, block, alert, hilt),
            "",
            f"Tool calls ({mode}, {source}):",
            *matrix_lines(mode, block, alert, hilt),
            self.levels_line(row),
            "",
            self._pack_line(row),
        ]
        protection = self.scope_protection(row)
        if protection:
            titles = [str(_attr(self.protection_pack(name), "title")) or name for name in protection]
            lines.append("Opt-in: " + ", ".join(titles))
        active = self.active_policy()
        if active is not None:
            lines.append(
                f"LLM traffic through the guardrail proxy: the {active.name} policy blocks "
                f"{active.block_at or '?'}, alerts at {active.alert_at or '?'}."
            )
        return f"Posture · {scope}", tuple(lines)

    def _pack_line(self, row: object) -> str:
        pack = str(_attr(row, "pack")) or "-"
        profile = pack_profile(str(_attr(row, "pack_path")))
        base = self.pack_bases.get(str(_attr(row, "pack_path")))
        if base:
            on = len(self.scope_protection(row))
            return (
                f"Rule pack: {pack} = {base} + {on} opt-in pack{'s' if on != 1 else ''}; its folder name "
                f"gives it {profile} levels (the gateway reads them from there)."
            )
        return f"Rule pack: {pack} ({profile} levels)"

    def _protection_aside(self) -> tuple[str, tuple[str, ...]]:
        pack = self.selected_protection()
        if pack is None:
            return "", ()
        name = str(_attr(pack, "name"))
        title = str(_attr(pack, "title")) or name
        lines = [str(_attr(pack, "summary")) or "-"]
        if _attr(pack, "status") == "staged":
            lines.append("Staged: this pack is a contract only and can't be turned on yet.")
        else:
            scope = self.scope_name() or "global"
            state = "on" if name in self.scope_protection() else "off"
            lines.append(f"{scope}: {state}. {protection_claim(name, scope)}")
        rules = self.pack_rules.get(name) or tuple(PackRule(rule_id) for rule_id in _attr(pack, "rule_ids", ()) or ())
        if rules:
            lines.append("")
            lines.append(f"Rules ({len(rules)}):")
            lines.extend(
                "  " + " · ".join(part for part in (rule.id, rule.severity, rule.title) if part) for rule in rules
            )
        return title, tuple(lines)

    def _chain_aside(self) -> tuple[str, tuple[str, ...]]:
        chain = self.selected_chain()
        if chain is None:
            return "", ()
        can_block = bool(_attr(chain, "can_block", False))
        requires = tuple(_attr(chain, "requires", ()) or ())
        lines = [
            f"{'✓ Can block' if can_block else '◐ Alert only'} · {_attr(chain, 'severity') or 'no severity'} · "
            f"{chain_domain_label(str(_attr(chain, 'domain')).lower())}",
            f"Looks at {_window_text(chain)}.",
        ]
        if requires:
            lines.append("Requires: " + ", ".join(requires) + ".")
        note = str(_attr(chain, "note"))
        if note:
            lines.append(note)
        lines.append(f"id: {_attr(chain, 'id')}")
        return str(_attr(chain, "title")), tuple(lines)

    def _family_aside(self) -> tuple[str, tuple[str, ...]]:
        family = self.selected_family()
        if family is None:
            return "", ()
        row = self.selected_scope()
        lines = [
            str(_attr(family, "description")) or "-",
            f"{_attr(family, 'enabled', 0)} of {_attr(family, 'rules', 0)} rules enabled",
            f"Pack: {_attr(row, 'pack') or '-'} ({_attr(row, 'scope') or '-'})",
        ]
        return f"Rule family · {_attr(family, 'name')}", tuple(lines)

    def _pack_aside(self) -> tuple[str, tuple[str, ...]]:
        row = self.selected_pack_row()
        if row is None:
            return "", ()
        lines = [f"pack: {row.pack}", f"source: {row.source}", f"folder: {row.path}"]
        pack = next((p for p in self.packs if getattr(p, "path", "") == row.path), None)
        if pack is not None:
            lines.append(f"kind: {pack.kind}")
            if pack.used_by:
                lines.append(f"used by: {', '.join(pack.used_by)}")
        return f"Rule pack · {row.connector}", tuple(lines)

    def _sandbox_aside(self) -> tuple[str, tuple[str, ...]]:
        pack = self.selected_sandbox_pack()
        if pack is None:
            return "", ()
        lines = [
            f"kind: {'built-in' if pack.builtin else 'custom'}",
            f"profile: {pack.profile or '-'}",
            f"source: {pack.source or '-'}",
            f"digest: {pack.digest or '-'}",
        ]
        if pack.description:
            lines.append(f"description: {pack.description}")
        if pack.error:
            lines.append(f"error: {pack.error}")
        return f"Sandbox pack · {pack.name}", tuple(lines)

    def _policy_aside(self) -> tuple[str, tuple[str, ...]]:
        policy = self.selected_policy()
        if policy is None:
            return "", ()
        kind = "built-in" if policy.builtin else "custom"
        effects = " · ".join(policy_side_effects(policy))
        lines = [
            f"LLM traffic (guardrail proxy): block {policy.block_at} · alert {policy.alert_at}",
            f"installs blocked at {policy.install_block_at} · firewall {policy.firewall_default or 'unchanged'} · "
            f"approval {_hilt_label(policy.hilt)}",
            policy.description or "-",
            policy.path + (f"  (activating it: {effects})" if effects else ""),
        ]
        return f"Policy · {policy.name} ({kind}{', active' if policy.active else ''})", tuple(lines)

    # ---- internals --------------------------------------------------------

    def _move(self, delta: int) -> None:
        if self.view == "chains":
            rows = self.chain_rows()
            if rows:
                self.cursors["chains"] = self._next_chain(self.cursors["chains"] + delta, delta)
            return
        self.cursor = self.cursor + delta

    def _next_chain(self, start: int, step: int) -> int:
        """The first chain row from ``start`` in direction ``step`` (headers skipped)."""
        rows = self.chain_rows()
        if not rows:
            return 0
        index = max(0, min(start, len(rows) - 1))
        probe = index
        while 0 <= probe < len(rows):
            if rows[probe][1] is not None:
                return probe
            probe += 1 if step >= 0 else -1
        probe = index
        while 0 <= probe < len(rows):
            if rows[probe][1] is not None:
                return probe
            probe += -1 if step >= 0 else 1
        return index

    def _clamp(self) -> None:
        scopes = len(self.postures)
        self.scope_index = max(0, min(self.scope_index, scopes - 1)) if scopes else 0
        for view in POLICY_VIEWS:
            if view == "posture":
                continue
            count = self.row_count(view)
            value = self.cursors[view]
            self.cursors[view] = max(0, min(value, count - 1)) if count else 0


__all__ = [
    "ALERT_LEVELS",
    "BLOCK_LEVELS",
    "CHAIN_DOMAINS",
    "DEFAULT_SANDBOX_PACK",
    "HILT_LEVELS",
    "INHERIT",
    "PACK_STRICTNESS",
    "POLICY_KEYMAP",
    "POLICY_VIEWS",
    "PROFILE_LEVELS",
    "PROTECTED_CONTEXT",
    "PROTECTED_PACK_PREFIX",
    "TOOL_ALERT_LEVELS",
    "TOOL_BLOCK_LEVELS",
    "VIEW_KEYS",
    "VIEW_SHORT_TITLES",
    "VIEW_TITLES",
    "LevelChange",
    "LevelEffect",
    "PackRule",
    "PackValidation",
    "PoliciesPanelModel",
    "PolicyCommandIntent",
    "PolicyPanelAction",
    "SandboxPackRow",
    "activate_intent",
    "actions_weaken",
    "chain_display_rows",
    "decode_sandbox_packs",
    "fit",
    "hilt_intent",
    "hilt_rank",
    "hilt_weakens",
    "level_intent",
    "level_origin",
    "level_rank",
    "levels_setting",
    "loosened_text",
    "matrix_lines",
    "mode_intent",
    "mode_weakens",
    "pack_profile",
    "pack_short_title",
    "pack_weakens",
    "parse_validation",
    "picker_level",
    "policies_keys_hint",
    "policy_keymap_rows",
    "policy_comparison",
    "policy_posture_text",
    "policy_side_effects",
    "policy_weakenings",
    "posture_summary",
    "profile_levels",
    "protection_claim",
    "protection_intent",
    "severity_actions",
    "threshold_intent",
    "threshold_rank",
    "threshold_weakens",
    "use_pack_intent",
]
