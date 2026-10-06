"""Shared admission evaluation helpers for Python CLI paths.

These helpers mirror the Go gateway/watcher admission (policies/rego/
admission.rego and internal/policy), reading only config.yaml:

1. The operator block list (asset_policy.<type>.denied) overrides everything.
2. Asset policy can block denied/unregistered/default-denied assets.
3. The operator allow list (asset_policy.<type>.allowed) skips scan and
   enforcement after asset policy; an allow pinned to a source path only
   matches that path.
4. The first-party allow list (admission.<type>.first_party_allow_list) may
   bypass scan when admission.<type>.allow_list_bypass_scan is on.
5. If no scan result exists yet, admission.<type>.scan_on_install decides
   whether scanning is required.
6. Once a scan result exists, the compiled admission action for the
   severity (scanner override, then severity action) decides whether the
   result is rejected, allowed, or only warned. A severity nothing covers
   fails closed.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, replace
from typing import Any

from defenseclaw import connector_paths
from defenseclaw.config import SeverityAction


@dataclass(frozen=True)
class AdmissionDecision:
    verdict: str
    reason: str
    action: SeverityAction = field(default_factory=SeverityAction)
    source: str = ""
    # GAP-2390: in asset-policy observe mode, what action mode would have
    # refused (reason and ``<source>-observe``). Empty when nothing was observed.
    observed_reason: str = ""
    observed_source: str = ""


@dataclass(frozen=True)
class CompiledAdmission:
    """``admission:`` compiled for one asset type (Go policy.CompiledAdmission).

    ``actions`` and ``scanner_overrides`` values are ``(SeverityAction, allow)``
    pairs, where ``allow`` marks the ``allow`` shorthand (verdict allowed
    rather than warning)."""

    scan_on_install: bool = True
    allow_list_bypass_scan: bool = True
    actions: dict[str, tuple[SeverityAction, bool]] = field(default_factory=dict)
    scanner_overrides: dict[str, dict[str, tuple[SeverityAction, bool]]] = field(default_factory=dict)
    first_party_allow: dict[str, list[str]] = field(default_factory=dict)
    source: str = "builtin"


ADMISSION_SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

_QUARANTINE = SeverityAction(file="quarantine", runtime="disable", install="block")
_BLOCK = SeverityAction(file="none", runtime="disable", install="block")
_WARN = SeverityAction(file="none", runtime="enable", install="none")
_FAIL_CLOSED = (_BLOCK, False)

_SHORTHANDS = {
    "block": (_BLOCK, False),
    "quarantine": (_QUARANTINE, False),
    "warn": (_WARN, False),
    "allow": (_WARN, True),
}


def _builtin_admission(target_type: str) -> CompiledAdmission:
    """The admission defaults that shipped in policies/rego/data.json up to 1.0."""
    actions = {
        "CRITICAL": (_QUARANTINE, False), "HIGH": (_QUARANTINE, False),
        "MEDIUM": (_WARN, False), "LOW": (_WARN, False), "INFO": (_WARN, False),
    }
    first_party: dict[str, list[str]] = {}
    if target_type == "skill":
        # F-0541/F-0902: markers are specific to the asset's own directory and
        # home-anchored, never a broad parent like ``.defenseclaw``.
        first_party["codeguard"] = [
            ".openclaw/workspace/skills/codeguard",
            ".openclaw/skills/codeguard",
            ".zeptoclaw/skills/codeguard",
            ".claude/skills/codeguard",
        ]
    elif target_type == "mcp":
        actions["MEDIUM"] = (_QUARANTINE, False)
        actions["LOW"] = (SeverityAction(file="none", runtime="disable", install="none"), False)
    elif target_type == "plugin":
        actions["HIGH"] = (_QUARANTINE, False)
        first_party["defenseclaw"] = [
            ".openclaw/extensions/defenseclaw",
            ".zeptoclaw/extensions/defenseclaw",
            ".claude/extensions/defenseclaw",
            ".codex/extensions/defenseclaw",
            ".config/amp/plugins/defenseclaw.ts",
        ]
    return CompiledAdmission(actions=actions, first_party_allow=first_party)


def _compile_action(raw: Any) -> tuple[SeverityAction, bool] | None:
    if isinstance(raw, str):
        return _SHORTHANDS.get(raw.strip().lower())
    if isinstance(raw, dict):
        return (
            SeverityAction(
                file=str(raw.get("file") or "none"),
                runtime="disable" if str(raw.get("runtime") or "") == "disable" else "enable",
                install=str(raw.get("install") or "none"),
            ),
            False,
        )
    if isinstance(raw, SeverityAction):
        return raw, False
    return None


def _compile_action_map(raw: Any) -> dict[str, tuple[SeverityAction, bool]]:
    out: dict[str, tuple[SeverityAction, bool]] = {}
    for sev, value in (raw or {}).items() if isinstance(raw, dict) else ():
        action = _compile_action(value)
        if action is not None:
            out[str(sev).upper()] = action
    return out


def _severity_rank(sev: str) -> int:
    try:
        return len(ADMISSION_SEVERITY_ORDER) - ADMISSION_SEVERITY_ORDER.index(str(sev).strip().upper())
    except ValueError:
        return 0


#: The skill-scanner gate defaults (Go config.DefaultSkillScannerFailOnSeverity
#: and DefaultSkillScannerReviewQueueMin), which setup, the TUI and doctor show.
_DEFAULT_FAIL_ON_SEVERITY = "HIGH"
_DEFAULT_REVIEW_QUEUE_MIN = "MEDIUM"


def _derived_scanner_gate(fail_on: str, review_min: str) -> dict[str, tuple[SeverityAction, bool]]:
    """scanners.skill_scanner.fail_on_severity/review_queue_min as an action
    map: at or above the gate quarantine, [review, gate) warn, below allow.
    Unset values take the defaults, as Go's Effective* do."""
    fail_on = str(fail_on or "").strip() or _DEFAULT_FAIL_ON_SEVERITY
    review_min = str(review_min or "").strip() or _DEFAULT_REVIEW_QUEUE_MIN
    gate = _severity_rank(fail_on)
    if not gate:
        return {}
    review = _severity_rank(review_min)
    if not review or review > gate:
        review = 1
    out = {}
    for sev in ADMISSION_SEVERITY_ORDER:
        rank = _severity_rank(sev)
        if rank >= gate:
            out[sev] = _SHORTHANDS["quarantine"]
        else:
            out[sev] = _SHORTHANDS["warn"] if rank >= review else _SHORTHANDS["allow"]
    return out


def compile_admission(cfg: Any, target_type: str) -> CompiledAdmission:
    """Compile ``admission:`` for one asset type, as the gateway does (Go
    ``policy.CompileAdmission``). Each field and severity resolves, first
    match wins: ``admission.<type>`` > (skill) the scanner gate >
    ``admission.defaults`` > the built-in default."""
    out = _builtin_admission(target_type)
    adm = getattr(cfg, "admission", None)
    if adm is None:
        return out
    defaults = getattr(adm, "defaults", None)
    own = getattr(adm, target_type, None)

    def first_bool(name: str, fallback: bool) -> bool:
        for layer in (own, defaults):
            value = getattr(layer, name, None) if layer is not None else None
            if value is not None:
                return bool(value)
        return fallback

    scan_on_install = first_bool("scan_on_install", out.scan_on_install)
    bypass = first_bool("allow_list_bypass_scan", out.allow_list_bypass_scan)

    own_actions = _compile_action_map(getattr(own, "actions", None))
    default_actions = _compile_action_map(getattr(defaults, "actions", None))
    derived: dict[str, tuple[SeverityAction, bool]] = {}
    if target_type == "skill":
        ss = getattr(getattr(cfg, "scanners", None), "skill_scanner", None)
        derived = _derived_scanner_gate(getattr(ss, "fail_on_severity", ""), getattr(ss, "review_queue_min", ""))
    actions = dict(out.actions)
    used = set()
    for sev in ADMISSION_SEVERITY_ORDER:
        for tag, layer in (("own", own_actions), ("derived", derived), ("defaults", default_actions)):
            if sev in layer:
                actions[sev] = layer[sev]
                used.add(tag)
                break
    source = out.source
    if "own" in used:
        source = f"config:admission.{target_type}.actions"
    elif "derived" in used:
        source = "derived:scanners.skill_scanner"
    elif "defaults" in used:
        source = "config:admission.defaults.actions"

    overrides: dict[str, dict[str, tuple[SeverityAction, bool]]] = {}
    for layer in (defaults, own):
        for scanner, raw in (getattr(layer, "scanner_overrides", None) or {}).items() if layer is not None else ():
            compiled = _compile_action_map(raw)
            if compiled:
                overrides.setdefault(str(scanner).strip(), {}).update(compiled)

    first_party = dict(out.first_party_allow)
    for layer in (own, defaults):
        entries = getattr(layer, "first_party_allow_list", None) if layer is not None else None
        # An explicit empty list allows nothing first party (Go firstParty
        # treats a non-nil empty list the same way); None inherits.
        if entries is not None:
            first_party = {
                str(getattr(e, "name", "")): list(getattr(e, "source_path_contains", []) or [])
                for e in entries
            }
            break
    if target_type == "tool":
        first_party = {}
    return CompiledAdmission(
        scan_on_install=scan_on_install,
        allow_list_bypass_scan=bypass,
        actions=actions,
        scanner_overrides=overrides,
        first_party_allow=first_party,
        source=source,
    )


def evaluate_admission(
    pe: Any,
    *,
    target_type: str,
    name: str,
    source_path: str = "",
    connector: str = "",
    url: str = "",
    command: str = "",
    args: list[str] | None = None,
    transport: str = "",
    runtime_surface: str = "cli",
    config: Any | None = None,
    asset_policy: Any | None = None,
    scan_result: Any | None = None,
    action_entry: Any | None = None,
    include_quarantine: bool = False,
    allow_first_party: bool = True,
) -> AdmissionDecision:
    """Evaluate admission for a target from config.yaml.

    ``config`` defaults to ``pe.cfg``; ``asset_policy`` to its
    ``asset_policy``. Operator block entries always win. Operator allow
    entries skip scanning after asset policy has enforced admin
    deny/default-deny controls. First-party entries are subject to
    ``allow_list_bypass_scan``.
    """
    if config is None:
        config = getattr(pe, "cfg", None)
    if asset_policy is None:
        asset_policy = getattr(config, "asset_policy", None)
    legacy = getattr(pe, "_legacy_rows", lambda: False)()

    blocked_reason = _action_reason(action_entry, default=f"{target_type} '{name}' is on the block list")
    if (
        pe.is_blocked_for_connector(target_type, name, connector)
        if connector
        else pe.is_blocked(target_type, name)
    ):
        return AdmissionDecision("blocked", blocked_reason, source="manual-block")

    asset_decision = evaluate_asset_policy(
        asset_policy,
        target_type=target_type,
        name=name,
        connector=connector,
        source_path=source_path,
        url=url,
        command=command,
        args=args or [],
        transport=transport,
        runtime_surface=runtime_surface,
    )
    if asset_decision.verdict == "blocked":
        return asset_decision

    def _done(decision: AdmissionDecision) -> AdmissionDecision:
        # GAP-2390: keep an observe-mode would-block on whatever decision the
        # rest of admission reaches, so install paths can warn and audit it.
        if not asset_decision.source.endswith("-observe"):
            return decision
        return replace(
            decision,
            observed_reason=asset_decision.reason,
            observed_source=asset_decision.source,
        )

    allowed_reason = _action_reason(action_entry, default=f"{target_type} '{name}' is on the allow list — scan skipped")
    if legacy:
        legacy_decision = _legacy_allow_decision(pe, target_type, name, connector, source_path, allowed_reason)
        if legacy_decision is not None:
            return _done(legacy_decision)
    elif asset_decision.source == "asset-policy-allow":
        # The allow matched with the presented source path, so an allow
        # pinned to one on-disk asset never transfers to another that only
        # shares the name (F-0941, F-0401).
        return _done(AdmissionDecision("allowed", allowed_reason, source="manual-allow"))

    quarantined = (
        pe.is_quarantined_for_connector(target_type, name, connector)
        if connector
        else pe.is_quarantined(target_type, name)
    )
    if include_quarantine and quarantined:
        reason = _action_reason(action_entry, default="quarantined")
        return _done(AdmissionDecision("rejected", f"quarantined: {reason}", source="quarantine"))

    policy = compile_admission(config, target_type)

    # F-0742: callers evaluating untrusted-provenance inventory rows (e.g. a
    # ``source: user`` AIBOM entry) pass ``allow_first_party=False`` so the
    # first-party allow list cannot bless an operator/third-party asset that
    # merely lands under a first-party provenance directory.
    fp_constraints = policy.first_party_allow.get(name)
    if allow_first_party and fp_constraints and policy.allow_list_bypass_scan:
        if _matches_provenance(fp_constraints, source_path):
            return _done(AdmissionDecision(
                "allowed", f"{target_type} '{name}' is on the allow list — scan skipped", source="policy-allow",
            ))

    if scan_result is None:
        if not policy.scan_on_install:
            return _done(AdmissionDecision(
                "allowed",
                "scan_on_install disabled — allowed without scan",
                source="scan-disabled",
            ))
        return _done(AdmissionDecision("scan", "scan required", source="scan-required"))

    finding_count, severity = _scan_summary(scan_result)
    action, allow = effective_action_for(policy, severity=severity, scanner=_scanner_name(scan_result))

    if finding_count <= 0:
        return _done(AdmissionDecision("clean", "scan clean", action=_WARN, source="scan-clean"))

    detail = f"{finding_count} {'finding' if finding_count == 1 else 'findings'}, max {severity}"
    if action.install == "block" or action.runtime == "disable":
        return _done(AdmissionDecision("rejected", detail, action=action, source="scan-rejected"))
    if allow:
        return _done(AdmissionDecision("allowed", detail, action=action, source="scan-allowed"))
    return _done(AdmissionDecision("warning", detail, action=action, source="scan-warning"))


def _legacy_allow_decision(
    pe: Any, target_type: str, name: str, connector: str, source_path: str, allowed_reason: str,
) -> AdmissionDecision | None:
    """The Secure Client allow read from the actions table, unchanged."""
    if not (
        pe.is_allowed_for_connector(target_type, name, connector)
        if connector
        else pe.is_allowed(target_type, name)
    ):
        return None
    # An allow registered with a source_path must not auto-allow a different
    # on-disk asset that shares the name; an empty presented path cannot
    # prove it is the pinned asset either (F-0401).
    existing = _effective_action_entry(pe, target_type, name, connector)
    existing_path = getattr(existing, "source_path", None) if existing else None
    if existing_path and existing_path != source_path:
        presented = source_path or "(no source path presented)"
        return AdmissionDecision(
            "rejected",
            (
                f"allow entry for {target_type} '{name}' is pinned to "
                f"{existing_path!r}, but the presented asset is at "
                f"{presented!r} — failing closed"
            ),
            source="manual-allow-path-mismatch",
        )
    return AdmissionDecision("allowed", allowed_reason, source="manual-allow")


def _scanner_name(scan_result: Any) -> str:
    if isinstance(scan_result, dict):
        return str(scan_result.get("scanner_name") or scan_result.get("scanner") or "")
    return str(getattr(scan_result, "scanner", "") or "")


def evaluate_asset_policy(
    asset_policy: Any | None,
    *,
    target_type: str,
    name: str,
    connector: str = "",
    source_path: str = "",
    url: str = "",
    command: str = "",
    args: list[str] | None = None,
    transport: str = "",
    runtime_surface: str = "cli",
) -> AdmissionDecision:
    # The explicit operator lists apply in every mode, as the audit.db
    # actions rows they replace did (config_version 9).
    from defenseclaw.enforce import asset_lists

    verdict, rule = asset_lists.list_decision(
        asset_policy, target_type, name, connector,
        source_path=source_path, url=url, command=command, args=args or [], transport=transport,
    )
    if verdict == asset_lists.LIST_DENY:
        reason = getattr(rule, "reason", "") or f"{target_type} {name!r} is denied by asset policy"
        return AdmissionDecision("blocked", reason, source="asset-policy-deny")
    if verdict == asset_lists.LIST_ALLOW:
        reason = getattr(rule, "reason", "") or f"{target_type} {name!r} is explicitly allowed"
        return AdmissionDecision("allowed", reason, source="asset-policy-allow")

    if not getattr(asset_policy, "enabled", False):
        return AdmissionDecision("allowed", "asset policy disabled", source="asset-policy-disabled")

    # Per-connector resolution (OTHER-7): prefer the AssetPolicyConfig
    # resolvers so a connector with an override gets its own scalar settings
    # (default / registry_required / registry_empty_action) and mode. Stay
    # duck-typed — callers/tests that pass a bare object without the resolvers
    # fall back to the global per-type policy and global mode, which is the
    # legacy behavior and also exactly what the resolvers return when no
    # per-connector override is configured.
    type_resolver = getattr(asset_policy, "effective_asset_type_policy", None)
    if callable(type_resolver):
        policy = type_resolver(connector, target_type)
    else:
        policy = getattr(asset_policy, target_type, None)
    if policy is None:
        return AdmissionDecision("allowed", "asset policy unsupported target", source="asset-policy-unsupported")

    mode_resolver = getattr(asset_policy, "effective_mode", None)
    if callable(mode_resolver):
        mode = mode_resolver(connector)
    else:
        mode = getattr(asset_policy, "mode", "observe")

    rule_args = args or []
    registry = getattr(policy, "registry", [])
    # F-1906: registry membership for MCP servers is the gate that lets a
    # command actually run, so it must be matched strictly. The loose match
    # (command BASENAME + argv PREFIX) let an attacker register a benign basename
    # like ``npx`` and then run ``/tmp/evil/npx`` with extra trailing argv while
    # still "matching" the registry rule. Compare the full command and require an
    # exact argv match for the MCP registry. Denied/allowed rules keep the looser
    # semantics so an over-broad *block* still fires.
    registered = _find_asset_rule(
        registry,
        name,
        connector,
        source_path,
        url,
        command,
        rule_args,
        transport,
        strict=(target_type == "mcp"),
    ) is not None
    if registry and registered:
        return AdmissionDecision("allowed", f"{target_type} {name!r} is registered", source="asset-policy-registry")

    if getattr(policy, "registry_required", False):
        # Split "registry configured but unmatched" from "registry empty",
        # mirroring the Go gateway (internal/config/asset_policy.go
        # EvaluateAssetPolicy): a *configured* (non-empty) registry that does
        # not list this asset is always a hard "not approved" block.
        if registry:
            return _asset_policy_block_or_observe(
                mode,
                f"{target_type} {name!r} is not in the approved registry",
                "asset-policy-registry-required",
            )
        # Registry required but empty → governed by registry_empty_action.
        # Only "deny" blocks; "warn"/"allow" fall through to the default check
        # below. The Go gateway now resolves "warn" the same way (warn → allow),
        # so this matches the runtime (see _normalize_registry_empty_action).
        if _normalize_registry_empty_action(
            getattr(policy, "registry_empty_action", "deny")
        ) == "deny":
            return _asset_policy_block_or_observe(
                mode,
                f"{target_type} {name!r} is blocked because asset policy "
                f"requires a registry but none is configured",
                "asset-policy-registry-required-empty",
            )

    if str(getattr(policy, "default", "allow")).strip().lower() in {"deny", "block"}:
        return _asset_policy_block_or_observe(
            mode,
            f"{target_type} {name!r} is denied by default asset policy",
            "asset-policy-default-deny",
        )

    return AdmissionDecision(
        "allowed",
        f"{target_type} {name!r} allowed by default asset policy",
        source="asset-policy-default-allow",
    )


def _asset_policy_block_or_observe(mode: Any, reason: str, source: str) -> AdmissionDecision:
    """Block in action mode, observe (allow + ``-observe`` source) otherwise.

    ``mode`` is the already-resolved effective mode for the connector (see
    OTHER-7 per-connector resolution in :func:`evaluate_asset_policy`), not
    the AssetPolicyConfig object — so a connector overriding ``mode: action``
    blocks while one inheriting ``observe`` only flags would-block.
    """
    if str(mode).strip().lower() == "action":
        return AdmissionDecision("blocked", reason, source=source)
    return AdmissionDecision("allowed", reason, source=source + "-observe")


def _normalize_registry_empty_action(value: Any) -> str:
    """Canonicalize registry_empty_action for an empty-but-required registry.

    Returns one of ``"deny"`` / ``"warn"`` / ``"allow"`` (the three values
    documented on ``config.AssetTypePolicy.registry_empty_action``). Only
    ``"deny"`` blocks; both ``"warn"`` and ``"allow"`` fall through to the
    default check. ``"deny"``/``"block"``/``""`` and any unrecognised value
    stay fail-closed as ``"deny"``.

    Python↔Go parity: the Go gateway's ``normalizeRegistryEmptyAction``
    (internal/config/asset_policy.go) now also treats ``"warn"`` as
    fall-through (warn → allow), so both sides agree that ``"warn"`` is
    "log-but-don't-block at the empty-registry gate". The earlier divergence
    (Go collapsing ``"warn"`` into ``"deny"``) is closed.
    """
    v = str(value).strip().lower()
    if v == "allow":
        return "allow"
    if v == "warn":
        return "warn"
    return "deny"


def _find_asset_rule(
    rules: list[Any],
    name: str,
    connector: str,
    source_path: str,
    url: str,
    command: str,
    args: list[str],
    transport: str,
    *,
    strict: bool = False,
    connector_scope: str | None = None,
) -> Any | None:
    for rule in rules:
        rule_connector = str(getattr(rule, "connector", "") or "").strip()
        if connector_scope == "scoped":
            if not rule_connector:
                continue
            if connector_paths.normalize(rule_connector) != connector_paths.normalize(connector):
                continue
        elif connector_scope == "global" and rule_connector:
            continue
        if _asset_rule_matches(
            rule, name, connector, source_path, url, command, args, transport, strict=strict
        ):
            return rule
    return None


def _effective_action_entry(
    pe: Any,
    target_type: str,
    name: str,
    connector: str = "",
) -> Any | None:
    if not hasattr(pe, "get_action"):
        return None
    if connector:
        try:
            scoped = pe.get_action(target_type, name, connector)
        except TypeError:
            scoped = None
        if scoped is not None and getattr(getattr(scoped, "actions", None), "install", ""):
            return scoped
    return pe.get_action(target_type, name)


_HTTP_TRANSPORT_NAMES = frozenset({"http", "streamable-http", "streamable_http", "streamablehttp"})


def _canonical_mcp_transport(transport: Any, url: str = "", command: str = "") -> str:
    """Fold the names of one MCP transport together (GAP-2122).

    ``http`` and ``streamable-http`` are the same HTTP transport for a URL
    server, so a registry rule pinned to either admits the other. An empty
    transport takes the one the server's shape implies (``http`` for a URL,
    ``stdio`` for a command), as ``mcp set --url`` without ``--transport``
    does. ``sse`` and the other transports stay distinct. Mirrors the Go
    ``canonicalMCPTransport``.
    """
    value = str(transport or "").strip().lower()
    if value in _HTTP_TRANSPORT_NAMES:
        return "http"
    if not value:
        if str(url or "").strip():
            return "http"
        if str(command or "").strip():
            return "stdio"
    return value


def _asset_rule_matches(
    rule: Any,
    name: str,
    connector: str,
    source_path: str,
    url: str,
    command: str,
    args: list[str],
    transport: str,
    *,
    strict: bool = False,
) -> bool:
    constrained = False
    if getattr(rule, "name", ""):
        constrained = True
        if str(rule.name).strip().lower() != name.strip().lower():
            return False
    if getattr(rule, "connector", ""):
        constrained = True
        # Compare connector-name-insensitively (case + hyphen/underscore
        # aliases) so an asset rule keyed on a documented alias such as
        # "open-hands" still matches the registry-canonical active connector
        # "openhands". A literal lower-case compare silently failed to fire
        # the rule, letting a server through that policy meant to block.
        if connector_paths.normalize(str(rule.connector)) != connector_paths.normalize(connector):
            return False
    if getattr(rule, "url", ""):
        constrained = True
        if str(rule.url).strip() != url.strip():
            return False
    if getattr(rule, "command", ""):
        constrained = True
        # F-1906: a basename-only compare lets ``/tmp/evil/npx`` satisfy a rule
        # pinned to ``npx``. Under strict matching (MCP registry membership) the
        # FULL command string must match so a substituted absolute path cannot
        # impersonate a registered binary. Denied/allowed rules stay basename-
        # based so an operator can broadly block by binary name.
        if strict:
            if str(rule.command).strip() != command.strip():
                return False
        elif os.path.basename(str(rule.command).strip()) != os.path.basename(command.strip()):
            return False
    prefix = getattr(rule, "args_prefix", []) or []
    if prefix:
        constrained = True
        # F-1906: an argv *prefix* match lets an attacker append trailing args
        # (e.g. a second server spec or ``--allow-everything``) while still
        # matching a registry rule. Under strict matching require an EXACT argv
        # match — no extra trailing arguments — so the registered command line
        # is the only one admitted.
        if strict:
            if len(args) != len(prefix):
                return False
        elif len(args) < len(prefix):
            return False
        for idx, want in enumerate(prefix):
            if str(want).strip() != str(args[idx]).strip():
                return False
    elif strict and args:
        # A strict registry rule that pins a command but specifies no argv must
        # only admit the bare command — reject any presented arguments rather
        # than ignoring them (which would let trailing argv slip through).
        if getattr(rule, "command", ""):
            constrained = True
            return False
    if getattr(rule, "transport", ""):
        constrained = True
        if _canonical_mcp_transport(rule.transport) != _canonical_mcp_transport(transport, url, command):
            return False
    needles = getattr(rule, "source_path_contains", []) or []
    if needles:
        constrained = True
        normalized = source_path.replace("\\", "/").lower()
        if not any(str(needle).replace("\\", "/").lower() in normalized for needle in needles):
            return False
    return constrained


def effective_action_for(
    policy: CompiledAdmission,
    *,
    severity: str,
    scanner: str = "",
) -> tuple[SeverityAction, bool]:
    """The scanner override, then the severity action, then fail closed
    (admission.rego ``_effective_action``)."""
    sev = severity.upper()
    override = policy.scanner_overrides.get(scanner, {})
    if sev in override:
        return override[sev]
    if sev in policy.actions:
        return policy.actions[sev]
    return _FAIL_CLOSED


def _scan_summary(scan_result: Any) -> tuple[int, str]:
    if hasattr(scan_result, "findings") and hasattr(scan_result, "max_severity"):
        findings = getattr(scan_result, "findings", []) or []
        return len(findings), str(scan_result.max_severity())

    if isinstance(scan_result, dict):
        count = scan_result.get("total_findings")
        if count is None:
            count = scan_result.get("finding_count", 0)
        severity = scan_result.get("max_severity", "INFO")
        return int(count or 0), str(severity)

    return 0, "INFO"


# F-0141: a first-party provenance marker is only trustworthy when it lives
# under a DefenseClaw/agent-framework *home* the attacker cannot create siblings
# in without already owning that home. These are the leaf directory names of the
# per-connector or shared agent-framework homes. A marker run must be anchored
# to one of these (either the marker begins with a home, or the component
# immediately preceding the matched run is a home) so a user-writable parent
# that merely *contains* the component subsequence — e.g.
# ``/tmp/attacker/extensions/defenseclaw`` — does NOT bless the asset.
_DEFENSECLAW_HOME_COMPONENTS = frozenset(
    {
        ".defenseclaw",
        ".openclaw",
        ".zeptoclaw",
        ".claude",
        ".codex",
    }
)
_AMP_HOME_PREFIX = (".config", "amp")


def _matches_amp_user_home(
    source_path: str,
    constraint_parts: list[str],
) -> bool:
    """Match an Amp first-party marker only at the resolved user-home path."""

    if tuple(constraint_parts[: len(_AMP_HOME_PREFIX)]) != _AMP_HOME_PREFIX:
        return False
    expanded_home = os.path.expanduser("~")
    if expanded_home == "~":
        return False
    resolved_home = os.path.realpath(expanded_home)
    resolved_source = os.path.realpath(os.path.expanduser(source_path))
    expected_source = os.path.realpath(os.path.join(resolved_home, *constraint_parts))
    try:
        common_path = os.path.commonpath((resolved_home, resolved_source))
    except ValueError:
        return False
    if os.path.normcase(common_path) != os.path.normcase(resolved_home):
        return False
    return os.path.normcase(resolved_source) == os.path.normcase(expected_source)


def _matches_provenance(constraints: list[str], source_path: str) -> bool:
    """True if no constraints exist, or if source_path is a path
    *component* match against one of them that is anchored to a
    DefenseClaw-owned home.

    The first iteration of this matcher compared each constraint with
    ``in normalised``, a substring test over the whole path string, which
    accepted attacker paths whose components incidentally embedded the
    constraint (``/tmp/user/.defenseclaw-evil/defenseclaw``). That was
    tightened to a contiguous full-*component* match, but that alone still
    accepted a user-writable parent that merely *contained* the component
    subsequence: a bare marker like ``extensions/defenseclaw`` matched
    ``/tmp/attacker/extensions/defenseclaw`` anywhere in the tree.

    F-0141 anchors the match to a DefenseClaw-owned home: the matched run
    must either start with a known home component (e.g.
    ``.openclaw/extensions/defenseclaw``) or be immediately preceded in the
    source path by one (so a marker leaf is only honored under a real home).
    A location an unprivileged principal controls — which by definition does
    not contain a DefenseClaw home as the anchoring parent — cannot match.
    """
    if not constraints:
        return True
    if not source_path:
        return False
    normalised = source_path.replace("\\", "/").lower()
    components = [c for c in normalised.split("/") if c]
    for raw in constraints:
        constraint = raw.replace("\\", "/").lower().strip("/")
        if not constraint:
            continue
        constraint_parts = [p for p in constraint.split("/") if p]
        if not constraint_parts:
            continue
        # Match constraint as a contiguous run of full path
        # components in the source path.
        clen = len(constraint_parts)
        for i in range(len(components) - clen + 1):
            if components[i : i + clen] != constraint_parts:
                continue
            # F-0141: the run must be anchored to a DefenseClaw-owned home —
            # either the constraint itself begins with one, or the component
            # directly above the matched run is one. Otherwise an attacker
            # parent (``/tmp/attacker/extensions/defenseclaw``) would match.
            if constraint_parts[0] in _DEFENSECLAW_HOME_COMPONENTS:
                return True
            # Amp's config home does not have a unique top-level component:
            # trusting the suffix ``.config/amp`` would bless the same marker
            # under an attacker path. Require its exact canonical location
            # beneath the current user's resolved home.
            if _matches_amp_user_home(source_path, constraint_parts):
                return True
            if i > 0 and components[i - 1] in _DEFENSECLAW_HOME_COMPONENTS:
                return True
    return False


def _action_reason(action_entry: Any | None, *, default: str) -> str:
    reason = getattr(action_entry, "reason", "") if action_entry is not None else ""
    return reason or default
