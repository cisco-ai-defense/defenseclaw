"""Shared admission evaluation helpers for Python CLI paths.

These helpers intentionally mirror the admission ordering used by the Go
gateway/watcher:

1. Explicit block list entries override everything.
2. Asset policy can block denied/unregistered/default-denied assets.
3. Explicit allow list entries skip scan/enforcement after asset policy.
4. Policy-managed allow entries (for example first-party bundles) may bypass
   scan depending on the active policy data.
5. If no scan result exists yet, the active policy decides whether scanning is
   required.
6. Once a scan result exists, the effective per-target action mapping decides
   whether the result is rejected or only warned.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any

from defenseclaw import connector_paths
from defenseclaw.config import SeverityAction


@dataclass(frozen=True)
class AdmissionDecision:
    verdict: str
    reason: str
    action: SeverityAction = field(default_factory=SeverityAction)
    source: str = ""


@dataclass(frozen=True)
class AdmissionPolicyData:
    allow_list_bypass_scan: bool = True
    scan_on_install: bool = True
    actions: dict[str, SeverityAction] = field(default_factory=dict)
    scanner_overrides: dict[str, dict[str, SeverityAction]] = field(default_factory=dict)
    first_party_allow: dict[tuple[str, str], tuple[str, list[str]]] = field(default_factory=dict)


def _default_admission_policy() -> AdmissionPolicyData:
    return AdmissionPolicyData(
        allow_list_bypass_scan=True,
        scan_on_install=True,
        actions={
            "CRITICAL": SeverityAction(file="quarantine", runtime="disable", install="block"),
            "HIGH": SeverityAction(file="quarantine", runtime="disable", install="block"),
            "MEDIUM": SeverityAction(file="none", runtime="enable", install="none"),
            "LOW": SeverityAction(file="none", runtime="enable", install="none"),
            "INFO": SeverityAction(file="none", runtime="enable", install="none"),
        },
        scanner_overrides={
            "mcp": {
                "MEDIUM": SeverityAction(file="quarantine", runtime="disable", install="block"),
                "LOW": SeverityAction(file="none", runtime="disable", install="none"),
            },
            "plugin": {
                "HIGH": SeverityAction(file="quarantine", runtime="disable", install="block"),
                "MEDIUM": SeverityAction(file="none", runtime="enable", install="none"),
            },
        },
        first_party_allow={
            # F-0541: provenance markers must be specific to the first-party
            # asset's own directory, not a broad parent like ``.defenseclaw``
            # or ``.openclaw/extensions`` that any sibling plugin/skill could
            # be dropped into. Each marker pins the asset's leaf component.
            #
            # F-0902: markers must also be home-anchored, not bare relative
            # sequences ("extensions/defenseclaw") — a bare marker blesses any
            # attacker path that merely contains the subsequence
            # (``/tmp/attacker/extensions/defenseclaw``). ``_matches_provenance``
            # anchors the match defensively, but these built-in defaults are
            # kept home-anchored too so they mirror the bundled policy data
            # (policies/{default,strict,permissive}.yaml + rego/data.json) and
            # never rely solely on the matcher.
            ("plugin", "defenseclaw"): (
                "first-party DefenseClaw plugin",
                [
                    ".openclaw/extensions/defenseclaw",
                    ".zeptoclaw/extensions/defenseclaw",
                    ".claude/extensions/defenseclaw",
                    ".codex/extensions/defenseclaw",
                ],
            ),
            ("skill", "codeguard"): (
                "first-party DefenseClaw skill",
                [
                    ".openclaw/workspace/skills/codeguard",
                    ".openclaw/skills/codeguard",
                    ".zeptoclaw/skills/codeguard",
                    ".claude/skills/codeguard",
                    ".codex/skills/codeguard",
                ],
            ),
        },
    )


def evaluate_admission(
    pe: Any,
    *,
    policy_dir: str,
    target_type: str,
    name: str,
    source_path: str = "",
    connector: str = "",
    url: str = "",
    command: str = "",
    args: list[str] | None = None,
    transport: str = "",
    runtime_surface: str = "cli",
    asset_policy: Any | None = None,
    scan_result: Any | None = None,
    action_entry: Any | None = None,
    fallback_actions: Any | None = None,
    include_quarantine: bool = False,
    allow_first_party: bool = True,
) -> AdmissionDecision:
    """Evaluate admission for a target using active policy data when available.

    Explicit block entries always win. Explicit allow entries skip scanning
    after asset policy has had a chance to enforce admin deny/default-deny
    controls. Policy-managed allow entries from ``first_party_allow_list`` are
    still subject to the policy's ``allow_list_bypass_scan`` setting.
    """
    blocked_reason = _action_reason(action_entry, default=f"{target_type} '{name}' is on the block list")
    # N2: honor a per-connector block at the admission gate. When a connector is
    # in play, resolve most-specific-wins (connector-scoped entry, else global)
    # via the *_for_connector engine method; the bare (global) path keeps the
    # pre-N2 call so duck-typed callers/fakes without the connector dimension are
    # unaffected (connector="" is equivalent to the global check anyway).
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

    allowed_reason = _action_reason(action_entry, default=f"{target_type} '{name}' is on the allow list — scan skipped")
    if (
        pe.is_allowed_for_connector(target_type, name, connector)
        if connector
        else pe.is_allowed(target_type, name)
    ):
        # an explicit operator allow that
        # was registered with a source_path MUST NOT auto-allow a
        # different on-disk asset just because it shares the
        # registered name. Look up the stored entry and compare its
        # source_path to the current source_path. If they differ
        # we drop the allow and force a fresh scan/decision rather
        # than honoring a name-only match. When the stored entry
        # has no source_path (legacy allow) we keep current
        # behavior to avoid breaking pre-fix entries; operators can
        # re-allow with a path to opt into the strict mode.
        #
        # F-0401: when the allow IS path-pinned but the current request
        # presents no source_path (empty/missing provenance, e.g. a
        # non-local plugin/MCP pre-scan admission), we must NOT honor the
        # pin as a match. An empty presented path cannot prove it is the
        # pinned asset, so treat it as a mismatch and fail closed instead
        # of falling through to an allow.
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

    quarantined = (
        pe.is_quarantined_for_connector(target_type, name, connector)
        if connector
        else pe.is_quarantined(target_type, name)
    )
    if include_quarantine and quarantined:
        reason = _action_reason(action_entry, default="quarantined")
        return AdmissionDecision("rejected", f"quarantined: {reason}", source="quarantine")

    policy = load_admission_policy(policy_dir)

    # F-0742: callers evaluating untrusted-provenance inventory rows (e.g. a
    # ``source: user`` AIBOM entry) pass ``allow_first_party=False`` so the
    # first-party allow list cannot bless an operator/third-party asset that
    # merely lands under a first-party provenance directory.
    fp_entry = policy.first_party_allow.get((target_type, name))
    if allow_first_party and fp_entry is not None and policy.allow_list_bypass_scan:
        fp_reason, fp_constraints = fp_entry
        if _matches_provenance(fp_constraints, source_path):
            return AdmissionDecision("allowed", fp_reason, source="policy-allow")

    if scan_result is None:
        if not policy.scan_on_install:
            return AdmissionDecision(
                "allowed",
                "scan_on_install disabled — allowed without scan",
                source="scan-disabled",
            )
        return AdmissionDecision("scan", "scan required", source="scan-required")

    finding_count, severity = _scan_summary(scan_result)
    action = effective_action_for(
        policy,
        target_type=target_type,
        severity=severity,
        fallback_actions=fallback_actions,
    )

    if finding_count <= 0:
        return AdmissionDecision("clean", "scan clean", action=action, source="scan-clean")

    detail = f"{finding_count} findings, max {severity}"
    if action.install == "block" or action.runtime == "disable":
        return AdmissionDecision("rejected", detail, action=action, source="scan-rejected")

    return AdmissionDecision("warning", detail, action=action, source="scan-warning")


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
    if rule := _find_asset_rule(
        getattr(policy, "denied", []),
        name,
        connector,
        source_path,
        url,
        command,
        rule_args,
        transport,
        connector_scope="scoped",
    ):
        reason = getattr(rule, "reason", "") or f"{target_type} {name!r} is denied by asset policy"
        return _asset_policy_block_or_observe(mode, reason, "asset-policy-deny")

    if rule := _find_asset_rule(
        getattr(policy, "allowed", []),
        name,
        connector,
        source_path,
        url,
        command,
        rule_args,
        transport,
        connector_scope="scoped",
    ):
        reason = getattr(rule, "reason", "") or f"{target_type} {name!r} is explicitly allowed"
        return AdmissionDecision("allowed", reason, source="asset-policy-allow")

    if rule := _find_asset_rule(
        getattr(policy, "denied", []),
        name,
        connector,
        source_path,
        url,
        command,
        rule_args,
        transport,
        connector_scope="global",
    ):
        reason = getattr(rule, "reason", "") or f"{target_type} {name!r} is denied by asset policy"
        return _asset_policy_block_or_observe(mode, reason, "asset-policy-deny")

    if rule := _find_asset_rule(
        getattr(policy, "allowed", []),
        name,
        connector,
        source_path,
        url,
        command,
        rule_args,
        transport,
        connector_scope="global",
    ):
        reason = getattr(rule, "reason", "") or f"{target_type} {name!r} is explicitly allowed"
        return AdmissionDecision("allowed", reason, source="asset-policy-allow")

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
        if str(rule.transport).strip().lower() != transport.strip().lower():
            return False
    needles = getattr(rule, "source_path_contains", []) or []
    if needles:
        constrained = True
        normalized = source_path.replace("\\", "/").lower()
        if not any(str(needle).replace("\\", "/").lower() in normalized for needle in needles):
            return False
    return constrained


def effective_action_for(
    policy: AdmissionPolicyData,
    *,
    target_type: str,
    severity: str,
    fallback_actions: Any | None = None,
) -> SeverityAction:
    sev = severity.upper()
    target_overrides = policy.scanner_overrides.get(target_type, {})
    if sev in target_overrides:
        return target_overrides[sev]
    if sev in policy.actions:
        return policy.actions[sev]
    if fallback_actions is not None:
        return fallback_actions.for_severity(sev)
    return SeverityAction()


def load_admission_policy(policy_dir: str) -> AdmissionPolicyData:
    data = _read_policy_data(policy_dir)
    if not data:
        return _default_admission_policy()

    defaults = _default_admission_policy()

    cfg = data.get("config", {}) or {}
    raw_actions = data.get("actions", {}) or {}
    raw_overrides = data.get("scanner_overrides", {}) or {}
    first_party = data.get("first_party_allow_list", []) or []

    actions = {
        severity.upper(): _severity_action_from_policy(raw)
        for severity, raw in raw_actions.items()
        if isinstance(raw, dict)
    }

    scanner_overrides: dict[str, dict[str, SeverityAction]] = {}
    for target_type, overrides in raw_overrides.items():
        if not isinstance(overrides, dict):
            continue
        scanner_overrides[target_type] = {
            severity.upper(): _severity_action_from_policy(raw)
            for severity, raw in overrides.items()
            if isinstance(raw, dict)
        }

    first_party_allow: dict[tuple[str, str], tuple[str, list[str]]] = dict(defaults.first_party_allow)
    for entry in first_party:
        if not isinstance(entry, dict):
            continue
        target_type = str(entry.get("target_type", ""))
        target_name = str(entry.get("target_name", ""))
        if target_type and target_name:
            reason = str(entry.get("reason", "first-party allow"))
            source_path_contains = entry.get("source_path_contains", [])
            if not isinstance(source_path_contains, list):
                source_path_contains = []
            first_party_allow[(target_type, target_name)] = (reason, source_path_contains)

    merged_actions = dict(defaults.actions)
    merged_actions.update(actions)

    merged_overrides = {
        target_type: dict(overrides)
        for target_type, overrides in defaults.scanner_overrides.items()
    }
    for target_type, overrides in scanner_overrides.items():
        merged_overrides.setdefault(target_type, {}).update(overrides)

    return AdmissionPolicyData(
        allow_list_bypass_scan=bool(cfg.get("allow_list_bypass_scan", defaults.allow_list_bypass_scan)),
        scan_on_install=bool(cfg.get("scan_on_install", defaults.scan_on_install)),
        actions=merged_actions,
        scanner_overrides=merged_overrides,
        first_party_allow=first_party_allow,
    )


def _severity_action_from_policy(raw: dict[str, Any]) -> SeverityAction:
    runtime = "disable" if raw.get("runtime", "allow") == "block" else "enable"
    return SeverityAction(
        file=str(raw.get("file", "none")),
        runtime=runtime,
        install=str(raw.get("install", "none")),
    )


def _read_policy_data(policy_dir: str) -> dict[str, Any] | None:
    for candidate in _policy_data_candidates(policy_dir):
        try:
            with open(candidate) as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(data, dict):
            return data
    return None


def _policy_data_candidates(policy_dir: str) -> list[str]:
    candidates: list[str] = []
    if policy_dir:
        candidates.append(os.path.join(policy_dir, "rego", "data.json"))
        candidates.append(os.path.join(policy_dir, "data.json"))
    return candidates


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
# per-connector homes (mirrors ``connector_paths.connector_home``). A marker run
# must be anchored to one of these (either the marker begins with a home, or the
# component immediately preceding the matched run is a home) so a user-writable
# parent that merely *contains* the component subsequence — e.g.
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
            if i > 0 and components[i - 1] in _DEFENSECLAW_HOME_COMPONENTS:
                return True
    return False


def _action_reason(action_entry: Any | None, *, default: str) -> str:
    reason = getattr(action_entry, "reason", "") if action_entry is not None else ""
    return reason or default
