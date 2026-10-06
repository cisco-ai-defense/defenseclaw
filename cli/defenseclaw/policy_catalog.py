# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""Read-only catalog of named security policies and guardrail rule packs.

Shared by ``defenseclaw policy`` / ``defenseclaw guardrail`` and the TUI.
Pure: no Click, no network, no writes. Every loader tolerates missing or
malformed files — a single bad YAML file is skipped, never raised to the
caller.

Besides named policies and rule packs it describes the opt-in protection
packs (``policies/guardrail-use-cases/``), the rule families of a pack, the
fixed bounded tool-call chains (``tool-chains.json``) and the posture of
every guardrail scope (global + each active connector), including the
tool-call block and alert levels it resolves to (:func:`resolve_levels`, the
gateway's ``guardrail.block_at`` / ``alert_at`` precedence and clamp).
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import yaml

from defenseclaw.paths import (
    bundled_guardrail_profiles_dir,
    bundled_guardrail_use_cases_dir,
    bundled_policies_dir,
    bundled_tool_chains_file,
)

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

#: Names of the policies that ship with DefenseClaw.
BUILTIN_POLICY_NAMES = ("default", "strict", "permissive")

#: Built-in guardrail rule-pack presets.
RULE_PACK_PRESETS = ("default", "strict", "permissive")

# guardrail.rego ``severity_rank``: CRITICAL=4 HIGH=3 MEDIUM=2 LOW=1.
_RANK_LABELS = {4: "CRITICAL", 3: "HIGH+", 2: "MEDIUM+", 1: "LOW+"}
_SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

# Top-level keys that only a named security policy carries.
_POLICY_KEYS = frozenset(
    {
        "admission",
        "skill_actions",
        "guardrail",
        "scanner_overrides",
        "first_party_allow_list",
        "enforcement",
    }
)
# Top-level keys of the host egress-firewall template
# (policies/firewall-deny-default.yaml).
_FIREWALL_TEMPLATE_KEYS = frozenset({"rules", "default_action", "allowlist"})

# Files/directories that mark a directory as a guardrail rule pack.
_PACK_MARKERS = ("rules", "judge", "sensitive-tools.yaml", "suppressions.yaml")


# ---------------------------------------------------------------------------
# Named policies
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PolicySummary:
    name: str
    description: str
    builtin: bool
    active: bool
    path: str
    block_at: str
    alert_at: str
    install_block_at: str
    firewall_default: str
    hilt: bool | None
    scanner_overrides: int
    adds_webhooks: bool
    sets_cisco: bool
    # A built-in name served from the user policy dir: ``policy edit`` saved
    # a copy that shadows the bundled file (``policy delete`` reverts it).
    edited: bool = False

    def to_json(self) -> dict[str, object]:
        return asdict(self)


def is_named_policy(data: Mapping[str, object]) -> bool:
    """True when *data* looks like a named security policy.

    Rejects the host egress-firewall template (top-level ``rules`` /
    ``default_action`` / ``allowlist`` without any policy section) and any
    non-mapping document.
    """
    if not isinstance(data, Mapping):
        return False
    keys = set(data.keys())
    if keys & _POLICY_KEYS:
        return True
    if keys & _FIREWALL_TEMPLATE_KEYS:
        return False
    name = data.get("name")
    return isinstance(name, str) and bool(name.strip())


def load_policy_yaml(path: str | os.PathLike[str]) -> dict[str, Any] | None:
    """Load a policy YAML file; ``None`` when unreadable or not a mapping."""
    try:
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except (OSError, yaml.YAMLError, UnicodeDecodeError, ValueError):
        return None
    if data is None:
        return {}
    return data if isinstance(data, dict) else None


def threshold_label(value: object) -> str:
    """Map a guardrail severity-rank threshold to the display scale."""
    rank: int | None = None
    if isinstance(value, bool):
        rank = None
    elif isinstance(value, int):
        rank = value
    elif isinstance(value, float) and value.is_integer():
        rank = int(value)
    elif isinstance(value, str):
        text = value.strip().upper()
        if text.isdigit():
            rank = int(text)
        else:
            rank = _SEVERITY_RANK.get(text)
    if rank is None:
        return "none"
    return _RANK_LABELS.get(rank, "none")


def _install_block_at(actions: object) -> str:
    if not isinstance(actions, Mapping):
        return "none"
    lowest = ""
    # Walk from CRITICAL down; the last severity that blocks installs wins.
    for sev in SEVERITIES:
        raw = actions.get(sev.lower())
        if raw is None:
            raw = actions.get(sev)
        if isinstance(raw, Mapping) and str(raw.get("install", "")).strip().lower() == "block":
            lowest = sev
    if not lowest:
        return "none"
    return lowest if lowest == "CRITICAL" else f"{lowest}+"


def _hilt(guardrail: Mapping[str, Any]) -> bool | None:
    raw = guardrail.get("hilt")
    if raw is None:
        raw = guardrail.get("hitl")
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, Mapping):
        enabled = raw.get("enabled")
        return enabled if isinstance(enabled, bool) else None
    return None


def _scanner_override_count(raw: object) -> int:
    if not isinstance(raw, Mapping):
        return 0
    return sum(len(sevs) for sevs in raw.values() if isinstance(sevs, Mapping))


def summarize_policy(
    name: str,
    data: Mapping[str, Any],
    *,
    path: str,
    builtin: bool,
    active: bool,
    edited: bool = False,
) -> PolicySummary:
    """Build a :class:`PolicySummary` from an already-loaded policy mapping."""
    guardrail = data.get("guardrail")
    if not isinstance(guardrail, Mapping):
        guardrail = {}
    firewall = data.get("firewall")
    fw_default = ""
    if isinstance(firewall, Mapping):
        candidate = str(firewall.get("default_action", "") or "").strip().lower()
        if candidate in ("deny", "allow"):
            fw_default = candidate
    desc = data.get("description")
    return PolicySummary(
        name=name,
        description=desc.strip() if isinstance(desc, str) else "",
        builtin=builtin,
        active=active,
        path=path,
        block_at=threshold_label(guardrail.get("block_threshold")),
        alert_at=threshold_label(guardrail.get("alert_threshold")),
        install_block_at=_install_block_at(data.get("skill_actions")),
        firewall_default=fw_default,
        hilt=_hilt(guardrail),
        scanner_overrides=_scanner_override_count(data.get("scanner_overrides")),
        adds_webhooks=isinstance(data.get("webhooks"), list) and bool(data.get("webhooks")),
        sets_cisco="cisco_ai_defense" in data,
        edited=edited,
    )


def _bundled_dir() -> str:
    try:
        return str(bundled_policies_dir())
    except Exception:  # noqa: BLE001 — packaging edge cases must not raise.
        return ""


def _yaml_files(directory: str) -> dict[str, str]:
    out: dict[str, str] = {}
    if not directory or not os.path.isdir(directory):
        return out
    try:
        names = os.listdir(directory)
    except OSError:
        return out
    for fname in names:
        if not fname.endswith(".yaml") or fname.startswith("."):
            continue
        full = os.path.join(directory, fname)
        if os.path.isfile(full):
            out[fname[: -len(".yaml")]] = full
    return out


def _is_within(path: str, directory: str) -> bool:
    if not directory:
        return False
    try:
        real_path = os.path.realpath(path)
        real_dir = os.path.realpath(directory)
    except OSError:
        return False
    return real_path == real_dir or real_path.startswith(real_dir + os.sep)


def active_policy_name(policy_dir: str | os.PathLike[str] | None, cfg: Any = None) -> str:
    """The named policy ``cfg`` runs ("" when none matches or there is no config).

    Since config_version 9 a named policy is a preset: ``policy activate``
    writes its admission, guardrail levels and Cisco trust level as config
    keys and records nothing else, so the active policy is the one whose
    values the config holds now. A config that sets none of them runs the
    shipped defaults, which is the ``default`` policy.
    """
    if cfg is None or getattr(cfg, "guardrail", None) is None:
        return ""
    import copy

    from defenseclaw.commands.cmd_policy import _admission_from_policy, _apply_policy_guardrail
    from defenseclaw.config import AdmissionConfig

    def keys(config: Any) -> tuple[Any, ...]:
        g = config.guardrail
        trust = str(getattr(g, "cisco_trust_level", "") or "").strip() or "full"
        return (
            getattr(config, "admission", None),
            level_value(getattr(g, "block_at", "")),
            level_value(getattr(g, "alert_at", "")),
            trust,
        )

    current = keys(cfg)
    sources = _policy_sources(policy_dir)
    if current == (AdmissionConfig(), "", "", "full") and "default" in sources:
        return "default"
    for stem, (path, _bundled) in sorted(sources.items()):
        data = load_policy_yaml(path)
        if data is None or not is_named_policy(data):
            continue
        preset = copy.copy(cfg)
        preset.guardrail = copy.copy(cfg.guardrail)
        preset.admission = _admission_from_policy(data)
        _apply_policy_guardrail(preset, data)
        if keys(preset) == current:
            return stem
    return ""


def _policy_sources(policy_dir: str | os.PathLike[str] | None) -> dict[str, tuple[str, bool]]:
    """Map policy stem -> (path, is_bundled). User files shadow bundled ones."""
    bundled = _bundled_dir()
    sources: dict[str, tuple[str, bool]] = {}
    for stem, path in _yaml_files(bundled).items():
        sources[stem] = (path, True)
    user_dir = os.fspath(policy_dir) if policy_dir else ""
    if user_dir and not (bundled and _is_within(user_dir, bundled)):
        for stem, path in _yaml_files(user_dir).items():
            sources[stem] = (path, False)
    return sources


def _summaries(policy_dir: str | os.PathLike[str] | None, cfg: Any = None) -> list[PolicySummary]:
    active = active_policy_name(policy_dir, cfg)
    loaded: list[tuple[str, dict[str, Any], str, bool]] = []
    for stem, (path, is_bundled) in sorted(_policy_sources(policy_dir).items()):
        data = load_policy_yaml(path)
        if data is None or not is_named_policy(data):
            continue
        loaded.append((stem, data, path, is_bundled))
    bundled_stems = set(_yaml_files(_bundled_dir()))
    out: list[PolicySummary] = []
    for stem, data, path, is_bundled in loaded:
        is_active = stem == active
        out.append(
            summarize_policy(
                stem,
                data,
                path=path,
                builtin=stem in BUILTIN_POLICY_NAMES and stem in bundled_stems,
                active=bool(active) and is_active,
                edited=not is_bundled and stem in BUILTIN_POLICY_NAMES and stem in bundled_stems,
            )
        )
    return out


def list_named_policies(policy_dir: str | os.PathLike[str] | None, cfg: Any = None) -> list[PolicySummary]:
    """All named policies (user dir + bundled), sorted by name, the one
    ``cfg`` runs marked active."""
    return _summaries(policy_dir, cfg)


def _safe_policy_name(name: str) -> bool:
    return bool(name) and os.path.basename(name) == name and ".." not in name and "/" not in name and "\\" not in name


def get_policy(name: str, policy_dir: str | os.PathLike[str] | None, cfg: Any = None) -> PolicySummary | None:
    """Return the named policy's summary, or ``None`` if absent / not a policy."""
    if not isinstance(name, str) or not _safe_policy_name(name):
        return None
    for summary in _summaries(policy_dir, cfg):
        if summary.name == name:
            return summary
    return None


def policy_file(name: str, policy_dir: str | os.PathLike[str] | None) -> str | None:
    """Path of ``<name>.yaml`` (user dir first, then bundled), policy or not."""
    if not isinstance(name, str) or not _safe_policy_name(name):
        return None
    entry = _policy_sources(policy_dir).get(name)
    return entry[0] if entry else None


# ---------------------------------------------------------------------------
# Guardrail rule packs
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RulePack:
    name: str
    path: str
    kind: str  # "preset" | "custom"
    used_by: tuple[str, ...]

    def to_json(self) -> dict[str, object]:
        return {"name": self.name, "path": self.path, "kind": self.kind, "used_by": list(self.used_by)}


@dataclass(frozen=True)
class ConnectorPack:
    connector: str
    pack: str
    path: str
    source: str  # "global" | "override" | "default"

    def to_json(self) -> dict[str, object]:
        return asdict(self)


def policy_root(cfg: Any) -> str:
    """The policy folder: ``policy_dir``, else ``<data_dir>/policies`` ("" without either)."""
    root = str(getattr(cfg, "policy_dir", "") or "").strip()
    if root:
        return os.path.expanduser(root)
    data_dir = str(getattr(cfg, "data_dir", "") or "").strip()
    return os.path.join(os.path.expanduser(data_dir), "policies") if data_dir else ""


def preset_pack_dir(cfg: Any, preset: str) -> str:
    """Directory for a built-in preset.

    ``<policy_dir>/guardrail/<preset>`` (seeded by ``init``) when it exists,
    else the bundled copy, else the seeded location (so the caller can report
    the path the gateway will look at).
    """
    root = policy_root(cfg)
    seeded = os.path.join(root, "guardrail", preset) if root else ""
    if seeded and os.path.isdir(seeded):
        return seeded
    try:
        bundled_root = bundled_guardrail_profiles_dir()
    except Exception:  # noqa: BLE001
        bundled_root = None
    if bundled_root is not None:
        bundled = Path(bundled_root) / preset
        if bundled.is_dir():
            return str(bundled)
    return seeded


def normalize_pack_path(path: str) -> str:
    """Absolute, user-expanded form of a configured rule-pack dir."""
    raw = (path or "").strip()
    if not raw:
        return ""
    return os.path.abspath(os.path.expanduser(raw))


def _same_path(a: str, b: str) -> bool:
    if not a or not b:
        return False
    try:
        return os.path.realpath(a) == os.path.realpath(b)
    except OSError:
        return os.path.normpath(a) == os.path.normpath(b)


def _preset_candidates(cfg: Any, preset: str) -> list[str]:
    out: list[str] = []
    root = policy_root(cfg)
    if root:
        out.append(os.path.join(root, "guardrail", preset))
    try:
        bundled_root = bundled_guardrail_profiles_dir()
    except Exception:  # noqa: BLE001
        bundled_root = None
    if bundled_root is not None:
        out.append(str(Path(bundled_root) / preset))
    return out


def pack_name_for_path(cfg: Any, path: str) -> tuple[str, str]:
    """Return ``(name, kind)`` for a rule-pack directory."""
    for preset in RULE_PACK_PRESETS:
        if any(_same_path(path, cand) for cand in _preset_candidates(cfg, preset)):
            return preset, "preset"
    if is_protected_pack_path(path):
        # protected-<scope>/<profile>: name it after the scope folder.
        return os.path.basename(os.path.dirname(os.path.normpath(path))), "custom"
    base = os.path.basename(os.path.normpath(path)) if path else ""
    return (base or path), "custom"


def looks_like_rule_pack(path: str) -> bool:
    """True when *path* is a directory containing a recognized pack file."""
    if not path or not os.path.isdir(path):
        return False
    return any(os.path.exists(os.path.join(path, marker)) for marker in _PACK_MARKERS)


def _guardrail(cfg: Any) -> Any:
    return getattr(cfg, "guardrail", None)


def configured_pack_dir(cfg: Any, block: Any) -> str:
    """The directory a guardrail scope block selects, "" when it selects none.

    ``rule_pack`` (a preset name or a ``guardrail.custom_packs`` key) wins
    over the v8 ``rule_pack_dir`` at the same scope, as in the gateway
    (``config.ResolveRulePackDir``).
    """
    if block is None:
        return ""
    name = str(getattr(block, "rule_pack", "") or "").strip()
    if name:
        custom = (getattr(_guardrail(cfg), "custom_packs", None) or {}).get(name)
        if custom is not None:
            return normalize_pack_path(str(getattr(custom, "path", "") or ""))
        if name in RULE_PACK_PRESETS:
            return preset_pack_dir(cfg, name)
        return ""
    return normalize_pack_path(str(getattr(block, "rule_pack_dir", "") or ""))


def global_pack(cfg: Any) -> ConnectorPack:
    """The pack connectors without an override enforce (connector="global")."""
    gc = _guardrail(cfg)
    configured = configured_pack_dir(cfg, gc)
    if configured:
        name, _ = pack_name_for_path(cfg, configured)
        return ConnectorPack(connector="global", pack=name, path=configured, source="global")
    return ConnectorPack(
        connector="global",
        pack="default",
        path=preset_pack_dir(cfg, "default"),
        source="default",
    )


def _override_dir(gc: Any, connector: str, cfg: Any = None) -> str:
    getter = getattr(gc, "_connector_override", None)
    block = None
    if callable(getter):
        try:
            block = getter(connector)
        except Exception:  # noqa: BLE001
            block = None
    if block is None:
        connectors = getattr(gc, "connectors", None)
        block = connectors.get(connector) if isinstance(connectors, Mapping) else None
    if block is not None:
        return configured_pack_dir(cfg, block)
    if callable(getter) or not callable(getattr(gc, "effective_rule_pack_dir", None)):
        return ""
    # Duck-typed configs that only expose the effective resolver: anything
    # that differs from the global dir is a per-connector override.
    try:
        effective = normalize_pack_path(str(gc.effective_rule_pack_dir(connector) or ""))
    except Exception:  # noqa: BLE001
        return ""
    global_dir = normalize_pack_path(str(getattr(gc, "rule_pack_dir", "") or ""))
    return effective if effective and effective != global_dir else ""


def _active_connectors(cfg: Any) -> list[str]:
    fn = getattr(cfg, "active_connectors", None)
    if not callable(fn):
        return []
    try:
        return [str(c) for c in fn()]
    except Exception:  # noqa: BLE001
        return []


def effective_packs(cfg: Any) -> list[ConnectorPack]:
    """One row per active connector: the pack it actually enforces."""
    gc = _guardrail(cfg)
    fallback = global_pack(cfg)
    out: list[ConnectorPack] = []
    for connector in _active_connectors(cfg):
        override = _override_dir(gc, connector, cfg)
        if override:
            name, _ = pack_name_for_path(cfg, override)
            out.append(ConnectorPack(connector=connector, pack=name, path=override, source="override"))
        else:
            out.append(
                ConnectorPack(connector=connector, pack=fallback.pack, path=fallback.path, source=fallback.source)
            )
    return out


def discover_rule_packs(cfg: Any) -> list[RulePack]:
    """Presets, on-disk packs under ``<policy_dir>/guardrail/`` and configured dirs."""
    gc = _guardrail(cfg)
    users: list[tuple[str, str]] = [("global", global_pack(cfg).path)]
    users.extend((row.connector, row.path) for row in effective_packs(cfg))

    entries: list[tuple[str, str, str]] = []  # (name, path, kind)

    def _add(name: str, path: str, kind: str) -> None:
        if any(_same_path(path, existing) or path == existing for _, existing, _ in entries):
            return
        entries.append((name, path, kind))

    for preset in RULE_PACK_PRESETS:
        _add(preset, preset_pack_dir(cfg, preset), "preset")

    root = policy_root(cfg)
    guardrail_root = os.path.join(root, "guardrail") if root else ""
    if guardrail_root and os.path.isdir(guardrail_root):
        try:
            children = sorted(os.listdir(guardrail_root))
        except OSError:
            children = []
        for child in children:
            if child.startswith("."):
                continue
            full = os.path.join(guardrail_root, child)
            if child in RULE_PACK_PRESETS or not looks_like_rule_pack(full):
                continue
            _add(child, full, "custom")

    configured = [configured_pack_dir(cfg, gc)]
    for connector in sorted((getattr(gc, "connectors", None) or {}).keys()):
        configured.append(_override_dir(gc, connector, cfg))
    for path in configured:
        if not path:
            continue
        name, kind = pack_name_for_path(cfg, path)
        _add(name, path, kind)

    out: list[RulePack] = []
    for name, path, kind in entries:
        used_by = tuple(who for who, used in users if _same_path(used, path) or used == path)
        out.append(RulePack(name=name, path=path, kind=kind, used_by=used_by))
    return out


# ---------------------------------------------------------------------------
# Opt-in protection packs (policies/guardrail-use-cases/<name>/)
# ---------------------------------------------------------------------------

#: File a composed ``protected-<scope>`` pack records its base and layered
#: protection packs in. The Go loader only inventories ``*.yaml`` files, so a
#: JSON manifest inside a pack directory is ignored there.
PROTECTION_MANIFEST = "defenseclaw-pack.json"

#: Directory-name prefix of the packs ``guardrail protection`` composes.
PROTECTED_PACK_PREFIX = "protected-"

# The C loader is ~15x faster on the 90 KB commands.yaml; same semantics.
_YAML_LOADER = getattr(yaml, "CSafeLoader", yaml.SafeLoader)

# Display order: the deterministic-detection reference's pack table.
_PROTECTION_ORDER = (
    "privacy-high-assurance",
    "cloud-production-protection",
    "database-destruction-protection",
    "infrastructure-destruction-protection",
    "kubernetes-production-protection",
    "ssh-authorized-keys-protection",
)

#: Short "what it covers" phrase per pack for a table cell (<= 40 chars).
_PROTECTION_COVERS = {
    "privacy-high-assurance": "SSNs, payment cards, IBANs, medical IDs",
    "cloud-production-protection": "Cloud data, resource and audit deletion",
    "database-destruction-protection": "Unbounded SQL deletes and schema drops",
    "infrastructure-destruction-protection": "Disk wipes, IaC destroy, kernel binds",
    "kubernetes-production-protection": "Secret reads, namespace and bulk deletes",
    "ssh-authorized-keys-protection": "Unapproved SSH authorized_keys writes",
}
COVERS_MAX_CHARS = 40

# Fields two rules must share for a pack to count as layered into a pack
# directory that has no manifest (Policy Creator ``equivalentRule``).
_EQUIVALENT_RULE_FIELDS = ("pattern", "expression", "tool_call_only", "title", "severity", "confidence", "tags")


@dataclass(frozen=True)
class PackRule:
    id: str
    severity: str
    title: str

    def to_json(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class ProtectionPack:
    name: str
    title: str
    summary: str
    covers: str  # short phrase for a table cell (<= 40 chars)
    rule_count: int
    rule_ids: tuple[str, ...]
    status: str  # "selectable" | "staged"
    rules: tuple[PackRule, ...] = ()

    @property
    def selectable(self) -> bool:
        return self.status == "selectable"

    def to_json(self) -> dict[str, object]:
        return {
            "name": self.name,
            "title": self.title,
            "summary": self.summary,
            "covers": self.covers,
            "rule_count": self.rule_count,
            "rule_ids": list(self.rule_ids),
            "status": self.status,
            "rules": [rule.to_json() for rule in self.rules],
        }


@dataclass(frozen=True)
class ProtectionManifest:
    base: str
    base_name: str
    protection: tuple[str, ...]


def _load_yaml_mapping(path: str | os.PathLike[str]) -> dict[str, Any] | None:
    try:
        with open(path, encoding="utf-8") as fh:
            data = yaml.load(fh, Loader=_YAML_LOADER)  # a SafeLoader (C or pure Python)
    except (OSError, yaml.YAMLError, UnicodeDecodeError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _rule_file_names(pack_dir: str) -> list[str]:
    """Sorted ``rules/*.yaml`` names the Go loader reads as rule files."""
    rules_dir = os.path.join(pack_dir, "rules") if pack_dir else ""
    if not rules_dir or not os.path.isdir(rules_dir):
        return []
    try:
        names = os.listdir(rules_dir)
    except OSError:
        return []
    return sorted(
        name
        for name in names
        if name.endswith(".yaml")
        and name != "local-patterns.yaml"
        and not name.startswith(".")
        and os.path.isfile(os.path.join(rules_dir, name))
    )


def load_rule_files(pack_dir: str) -> list[tuple[str, dict[str, Any]]]:
    """``(filename, mapping)`` for every parseable rule file of a pack.

    Only mappings with a ``rules:`` list count; unreadable files are skipped.
    """
    out: list[tuple[str, dict[str, Any]]] = []
    for name in _rule_file_names(pack_dir):
        data = _load_yaml_mapping(os.path.join(pack_dir, "rules", name))
        if data is not None and isinstance(data.get("rules"), list):
            out.append((name, data))
    return out


def _rule_entries(data: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    return [rule for rule in data.get("rules") or [] if isinstance(rule, Mapping)]


def _rule_id(rule: Mapping[str, Any]) -> str:
    raw = rule.get("id")
    return raw.strip() if isinstance(raw, str) else ""


def _rule_enabled(rule: Mapping[str, Any]) -> bool:
    return rule.get("enabled") is not False


def _readme_title_summary(readme: str, fallback: str) -> tuple[str, str]:
    """First ``# heading`` and first paragraph, like the docs asset builder."""
    title = ""
    body: list[str] = []
    for line in readme.splitlines():
        if not title and line.startswith("# "):
            title = line[2:].strip()
            continue
        body.append(line)
    paragraph: list[str] = []
    for line in body:
        if line.strip():
            if line.lstrip().startswith("#") and not paragraph:
                continue  # a sub-heading before the first paragraph
            paragraph.append(line.strip())
        elif paragraph:
            break
    return (title or fallback), " ".join(" ".join(paragraph).split())


def _covers_for(name: str, title: str) -> str:
    covers = _PROTECTION_COVERS.get(name) or title
    if len(covers) > COVERS_MAX_CHARS:
        covers = covers[: COVERS_MAX_CHARS - 1].rstrip() + "…"
    return covers


def protection_packs_dir() -> str:
    """Bundled use-case pack root (``_data`` in a wheel, repo in a checkout)."""
    try:
        root = bundled_guardrail_use_cases_dir()
    except Exception:  # noqa: BLE001 — packaging edge cases must not raise.
        root = None
    return str(root) if root is not None else ""


def _protection_sort_key(pack: ProtectionPack) -> tuple[int, int, str]:
    try:
        index = _PROTECTION_ORDER.index(pack.name)
    except ValueError:
        index = len(_PROTECTION_ORDER)
    return (0 if pack.selectable else 1, index, pack.name)


def protection_packs(root: str | os.PathLike[str] | None = None) -> list[ProtectionPack]:
    """The opt-in protection packs, selectable first then staged.

    A pack is ``selectable`` when its ``rules/*.yaml`` declare at least one
    rule, otherwise ``staged`` (a contract that can't be enabled yet).
    """
    base = os.fspath(root) if root is not None else protection_packs_dir()
    if not base or not os.path.isdir(base):
        return []
    try:
        children = sorted(os.listdir(base))
    except OSError:
        return []
    out: list[ProtectionPack] = []
    for name in children:
        pack_dir = os.path.join(base, name)
        if name.startswith(".") or not os.path.isdir(pack_dir):
            continue
        readme = ""
        try:
            with open(os.path.join(pack_dir, "README.md"), encoding="utf-8") as fh:
                readme = fh.read()
        except (OSError, UnicodeDecodeError):
            readme = ""
        title, summary = _readme_title_summary(readme, name)
        rules: list[PackRule] = []
        for _fname, data in load_rule_files(pack_dir):
            for rule in _rule_entries(data):
                rule_id = _rule_id(rule)
                if not rule_id:
                    continue
                rules.append(
                    PackRule(
                        id=rule_id,
                        severity=str(rule.get("severity") or "").strip().upper(),
                        title=str(rule.get("title") or "").strip(),
                    )
                )
        out.append(
            ProtectionPack(
                name=name,
                title=title,
                summary=summary,
                covers=_covers_for(name, title),
                rule_count=len(rules),
                rule_ids=tuple(rule.id for rule in rules),
                status="selectable" if rules else "staged",
                rules=tuple(rules),
            )
        )
    out.sort(key=_protection_sort_key)
    return out


#: Posture profiles the gateway derives from a rule-pack folder's name.
PACK_PROFILES = ("default", "strict", "permissive")


def pack_profile(path: str) -> str:
    """The posture profile the gateway gives a rule-pack directory.

    Mirrors ``packPosture`` in internal/gateway/thresholds.go: the
    ``posture`` of the pack's ``defenseclaw-pack.json`` manifest when it
    names one, else the folder's base name (``strict`` and ``permissive``
    keep theirs, every other name reads as ``default``).
    """
    raw = (path or "").strip().rstrip("/\\")
    if not raw:
        return "default"
    try:
        with open(os.path.join(raw, PROTECTION_MANIFEST), encoding="utf-8") as fh:
            manifest = json.load(fh)
    except (OSError, ValueError, UnicodeDecodeError):
        manifest = None
    posture = manifest.get("posture") if isinstance(manifest, dict) else None
    if isinstance(posture, str) and posture.strip().lower() in PACK_PROFILES:
        return posture.strip().lower()
    base = os.path.basename(os.path.normpath(raw)).lower()
    return base if base in {"strict", "permissive"} else "default"


def is_protected_pack_path(path: str) -> bool:
    """True for a ``protected-<scope>/<profile>`` folder ``guardrail protection`` composes."""
    if not path:
        return False
    norm = os.path.normpath(path)
    return os.path.basename(os.path.dirname(norm)).startswith(PROTECTED_PACK_PREFIX) and (
        os.path.basename(norm) in PACK_PROFILES
    )


def protection_pack_dir(name: str, root: str | os.PathLike[str] | None = None) -> str:
    """Directory of the named use-case pack ("" when unknown or unsafe)."""
    if not isinstance(name, str) or not _safe_policy_name(name):
        return ""
    base = os.fspath(root) if root is not None else protection_packs_dir()
    candidate = os.path.join(base, name) if base else ""
    return candidate if candidate and os.path.isdir(candidate) else ""


def read_protection_manifest(pack_dir: str) -> ProtectionManifest | None:
    """The ``defenseclaw-pack.json`` of a composed pack, or ``None``."""
    if not pack_dir:
        return None
    try:
        with open(os.path.join(pack_dir, PROTECTION_MANIFEST), encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError, UnicodeDecodeError):
        return None
    if not isinstance(data, dict) or data.get("version") != 1:
        return None
    base = data.get("base")
    names = data.get("protection")
    if not isinstance(base, str) or not base.strip() or not isinstance(names, list):
        return None
    base_name = data.get("base_name")
    return ProtectionManifest(
        base=base,
        base_name=base_name if isinstance(base_name, str) else "",
        protection=tuple(n for n in names if isinstance(n, str) and n),
    )


def _equivalent_rule(current: Mapping[str, Any] | None, wanted: Mapping[str, Any]) -> bool:
    if current is None or not _rule_enabled(current):
        return False
    return all(current.get(field) == wanted.get(field) for field in _EQUIVALENT_RULE_FIELDS)


def _bundled_default_pack_dir() -> str:
    return preset_pack_dir(None, "default")


def _pack_rules_by_id(pack_dir: str) -> dict[str, Mapping[str, Any]]:
    out: dict[str, Mapping[str, Any]] = {}
    for _fname, data in load_rule_files(pack_dir):
        for rule in _rule_entries(data):
            rule_id = _rule_id(rule)
            if rule_id:
                out[rule_id] = rule
    return out


def _raw_rule_text(pack_dir: str) -> str:
    chunks: list[str] = []
    for name in _rule_file_names(pack_dir):
        try:
            with open(os.path.join(pack_dir, "rules", name), encoding="utf-8") as fh:
                chunks.append(fh.read())
        except (OSError, UnicodeDecodeError):
            continue
    return "\n".join(chunks)


def packs_layered_in(pack_dir: str, packs: list[ProtectionPack] | None = None) -> tuple[str, ...]:
    """Selectable packs whose every rule is present, enabled and unchanged.

    Rule-id match with Policy Creator's equivalence check, for pack dirs that
    carry no manifest (e.g. a Policy Creator export).
    """
    packs = protection_packs() if packs is None else packs
    selectable = [p for p in packs if p.selectable and p.rule_ids]
    if not selectable or not pack_dir:
        return ()
    # Cheap pre-check: skip the YAML parse unless some pack's ids all appear.
    blob = _raw_rule_text(pack_dir)
    candidates = [p for p in selectable if all(rule_id in blob for rule_id in p.rule_ids)]
    if not candidates:
        return ()
    present = _pack_rules_by_id(pack_dir)
    root = protection_packs_dir()
    out: list[str] = []
    for pack in candidates:
        source = protection_pack_dir(pack.name, root or None)
        wanted = _pack_rules_by_id(source) if source else {}
        if wanted and all(_equivalent_rule(present.get(rule_id), wanted.get(rule_id, {})) for rule_id in pack.rule_ids):
            out.append(pack.name)
    return tuple(out)


def enabled_protection(pack_dir: str) -> tuple[str, ...]:
    """Opt-in pack names layered into *pack_dir* ("" = bundled default).

    The manifest of a composed pack wins; otherwise every selectable pack
    whose rules are all present (and unchanged) counts. Catalog order.
    """
    path = pack_dir or _bundled_default_pack_dir()
    packs = protection_packs()
    order = {pack.name: index for index, pack in enumerate(packs) if pack.selectable}
    manifest = read_protection_manifest(path)
    if manifest is not None:
        names = {name for name in manifest.protection if name in order}
        return tuple(sorted(names, key=lambda name: order[name]))
    return packs_layered_in(path, packs)


# ---------------------------------------------------------------------------
# Rule families (the ``category:`` of each rules/*.yaml)
# ---------------------------------------------------------------------------

#: What each built-in family catches (deterministic-detection.mdx table).
_FAMILY_DESCRIPTIONS = {
    "command": (
        "Execution, reverse shells, destructive storage operations, persistence, privilege changes, "
        "credential access, security-control tampering, cloud, database, Kubernetes, and "
        "source-control effects"
    ),
    "sensitive-path": (
        "Reads or writes involving SSH, cloud, Kubernetes, container, package-manager, Git, "
        "environment, browser-session, workload-identity, history, shell-profile, hook, and "
        "runtime-socket paths"
    ),
    "secret": (
        "Provider credentials, API tokens, private keys, JWTs, authenticated connection strings, "
        "bearer tokens, and high-confidence secret assignments"
    ),
    "trust-exploit": (
        "Instruction override, authority impersonation, jailbreak, prompt extraction, persona "
        "manipulation, delimiter abuse, and obfuscation signals"
    ),
    "c2": "Known exfiltration endpoints, cloud metadata SSRF forms, DNS tunneling, and DNS exfiltration indicators",
    "enterprise-data": "Structured payment, banking, contact, medical, birth-date, CSV, and JSON PII shapes",
    "cognitive-file": "Agent instruction, memory, configuration, gateway, and detector-state modification",
}
_FAMILY_ORDER = tuple(_FAMILY_DESCRIPTIONS)


@dataclass(frozen=True)
class RuleFamily:
    name: str
    rules: int
    enabled: int
    description: str

    def to_json(self) -> dict[str, object]:
        return asdict(self)


def _family_counts(pack_dir: str) -> list[tuple[str, int, int]]:
    """``(category, declared, enabled)`` per rule file, in Go load order."""
    out: list[tuple[str, int, int]] = []
    for _fname, data in load_rule_files(pack_dir):
        category = data.get("category")
        if not isinstance(category, str) or not category.strip():
            continue
        rules = _rule_entries(data)
        out.append((category.strip(), len(rules), sum(1 for rule in rules if _rule_enabled(rule))))
    return out


def rule_families(pack_dir: str) -> list[RuleFamily]:
    """Rule families an effective pack enforces ("" = bundled default).

    Mirrors the gateway's overlay: the built-in (bundled default) families
    come first, and each rule file with at least one enabled rule replaces
    the family named by its ``category:`` or adds a new one. Built-in
    families keep the reference order; added ones follow in load order.
    """
    families: dict[str, tuple[int, int]] = {}
    default_dir = _bundled_default_pack_dir()
    for category, declared, enabled in _family_counts(default_dir):
        families[category] = (declared, enabled)
    if pack_dir and not _same_path(pack_dir, default_dir):
        for category, declared, enabled in _family_counts(pack_dir):
            if enabled:
                families[category] = (declared, enabled)

    opt_in: dict[str, str] = {}
    for pack in protection_packs():
        source = protection_pack_dir(pack.name)
        for _fname, data in load_rule_files(source) if source else []:
            category = data.get("category")
            if isinstance(category, str) and category.strip() not in _FAMILY_DESCRIPTIONS:
                opt_in.setdefault(category.strip(), f"Opt-in: {pack.covers}")

    def _key(item: tuple[str, tuple[int, int]]) -> int:
        name = item[0]
        return _FAMILY_ORDER.index(name) if name in _FAMILY_ORDER else len(_FAMILY_ORDER)

    ordered = sorted(families.items(), key=_key)  # stable: added families keep load order
    return [
        RuleFamily(
            name=name,
            rules=declared,
            enabled=enabled,
            description=_FAMILY_DESCRIPTIONS.get(name) or opt_in.get(name, ""),
        )
        for name, (declared, enabled) in ordered
    ]


# ---------------------------------------------------------------------------
# Fixed bounded tool-call chains (policies/guardrail/tool-chains.json)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ToolChain:
    id: str
    title: str
    severity: str
    domain: str
    can_block: bool
    event_window: int
    time_window_seconds: int
    requires: tuple[str, ...]
    note: str

    def to_json(self) -> dict[str, object]:
        out = asdict(self)
        out["requires"] = list(self.requires)
        return out


def _int_field(value: object) -> int:
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return max(value, 0)
    if isinstance(value, float) and value.is_integer():
        return max(int(value), 0)
    return 0


def _str_field(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


def tool_chains(path: str | os.PathLike[str] | None = None) -> list[ToolChain]:
    """The code-owned chain catalog in catalog order; ``[]`` when missing.

    Reads ``tool-chains.json`` (bundled ``_data`` copy in a wheel, the repo's
    ``policies/guardrail/`` in a checkout). Chains are not configurable.
    """
    if path is None:
        try:
            found = bundled_tool_chains_file()
        except Exception:  # noqa: BLE001 — packaging edge cases must not raise.
            found = None
        if found is None:
            return []
        path = found
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError, UnicodeDecodeError):
        return []
    if not isinstance(data, dict) or data.get("version") != 1 or not isinstance(data.get("chains"), list):
        return []
    out: list[ToolChain] = []
    for entry in data["chains"]:
        if not isinstance(entry, Mapping):
            continue
        chain_id = _str_field(entry.get("id"))
        if not chain_id:
            continue
        requires = entry.get("requires")
        out.append(
            ToolChain(
                id=chain_id,
                title=_str_field(entry.get("title")) or chain_id,
                severity=_str_field(entry.get("severity")).upper(),
                domain=_str_field(entry.get("domain")),
                can_block=entry.get("can_block") is True,
                event_window=_int_field(entry.get("event_window")),
                time_window_seconds=_int_field(entry.get("time_window_seconds")),
                requires=tuple(r.strip() for r in requires if isinstance(r, str) and r.strip())
                if isinstance(requires, list)
                else (),
                note=_str_field(entry.get("note")),
            )
        )
    return out


# ---------------------------------------------------------------------------
# Tool-call levels (guardrail.block_at / alert_at)
# ---------------------------------------------------------------------------

#: Values of ``guardrail.block_at`` / ``alert_at`` (global or per connector),
#: strongest first. Empty inherits.
LEVELS = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

#: Where a scope's tool-call level comes from, most specific first.
LEVEL_SOURCES = ("override", "global", "pack")

# (block rank, alert rank) of each rule-pack profile: decision.go
# ``guardrailProfileThresholds``.
_PROFILE_RANKS = {"strict": (2, 1), "permissive": (4, 3), "default": (4, 2)}


def level_value(value: object) -> str:
    """A stored ``block_at`` / ``alert_at`` as ``CRITICAL`` … ``LOW``.

    "" for inherit and for anything the gateway would ignore (it only
    honours the four levels, in any case).
    """
    text = str(value or "").strip().upper()
    return text if text in _SEVERITY_RANK else ""


def level_label(rank: int) -> str:
    """Severity rank → the catalog scale (4 → ``CRITICAL``, 3 → ``HIGH+`` …)."""
    return _RANK_LABELS.get(rank, "none")


def level_name(rank: int) -> str:
    """Severity rank → the stored level (4 → ``CRITICAL``, 3 → ``HIGH`` …; "" if unknown)."""
    return next((name for name, value in _SEVERITY_RANK.items() if value == rank), "")


@dataclass(frozen=True)
class ScopeLevels:
    """The tool-call block and alert levels one scope resolves to."""

    block_rank: int
    alert_rank: int  # already clamped to block_rank
    block_source: str  # "override" | "global" | "pack"
    alert_source: str
    wanted_alert_rank: int  # before the clamp

    @property
    def block_at(self) -> str:
        return level_label(self.block_rank)

    @property
    def alert_at(self) -> str:
        return level_label(self.alert_rank)

    @property
    def alert_clamped(self) -> bool:
        """The alert level was set above the block level and follows it down."""
        return self.wanted_alert_rank > self.alert_rank

    @property
    def source(self) -> str:
        """The more specific source of the two levels (override > global > pack)."""
        for source in ("override", "global"):
            if source in (self.block_source, self.alert_source):
                return source
        return "pack"


def resolve_levels(
    pack_path: str,
    global_levels: tuple[object, object] = ("", ""),
    connector_levels: tuple[object, object] | None = None,
) -> ScopeLevels:
    """Tool-call levels exactly as the gateway resolves them.

    Mirrors ``resolveThresholds`` in internal/gateway/thresholds.go, which
    every guardrail surface (prompts, completions, tool calls, the proxy)
    uses:
    block and alert each take the connector's own value
    (``connector_levels``, None for the global scope), else the global
    ``guardrail.block_at`` / ``alert_at`` (``global_levels``), else the level
    of the scope's rule-pack profile (:func:`pack_profile` of
    ``pack_path``). The alert rank is then clamped to the block rank:
    anything that blocks also alerts.
    """
    pack_block, pack_alert = _PROFILE_RANKS[pack_profile(pack_path)]

    def pick(index: int, pack_rank: int) -> tuple[int, str]:
        if connector_levels is not None:
            own = level_value(connector_levels[index])
            if own:
                return _SEVERITY_RANK[own], "override"
        shared = level_value(global_levels[index])
        if shared:
            return _SEVERITY_RANK[shared], "global"
        return pack_rank, "pack"

    block_rank, block_source = pick(0, pack_block)
    alert_rank, alert_source = pick(1, pack_alert)
    return ScopeLevels(
        block_rank=block_rank,
        alert_rank=min(alert_rank, block_rank),
        block_source=block_source,
        alert_source=alert_source,
        wanted_alert_rank=alert_rank,
    )


def _level_pair(block: Any) -> tuple[str, str]:
    """``(block_at, alert_at)`` stored on a guardrail block ("" when unset)."""
    if block is None:
        return "", ""
    return level_value(getattr(block, "block_at", "")), level_value(getattr(block, "alert_at", ""))


def scope_levels(cfg: Any, connector: str = "") -> ScopeLevels:
    """:func:`resolve_levels` for the global scope ("") or one active connector of *cfg*.

    An active (manually configured) connector's pack is its
    ``guardrail.connectors`` override, else the global pack, exactly as the
    gateway resolves it: the ``application_protection`` overlay pack only
    applies to connectors that are *not* active (``manualConnectorConfigured``
    in internal/config/application_protection.go), which no catalog scope is.
    """
    gc = _guardrail(cfg)
    path = scope_pack_path(cfg, connector)
    if not connector:
        return resolve_levels(path, _level_pair(gc))
    return resolve_levels(path, _level_pair(gc), _level_pair(_connector_block(gc, connector)))


def scope_pack_path(cfg: Any, connector: str = "") -> str:
    """The rule-pack directory the global scope ("") or an active connector enforces."""
    fallback = global_pack(cfg).path
    if not connector:
        return fallback
    return _override_dir(_guardrail(cfg), connector, cfg) or fallback


# ---------------------------------------------------------------------------
# Scope posture (global + each active connector)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ScopePosture:
    scope: str  # "global" or a connector name
    mode: str  # "observe" | "action"
    mode_source: str  # "global" | "override"
    hilt: str  # "off" | "CRITICAL" | "HIGH+" | "MEDIUM+" | "LOW+"
    pack: str
    pack_path: str
    pack_source: str  # ConnectorPack.source: "global" | "override" | "default"
    protection: tuple[str, ...]  # opt-in packs layered into the effective pack
    # Tool-call levels after guardrail.block_at / alert_at (see resolve_levels),
    # on the catalog scale: "CRITICAL" | "HIGH+" | "MEDIUM+" | "LOW+".
    block_at: str = ""
    alert_at: str = ""
    levels_source: str = "pack"  # "override" | "global" | "pack": the more specific of the two
    # The values set at this scope itself (the global ones on the global row):
    # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW", "" = inherits.
    own_block_at: str = ""
    own_alert_at: str = ""

    def to_json(self) -> dict[str, object]:
        out = asdict(self)
        out["protection"] = list(self.protection)
        return out


def mode_label(value: object) -> str:
    """``"action"`` or ``"observe"`` (anything else observes)."""
    return "action" if str(value or "").strip().lower() == "action" else "observe"


def hilt_label(hilt: object) -> str:
    """Human-approval posture: ``"off"`` or the lowest severity that asks."""
    if hilt is None or not bool(getattr(hilt, "enabled", False)):
        return "off"
    label = threshold_label(str(getattr(hilt, "min_severity", "") or "HIGH"))
    return "HIGH+" if label == "none" else label


def _connector_block(gc: Any, connector: str) -> Any:
    getter = getattr(gc, "_connector_override", None)
    if callable(getter):
        try:
            return getter(connector)
        except Exception:  # noqa: BLE001
            return None
    connectors = getattr(gc, "connectors", None)
    return connectors.get(connector) if isinstance(connectors, Mapping) else None


def configured_protection(block: Any) -> tuple[str, ...]:
    """``rules.protections`` of a guardrail scope block (global, connector or
    profile), in the order config.yaml lists them."""
    rules = getattr(block, "rules", None) if block is not None else None
    names = getattr(rules, "protections", None) if rules is not None else None
    return tuple(str(name) for name in (names or []) if str(name or "").strip())


def scope_postures(cfg: Any) -> list[ScopePosture]:
    """Posture of the global scope, then of every active connector.

    A scope's protection packs are its ``guardrail.rules.protections``
    (a connector also gets the global ones: the gateway layers them), plus
    any a v8 composed pack directory still records until the config is
    migrated to version 9.
    """
    gc = _guardrail(cfg)
    order = {pack.name: index for index, pack in enumerate(protection_packs())}
    memo: dict[str, tuple[str, ...]] = {}
    global_on = configured_protection(gc)

    def _protection(path: str, block: Any = None) -> tuple[str, ...]:
        key = os.path.realpath(path) if path else ""
        if key not in memo:
            memo[key] = enabled_protection(path)
        names = dict.fromkeys((*global_on, *configured_protection(block), *memo[key]))
        return tuple(sorted(names, key=lambda name: order.get(name, len(order))))

    fallback = global_pack(cfg)
    global_levels = _level_pair(gc)
    levels = resolve_levels(fallback.path, global_levels)
    out = [
        ScopePosture(
            scope="global",
            mode=mode_label(getattr(gc, "mode", "")),
            mode_source="global",
            hilt=hilt_label(getattr(gc, "hilt", None)),
            pack=fallback.pack,
            pack_path=fallback.path,
            pack_source=fallback.source,
            protection=_protection(fallback.path),
            block_at=levels.block_at,
            alert_at=levels.alert_at,
            levels_source=levels.source,
            own_block_at=global_levels[0],
            own_alert_at=global_levels[1],
        )
    ]
    for row in effective_packs(cfg):
        block = _connector_block(gc, row.connector)
        override_mode = str(getattr(block, "mode", "") or "").strip() if block is not None else ""
        effective_mode = getattr(gc, "effective_mode", None)
        mode = effective_mode(row.connector) if callable(effective_mode) else (override_mode or getattr(gc, "mode", ""))
        effective_hilt = getattr(gc, "effective_hilt", None)
        hilt = effective_hilt(row.connector) if callable(effective_hilt) else getattr(gc, "hilt", None)
        own_levels = _level_pair(block)
        levels = resolve_levels(row.path, global_levels, own_levels)
        out.append(
            ScopePosture(
                scope=row.connector,
                mode=mode_label(mode),
                mode_source="override" if override_mode else "global",
                hilt=hilt_label(hilt),
                pack=row.pack,
                pack_path=row.path,
                pack_source=row.source,
                protection=_protection(row.path, block),
                block_at=levels.block_at,
                alert_at=levels.alert_at,
                levels_source=levels.source,
                own_block_at=own_levels[0],
                own_alert_at=own_levels[1],
            )
        )
    return out


__all__ = [
    "BUILTIN_POLICY_NAMES",
    "COVERS_MAX_CHARS",
    "LEVELS",
    "LEVEL_SOURCES",
    "PACK_PROFILES",
    "PROTECTED_PACK_PREFIX",
    "PROTECTION_MANIFEST",
    "RULE_PACK_PRESETS",
    "SEVERITIES",
    "ConnectorPack",
    "PackRule",
    "PolicySummary",
    "ProtectionManifest",
    "ProtectionPack",
    "RuleFamily",
    "RulePack",
    "ScopeLevels",
    "ScopePosture",
    "ToolChain",
    "active_policy_name",
    "discover_rule_packs",
    "effective_packs",
    "configured_pack_dir",
    "configured_protection",
    "enabled_protection",
    "get_policy",
    "global_pack",
    "hilt_label",
    "is_named_policy",
    "level_label",
    "level_name",
    "level_value",
    "list_named_policies",
    "load_policy_yaml",
    "load_rule_files",
    "looks_like_rule_pack",
    "mode_label",
    "normalize_pack_path",
    "pack_name_for_path",
    "packs_layered_in",
    "policy_file",
    "preset_pack_dir",
    "is_protected_pack_path",
    "pack_profile",
    "policy_root",
    "protection_pack_dir",
    "protection_packs",
    "protection_packs_dir",
    "read_protection_manifest",
    "resolve_levels",
    "rule_families",
    "scope_levels",
    "scope_postures",
    "summarize_policy",
    "threshold_label",
    "tool_chains",
]
