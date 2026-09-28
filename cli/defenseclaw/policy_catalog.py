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
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import yaml

from defenseclaw.paths import bundled_guardrail_profiles_dir, bundled_policies_dir

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
    replaces_webhooks: bool
    sets_cisco: bool

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
        replaces_webhooks="webhooks" in data,
        sets_cisco="cisco_ai_defense" in data,
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


def _data_json_candidates(policy_dir: str | os.PathLike[str] | None) -> list[str]:
    out: list[str] = []
    if policy_dir:
        out.append(os.path.join(os.fspath(policy_dir), "rego", "data.json"))
    bundled = _bundled_dir()
    if bundled:
        out.append(os.path.join(bundled, "rego", "data.json"))
    return out


def active_policy_name(policy_dir: str | os.PathLike[str] | None) -> str:
    """Return ``config.policy_name`` from the OPA data.json ("" if unknown).

    Reads ``<policy_dir>/rego/data.json`` (where ``policy activate`` writes),
    falling back to the bundled copy — the same order the CLI always used.
    """
    for candidate in _data_json_candidates(policy_dir):
        if not os.path.isfile(candidate):
            continue
        try:
            with open(candidate, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError, UnicodeDecodeError):
            continue
        cfg = data.get("config") if isinstance(data, dict) else None
        name = cfg.get("policy_name") if isinstance(cfg, dict) else None
        return name if isinstance(name, str) else ""
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


def _summaries(policy_dir: str | os.PathLike[str] | None) -> list[PolicySummary]:
    active = active_policy_name(policy_dir)
    loaded: list[tuple[str, dict[str, Any], str, bool]] = []
    for stem, (path, is_bundled) in sorted(_policy_sources(policy_dir).items()):
        data = load_policy_yaml(path)
        if data is None or not is_named_policy(data):
            continue
        loaded.append((stem, data, path, is_bundled))
    stems = {stem for stem, *_ in loaded}
    out: list[PolicySummary] = []
    for stem, data, path, is_bundled in loaded:
        if stem == active:
            is_active = True
        elif active and active not in stems:
            # data.json records the policy's ``name:`` field, which may
            # differ from its file name.
            is_active = data.get("name") == active
        else:
            is_active = False
        out.append(
            summarize_policy(
                stem,
                data,
                path=path,
                builtin=is_bundled and stem in BUILTIN_POLICY_NAMES,
                active=bool(active) and is_active,
            )
        )
    return out


def list_named_policies(policy_dir: str | os.PathLike[str] | None) -> list[PolicySummary]:
    """All named policies (user dir + bundled), sorted by name, active marked."""
    return _summaries(policy_dir)


def _safe_policy_name(name: str) -> bool:
    return bool(name) and os.path.basename(name) == name and ".." not in name and "/" not in name and "\\" not in name


def get_policy(name: str, policy_dir: str | os.PathLike[str] | None) -> PolicySummary | None:
    """Return the named policy's summary, or ``None`` if absent / not a policy."""
    if not isinstance(name, str) or not _safe_policy_name(name):
        return None
    for summary in _summaries(policy_dir):
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


def _policy_root(cfg: Any) -> str:
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
    root = _policy_root(cfg)
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
    root = _policy_root(cfg)
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
    base = os.path.basename(os.path.normpath(path)) if path else ""
    return (base or path), "custom"


def looks_like_rule_pack(path: str) -> bool:
    """True when *path* is a directory containing a recognized pack file."""
    if not path or not os.path.isdir(path):
        return False
    return any(os.path.exists(os.path.join(path, marker)) for marker in _PACK_MARKERS)


def _guardrail(cfg: Any) -> Any:
    return getattr(cfg, "guardrail", None)


def global_pack(cfg: Any) -> ConnectorPack:
    """The pack connectors without an override enforce (connector="global")."""
    gc = _guardrail(cfg)
    configured = normalize_pack_path(str(getattr(gc, "rule_pack_dir", "") or ""))
    if configured:
        name, _ = pack_name_for_path(cfg, configured)
        return ConnectorPack(connector="global", pack=name, path=configured, source="global")
    return ConnectorPack(
        connector="global",
        pack="default",
        path=preset_pack_dir(cfg, "default"),
        source="default",
    )


def _override_dir(gc: Any, connector: str) -> str:
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
        return normalize_pack_path(str(getattr(block, "rule_pack_dir", "") or ""))
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
        override = _override_dir(gc, connector)
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

    root = _policy_root(cfg)
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

    configured = [normalize_pack_path(str(getattr(gc, "rule_pack_dir", "") or ""))]
    for connector in sorted((getattr(gc, "connectors", None) or {}).keys()):
        configured.append(_override_dir(gc, connector))
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


__all__ = [
    "BUILTIN_POLICY_NAMES",
    "RULE_PACK_PRESETS",
    "SEVERITIES",
    "ConnectorPack",
    "PolicySummary",
    "RulePack",
    "active_policy_name",
    "discover_rule_packs",
    "effective_packs",
    "get_policy",
    "global_pack",
    "is_named_policy",
    "list_named_policies",
    "load_policy_yaml",
    "looks_like_rule_pack",
    "normalize_pack_path",
    "pack_name_for_path",
    "policy_file",
    "preset_pack_dir",
    "summarize_policy",
    "threshold_label",
]
