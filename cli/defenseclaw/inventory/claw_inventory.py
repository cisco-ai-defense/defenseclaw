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

"""Build a live OpenClaw bill-of-materials by querying the ``openclaw`` CLI.

Indexes: Skills, Plugins, MCP servers, Agents/sub-agents, Rules, Tools, Model providers, Memory.

Commands are dispatched in parallel via ``ThreadPoolExecutor`` and deduplicated
(e.g. ``plugins list`` is fetched once even though three categories use it).
"""

from __future__ import annotations

import json
import os
import re
import stat
import subprocess
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, NamedTuple, TypedDict

import yaml

from defenseclaw import connector_paths
from defenseclaw.config import Config, SkillActionsConfig, _expand
from defenseclaw.file_permissions import open_regular_file_no_follow

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib

from defenseclaw.inventory.plugin_directories import (
    discover_exact_plugin_directory,
    discover_plugin_directories,
)
from defenseclaw.inventory.plugin_identity import (
    AmbiguousPluginIdentityError,
    filesystem_identity_key,
)
from defenseclaw.models import ActionEntry, Finding, ScanResult
from defenseclaw.safety import is_symlink

# v4 adds the top-level ``rules`` category and its summary/finding/render
# surface; consumers can distinguish it from the seven-category v3 schema.
INVENTORY_VERSION = 4

ALL_CATEGORIES: frozenset[str] = frozenset(
    ["skills", "plugins", "mcp", "agents", "rules", "tools", "models", "memory"]
)

_CATEGORY_ALIASES: dict[str, str] = {"model_providers": "models"}

_COMMANDS: dict[str, tuple[str, ...]] = {
    "skills_list": ("skills", "list"),
    "plugins_list": ("plugins", "list"),
    "mcp_list": ("mcp", "list"),
    "agents_list": ("agents", "list"),
    "config_agents": ("config", "get", "agents"),
    "models_status": ("models", "status"),
    "models_list": ("models", "list"),
    "memory_status": ("memory", "status"),
}

_CATEGORY_DEPS: dict[str, list[str]] = {
    "skills": ["skills_list"],
    "plugins": ["plugins_list"],
    "mcp": ["mcp_list"],
    "agents": ["agents_list", "config_agents"],
    "tools": ["plugins_list"],
    "models": ["models_status", "plugins_list", "models_list"],
    "memory": ["memory_status"],
}


class _CmdResult(NamedTuple):
    data: Any
    error: str | None
    command: str


class InventoryCapabilityStatus(str, Enum):
    """Machine-readable availability of an inventory surface."""

    UNSUPPORTED = "unsupported"
    UNVERIFIED = "unverified"


class InventoryLimitation(TypedDict):
    """Expected connector capability gap; never an attempted-operation error."""

    connector: str
    category: str
    status: InventoryCapabilityStatus
    reason: str


class _FilesystemCollectionResult(NamedTuple):
    items: list[dict[str, Any]]
    error: dict[str, str] | None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def build_claw_aibom(
    cfg: Config,
    *,
    live: bool = True,
    categories: set[str] | None = None,
    connector: str | None = None,
) -> dict[str, Any]:
    """Collect a connector-agnostic agent-framework inventory.

    Dispatches via :meth:`Config.active_connector` (or the explicit
    *connector* override used by multi-connector focus). For OpenClaw —
    the historical default — *live=True* shells out to ``openclaw …
    --json`` commands in parallel; for Codex / Claude Code / ZeptoClaw
    we walk the filesystem under :func:`connector_paths.skill_dirs`,
    :func:`connector_paths.plugin_dirs`, and
    :func:`connector_paths.mcp_servers`.

    *connector* targets a specific connector's inventory (the TUI focus
    selector and ``aibom scan --connector`` rely on this); defaults to
    the active connector so single-connector behaviour is unchanged.
    *categories* restricts which sections are collected (default: all).
    *live=False* always returns the disk-only shape (no subprocess
    calls, no filesystem walk).
    """
    cats = _resolve_categories(categories)
    connector = connector or cfg.active_connector()
    if connector != "openclaw" and live:
        return _build_aibom_from_filesystem(cfg, connector, cats)

    claw_home = cfg.claw_home_dir()
    now = datetime.now(timezone.utc).isoformat()

    if live:
        cache, errors = _fetch_all(_needed_commands(cats))
    else:
        cache, errors = {}, []

    out: dict[str, Any] = {
        "version": INVENTORY_VERSION,
        "generated_at": now,
        "connector": connector,
        "openclaw_config": _expand(cfg.claw.config_file),
        "claw_home": claw_home,
        # The inventory is scoped to ``connector`` (defaults to the active
        # connector), so report that as the framework "mode" rather than the
        # global cfg.claw.mode, which is a stale last-activated pointer in
        # multi-connector installs.
        "claw_mode": connector,
        "live": live,
        "skills": _parse_skills(cache.get("skills_list")) if "skills" in cats else [],
        "plugins": _parse_plugins(cache.get("plugins_list")) if "plugins" in cats else [],
        "mcp": _parse_mcp(cache.get("mcp_list")) if "mcp" in cats else [],
        "agents": (_parse_agents(cache.get("agents_list"), cache.get("config_agents")) if "agents" in cats else []),
        "rules": [],
        "tools": _parse_tools(cache.get("plugins_list")) if "tools" in cats else [],
        "model_providers": (
            _parse_model_providers(
                cache.get("models_status"),
                cache.get("plugins_list"),
                cache.get("models_list"),
            )
            if "models" in cats
            else []
        ),
        "memory": _parse_memory(cache.get("memory_status")) if "memory" in cats else [],
        "errors": errors,
        "limitations": [],
    }
    _attach_connector_paths(out, cfg, connector)
    _sync_legacy_connector_paths(out)
    out["summary"] = _build_summary(out)
    return out


def claw_aibom_to_scan_result(inv: dict[str, Any], cfg: Config) -> ScanResult:
    """One INFO finding per category so audit logging stays compact."""
    target = _aibom_target_path(inv, cfg)
    ts = datetime.now(timezone.utc)
    category_labels = [
        ("skills", "Skills"),
        ("plugins", "Plugins"),
        ("mcp", "MCP servers"),
        ("agents", "Agents / sub-agents"),
        ("rules", "Rules"),
        ("tools", "Tools"),
        ("model_providers", "Model providers"),
        ("memory", "Memory"),
    ]
    findings: list[Finding] = []
    for key, label in category_labels:
        payload = inv.get(key, [])
        count = len(payload) if isinstance(payload, list) else 0
        findings.append(
            Finding(
                id=f"claw-aibom-{key}",
                severity="INFO",
                title=f"{label} ({count})",
                description=json.dumps(payload, indent=2) if payload else "[]",
                location=target,
                scanner="aibom-claw",
                tags=["claw-aibom", key],
            ),
        )
    return ScanResult(
        scanner="aibom-claw",
        target=target,
        timestamp=ts,
        findings=findings,
        duration=timedelta(0),
    )


_POLICY_CATEGORIES: list[tuple[str, str, str]] = [
    ("skills", "skill", "skill-scanner"),
    ("plugins", "plugin", "plugin-scanner"),
    ("mcp", "mcp", "mcp-scanner"),
]


def enrich_with_policy(
    inv: dict[str, Any],
    store: Any,
    skill_actions: SkillActionsConfig | None = None,
    policy_dir: str = "",
    cfg: Config | None = None,
) -> None:
    """Evaluate OPA-style admission gate per item and annotate the inventory.

    Adds ``policy_verdict`` and ``policy_detail`` to each skill, plugin, and
    MCP server dict. Adds per-category ``policy_<category>`` counts to the
    summary. Mirrors the Rego ``admission.rego`` logic:
    block list -> allow list -> scan -> severity-based verdict.
    """
    if not store:
        return

    from defenseclaw.enforce import PolicyEngine

    pe = PolicyEngine(store)
    if skill_actions is None:
        skill_actions = SkillActionsConfig()

    for inv_key, target_type, scanner_name in _POLICY_CATEGORIES:
        items = inv.get(inv_key, [])
        if not items:
            continue

        actions_map = _build_actions_map_for_type(store, target_type)
        scan_map = _build_scan_map_for_type(store, scanner_name)

        counts: dict[str, int] = {
            "blocked": 0,
            "allowed": 0,
            "rejected": 0,
            "warning": 0,
            "clean": 0,
            "unscanned": 0,
        }

        for item in items:
            name = item.get("id", "")
            if not name:
                continue

            candidates = _inventory_key_candidates(item, target_type, name)
            scan_entry = _lookup_by_candidates(scan_map, candidates)
            fallback_actions = _fallback_actions_for(target_type, skill_actions, cfg)
            action_entry = _lookup_by_candidates(actions_map, candidates)
            policy_name = _inventory_policy_name(item, target_type, name, action_entry)
            source_path = _inventory_source_path(
                item,
                target_type,
                candidates,
                scan_entry,
                action_entry,
                cfg,
            )
            # F-0423: prior scans are indexed by both full target and
            # ``basename(target)``. A basename hit alone must NOT credit a
            # *different* on-disk asset that merely shares the basename with
            # a clean/already-scanned verdict. Once the item resolved to a
            # concrete path, require the matched scan's target to refer to
            # the same path; otherwise drop the scan so the asset is treated
            # as unscanned rather than inheriting a stranger's result.
            if scan_entry is not None and not _scan_entry_matches_path(scan_entry, source_path):
                scan_entry = None
            # F-0742: a ``source: user`` (or other operator/third-party)
            # AIBOM row must not be silently blessed by the first-party
            # allow list just because its resolved path lands under a
            # first-party provenance dir. Suppress the first-party bypass
            # for untrusted provenance so those rows still get scanned.
            allow_first_party = _source_allows_first_party(item.get("source"))
            verdict, detail = _admission_verdict(
                pe,
                target_type,
                policy_name,
                scan_entry,
                action_entry,
                fallback_actions,
                policy_dir=policy_dir,
                source_path=source_path,
                allow_first_party=allow_first_party,
            )
            item["policy_verdict"] = verdict
            item["policy_detail"] = detail
            if scan_entry:
                item["scan_findings"] = scan_entry["finding_count"]
                item["scan_severity"] = scan_entry["max_severity"]
                item["scan_target"] = scan_entry.get("target", "")
            counts[verdict] = counts.get(verdict, 0) + 1

        scanned = sum(1 for it in items if "scan_findings" in it)
        total_findings = sum(it.get("scan_findings", 0) for it in items)

        summary = inv.get("summary")
        if summary:
            summary[f"policy_{inv_key}"] = counts
            summary[f"scan_{inv_key}"] = {
                "scanned": scanned,
                "unscanned": len(items) - scanned,
                "total_findings": total_findings,
            }


# keep the old name as an alias for backward compatibility
enrich_skills_with_policy = enrich_with_policy


def _fallback_actions_for(
    target_type: str,
    skill_actions: SkillActionsConfig,
    cfg: Config | None,
) -> Any:
    if target_type == "skill" or cfg is None:
        return skill_actions
    if target_type == "plugin":
        return cfg.plugin_actions
    if target_type == "mcp":
        return cfg.mcp_actions
    return skill_actions


# F-0742: AIBOM rows carry a ``source`` describing where the asset came
# from. Anything that is operator-, workspace-, or third-party-sourced is
# untrusted provenance and must not be auto-allowed by the first-party
# allow list (which is meant only for genuinely bundled first-party
# assets). Unknown/empty sources keep the prior behaviour so we don't
# regress legitimate first-party (e.g. bundled plugin) detection.
_UNTRUSTED_INVENTORY_SOURCES: frozenset[str] = frozenset(
    {"user", "workspace", "local", "project", "third-party", "thirdparty", "external"}
)


def _source_allows_first_party(source: Any) -> bool:
    """Return ``False`` when an inventory ``source`` is untrusted provenance.

    A ``source: user`` row (and similar operator/third-party provenance)
    must not bypass scanning via the first-party allow list (F-0742).
    """
    return str(source or "").strip().lower() not in _UNTRUSTED_INVENTORY_SOURCES


def _paths_equivalent(a: str, b: str) -> bool:
    """True if two paths/identifiers refer to the same location.

    Compares raw strings first (covers URLs / commands / identical paths)
    then falls back to ``realpath`` so symlink or ``..`` differences don't
    register as a spurious mismatch.
    """
    if not a or not b:
        return False
    if a == b:
        return True
    try:
        return os.path.realpath(a) == os.path.realpath(b)
    except (OSError, ValueError):
        return False


def _scan_entry_matches_path(scan_entry: dict[str, Any], source_path: str) -> bool:
    """F-0423: gate a (possibly basename-indexed) scan hit by full path.

    A scan entry selected via ``basename(target)`` must only be trusted for
    the inventory item when the item resolved to the *same* path as the
    scan target. When we have no independent path to compare (the source
    path itself fell back to the scan target, or no path is known) we keep
    the name/basename match so existing no-path inventories still resolve.
    """
    target = str(scan_entry.get("target") or "")
    if not target or not source_path:
        return True
    return _paths_equivalent(source_path, target)


def _admission_verdict(
    pe: Any,
    target_type: str,
    name: str,
    scan_entry: dict[str, Any] | None,
    action_entry: ActionEntry | None,
    skill_actions: SkillActionsConfig,
    policy_dir: str = "",
    source_path: str = "",
    allow_first_party: bool = True,
) -> tuple[str, str]:
    """Replicate admission ordering for offline inventory evaluation."""
    from defenseclaw.enforce.admission import evaluate_admission

    decision = evaluate_admission(
        pe,
        policy_dir=policy_dir,
        target_type=target_type,
        name=name,
        source_path=source_path,
        scan_result=scan_entry,
        action_entry=action_entry,
        fallback_actions=skill_actions,
        include_quarantine=True,
        allow_first_party=allow_first_party,
    )
    if decision.verdict == "scan":
        return "unscanned", "no scan result"
    if decision.verdict == "blocked" and action_entry is None:
        return "blocked", "block list"
    if decision.verdict == "allowed" and action_entry is None and decision.source == "manual-allow":
        return "allowed", "allow list"
    return decision.verdict, decision.reason


def _inventory_source_path(
    item: dict[str, Any],
    target_type: str,
    candidates: list[str],
    scan_entry: dict[str, Any] | None,
    action_entry: ActionEntry | None,
    cfg: Config | None,
) -> str:
    import os

    # F-0422: prefer the LIVE on-disk location advertised by the inventory
    # item over the stored ``ActionEntry.source_path``. The stored path is
    # recorded at allow/scan time and can be stale; returning it first hid a
    # mismatch between where the asset actually lives now and the pinned
    # path, letting admission honour a path-pinned allow for a *different*
    # on-disk asset that merely shares the registered name. The live path is
    # authoritative for the admission decision (it is what gets compared
    # against the pin / first-party provenance); the stored path is only a
    # fallback when the item advertises no concrete location.
    for key in ("path", "baseDir", "filePath", "scan_target", "url", "command"):
        raw = item.get(key)
        if raw:
            return str(raw)

    if action_entry is not None and action_entry.source_path:
        return action_entry.source_path

    if cfg is None:
        if scan_entry is not None and scan_entry.get("target"):
            return str(scan_entry["target"])
        return ""

    if target_type == "skill":
        for skill_name in candidates:
            for skill_dir in cfg.skill_dirs():
                candidate = os.path.join(skill_dir, skill_name)
                if os.path.isdir(candidate):
                    return candidate
    elif target_type == "plugin":
        for plugin_name in candidates:
            for plugin_dir in cfg.plugin_dirs():
                candidate = os.path.join(plugin_dir, plugin_name)
                if os.path.isdir(candidate):
                    return candidate

    if scan_entry is not None and scan_entry.get("target"):
        return str(scan_entry["target"])

    return ""


def _inventory_key_candidates(
    item: dict[str, Any],
    target_type: str,
    name: str,
) -> list[str]:
    import os

    candidates: list[str] = []

    def add(raw: Any) -> None:
        val = str(raw or "").strip()
        if val and val not in candidates:
            candidates.append(val)

    add(name)
    add(os.path.basename(name.rstrip("/")))

    if target_type == "plugin":
        plugin_name = item.get("name", "")
        add(plugin_name)
        add(os.path.basename(str(plugin_name).rstrip("/")))
        add(item.get("path", ""))
        add(item.get("baseDir", ""))
        add(item.get("filePath", ""))
    elif target_type == "mcp":
        add(item.get("url", ""))
        add(item.get("command", ""))

    return candidates


def _inventory_policy_name(
    item: dict[str, Any],
    target_type: str,
    name: str,
    action_entry: ActionEntry | None,
) -> str:
    import os

    if action_entry is not None and action_entry.target_name:
        return action_entry.target_name

    if target_type == "plugin":
        plugin_name = str(item.get("name", "")).strip()
        alias = os.path.basename(plugin_name.rstrip("/"))
        if alias and (plugin_name.startswith("@") or alias.endswith("-plugin") or alias.endswith("-provider")):
            return alias

    return name


def _lookup_by_candidates(mapping: dict[str, Any], candidates: list[str]) -> Any | None:
    for candidate in candidates:
        if candidate in mapping:
            return mapping[candidate]
    return None


def _build_actions_map_for_type(store: Any, target_type: str) -> dict[str, ActionEntry]:
    actions_map: dict[str, ActionEntry] = {}
    try:
        entries = store.list_actions_by_type(target_type)
    except Exception:
        return actions_map
    for e in entries:
        actions_map[e.target_name] = e
    return actions_map


def _build_scan_map_for_type(store: Any, scanner_name: str) -> dict[str, dict[str, Any]]:
    import os

    scan_map: dict[str, dict[str, Any]] = {}
    try:
        latest = store.latest_scans_by_scanner(scanner_name)
    except Exception:
        return scan_map
    for ls in latest:
        entry = {
            "target": ls["target"],
            "finding_count": ls["finding_count"],
            "max_severity": ls["max_severity"] or "INFO",
        }
        target = ls["target"]
        for key in (target, os.path.basename(target)):
            if key:
                scan_map[key] = entry
    return scan_map


def format_claw_aibom_human(
    inv: dict[str, Any],
    *,
    summary_only: bool = False,
) -> None:
    """Render the inventory to the terminal using Rich tables."""
    from rich.console import Console

    console = Console(stderr=False)
    mode = "live" if inv.get("live") else "disk"

    connector = str(inv.get("connector") or inv.get("claw_mode") or "openclaw")
    title = "OpenClaw AIBOM" if connector.lower() == "openclaw" else f"{connector} AIBOM"
    home = inv.get("connector_home") or inv.get("claw_home", "")
    config_files = inv.get("connector_config_files") or [inv.get("openclaw_config", "")]
    primary_config = next((c for c in config_files if c), "")
    console.print()
    console.print(f"[bold]{title}[/bold]  (source: {mode})")
    if primary_config:
        console.print(f"  Config:    {primary_config}")
    if home:
        console.print(f"  Home:      {home}")
    if inv.get("claw_mode"):
        console.print(f"  Mode:      {inv.get('claw_mode', '')}")
    console.print()

    _render_summary(console, inv)
    console.print()

    if not summary_only:
        _render_skills(console, inv.get("skills", []))
        _render_plugins(console, inv.get("plugins", []))
        _render_mcp(console, inv.get("mcp", []))
        _render_agents(console, inv.get("agents", []))
        _render_rules(console, inv.get("rules", []))
        _render_tools(console, inv.get("tools", []))
        _render_models(console, inv.get("model_providers", []))
        _render_memory(console, inv.get("memory", []))

    _render_limitations(console, inv.get("limitations", []))
    _render_errors(console, inv.get("errors", []))


# ---------------------------------------------------------------------------
# Polymorphic-path attachment
#
# Connector-aware path metadata lives in ``connector_*`` fields. The
# historical ``openclaw_config`` field is retained only for OpenClaw
# inventories; non-OpenClaw JSON should not imply OpenClaw is installed.
# ---------------------------------------------------------------------------


def _attach_connector_paths(
    out: dict[str, Any],
    cfg: Config,
    connector: str,
) -> None:
    """Populate ``connector_*`` polymorphic path fields on *out*.

    Best-effort: any helper that raises is silently elided so a
    misconfigured cfg never hijacks the inventory pipeline.
    """
    try:
        out["connector_home"] = connector_paths.connector_home(
            connector,
            openclaw_home=cfg.claw.home_dir,
        )
    except Exception:
        out["connector_home"] = ""
    try:
        out["connector_config_files"] = connector_paths.connector_config_files(
            connector,
            openclaw_config=cfg.claw.config_file,
            openclaw_home=cfg.claw.home_dir,
            workspace_dir=cfg.connector_workspace_dir(),
        )
    except Exception:
        out["connector_config_files"] = []
    try:
        out["connector_skill_dirs"] = list(cfg.skill_dirs(connector))
    except Exception:
        out["connector_skill_dirs"] = []
    try:
        out["connector_plugin_dirs"] = (
            connector_paths.plugin_inventory_dirs(
                connector,
                openclaw_home=cfg.claw.home_dir,
                workspace_dir=cfg.connector_workspace_dir(),
            )
            if connector == "cursor"
            else list(cfg.plugin_dirs(connector))
        )
    except Exception:
        out["connector_plugin_dirs"] = []
    try:
        out["connector_agent_dirs"] = connector_paths.agent_dirs(
            connector,
            workspace_dir=cfg.connector_workspace_dir(),
        )
    except Exception:
        out["connector_agent_dirs"] = []
    try:
        out["connector_rule_dirs"] = connector_paths.rule_dirs(
            connector,
            workspace_dir=cfg.connector_workspace_dir(),
        )
    except Exception:
        out["connector_rule_dirs"] = []
    try:
        out["connector_mcp_files"] = list(_collect_mcp_config_files(connector, cfg))
    except Exception:
        out["connector_mcp_files"] = []


def _sync_legacy_connector_paths(out: dict[str, Any]) -> None:
    """Publish a connector-neutral primary config path.

    ``openclaw_config`` predates multi-connector inventory and is now emitted
    only for actual OpenClaw scans. ``connector_config`` is the neutral single
    primary path; ``connector_config_files`` remains the full ordered list.
    """
    connector = str(out.get("connector") or out.get("claw_mode") or "").lower()
    home = str(out.get("connector_home") or "")
    if home:
        out["claw_home"] = home

    config_files = out.get("connector_config_files") or []
    if isinstance(config_files, list) and config_files:
        first = config_files[0]
        if first:
            out["connector_config"] = first
            if connector == "openclaw":
                out["openclaw_config"] = first
    if connector != "openclaw":
        out.pop("openclaw_config", None)


def _aibom_target_path(inv: dict[str, Any], cfg: Config) -> str:
    config_files = inv.get("connector_config_files") or []
    if isinstance(config_files, list) and config_files:
        first = config_files[0]
        if first:
            return str(first)
    legacy = inv.get("openclaw_config")
    if legacy:
        return str(legacy)
    return _expand(cfg.claw.config_file)


def _collect_mcp_config_files(connector: str, cfg: Config) -> list[str]:
    """Return the on-disk MCP config files for *connector*.

    Copilot's MCP surface is distinct from its settings and hooks, and spans
    every pinned workspace ancestor. Other connectors reuse
    :func:`connector_paths.connector_config_files` and retain the historical
    extension filter.
    """
    if connector_paths.normalize(connector) == "copilot":
        return connector_paths.copilot_mcp_config_files(_connector_workspace_dir(cfg))

    candidates = connector_paths.connector_config_files(
        connector,
        openclaw_config=cfg.claw.config_file,
        openclaw_home=cfg.claw.home_dir,
        workspace_dir=cfg.connector_workspace_dir(),
    )
    out: list[str] = []
    for path in candidates:
        base = os.path.basename(path).lower()
        if connector.lower() == "codex" and base != "config.toml":
            continue
        if base.endswith(".json") or base.endswith(".toml") or base.endswith(".yaml") or base.endswith(".yml"):
            out.append(path)
    return out


# ---------------------------------------------------------------------------
# Summary builder (shared by JSON and human output)
# ---------------------------------------------------------------------------


def _build_summary(inv: dict[str, Any]) -> dict[str, Any]:
    skills = inv.get("skills", [])
    plugins = inv.get("plugins", [])

    n_eligible = sum(1 for s in skills if s.get("eligible"))
    n_loaded = sum(1 for p in plugins if p.get("status") == "loaded")
    n_disabled = sum(1 for p in plugins if not p.get("enabled"))

    cats = {
        "skills": {"count": len(skills), "eligible": n_eligible},
        "plugins": {"count": len(plugins), "loaded": n_loaded, "disabled": n_disabled},
        "mcp": {"count": len(inv.get("mcp", []))},
        "agents": {"count": len(inv.get("agents", []))},
        "rules": {"count": len(inv.get("rules", []))},
        "tools": {"count": len(inv.get("tools", []))},
        "model_providers": {"count": len(inv.get("model_providers", []))},
        "memory": {"count": len(inv.get("memory", []))},
    }
    total = sum(c["count"] for c in cats.values())
    return {
        "total_items": total,
        **cats,
        "errors": len(inv.get("errors", [])),
        "limitations": len(inv.get("limitations", [])),
    }


# ---------------------------------------------------------------------------
# Category helpers
# ---------------------------------------------------------------------------


def _resolve_categories(categories: set[str] | None) -> frozenset[str]:
    if categories is None:
        return ALL_CATEGORIES
    resolved: set[str] = set()
    for c in categories:
        c = c.strip().lower()
        c = _CATEGORY_ALIASES.get(c, c)
        if c in ALL_CATEGORIES:
            resolved.add(c)
    return frozenset(resolved) if resolved else ALL_CATEGORIES


def _needed_commands(cats: frozenset[str]) -> set[str]:
    needed: set[str] = set()
    for cat in cats:
        needed.update(_CATEGORY_DEPS.get(cat, []))
    return needed


# ---------------------------------------------------------------------------
# Rich formatting helpers
# ---------------------------------------------------------------------------


def _render_summary(console: Any, inv: dict[str, Any]) -> None:
    from rich.table import Table

    summary = inv.get("summary")
    if summary:
        data = summary
    else:
        data = _build_summary(inv)

    table = Table(title="Inventory Summary", show_edge=False, pad_edge=False)
    table.add_column("Category", style="bold")
    table.add_column("Count", justify="right")
    table.add_column("Detail")

    sk = data.get("skills", {})
    sk_detail = f"{sk.get('eligible', 0)} eligible"
    sk_detail += _scan_detail_suffix(data.get("scan_skills"))
    sk_detail += _policy_detail_suffix(data.get("policy_skills"))
    table.add_row("Skills", str(sk.get("count", 0)), sk_detail)

    pl = data.get("plugins", {})
    pl_detail = f"{pl.get('loaded', 0)} loaded, {pl.get('disabled', 0)} disabled"
    pl_detail += _scan_detail_suffix(data.get("scan_plugins"))
    pl_detail += _policy_detail_suffix(data.get("policy_plugins"))
    table.add_row("Plugins", str(pl.get("count", 0)), pl_detail)

    mcp_detail = ""
    mcp_detail += _scan_detail_suffix(data.get("scan_mcp")).lstrip(" · ")
    mcp_detail += _policy_detail_suffix(data.get("policy_mcp"))
    if mcp_detail.startswith(" · "):
        mcp_detail = mcp_detail.lstrip(" · ")
    table.add_row("MCP servers", str(data.get("mcp", {}).get("count", 0)), mcp_detail)
    table.add_row("Agents", str(data.get("agents", {}).get("count", 0)))
    table.add_row("Rules", str(data.get("rules", {}).get("count", 0)))
    table.add_row("Tools", str(data.get("tools", {}).get("count", 0)))
    table.add_row("Model providers", str(data.get("model_providers", {}).get("count", 0)))
    table.add_row("Memory stores", str(data.get("memory", {}).get("count", 0)))
    console.print(table)


def _policy_detail_suffix(policy: dict[str, int] | None) -> str:
    if not policy:
        return ""
    parts: list[str] = []
    if policy.get("blocked"):
        parts.append(f"[red]{policy['blocked']} blocked[/red]")
    if policy.get("rejected"):
        parts.append(f"[red]{policy['rejected']} rejected[/red]")
    if policy.get("warning"):
        parts.append(f"[yellow]{policy['warning']} warning[/yellow]")
    if policy.get("clean"):
        parts.append(f"[green]{policy['clean']} clean[/green]")
    if policy.get("unscanned"):
        parts.append(f"[dim]{policy['unscanned']} unscanned[/dim]")
    return " · " + ", ".join(parts) if parts else ""


def _scan_detail_suffix(scan: dict[str, int] | None) -> str:
    if not scan:
        return ""
    scanned = scan.get("scanned", 0)
    findings = scan.get("total_findings", 0)
    if scanned == 0:
        return ""
    parts = [f"{scanned} scanned"]
    if findings:
        parts.append(f"[yellow]{findings} findings[/yellow]")
    return " · " + ", ".join(parts)


_VERDICT_STYLES: dict[str, tuple[str, str]] = {
    "blocked": ("bold red", "⛔ blocked"),
    "rejected": ("red", "✗ rejected"),
    "warning": ("yellow", "⚠ warning"),
    "clean": ("green", "✓ clean"),
    "allowed": ("cyan", "↪ allowed"),
    "unscanned": ("dim", "… unscanned"),
}


def _render_skills(console: Any, skills: list[dict[str, Any]]) -> None:
    if not skills:
        console.print("[dim]Skills: none[/dim]")
        return

    from rich.table import Table

    eligible = [s for s in skills if s.get("eligible")]
    ineligible = [s for s in skills if not s.get("eligible")]
    has_policy = any(s.get("policy_verdict") for s in skills)
    has_scan = any("scan_findings" in s for s in skills)

    if eligible:
        table = Table(title=f"Skills — eligible ({len(eligible)})")
        table.add_column("Name", style="green bold")
        table.add_column("Source")
        table.add_column("Description", max_width=50)
        if has_scan:
            table.add_column("Findings", min_width=12)
        if has_policy:
            table.add_column("Policy", min_width=14)
        for s in eligible:
            row = [
                s.get("id", ""),
                s.get("source", ""),
                _trunc(s.get("description", ""), 50),
            ]
            if has_scan:
                row.append(_format_scan(s))
            if has_policy:
                row.append(_format_verdict(s))
            table.add_row(*row)
        console.print(table)

    if ineligible:
        blocked_count = sum(1 for s in ineligible if s.get("policy_verdict") == "blocked")
        parts = ["missing deps"]
        if blocked_count:
            parts.append(f"{blocked_count} blocked by policy")
        console.print(f"  [dim]+ {len(ineligible)} ineligible skills ({', '.join(parts)})[/dim]")
    console.print()


def _format_verdict(item: dict[str, Any]) -> str:
    verdict = item.get("policy_verdict", "")
    if not verdict:
        return "[dim]-[/dim]"
    style, label = _VERDICT_STYLES.get(verdict, ("dim", verdict))
    detail = item.get("policy_detail", "")
    cell = f"[{style}]{label}[/{style}]"
    if detail and verdict in ("rejected", "warning"):
        cell += f"\n[dim]{_trunc(detail, 30)}[/dim]"
    return cell


_SEVERITY_COLORS: dict[str, str] = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "dim",
}


def _format_scan(item: dict[str, Any]) -> str:
    n = item.get("scan_findings")
    if n is None:
        return "[dim]-[/dim]"
    if n == 0:
        return "[green]clean[/green]"
    sev = item.get("scan_severity", "INFO")
    color = _SEVERITY_COLORS.get(sev, "dim")
    return f"[{color}]{n} ({sev})[/{color}]"


def _render_plugins(console: Any, plugins: list[dict[str, Any]]) -> None:
    if not plugins:
        console.print("[dim]Plugins: none[/dim]")
        return

    from rich.table import Table

    loaded = [p for p in plugins if p.get("status") == "loaded"]
    disabled = [p for p in plugins if not p.get("enabled")]
    has_policy = any(p.get("policy_verdict") for p in plugins)
    has_scan = any("scan_findings" in p for p in plugins)

    table = Table(title=f"Plugins — loaded ({len(loaded)})")
    table.add_column("ID", style="bold")
    table.add_column("Origin")
    table.add_column("Providers")
    table.add_column("Tools")
    if has_scan:
        table.add_column("Findings", min_width=12)
    if has_policy:
        table.add_column("Policy", min_width=14)
    for p in loaded:
        provs = ", ".join(p.get("providerIds", []))
        tools = ", ".join(p.get("toolNames", []))
        row = [p.get("id", ""), p.get("origin", ""), provs or "-", tools or "-"]
        if has_scan:
            row.append(_format_scan(p))
        if has_policy:
            row.append(_format_verdict(p))
        table.add_row(*row)
    console.print(table)

    if disabled:
        blocked_count = sum(1 for p in disabled if p.get("policy_verdict") == "blocked")
        parts = [f"{len(disabled)} disabled"]
        if blocked_count:
            parts.append(f"{blocked_count} blocked by policy")
        console.print(f"  [dim]+ {', '.join(parts)}[/dim]")
    console.print()


def _render_mcp(console: Any, mcps: list[dict[str, Any]]) -> None:
    if not mcps:
        console.print("[dim]MCP servers: none configured[/dim]\n")
        return

    from rich.table import Table

    has_policy = any(m.get("policy_verdict") for m in mcps)
    has_scan = any("scan_findings" in m for m in mcps)

    table = Table(title=f"MCP Servers ({len(mcps)})")
    table.add_column("Name", style="bold")
    table.add_column("Transport")
    table.add_column("Command / URL")
    table.add_column("Env keys")
    if has_scan:
        table.add_column("Findings", min_width=12)
    if has_policy:
        table.add_column("Policy", min_width=14)
    for m in mcps:
        cmd_or_url = m.get("command") or m.get("url", "")
        if m.get("args"):
            cmd_or_url += " " + " ".join(str(a) for a in m["args"][:3])
        row = [
            m.get("id", ""),
            m.get("transport", "stdio"),
            _trunc(cmd_or_url, 50),
            ", ".join(m.get("env_keys", [])) or "-",
        ]
        if has_scan:
            row.append(_format_scan(m))
        if has_policy:
            row.append(_format_verdict(m))
        table.add_row(*row)
    console.print(table)
    console.print()


def _render_agents(console: Any, agents: list[dict[str, Any]]) -> None:
    if not agents:
        console.print("[dim]Agents: none[/dim]\n")
        return

    from rich.table import Table

    table = Table(title=f"Agents ({len(agents)})")
    table.add_column("ID", style="bold")
    table.add_column("Model")
    table.add_column("Default")
    table.add_column("Workspace")
    for a in agents:
        table.add_row(
            a.get("id", ""),
            a.get("model", "-"),
            "yes" if a.get("is_default") else "",
            _trunc(a.get("workspace", ""), 45),
        )
    console.print(table)
    console.print()


def _render_rules(console: Any, rules: list[dict[str, Any]]) -> None:
    if not rules:
        console.print("[dim]Rules: none[/dim]\n")
        return

    from rich.table import Table

    table = Table(title=f"Rules ({len(rules)})")
    table.add_column("Name", style="bold")
    table.add_column("Scope")
    table.add_column("Source")
    for rule in rules:
        table.add_row(
            rule.get("id", ""),
            rule.get("scope", ""),
            _trunc(rule.get("source", ""), 70),
        )
    console.print(table)
    console.print()


def _render_tools(console: Any, tools: list[dict[str, Any]]) -> None:
    if not tools:
        console.print("[dim]Tools: none registered[/dim]\n")
        return

    from rich.table import Table

    table = Table(title=f"Tools ({len(tools)})")
    table.add_column("Name", style="bold")
    table.add_column("Source")
    for t in tools:
        table.add_row(t.get("id", ""), t.get("source", ""))
    console.print(table)
    console.print()


def _render_models(console: Any, providers: list[dict[str, Any]]) -> None:
    if not providers:
        console.print("[dim]Model providers: none[/dim]\n")
        return

    from rich.table import Table

    config_rows = [p for p in providers if p.get("source") == "models status"]
    auth_rows = [p for p in providers if p.get("source") == "auth"]
    plugin_rows = [p for p in providers if str(p.get("source", "")).startswith("plugin:")]
    model_rows = [p for p in providers if p.get("source") == "models list"]

    if config_rows:
        c = config_rows[0]
        console.print("[bold]Model Config[/bold]")
        console.print(f"  Primary:   {c.get('default_model', '-')}")
        fb = c.get("fallbacks", [])
        if fb:
            console.print(f"  Fallbacks: {', '.join(fb)}")
        allowed = c.get("allowed", [])
        if allowed:
            console.print(f"  Allowed:   {', '.join(allowed)}")
        console.print()

    if auth_rows:
        for a in auth_rows:
            status = a.get("status", "")
            style = "red" if status == "missing" else "green"
            console.print(f"  Auth: [bold]{a.get('id', '')}[/bold] [{style}]{status}[/{style}]")
        console.print()

    if model_rows:
        table = Table(title=f"Configured Models ({len(model_rows)})")
        table.add_column("Model", style="bold")
        table.add_column("Name")
        table.add_column("Available")
        table.add_column("Input")
        table.add_column("Context", justify="right")
        for m in model_rows:
            avail = "[green]yes[/green]" if m.get("available") else "[red]no[/red]"
            ctx = f"{m.get('context_window', 0):,}" if m.get("context_window") else "-"
            table.add_row(
                m.get("id", ""),
                m.get("name", ""),
                avail,
                m.get("input", ""),
                ctx,
            )
        console.print(table)
        console.print()

    if plugin_rows:
        enabled = [p for p in plugin_rows if p.get("enabled")]
        disabled = [p for p in plugin_rows if not p.get("enabled")]
        names = ", ".join(p.get("id", "") for p in enabled)
        console.print(f"  [dim]Provider plugins ({len(enabled)} loaded): {names}[/dim]")
        if disabled:
            console.print(f"  [dim]+ {len(disabled)} disabled provider plugins[/dim]")
        console.print()


def _render_memory(console: Any, memory: list[dict[str, Any]]) -> None:
    if not memory:
        console.print("[dim]Memory: no stores[/dim]\n")
        return

    from rich.table import Table

    table = Table(title=f"Memory ({len(memory)})")
    table.add_column("Agent", style="bold")
    table.add_column("Backend")
    table.add_column("Files", justify="right")
    table.add_column("Chunks", justify="right")
    table.add_column("Provider")
    table.add_column("FTS")
    table.add_column("Vector")
    table.add_column("DB path")
    for m in memory:
        fts = "[green]yes[/green]" if m.get("fts_available") else "[red]no[/red]"
        vec = "[green]yes[/green]" if m.get("vector_enabled") else "[dim]no[/dim]"
        table.add_row(
            m.get("id", ""),
            m.get("backend", ""),
            str(m.get("files", 0)),
            str(m.get("chunks", 0)),
            m.get("provider", "-"),
            fts,
            vec,
            _trunc(m.get("db_path", ""), 40),
        )
    console.print(table)
    console.print()


def _render_errors(console: Any, errors: list[dict[str, Any]]) -> None:
    if not errors:
        return
    console.print(f"[bold yellow]Warning:[/bold yellow] {len(errors)} command(s) failed:")
    for e in errors:
        console.print(f"  [yellow]{e.get('command', '?')}[/yellow] — {e.get('error', 'unknown')}")
    console.print()


def _render_limitations(console: Any, limitations: list[dict[str, Any]]) -> None:
    """Render expected connector gaps as information, never warnings."""

    if not limitations:
        return
    console.print("[bold cyan]Unsupported inventory capabilities[/bold cyan] [dim](informational)[/dim]:")
    for limitation in limitations:
        category = limitation.get("category", "?")
        reason = limitation.get("reason", "unsupported by this connector")
        console.print(f"  [cyan]{category}[/cyan] — {reason}")
    console.print()


def _trunc(s: str, n: int) -> str:
    return s if len(s) <= n else s[: n - 3] + "..."


# ---------------------------------------------------------------------------
# Parallel command dispatcher
# ---------------------------------------------------------------------------


def _run_openclaw(*args: str) -> _CmdResult:
    """Run an ``openclaw`` subcommand and return parsed JSON with error info.

    Some OpenClaw subcommands write JSON to stdout, others to stderr.
    We try stdout first, then fall back to stderr.
    """
    cmd_str = "openclaw " + " ".join(args) + " --json"
    try:
        from defenseclaw.config import openclaw_bin, openclaw_cmd_prefix

        prefix = openclaw_cmd_prefix()
        proc = subprocess.run(
            [*prefix, openclaw_bin(), *args, "--json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except FileNotFoundError:
        return _CmdResult(data=None, error="openclaw not found on PATH", command=cmd_str)
    except subprocess.TimeoutExpired:
        return _CmdResult(data=None, error="timed out after 30s", command=cmd_str)

    if proc.returncode != 0:
        stderr_snippet = (proc.stderr or "").strip()[:200]
        msg = f"exit code {proc.returncode}"
        if stderr_snippet:
            msg += f": {stderr_snippet}"
        return _CmdResult(data=None, error=msg, command=cmd_str)

    decoder = json.JSONDecoder()
    for stream in (proc.stdout, proc.stderr):
        text = stream.strip()
        if not text:
            continue
        try:
            return _CmdResult(data=json.loads(text), error=None, command=cmd_str)
        except json.JSONDecodeError:
            pass
        # stderr may contain Node.js warnings before or after the JSON;
        # find the earliest { or [ and try raw_decode from there.
        candidates = []
        for ch in ("{", "["):
            pos = text.find(ch)
            if pos >= 0:
                candidates.append(pos)
        for idx in sorted(candidates):
            try:
                obj, _ = decoder.raw_decode(text, idx)
                return _CmdResult(data=obj, error=None, command=cmd_str)
            except (json.JSONDecodeError, ValueError):
                pass
        continue

    return _CmdResult(data=None, error="no JSON in output", command=cmd_str)


def _fetch_all(needed: set[str]) -> tuple[dict[str, Any], list[dict[str, str]]]:
    """Run all *needed* openclaw commands in parallel, return (cache, errors)."""
    cache: dict[str, Any] = {}
    errors: list[dict[str, str]] = []

    if not needed:
        return cache, errors

    with ThreadPoolExecutor(max_workers=min(len(needed), 8)) as pool:
        futures = {pool.submit(_run_openclaw, *_COMMANDS[key]): key for key in needed if key in _COMMANDS}
        for fut in as_completed(futures):
            key = futures[fut]
            result = fut.result()
            cache[key] = result.data
            if result.error:
                errors.append({"command": result.command, "error": result.error})

    return cache, errors


# ---------------------------------------------------------------------------
# Parsers — transform raw CLI JSON into normalized inventory rows
# ---------------------------------------------------------------------------


def _parse_skills(raw: Any) -> list[dict[str, Any]]:
    if not raw or not isinstance(raw, dict):
        return []
    skills = raw.get("skills", [])
    rows: list[dict[str, Any]] = []
    for s in skills:
        if not isinstance(s, dict):
            continue
        row: dict[str, Any] = {
            "id": s.get("name", ""),
            "source": s.get("source", ""),
            "eligible": s.get("eligible", False),
            "enabled": not s.get("disabled", False),
            "bundled": s.get("bundled", False),
        }
        if s.get("description"):
            row["description"] = s["description"]
        if s.get("emoji"):
            row["emoji"] = s["emoji"]
        missing = s.get("missing", {})
        if isinstance(missing, dict):
            missing_bins = missing.get("bins", []) + missing.get("anyBins", [])
            missing_env = missing.get("env", [])
            if missing_bins:
                row["missing_bins"] = missing_bins
            if missing_env:
                row["missing_env"] = missing_env
        rows.append(row)
    return rows


def _parse_plugins(raw: Any) -> list[dict[str, Any]]:
    if not raw or not isinstance(raw, dict):
        return []
    plugins = raw.get("plugins", [])
    rows: list[dict[str, Any]] = []
    for p in plugins:
        if not isinstance(p, dict):
            continue
        row: dict[str, Any] = {
            "id": p.get("id", ""),
            "name": p.get("name", ""),
            "version": p.get("version", ""),
            "origin": p.get("origin", ""),
            "enabled": p.get("enabled", False),
            "status": p.get("status", ""),
        }
        for field in ("toolNames", "providerIds", "hookNames", "channelIds", "cliCommands", "services"):
            val = p.get(field, [])
            if val:
                row[field] = val
        rows.append(row)
    return rows


def _parse_mcp(raw: Any) -> list[dict[str, Any]]:
    if raw is None:
        return []
    if isinstance(raw, dict):
        servers = raw.get("servers") or raw.get("mcpServers")
        if not servers:
            servers = raw
        if isinstance(servers, dict):
            rows: list[dict[str, Any]] = []
            for name, spec in servers.items():
                row: dict[str, Any] = {"id": str(name), "source": "openclaw mcp list"}
                if isinstance(spec, dict):
                    if spec.get("command"):
                        row["command"] = spec["command"]
                    if spec.get("args"):
                        row["args"] = spec["args"]
                    if spec.get("url"):
                        row["url"] = spec["url"]
                    if spec.get("transport"):
                        row["transport"] = spec["transport"]
                    if isinstance(spec.get("env"), dict):
                        row["env_keys"] = sorted(str(k) for k in spec["env"].keys())
                rows.append(row)
            return rows
        return []
    if isinstance(raw, list):
        return [{"id": str(i), **s} for i, s in enumerate(raw) if isinstance(s, dict)]
    return []


def _parse_agents(raw_agents: Any, raw_defaults: Any) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    if isinstance(raw_agents, list):
        for a in raw_agents:
            if not isinstance(a, dict):
                continue
            rows.append(
                {
                    "id": a.get("id", ""),
                    "model": a.get("model", ""),
                    "workspace": a.get("workspace", ""),
                    "is_default": a.get("isDefault", False),
                    "bindings": a.get("bindings", 0),
                }
            )

    if isinstance(raw_defaults, dict) and raw_defaults.get("defaults"):
        d = raw_defaults["defaults"]
        row: dict[str, Any] = {"id": "_defaults", "source": "agents.defaults"}
        model = d.get("model")
        if isinstance(model, dict):
            row["model"] = model.get("primary", "")
            fb = model.get("fallbacks", [])
            if fb:
                row["fallbacks"] = fb
        sub = d.get("subagents")
        if isinstance(sub, dict):
            row["subagents_max_concurrent"] = sub.get("maxConcurrent", 0)
        rows.append(row)

    return rows


def _parse_tools(raw_plugins: Any) -> list[dict[str, Any]]:
    """Extract tools from plugin declarations — the canonical source."""
    if not raw_plugins or not isinstance(raw_plugins, dict):
        return []
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for p in raw_plugins.get("plugins", []):
        if not isinstance(p, dict):
            continue
        pid = p.get("id", "")
        for t in p.get("toolNames", []):
            if t not in seen:
                seen.add(t)
                rows.append({"id": t, "source": f"plugin:{pid}"})
    return rows


def _parse_model_providers(
    raw_status: Any,
    raw_plugins: Any,
    raw_models: Any,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    if isinstance(raw_status, dict):
        rows.append(
            {
                "id": "_config",
                "source": "models status",
                "default_model": raw_status.get("defaultModel") or raw_status.get("resolvedDefault", ""),
                "fallbacks": raw_status.get("fallbacks", []),
                "allowed": raw_status.get("allowed", []),
                "config_path": raw_status.get("configPath", ""),
            }
        )
        auth = raw_status.get("auth", {})
        if isinstance(auth, dict):
            for prov in auth.get("providers", []):
                if isinstance(prov, dict):
                    rows.append(
                        {
                            "id": prov.get("provider", ""),
                            "source": "auth",
                            "status": prov.get("status", ""),
                        }
                    )
            for m in auth.get("missingProvidersInUse", []):
                rows.append({"id": str(m), "source": "auth", "status": "missing"})

    if isinstance(raw_plugins, dict):
        seen: set[str] = set()
        for p in raw_plugins.get("plugins", []):
            if not isinstance(p, dict):
                continue
            for pid in p.get("providerIds", []):
                if pid not in seen:
                    seen.add(pid)
                    rows.append(
                        {
                            "id": pid,
                            "source": f"plugin:{p.get('id', '')}",
                            "enabled": p.get("enabled", False),
                            "status": p.get("status", ""),
                        }
                    )

    if isinstance(raw_models, dict):
        for m in raw_models.get("models", []):
            if not isinstance(m, dict):
                continue
            rows.append(
                {
                    "id": m.get("key", ""),
                    "name": m.get("name", ""),
                    "source": "models list",
                    "available": m.get("available", False),
                    "local": m.get("local", False),
                    "input": m.get("input", ""),
                    "context_window": m.get("contextWindow", 0),
                }
            )

    return rows


def _parse_memory(raw: Any) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        return []
    rows: list[dict[str, Any]] = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        s = entry.get("status", {})
        if not isinstance(s, dict):
            continue
        row: dict[str, Any] = {
            "id": entry.get("agentId", ""),
            "backend": s.get("backend", ""),
            "files": s.get("files", 0),
            "chunks": s.get("chunks", 0),
            "db_path": s.get("dbPath", ""),
            "provider": s.get("provider", ""),
            "sources": s.get("sources", []),
            "workspace": s.get("workspaceDir", ""),
        }
        fts = s.get("fts", {})
        if isinstance(fts, dict):
            row["fts_available"] = fts.get("available", False)
        vector = s.get("vector", {})
        if isinstance(vector, dict):
            row["vector_enabled"] = vector.get("enabled", False)
        rows.append(row)
    return rows


# ---------------------------------------------------------------------------
# Non-OpenClaw filesystem adapter (S4.3)
# ---------------------------------------------------------------------------
#
# Non-OpenClaw connectors don't consistently expose a ``<framework> …
# --json`` style introspection CLI, so we discover their installed
# components by walking the directory layouts documented in
# defenseclaw.connector_paths. Categories that are OpenClaw-only
# concepts (agents, models, memory, tools-as-plugin-export) come back
# as empty lists with typed limitation metadata pointing the reader at
# the connector-specific surface that owns that concept.

_FILESYSTEM_ONLY_CONNECTOR_NOTES: dict[str, str] = {
    "agents": "agents are not a first-class concept on this connector",
    "tools": "tool registry is owned by each plugin's manifest",
    "models": "model providers are configured inside the framework",
    "memory": "memory backend is private to the framework",
}

_PARTIAL_CONNECTOR_NOTES: dict[tuple[str, str], str] = {
    (
        "copilot",
        "skills",
    ): (
        "documented local project, inherited, personal, and COPILOT_SKILLS_DIRS "
        "sources are inventoried; plugin, built-in, and organization/remote "
        "skills are not expanded from private or remote stores"
    ),
    (
        "copilot",
        "agents",
    ): (
        "documented local project/ancestor and personal agents plus the "
        "reviewed Copilot CLI 1.0.77 built-in agent set are inventoried; "
        "built-ins cannot be shadowed by local files, while plugin-contributed "
        "agents and remote organization/enterprise agents require "
        "official-client live-session inspection"
    ),
    (
        "copilot",
        "mcp",
    ): (
        "documented workspace/ancestor and personal MCP configuration is "
        "inventoried in priority order irrespective of folder trust; effective "
        "workspace activation requires a trusted folder (or "
        "GITHUB_COPILOT_PROMPT_MODE_WORKSPACE_MCP=true in untrusted prompt "
        "mode), while session flag, plugin-contributed, built-in, and remote "
        "runtime servers require official-client live inspection"
    ),
}


def _collect_filesystem_category(
    connector: str,
    category: str,
    collector: Callable[[], list[dict[str, Any]]],
) -> _FilesystemCollectionResult:
    """Run one filesystem collector while preserving partial inventory.

    An exception means an attempted collection unexpectedly failed and belongs
    in ``errors``. An empty successful result is not an error; callers may
    separately describe a connector's expected capability limitation.
    """

    try:
        return _FilesystemCollectionResult(collector(), None)
    except Exception as exc:  # noqa: BLE001 - partial inventory records the failure.
        return _FilesystemCollectionResult(
            [],
            {"command": f"{connector}:{category}", "error": str(exc)},
        )


# ---------------------------------------------------------------------------
# Plan C7 / matrix #4 — per-connector AIBOM adapters
#
# For non-OpenClaw connectors, agents / tools / model_providers / memory
# come from on-disk filesystem fixtures rather than a CLI shellout. Each
# adapter returns a list of plain dicts that share the schema produced
# by the OpenClaw _parse_* helpers above (id / name / description /
# source). The dispatchers below select the right adapter based on
# the active connector.
#
# OpenClaw is intentionally absent from these dispatch tables — it
# stays on the live ``openclaw <cat> --json`` path. Adding it here
# would create two competing data sources for the same inventory.
# ---------------------------------------------------------------------------


def _agents_for_connector(connector: str, cfg: Config) -> list[dict[str, Any]]:
    """Per-connector agent enumeration.

    * claudecode — recursive user/project Markdown agents, identified by YAML
      frontmatter with closest-project-over-user precedence
    * codex      — standalone TOML in candidate project and user agent layers
    * zeptoclaw  — ``~/.zeptoclaw/agents.json`` array
    * geminicli  — ``.gemini/agents`` and ``~/.gemini/agents``
    * copilot    — precedence-aware project/ancestor agents plus
      ``$COPILOT_HOME/agents`` (default ``~/.copilot/agents``)
    * cursor     — explicitly pinned project ``.cursor/agents`` and user ``~/.cursor/agents``
    * antigravity — global/workspace custom agents plus plugin agent components
    * opencode   — singular/plural agent roots in project and config directories
    """
    home = os.path.expanduser("~")
    name = connector_paths.normalize(connector)
    if name == "claudecode":
        workspace = _connector_workspace_dir(cfg)
        return _claude_agents_from_dirs(
            connector_paths.claude_agent_dirs(workspace),
        )
    if name == "codex":
        return _agents_from_codex_toml_dirs(
            connector_paths.agent_dirs(
                name,
                workspace_dir=_connector_workspace_dir(cfg),
            ),
        )
    if name == "zeptoclaw":
        return _agents_from_zeptoclaw_json(
            os.path.join(home, ".zeptoclaw", "agents.json"),
        )
    if name == "geminicli":
        return _agents_from_md_dirs(
            [
                os.path.join(os.getcwd(), ".gemini", "agents"),
                os.path.join(home, ".gemini", "agents"),
            ]
        )
    if name == "copilot":
        return _agents_from_copilot_dirs(connector_paths.copilot_agent_dirs(_connector_workspace_dir(cfg)))
    if name == "cursor":
        workspace = cfg.connector_workspace_dir()
        return _agents_from_md_dirs(
            [
                os.path.join(workspace, ".cursor", "agents") if workspace else "",
                os.path.join(home, ".cursor", "agents"),
            ]
        )
    if name == "antigravity":
        return _agents_from_antigravity_dirs(_antigravity_agent_dirs(_connector_workspace_dir(cfg)))
    if name == "opencode":
        custom = os.environ.get("OPENCODE_CONFIG_DIR", "").strip()
        config_home = os.path.expanduser(custom) if custom else os.path.join(home, ".config", "opencode")
        rows = _agents_from_md_dirs(
            [
                os.path.join(os.getcwd(), ".opencode", "agent"),
                os.path.join(os.getcwd(), ".opencode", "agents"),
                os.path.join(config_home, "agent"),
                os.path.join(config_home, "agents"),
            ]
        )
        workspace = _connector_workspace_dir(cfg)
        for path in connector_paths._opencode_config_paths(workspace):  # type: ignore[attr-defined]
            rows.extend(_agents_from_opencode_config(path))
        return _dedup_agent_rows(rows)
    return []


def _rules_for_connector(connector: str, cfg: Config) -> list[dict[str, Any]]:
    """Enumerate documented Codex ``*.rules`` files without evaluating them."""
    if (connector or "").lower() != "codex":
        return []

    user_rules = os.path.normcase(
        os.path.abspath(os.path.join(connector_paths.codex_home(), "rules"))
    )
    rows: list[dict[str, Any]] = []
    for rules_dir in connector_paths.rule_dirs(
        "codex",
        workspace_dir=cfg.connector_workspace_dir(),
    ):
        entries = _safe_codex_directory_entries(rules_dir)
        if entries is None:
            continue
        normalized = os.path.normcase(os.path.abspath(rules_dir))
        if normalized == user_rules:
            scope = "user"
        elif normalized == os.path.normcase(os.path.abspath(os.path.join(os.sep, "etc", "codex", "rules"))):
            scope = "system"
        else:
            scope = "project"
        for entry in entries:
            if not entry.lower().endswith(".rules"):
                continue
            full = os.path.join(rules_dir, entry)
            try:
                connector_paths.reject_reparse_path(full)
                info = os.stat(full, follow_symlinks=False)
            except OSError:
                continue
            if not stat.S_ISREG(info.st_mode):
                continue
            rows.append(
                {
                    "id": os.path.splitext(entry)[0],
                    "name": entry,
                    "source": full,
                    "kind": "exec-policy",
                    "scope": scope,
                    "trust_required": scope == "project",
                }
            )
    return rows


def _tools_for_connector(connector: str, cfg: Config) -> list[dict[str, Any]]:
    """Per-connector tool enumeration.

    * claudecode — connector-home ``settings.json`` ``tools`` field
    * codex      — deprecated connector-home ``prompts/*.md`` slash commands
    * zeptoclaw  — ``~/.zeptoclaw/agents.json`` (tools are inline)
    * opencode   — ``opencode.json`` tool map + ``tools/`` JS/TS files
    * antigravity — plugin/global slash command files as invokable tools
    """
    home = os.path.expanduser("~")
    name = (connector or "").lower()
    if name == "claudecode":
        return _tools_from_claude_settings(
            os.path.join(connector_paths.connector_home(name), "settings.json"),
        )
    if name == "codex":
        return _codex_custom_prompt_commands(os.path.join(connector_paths.connector_home(name), "prompts"))
    if name == "zeptoclaw":
        return _tools_from_zeptoclaw_json(
            os.path.join(home, ".zeptoclaw", "agents.json"),
        )
    if name == "opencode":
        # PR #655's native-Windows contract intentionally leaves this surface
        # unsupported. The macOS audit verified OpenCode tool/command roots.
        return [] if os.name == "nt" else _tools_from_opencode(cfg)
    if name == "antigravity":
        return _tools_from_antigravity(cfg)
    return []


def _model_providers_for_connector(
    connector: str,
    cfg: Config,
) -> list[dict[str, Any]]:
    """Per-connector model-provider enumeration.

    * claudecode — ``ANTHROPIC_BASE_URL`` env + the resolved key store
    * codex      — ``OPENAI_BASE_URL`` env + key store
    * zeptoclaw  — re-parse ``~/.zeptoclaw/config.json`` providers map
                   (the Setup-time snapshot is held in-process by
                   the Go connector; offline AIBOM doesn't have it,
                   so we re-derive from disk).
    """
    home = os.path.expanduser("~")
    name = (connector or "").lower()
    if name == "claudecode":
        return _providers_from_env(
            "ANTHROPIC_BASE_URL",
            "ANTHROPIC_API_KEY",
            default_provider="anthropic",
            default_base_url="https://api.anthropic.com",
        )
    if name == "codex":
        return _providers_from_env(
            "OPENAI_BASE_URL",
            "OPENAI_API_KEY",
            default_provider="openai",
            default_base_url="https://api.openai.com/v1",
        )
    if name == "zeptoclaw":
        return _providers_from_zeptoclaw_config(
            os.path.join(home, ".zeptoclaw", "config.json"),
        )
    return []


def _memory_for_connector(connector: str, cfg: Config) -> list[dict[str, Any]]:
    """Per-connector memory backend enumeration.

    Memory backends are rarely declarative across these frameworks; the
    conservative shape is "report the directory if present". Claude Code uses
    its effective autoMemoryDirectory setting or project-derived default.
    """
    home = os.path.expanduser("~")
    name = (connector or "").lower()
    candidates: list[str] = []
    claude_resolution: connector_paths.ClaudeAutoMemoryResolution | None = None
    if name == "claudecode":
        claude_resolution = connector_paths.claude_auto_memory_resolution(
            _connector_workspace_dir(cfg),
        )
        candidates = [claude_resolution.path] if claude_resolution.path else []
    elif name == "codex":
        connector_home = connector_paths.connector_home(name)
        candidates = [
            os.path.join(connector_home, "memory"),
            os.path.join(connector_home, "history"),
        ]
    elif name == "zeptoclaw":
        candidates = [os.path.join(home, ".zeptoclaw", "memory")]
    else:
        return []

    rows: list[dict[str, Any]] = []
    for path in candidates:
        if not os.path.isdir(path) or is_symlink(path):
            continue
        try:
            entry_count = sum(1 for _ in os.scandir(path))
        except OSError:
            entry_count = 0
        row: dict[str, Any] = {
            "id": os.path.basename(path) or path,
            "name": path,
            "source": path,
            "kind": "filesystem",
            "entry_count": entry_count,
        }
        if claude_resolution is not None:
            row.update(
                {
                    "settings_source": claude_resolution.source,
                    "project_root": claude_resolution.project_root,
                    "activation_verified": claude_resolution.activation_verified,
                }
            )
        rows.append(row)
    return rows


# --- adapter helpers -------------------------------------------------------


def _agents_from_md_dir(agents_dir: str) -> list[dict[str, Any]]:
    """Each documented Markdown file under *agents_dir* is one agent."""
    entries = _safe_codex_directory_entries(agents_dir)
    if entries is None:
        return []
    rows: list[dict[str, Any]] = []
    for entry in entries:
        full = os.path.join(agents_dir, entry)
        if not entry.lower().endswith(".md"):
            continue
        try:
            connector_paths.reject_reparse_path(full)
            info = os.stat(full, follow_symlinks=False)
        except OSError:
            continue
        if not stat.S_ISREG(info.st_mode):
            continue
        agent_id = os.path.splitext(entry)[0]
        rows.append(
            {
                "id": agent_id,
                "name": agent_id,
                "source": full,
                "kind": "subagent",
            }
        )
    return rows


def _agents_from_md_dirs(agent_dirs: list[str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for agents_dir in agent_dirs:
        for row in _agents_from_md_dir(agents_dir):
            key = str(row.get("source") or row.get("id") or "")
            if not key or key in seen:
                continue
            seen.add(key)
            rows.append(row)
    return rows


_COPILOT_BUILTIN_AGENTS: tuple[str, ...] = (
    "code-review",
    "explore",
    "general-purpose",
    "research",
    "rubber-duck",
    "security-review",
    "task",
)


def _agents_from_copilot_dirs(agent_dirs: list[str]) -> list[dict[str, Any]]:
    """Enumerate effective Copilot agents using its exact identity contract.

    Copilot accepts only ``*.md`` and ``*.agent.md`` custom-agent files.
    The compound ``.agent.md`` suffix is the extension, so
    ``reviewer.agent.md`` has the ID ``reviewer``. Directories arrive in
    official precedence order; the first occurrence of an ID wins. The
    versioned built-in set is emitted first because official documentation
    says built-in agents are always present and cannot be overridden.
    """

    rows: list[dict[str, Any]] = [
        {
            "id": agent_id,
            "name": agent_id,
            "source": "official-contract:copilot-cli-1.0.77",
            "kind": "built-in-agent",
            "immutable": True,
        }
        for agent_id in _COPILOT_BUILTIN_AGENTS
    ]
    seen_ids: set[str] = {os.path.normcase(agent_id) for agent_id in _COPILOT_BUILTIN_AGENTS}
    for agents_dir in agent_dirs:
        entries = _safe_codex_directory_entries(agents_dir)
        if entries is None:
            continue
        for entry in entries:
            full = os.path.join(agents_dir, entry)
            try:
                connector_paths.reject_reparse_path(full)
                info = os.stat(full, follow_symlinks=False)
            except OSError:
                continue
            if not stat.S_ISREG(info.st_mode):
                continue
            lowered = entry.lower()
            if lowered.endswith(".agent.md"):
                agent_id = entry[: -len(".agent.md")]
            elif lowered.endswith(".md"):
                agent_id = entry[: -len(".md")]
            else:
                continue
            if not agent_id:
                continue
            identity = os.path.normcase(agent_id)
            if identity in seen_ids:
                continue
            seen_ids.add(identity)
            rows.append(
                {
                    "id": agent_id,
                    "name": agent_id,
                    "source": full,
                    "kind": "subagent",
                }
            )
    return rows


class AmbiguousClaudeAgentIdentityError(ValueError):
    """Raised when one Claude agent scope contains duplicate identities."""


_CLAUDE_AGENT_NAME_PATTERN = re.compile(r"[a-z]+(?:-[a-z]+)*\Z")
_CLAUDE_AGENT_WALK_LIMIT = 32768
_CLAUDE_AGENT_FRONTMATTER_LIMIT = 65536


def _claude_agents_from_dirs(agent_dirs: list[str]) -> list[dict[str, Any]]:
    """Resolve Claude agents by documented identity and scope precedence."""

    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for agent_dir in agent_dirs:
        scope_rows = _claude_agents_from_dir(agent_dir)
        scope_names: set[str] = set()
        for row in scope_rows:
            identity = str(row["id"])
            if identity in scope_names:
                raise AmbiguousClaudeAgentIdentityError(
                    f"Claude agent identity {identity!r} is duplicated under {agent_dir}",
                )
            scope_names.add(identity)
        for row in scope_rows:
            identity = str(row["id"])
            if identity in seen:
                continue
            seen.add(identity)
            rows.append(row)
    return rows


def _agents_from_codex_toml_dirs(
    agent_dirs: list[str],
) -> list[dict[str, Any]]:
    """Inventory Codex standalone custom-agent TOML without exposing prompts.

    Directories arrive highest-precedence first. Duplicate ``name`` values are
    retained for custody/tamper visibility and lower-precedence definitions are
    marked ``shadowed``. Project entries are candidates only: Codex activates
    them when the project is trusted, and filesystem inventory does not infer
    that private client decision.
    """
    rows: list[dict[str, Any]] = []
    seen_names: set[str] = set()
    user_agents = os.path.normcase(os.path.abspath(os.path.join(connector_paths.codex_home(), "agents")))
    for agents_dir in agent_dirs:
        entries = _safe_codex_directory_entries(agents_dir)
        if entries is None:
            continue
        scope = (
            "user"
            if os.path.normcase(os.path.abspath(agents_dir)) == user_agents
            else "project"
        )
        for entry in entries:
            if not entry.lower().endswith(".toml"):
                continue
            full = os.path.join(agents_dir, entry)
            data, parse_error = _load_codex_agent_toml(full)
            if parse_error.startswith("unreadable agent file:"):
                continue
            agent_id = os.path.splitext(entry)[0]
            if isinstance(data, dict):
                configured_name = data.get("name")
                if isinstance(configured_name, str) and configured_name.strip():
                    agent_id = configured_name.strip()
            required = ("name", "description", "developer_instructions")
            eligible = isinstance(data, dict) and all(
                isinstance(data.get(field), str) and data[field].strip()
                for field in required
            )
            # Codex ignores incomplete custom-agent TOML on every platform.
            # Do not admit an unloadable file as an active inventory row.
            if not eligible:
                continue
            row: dict[str, Any] = {
                "id": agent_id,
                "name": agent_id,
                "source": full,
                "kind": "custom-agent",
                "scope": scope,
                "trust_required": scope == "project",
                "eligible": eligible,
                "shadowed": agent_id in seen_names,
            }
            if isinstance(data, dict):
                for key in ("description", "model", "model_reasoning_effort", "sandbox_mode"):
                    value = data.get(key)
                    if isinstance(value, str) and value:
                        row[key] = value
            if parse_error:
                row["parse_error"] = parse_error
            seen_names.add(agent_id)
            rows.append(row)
    return rows


def _claude_agents_from_dir(agents_dir: str) -> list[dict[str, Any]]:
    if (
        not os.path.isdir(agents_dir)
        or is_symlink(agents_dir)
    ):
        return []
    rows: list[dict[str, Any]] = []
    visited = 0
    for current, dirs, files in os.walk(
        agents_dir,
        topdown=True,
        followlinks=False,
    ):
        dirs[:] = [
            name
            for name in sorted(dirs, key=str.casefold)
            if not is_symlink(os.path.join(current, name))
        ]
        visited += 1
        if visited > _CLAUDE_AGENT_WALK_LIMIT:
            dirs[:] = []
            break
        for filename in sorted(files, key=str.casefold):
            if not filename.lower().endswith(".md"):
                continue
            path = os.path.join(current, filename)
            if is_symlink(path):
                continue
            metadata = _read_claude_agent_frontmatter(path)
            if metadata is None:
                continue
            rows.append(
                {
                    "id": metadata["name"],
                    "name": metadata["name"],
                    "description": metadata["description"],
                    "source": path,
                    "kind": "subagent",
                }
            )
    return rows


def _agents_from_antigravity_dirs(agent_dirs: list[str]) -> list[dict[str, Any]]:
    """Read Antigravity's direct ``*.md`` and ``<name>/agent.md`` forms."""

    rows = _agents_from_md_dirs(agent_dirs)
    seen = {str(row.get("source") or "") for row in rows}
    for agents_dir in agent_dirs:
        entries = _safe_codex_directory_entries(agents_dir)
        if entries is None:
            continue
        for entry in entries:
            nested = os.path.join(agents_dir, entry)
            source = os.path.join(nested, "agent.md")
            if source in seen:
                continue
            try:
                connector_paths.reject_reparse_path(nested)
                nested_info = os.stat(nested, follow_symlinks=False)
                connector_paths.reject_reparse_path(source)
                source_info = os.stat(source, follow_symlinks=False)
            except OSError:
                continue
            if not stat.S_ISDIR(nested_info.st_mode) or not stat.S_ISREG(source_info.st_mode):
                continue
            seen.add(source)
            rows.append(
                {
                    "id": entry,
                    "name": entry,
                    "source": source,
                    "kind": "subagent",
                }
            )
    return rows


def _read_claude_agent_frontmatter(path: str) -> dict[str, str] | None:
    try:
        descriptor = open_regular_file_no_follow(path)
        with os.fdopen(descriptor, "rb") as source:
            raw = source.read(_CLAUDE_AGENT_FRONTMATTER_LIMIT + 1)
    except (OSError, ValueError):
        return None
    if len(raw) > _CLAUDE_AGENT_FRONTMATTER_LIMIT:
        raw = raw[:_CLAUDE_AGENT_FRONTMATTER_LIMIT]
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return None
    try:
        end = next(index for index, line in enumerate(lines[1:], start=1) if line.strip() == "---")
    except StopIteration:
        return None
    try:
        metadata = yaml.safe_load("\n".join(lines[1:end])) or {}
    except yaml.YAMLError:
        return None
    if not isinstance(metadata, dict):
        return None
    name = str(metadata.get("name") or "").strip()
    description = str(metadata.get("description") or "").strip()
    if not _CLAUDE_AGENT_NAME_PATTERN.fullmatch(name) or not description:
        return None
    return {"name": name, "description": description}


def _safe_codex_directory_entries(path: str) -> list[str] | None:
    """List one real directory after rejecting reparse ancestors and the leaf."""
    try:
        connector_paths.reject_reparse_path(path)
        before = os.stat(path, follow_symlinks=False)
        if not stat.S_ISDIR(before.st_mode):
            return None
        entries = sorted(os.listdir(path))
        connector_paths.reject_reparse_path(path)
        after = os.stat(path, follow_symlinks=False)
        if not stat.S_ISDIR(after.st_mode) or not os.path.samestat(before, after):
            return None
        return entries
    except OSError:
        return None


def _load_codex_agent_toml(path: str) -> tuple[dict[str, Any] | None, str]:
    """Safely parse one custom-agent TOML file with a bounded read."""
    try:
        payload = connector_paths._read_bounded_stable_file(
            path,
            max_bytes=1024 * 1024,
        )
    except OSError as exc:
        return None, f"unreadable agent file: {exc}"
    try:
        data = tomllib.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        return None, f"invalid TOML: {exc}"
    return data, ""


def _codex_custom_prompt_commands(prompts_dir: str) -> list[dict[str, Any]]:
    """Inventory deprecated Codex custom prompts as explicit slash commands."""

    if not os.path.isdir(prompts_dir):
        return []
    rows: list[dict[str, Any]] = []
    try:
        entries = sorted(os.listdir(prompts_dir))
    except OSError:
        return []
    for entry in entries:
        if not entry.endswith(".md"):
            continue
        path = os.path.join(prompts_dir, entry)
        if not os.path.isfile(path):
            continue
        command = os.path.splitext(entry)[0]
        rows.append(
            {
                "id": f"prompts:{command}",
                "name": f"/prompts:{command}",
                "description": "Deprecated Codex custom prompt; migrate reusable workflows to skills.",
                "source": path,
                "kind": "custom-command",
            }
        )
    return rows


def _agents_from_zeptoclaw_json(path: str) -> list[dict[str, Any]]:
    """``~/.zeptoclaw/agents.json`` is a list of agent records."""
    raw = _safe_load_json(path)
    if not isinstance(raw, list):
        return []
    rows: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        agent_id = item.get("id") or item.get("name")
        if not agent_id:
            continue
        rows.append(
            {
                "id": str(agent_id),
                "name": str(item.get("name") or agent_id),
                "description": str(item.get("description", "")),
                "source": path,
                "kind": "agent",
            }
        )
    return rows


def _tools_from_claude_settings(path: str) -> list[dict[str, Any]]:
    raw = _safe_load_json(path)
    if not isinstance(raw, dict):
        return []
    tools = raw.get("tools")
    rows: list[dict[str, Any]] = []
    if isinstance(tools, list):
        for item in tools:
            if isinstance(item, str):
                rows.append({"id": item, "name": item, "source": path})
            elif isinstance(item, dict) and (item.get("name") or item.get("id")):
                tool_id = item.get("id") or item.get("name")
                rows.append(
                    {
                        "id": str(tool_id),
                        "name": str(item.get("name") or tool_id),
                        "description": str(item.get("description", "")),
                        "source": path,
                    }
                )
    elif isinstance(tools, dict):
        for tool_id, item in tools.items():
            if isinstance(item, dict):
                rows.append(
                    {
                        "id": str(tool_id),
                        "name": str(item.get("name") or tool_id),
                        "description": str(item.get("description", "")),
                        "source": path,
                    }
                )
    return rows


def _tools_from_codex_config(path: str) -> list[dict[str, Any]]:
    """Codex's ``[tools]`` table — TOML."""
    if not os.path.isfile(path):
        return []
    try:
        # tomllib ships in the stdlib on Python 3.11+. On 3.10 (still an
        # advertised target) it is absent, so fall back to the tomli
        # backport rather than silently dropping Codex tool definitions.
        try:
            import tomllib
        except ModuleNotFoundError:
            import tomli as tomllib

        with open(path, "rb") as fh:
            raw = tomllib.load(fh)
    except (OSError, ValueError, ModuleNotFoundError):
        return []
    tools = raw.get("tools") if isinstance(raw, dict) else None
    if not isinstance(tools, dict):
        return []
    rows: list[dict[str, Any]] = []
    for tool_id, body in tools.items():
        if not isinstance(body, dict):
            rows.append({"id": str(tool_id), "name": str(tool_id), "source": path})
            continue
        rows.append(
            {
                "id": str(tool_id),
                "name": str(body.get("name") or tool_id),
                "description": str(body.get("description", "")),
                "source": path,
            }
        )
    return rows


def _tools_from_zeptoclaw_json(path: str) -> list[dict[str, Any]]:
    """ZeptoClaw stores agent + tool defs in a single agents.json."""
    raw = _safe_load_json(path)
    if not isinstance(raw, list):
        return []
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in raw:
        if not isinstance(item, dict):
            continue
        for tool in item.get("tools", []) or []:
            if not isinstance(tool, dict):
                continue
            tid = tool.get("id") or tool.get("name")
            if not tid or tid in seen:
                continue
            seen.add(tid)
            rows.append(
                {
                    "id": str(tid),
                    "name": str(tool.get("name") or tid),
                    "description": str(tool.get("description", "")),
                    "source": path,
                }
            )
    return rows


def _tools_from_opencode(cfg: Config) -> list[dict[str, Any]]:
    workspace = _connector_workspace_dir(cfg)
    rows = (
        _tools_from_script_dirs(
            _opencode_tool_dirs(workspace),
            kind="custom-tool",
            extensions=(".js", ".mjs", ".cjs", ".ts", ".mts", ".cts"),
        )
    )
    rows.extend(
        _tools_from_script_dirs(
            _opencode_command_dirs(workspace),
            kind="slash-command",
            extensions=(".md", ".txt"),
        )
    )
    return _dedup_tool_rows(rows)


def _tools_from_antigravity(cfg: Config) -> list[dict[str, Any]]:
    workspace = _connector_workspace_dir(cfg)
    return _dedup_tool_rows(
        _tools_from_script_dirs(
            _antigravity_command_dirs(workspace),
            kind="slash-command",
            extensions=(".md", ".txt", ".json", ".yaml", ".yml"),
        )
    )


def _connector_workspace_dir(cfg: Config) -> str:
    try:
        return cfg.connector_workspace_dir()
    except Exception:
        return ""


def _opencode_tool_dirs(workspace_dir: str) -> list[str]:
    home = os.path.expanduser("~")
    custom = os.environ.get("OPENCODE_CONFIG_DIR", "").strip()
    return _dedup_paths(
        [
            os.path.join(workspace_dir, ".opencode", "tool") if workspace_dir else "",
            os.path.join(workspace_dir, ".opencode", "tools") if workspace_dir else "",
            os.path.join(home, ".config", "opencode", "tool"),
            os.path.join(home, ".config", "opencode", "tools"),
            os.path.join(os.path.expanduser(custom), "tool") if custom else "",
            os.path.join(os.path.expanduser(custom), "tools") if custom else "",
        ]
    )

def _opencode_command_dirs(workspace_dir: str) -> list[str]:
    home = os.path.expanduser("~")
    custom = os.environ.get("OPENCODE_CONFIG_DIR", "").strip()
    return _dedup_paths(
        [
            os.path.join(workspace_dir, ".opencode", "command") if workspace_dir else "",
            os.path.join(workspace_dir, ".opencode", "commands") if workspace_dir else "",
            os.path.join(home, ".config", "opencode", "command"),
            os.path.join(home, ".config", "opencode", "commands"),
            os.path.join(os.path.expanduser(custom), "command") if custom else "",
            os.path.join(os.path.expanduser(custom), "commands") if custom else "",
        ]
    )


def _antigravity_command_dirs(workspace_dir: str) -> list[str]:
    home = os.path.expanduser("~")
    plugin_dirs = connector_paths.plugin_dirs("antigravity", workspace_dir=workspace_dir)
    return _dedup_paths(
        [
            os.path.join(workspace_dir, ".agents", "commands") if workspace_dir else "",
            os.path.join(workspace_dir, "_agents", "commands") if workspace_dir else "",
            os.path.join(home, ".gemini", "antigravity-cli", "commands"),
            *list(_plugin_component_dirs(plugin_dirs, "commands")),
        ]
    )


def _antigravity_agent_dirs(workspace_dir: str) -> list[str]:
    home = os.path.expanduser("~")
    plugin_dirs = connector_paths.plugin_dirs("antigravity", workspace_dir=workspace_dir)
    return _dedup_paths(
        [
            os.path.join(home, ".gemini", "config", "agents"),
            os.path.join(workspace_dir, ".agents", "agents") if workspace_dir else "",
            *list(_plugin_component_dirs(plugin_dirs, "agents")),
        ]
    )


def _plugin_component_dirs(plugin_dirs: list[str], component: str) -> list[str]:
    out: list[str] = []
    for plugin_dir in plugin_dirs:
        if not os.path.isdir(plugin_dir):
            continue
        try:
            entries = sorted(os.listdir(plugin_dir))
        except OSError:
            continue
        for entry in entries:
            plugin_root = os.path.join(plugin_dir, entry)
            if not os.path.isdir(plugin_root):
                continue
            component_dir = os.path.join(plugin_root, component)
            if os.path.isdir(component_dir):
                out.append(component_dir)
    return _dedup_paths(out)


def _agents_from_opencode_config(path: str) -> list[dict[str, Any]]:
    data = connector_paths._load_json_or_jsonc(path)  # type: ignore[attr-defined]
    if not isinstance(data, dict):
        return []
    raw_agents = data.get("agent")
    if not isinstance(raw_agents, dict):
        return []
    rows: list[dict[str, Any]] = []
    for agent_id, body in raw_agents.items():
        if isinstance(body, dict):
            rows.append(
                {
                    "id": str(agent_id),
                    "name": str(body.get("name") or agent_id),
                    "description": str(body.get("description", "")),
                    "source": path,
                    "kind": "agent",
                    "model": str(body.get("model", "")),
                }
            )
        else:
            rows.append(
                {
                    "id": str(agent_id),
                    "name": str(agent_id),
                    "source": path,
                    "kind": "agent",
                }
            )
    return rows


def _dedup_agent_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for row in rows:
        key = str(row.get("id", "")).casefold()
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(row)
    return out


def _tools_from_script_dirs(
    dirs: list[str],
    *,
    kind: str,
    extensions: tuple[str, ...],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for root in dirs:
        if not os.path.isdir(root):
            continue
        try:
            entries = sorted(os.listdir(root))
        except OSError:
            continue
        for entry in entries:
            full = os.path.join(root, entry)
            if not os.path.isfile(full):
                continue
            stem, ext = os.path.splitext(entry)
            if ext.lower() not in extensions:
                continue
            rows.append(
                {
                    "id": stem,
                    "name": stem,
                    "source": full,
                    "kind": kind,
                }
            )
    return rows


def _dedup_tool_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for row in rows:
        key = str(row.get("id") or row.get("name") or row.get("source") or "")
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(row)
    return out


def _dedup_paths(paths: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for path in paths:
        if not path or path in seen:
            continue
        seen.add(path)
        out.append(path)
    return out


def _providers_from_env(
    base_url_var: str,
    api_key_var: str,
    *,
    default_provider: str,
    default_base_url: str,
) -> list[dict[str, Any]]:
    """Synthesize a provider entry from env vars without leaking the key value.

    Only emits a row when at least ONE of the relevant env vars is
    actually set. This preserves the historical "no env -> empty BOM"
    contract that pre-C7 tests rely on, while still surfacing a
    provider record the moment an operator wires up either side
    (custom base URL or API key) of the connector env.
    """
    base_url_env = os.environ.get(base_url_var, "").strip()
    has_key = bool(os.environ.get(api_key_var, "").strip())
    if not base_url_env and not has_key:
        return []
    base_url = base_url_env or default_base_url
    return [
        {
            "id": default_provider,
            "name": default_provider,
            "base_url": base_url,
            "api_key_present": has_key,
            "source": f"env:{base_url_var}",
        }
    ]


def _providers_from_zeptoclaw_config(path: str) -> list[dict[str, Any]]:
    raw = _safe_load_json(path)
    if not isinstance(raw, dict):
        return []
    providers = raw.get("providers")
    if not isinstance(providers, dict):
        return []
    rows: list[dict[str, Any]] = []
    for pid, body in providers.items():
        if not isinstance(body, dict):
            continue
        rows.append(
            {
                "id": str(pid),
                "name": str(body.get("name") or pid),
                "base_url": str(body.get("api_base") or ""),
                # Don't echo the key. Reporting "present/absent" is the
                # only safe inventory signal.
                "api_key_present": bool(body.get("api_key")),
                "source": path,
            }
        )
    return rows


def _safe_load_json(path: str) -> Any:
    """Read JSON from *path*; return None on any I/O or parse error."""
    if not os.path.isfile(path):
        return None
    try:
        with open(path) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def _build_aibom_from_filesystem(
    cfg: Config,
    connector: str,
    cats: frozenset[str],
) -> dict[str, Any]:
    """Build an inventory by walking the on-disk skill / plugin / MCP
    layout for non-OpenClaw connectors.

    Mirrors the schema produced by the OpenClaw CLI path so callers
    (``defenseclaw aibom``, OPA enrichment, JSON serialization) can
    treat the result uniformly.
    """
    now = datetime.now(timezone.utc).isoformat()
    collectors: dict[str, Callable[[], list[dict[str, Any]]]] = {
        "skills": lambda: _enumerate_skills_filesystem(cfg, connector),
        "plugins": lambda: _enumerate_plugins_filesystem(cfg, connector),
        "mcp": lambda: _enumerate_mcp_filesystem(cfg, connector),
        "agents": lambda: _agents_for_connector(connector, cfg),
        "rules": lambda: _rules_for_connector(connector, cfg),
        "tools": lambda: _tools_for_connector(connector, cfg),
        "models": lambda: _model_providers_for_connector(connector, cfg),
        "memory": lambda: _memory_for_connector(connector, cfg),
    }
    results: dict[str, _FilesystemCollectionResult] = {}
    for category, collector in collectors.items():
        if category in cats:
            results[category] = _collect_filesystem_category(connector, category, collector)

    errors = [result.error for result in results.values() if result.error is not None]

    def _items(category: str) -> list[dict[str, Any]]:
        result = results.get(category)
        return result.items if result is not None else []

    skills = _items("skills")
    plugins = _items("plugins")
    mcps = _items("mcp")
    agents = _items("agents")
    rules = _items("rules")
    tools = _items("tools")
    model_providers = _items("models")
    memory = _items("memory")

    # Empty adapters for these connector-owned surfaces are deterministic
    # capability gaps, not failed commands. Keep them typed and separate so
    # automation never has to infer semantics from human-readable text.
    limitations: list[InventoryLimitation] = []
    for (partial_connector, cat_key), note in _PARTIAL_CONNECTOR_NOTES.items():
        if partial_connector != connector or cat_key not in cats:
            continue
        result = results.get(cat_key)
        if result is None or result.error is not None:
            continue
        limitations.append(
            {
                "connector": connector,
                "category": cat_key,
                "status": InventoryCapabilityStatus.UNSUPPORTED,
                "reason": note,
            }
        )
    if connector_paths.normalize(connector) == "claudecode" and "memory" in cats:
        memory_resolution = connector_paths.claude_auto_memory_resolution(
            _connector_workspace_dir(cfg),
        )
        if memory_resolution.limitation:
            limitations.append(
                {
                    "connector": connector,
                    "category": "memory",
                    "status": InventoryCapabilityStatus.UNVERIFIED,
                    "reason": memory_resolution.limitation,
                }
            )
    for cat_key, note in _FILESYSTEM_ONLY_CONNECTOR_NOTES.items():
        if connector == "codex" and cat_key == "agents":
            continue
        if cat_key not in cats:
            continue
        # Cursor has a documented local subagent surface. An empty directory is
        # a successful empty inventory, not an unsupported capability.
        if connector == "cursor" and cat_key == "agents":
            continue
        result = results.get(cat_key)
        if connector_paths.normalize(connector) == "claudecode" and cat_key == "memory":
            continue
        if result is None or result.error is not None:
            continue
        if (connector, cat_key) in _PARTIAL_CONNECTOR_NOTES:
            continue
        if result.items:
            continue
        limitations.append(
            {
                "connector": connector,
                "category": cat_key,
                "status": InventoryCapabilityStatus.UNSUPPORTED,
                "reason": note,
            }
        )

    out: dict[str, Any] = {
        "version": INVENTORY_VERSION,
        "generated_at": now,
        "connector": connector,
        "openclaw_config": _expand(cfg.claw.config_file),
        "claw_home": cfg.claw_home_dir(),
        # This builder is per-connector (filesystem) scoped, so the framework
        # "mode" is the connector being scanned — NOT the global cfg.claw.mode,
        # which in a multi-connector install is a stale pointer to whichever
        # connector was last activated (e.g. shows "antigravity" for a codex
        # scan). Mirrors single-connector installs where claw.mode == connector.
        "claw_mode": connector,
        "live": True,
        "skills": skills,
        "plugins": plugins,
        "mcp": mcps,
        "agents": agents,
        "rules": rules,
        "tools": tools,
        "model_providers": model_providers,
        "memory": memory,
        "errors": errors,
        "limitations": limitations,
    }
    if connector == "codex":
        out["extension_surfaces"] = _codex_extension_surfaces(cfg)
    _attach_connector_paths(out, cfg, connector)
    _sync_legacy_connector_paths(out)
    out["summary"] = _build_summary(out)
    return out


def _codex_extension_surfaces(cfg: Config) -> dict[str, dict[str, Any]]:
    """Describe every current official Codex CLI extension inventory surface."""

    workspace = _connector_workspace_dir(cfg)
    codex_root = connector_paths.connector_home("codex")
    home = os.path.expanduser("~")
    project_layers = connector_paths._codex_project_layer_dirs(workspace)
    project_root = project_layers[0] if project_layers else ""
    project_codex_dirs = [os.path.join(layer, ".codex") for layer in project_layers]
    project_agents_dirs = [os.path.join(layer, ".agents") for layer in reversed(project_layers)]
    instruction_paths = [
        os.path.join(codex_root, "AGENTS.override.md"),
        os.path.join(codex_root, "AGENTS.md"),
    ]
    for layer in project_layers:
        instruction_paths.extend(
            [
                os.path.join(layer, "AGENTS.override.md"),
                os.path.join(layer, "AGENTS.md"),
            ]
        )
    return {
        "config": {
            "classification": "I",
            "paths": _dedup_paths(
                [
                    os.path.join(codex_root, "config.toml"),
                    *(os.path.join(path, "config.toml") for path in project_codex_dirs),
                    "/etc/codex/config.toml",
                    "/etc/codex/managed_config.toml",
                    "/etc/codex/requirements.toml",
                ]
            ),
        },
        "hooks_notify_otel": {
            "classification": "I/L",
            "paths": _dedup_paths(
                [
                    os.path.join(codex_root, "config.toml"),
                    os.path.join(codex_root, "hooks.json"),
                    *(os.path.join(path, "hooks.json") for path in project_codex_dirs),
                ]
            ),
            "limitation": (
                "DefenseClaw inventories command hooks; prompt and agent hook handlers "
                "are parsed by Codex but skipped."
            ),
        },
        "mcp": {
            "classification": "I",
            "paths": _dedup_paths(
                [
                    os.path.join(codex_root, "config.toml"),
                    *(os.path.join(path, "config.toml") for path in project_codex_dirs),
                    "/etc/codex/config.toml",
                ]
            ),
        },
        "skills": {
            "classification": "I/L",
            "paths": _dedup_paths(
                [
                    os.path.join(home, ".agents", "skills"),
                    *(os.path.join(path, "skills") for path in project_agents_dirs),
                    "/etc/codex/skills",
                ]
            ),
            "limitation": "OpenAI-bundled system skills have no operator-owned filesystem root to scan.",
        },
        "plugins": {
            "classification": "I",
            "paths": _dedup_paths(
                [
                    os.path.join(codex_root, "plugins", "cache"),
                    os.path.join(home, ".agents", "plugins", "marketplace.json"),
                    os.path.join(home, ".agents", "plugins", "api_marketplace.json"),
                    os.path.join(home, ".claude-plugin", "marketplace.json"),
                    os.path.join(home, ".cursor-plugin", "marketplace.json"),
                    os.path.join(project_root, ".agents", "plugins", "marketplace.json")
                    if project_root
                    else "",
                    os.path.join(project_root, ".agents", "plugins", "api_marketplace.json")
                    if project_root
                    else "",
                    os.path.join(project_root, ".claude-plugin", "marketplace.json")
                    if project_root
                    else "",
                    os.path.join(project_root, ".cursor-plugin", "marketplace.json")
                    if project_root
                    else "",
                ]
            ),
        },
        "rules": {
            "classification": "I/L",
            "paths": _dedup_paths(
                [
                    os.path.join(codex_root, "rules"),
                    *(os.path.join(path, "rules") for path in project_codex_dirs),
                    "/etc/codex/rules",
                    "/etc/codex/requirements.toml",
                ]
            ),
            "limitation": "Project rules are effective only for a trusted project config layer.",
        },
        "instructions_agents_md": {
            "classification": "I/L",
            "paths": _dedup_paths(instruction_paths),
            "limitation": (
                "The inventory is bounded to the explicitly pinned workspace; Codex "
                "resolves nested precedence at session start."
            ),
        },
        "custom_agents": {
            "classification": "I",
            "paths": _dedup_paths(
                [
                    os.path.join(codex_root, "agents"),
                    *(os.path.join(path, "agents") for path in project_codex_dirs),
                ]
            ),
        },
        "microagents": {
            "classification": "N/A",
            "paths": [],
            "limitation": (
                "Codex exposes custom agents and subagents; it does not document a "
                "separate connector-owned microagents extension directory."
            ),
        },
        "custom_commands": {
            "classification": "L",
            "paths": [os.path.join(codex_root, "prompts")],
            "limitation": (
                "Custom prompts remain readable as /prompts:* commands but are deprecated; "
                "skills are the supported replacement."
            ),
        },
        "legacy_extensions_directory": {
            "classification": "N/A",
            "paths": [],
            "limitation": (
                "Current Codex plugins use marketplace metadata and the plugin cache; "
                "DefenseClaw does not invent ~/.codex/extensions."
            ),
        },
        "separate_memory_files": {
            "classification": "N/A",
            "paths": [],
            "limitation": "No current official connector-owned memory-file extension root is documented for Codex CLI.",
        },
    }


def _enumerate_skills_filesystem(
    cfg: Config,
    connector: str | None = None,
) -> list[dict[str, Any]]:
    """Walk every directory in ``cfg.skill_dirs(connector)`` and emit one
    row per immediate subdirectory. Codex's reserved ``.system`` container is
    expanded into its marked child skills instead of being reported as one
    ineligible skill.

    A skill is treated as the directory itself; its ``id`` is the
    basename. ``eligible`` is True if the directory contains at
    least one of: SKILL.md, skill.json, README.md (matches the
    discovery contract used by the connector-specific OTel
    component scanner). ``connector`` scopes the walk to a specific
    connector for multi-connector focus (defaults to active).
    """
    from defenseclaw.skill_discovery import discover_skill_directories

    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    resolved_connector = connector or cfg.active_connector()
    normalized_connector = connector_paths.normalize(resolved_connector)
    claude_workspace = (
        cfg.connector_workspace_dir()
        if normalized_connector in {"claude", "claudecode"}
        else ""
    )
    for skill_dir in cfg.skill_dirs(connector):
        for discovered in discover_skill_directories(
            skill_dir,
            connector=resolved_connector,
        ):
            entry = discovered.name
            if _is_openhands_installed_container(skill_dir, entry):
                continue
            full = discovered.path
            row_id = entry
            nested_prefix = _claude_nested_skill_prefix(
                skill_dir,
                claude_workspace,
            )
            if normalized_connector in {"claude", "claudecode"}:
                identity = row_id
                if identity in seen:
                    if not nested_prefix:
                        continue
                    row_id = f"{nested_prefix}:{entry}"
                    identity = row_id
                    if identity in seen:
                        continue
            else:
                identity = full if normalized_connector == "codex" else entry
                if identity in seen:
                    continue
            seen.add(identity)
            row: dict[str, Any] = {
                "id": row_id,
                "source": discovered.source,
                "eligible": _skill_dir_is_eligible(full),
                "enabled": not bool(nested_prefix),
                "activation_verified": not bool(nested_prefix),
                "bundled": discovered.bundled,
                "path": full,
            }
            if nested_prefix:
                row["activation_state"] = "discoverable-unverified"
            description = _read_skill_description(full)
            if description:
                row["description"] = description
            rows.append(row)
    return rows


def _claude_nested_skill_prefix(skill_dir: str, workspace_dir: str) -> str:
    """Return Claude's directory qualifier for a nested project skill root."""

    if not workspace_dir:
        return ""
    normalized = os.path.normpath(skill_dir)
    if (
        os.path.basename(normalized).casefold() != "skills"
        or os.path.basename(os.path.dirname(normalized)).casefold() != ".claude"
    ):
        return ""
    project_dir = os.path.dirname(os.path.dirname(normalized))
    try:
        relative = os.path.relpath(project_dir, workspace_dir)
    except ValueError:
        return ""
    if relative in {"", "."} or relative == ".." or relative.startswith(f"..{os.sep}"):
        return ""
    return relative.replace(os.sep, "/")


def _is_openhands_installed_container(skill_dir: str, entry: str) -> bool:
    return (
        entry == "installed"
        and os.path.basename(skill_dir) == "skills"
        and os.path.basename(os.path.dirname(skill_dir)) == ".openhands"
    )


def _skill_dir_is_eligible(path: str) -> bool:
    if (
        os.path.isfile(path)
        and not os.path.islink(path)
        and os.path.splitext(path)[1].casefold() == ".md"
    ):
        return True
    from defenseclaw.skill_discovery import skill_dir_is_eligible

    return skill_dir_is_eligible(path)


def _read_skill_description(path: str) -> str:
    """Return a short description from SKILL.md / README.md, if any.

    Bounded to 2 KiB so we don't accidentally slurp a multi-MB README
    into the inventory dict.
    """
    marker_paths = [path] if os.path.isfile(path) else []
    for marker_path in marker_paths:
        # F-0424: a skill directory is attacker-influenced content. A
        # ``SKILL.md``/``README.md`` that is a symlink could point at an
        # arbitrary readable file (``~/.ssh/id_rsa``, ``/etc/passwd``, …)
        # and leak its first lines into the inventory ``description``.
        # Reject symlinked markers and open with ``O_NOFOLLOW`` so the
        # final component cannot be a symlink even under a TOCTOU race.
        try:
            if os.path.islink(marker_path):
                continue
        except OSError:
            continue
        if not os.path.isfile(marker_path):
            continue
        try:
            fd = os.open(marker_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        except OSError:
            continue
        try:
            reader = os.fdopen(fd, encoding="utf-8", errors="replace")
        except OSError:
            try:
                os.close(fd)
            except OSError:
                pass
            continue
        try:
            with reader as f:
                text = f.read(2048)
        except OSError:
            continue
        frontmatter_description = _frontmatter_description(text)
        if frontmatter_description:
            return frontmatter_description[:200]
        for line in text.splitlines():
            stripped = line.strip().lstrip("#").strip()
            if stripped:
                return stripped[:200]

    from defenseclaw.skill_discovery import read_skill_marker_text

    for marker in ("SKILL.md", "README.md"):
        text = read_skill_marker_text(path, marker, max_bytes=2048)
        if text is None:
            continue
        frontmatter_description = _frontmatter_description(text)
        if frontmatter_description:
            return frontmatter_description[:200]
        for line in text.splitlines():
            stripped = line.strip().lstrip("#").strip()
            if stripped:
                return stripped[:200]
    return ""


def _frontmatter_description(text: str) -> str:
    if not text.startswith("---"):
        return ""
    end = text.find("\n---", 3)
    if end < 0:
        return ""
    for line in text[3:end].splitlines():
        key, sep, value = line.partition(":")
        if sep and key.strip() == "description":
            return value.strip().strip("\"'")
    return ""


def _enumerate_plugins_filesystem(
    cfg: Config,
    connector: str | None = None,
) -> list[dict[str, Any]]:
    """One row per logical plugin under ``cfg.plugin_dirs(connector)``.

    A plugin is treated as a directory containing one of the
    documented manifest names (matches plugin_scanner._MANIFEST_CANDIDATES
    after S2.3): package.json, manifest.json, plugin.json,
    openclaw.plugin.json, .codex-plugin/plugin.json,
    .claude-plugin/plugin.json, .cursor-plugin/plugin.json. Codex cache
    registry buckets are expanded to their exact manifest roots and logical
    names are deduplicated using Codex's active-plugin metadata. ``connector``
    scopes the walk for multi-connector focus (defaults to active).
    """
    rows: list[dict[str, Any]] = []
    seen: dict[str, str] = {}
    resolved_connector = connector or cfg.active_connector()
    workspace_dir = _connector_workspace_dir(cfg)
    if connector_paths.normalize(resolved_connector) == "opencode":
        for plugin_dir in connector_paths.plugin_dirs("opencode", workspace_dir=workspace_dir):
            if not os.path.isdir(plugin_dir):
                continue
            try:
                entries = sorted(os.listdir(plugin_dir))
            except OSError:
                continue
            for entry in entries:
                full = os.path.join(plugin_dir, entry)
                if not os.path.isfile(full) or not entry.lower().endswith(
                    (".js", ".mjs", ".cjs", ".ts", ".mts", ".cts")
                ):
                    continue
                plugin_id = os.path.splitext(entry)[0]
                if plugin_id.casefold() in seen:
                    continue
                seen[plugin_id.casefold()] = full
                rows.append({
                    "id": plugin_id,
                    "name": plugin_id,
                    "origin": plugin_dir,
                    "enabled": True,
                    "status": "loaded",
                    "path": full,
                })
        for path in connector_paths._opencode_config_paths(workspace_dir):  # type: ignore[attr-defined]
            data = connector_paths._load_json_or_jsonc(path)  # type: ignore[attr-defined]
            configured = data.get("plugin") if isinstance(data, dict) else None
            if not isinstance(configured, list):
                continue
            for value in configured:
                if not isinstance(value, str) or not value.strip():
                    continue
                plugin_id = value.strip()
                if plugin_id.casefold() in seen:
                    continue
                seen[plugin_id.casefold()] = path
                rows.append({
                    "id": plugin_id,
                    "name": plugin_id,
                    "origin": path,
                    "enabled": True,
                    "status": "configured",
                    "path": path,
                })
        return rows
    plugin_dirs = (
        connector_paths.plugin_inventory_dirs(
            resolved_connector,
            openclaw_home=cfg.claw.home_dir,
            workspace_dir=workspace_dir,
        )
        if connector_paths.normalize(resolved_connector) == "cursor"
        else cfg.plugin_dirs(connector)
    )
    exact_codex_sources = (
        {
            os.path.normcase(os.path.abspath(path))
            for path in connector_paths.codex_marketplace_plugin_dirs(
                workspace_dir
            )
        }
        if connector_paths.normalize(resolved_connector) == "codex"
        else set()
    )
    for plugin_dir in plugin_dirs:
        normalized = os.path.normcase(os.path.abspath(plugin_dir))
        discovered_plugins = (
            discover_exact_plugin_directory(plugin_dir, origin="codex marketplace")
            if normalized in exact_codex_sources
            else discover_plugin_directories(
                plugin_dir,
                connector=resolved_connector,
                workspace_dir=workspace_dir,
            )
        )
        for discovered in discovered_plugins:
            entry = discovered.id
            entry_key = filesystem_identity_key(entry, plugin_dir)
            full = discovered.path
            if entry_key in seen:
                if os.path.realpath(seen[entry_key]) == os.path.realpath(full):
                    continue
                raise AmbiguousPluginIdentityError(
                    f"ambiguous plugin identity {entry!r}: {seen[entry_key]}, {full}; "
                    "remove or rename duplicate directories"
                )
            seen[entry_key] = full
            manifest = discovered.manifest or _detect_plugin_manifest(full)
            row: dict[str, Any] = {
                "id": entry,
                "name": discovered.name or entry,
                "version": discovered.version,
                "origin": discovered.origin or plugin_dir,
                "enabled": discovered.enabled,
                "status": (
                    "no-manifest"
                    if not manifest
                    else "loaded"
                    if discovered.enabled
                    else "cache-unverified"
                    if discovered.cached and not discovered.activation_verified
                    else "disabled"
                ),
                "path": full,
            }
            if manifest:
                row["manifest"] = manifest.replace("\\", "/")
            if discovered.description:
                row["description"] = discovered.description
            if discovered.registry:
                row["registry"] = discovered.registry
            if discovered.cached:
                row["cached"] = True
                row["activation_verified"] = discovered.activation_verified
            if discovered.logical_id and discovered.logical_id != discovered.id:
                row["logical_id"] = discovered.logical_id
            rows.append(row)
    return rows


_PLUGIN_MANIFEST_FILES: tuple[str, ...] = (
    "package.json",
    "manifest.json",
    "plugin.json",
    "openclaw.plugin.json",
    os.path.join(".codex-plugin", "plugin.json"),
    os.path.join(".claude-plugin", "plugin.json"),
    os.path.join(".cursor-plugin", "plugin.json"),
)


def _detect_plugin_manifest(plugin_root: str) -> str:
    for rel in _PLUGIN_MANIFEST_FILES:
        candidate = os.path.join(plugin_root, rel)
        if os.path.isfile(candidate):
            return rel
    return ""


def _enumerate_mcp_filesystem(
    cfg: Config,
    connector: str | None = None,
) -> list[dict[str, Any]]:
    """Read MCP servers via the connector-aware
    :meth:`Config.mcp_servers` helper and convert
    :class:`MCPServerEntry` rows into the inventory dict shape used by
    the OpenClaw CLI parser. ``connector`` scopes the read for
    multi-connector focus (defaults to active).
    """
    rows: list[dict[str, Any]] = []
    resolved = connector or cfg.active_connector()
    for entry in cfg.mcp_servers(connector):
        row: dict[str, Any] = {
            "id": entry.name,
            "source": entry.source or f"{resolved} mcp registry",
        }
        if entry.command:
            row["command"] = entry.command
        if entry.args:
            row["args"] = list(entry.args)
        if entry.url:
            row["url"] = entry.url
        if entry.transport:
            row["transport"] = entry.transport
        if entry.env:
            row["env_keys"] = sorted(entry.env.keys())
        if entry.source_scope:
            row["scope"] = entry.source_scope
        if entry.trust_required:
            row["trust_required"] = True
        rows.append(row)
    return rows
