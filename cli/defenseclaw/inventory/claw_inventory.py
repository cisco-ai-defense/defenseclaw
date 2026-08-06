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

import hashlib
import heapq
import importlib.metadata
import importlib.util
import json
import os
import re
import stat
import subprocess
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
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
    read_amp_plugin_source,
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

_ANTIGRAVITY_RULE_FILE_MAX_BYTES = 1 << 20
_ANTIGRAVITY_RULE_DIRECTORY_MAX_ENTRIES = 4096
_ANTIGRAVITY_RULE_INVENTORY_MAX_FILES = 16_384

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
    try:
        out["connector_rule_files"] = connector_paths.rule_paths(
            connector,
            workspace_dir=cfg.connector_workspace_dir(),
        )
    except Exception:
        out["connector_rule_files"] = []
    try:
        out["connector_policy_settings"] = connector_paths.connector_policy_settings(
            connector,
            workspace_dir=cfg.connector_workspace_dir(),
        )
    except Exception:
        out["connector_policy_settings"] = {}


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
        if (
            base.endswith(".json")
            or base.endswith(".jsonc")
            or base.endswith(".toml")
            or base.endswith(".yaml")
            or base.endswith(".yml")
        ):
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
        "windsurf",
        "skills",
    ): (
        "legacy Cascade user and pinned-workspace .windsurf/skills and "
        ".agents/skills roots are inventoried with no-follow discovery; "
        "optional Claude-config reading plus system/ProgramData and managed "
        "enterprise skill layers are excluded and unverified"
    ),
    (
        "windsurf",
        "rules",
    ): (
        "legacy Cascade user-global, preferred .devin/rules, legacy "
        ".windsurf/rules and .windsurfrules, and recursive/ancestor AGENTS.md "
        "sources are inventoried with bounded no-follow discovery; cloud "
        "dashboard, MDM, ProgramData/system, and effective higher-layer "
        "enforcement are excluded and unverified"
    ),
    (
        "windsurf",
        "mcp",
    ): (
        "only the legacy Cascade mcp_config.json under the persisted bound "
        "WINDSURF_USER_HOME is inventoried; Devin Local config files, cloud, "
        "Team/Enterprise registry, and allowlist state are unsupported and "
        "unverified"
    ),
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
    (
        "copilot",
        "rules",
    ): (
        "documented personal, repository-root, current-workspace, intermediate, "
        "nested active-file candidates, modular, imported, and "
        "COPILOT_CUSTOM_INSTRUCTIONS_DIRS sources are inventoried with no-follow "
        "file/directory/size bounds and collision metadata; exact active-file "
        "selection, path-specific applyTo, session enable/disable state, folder "
        "trust, managed/organization policy, and remote instructions remain "
        "unverified"
    ),
    (
        "copilot",
        "plugins",
    ): (
        "declared plugins are queried only through the trusted Copilot executable "
        "with `plugins list --kind plugin --json`, the pinned workspace, and exact "
        "COPILOT_HOME; semantic activation and managed/organization policy remain "
        "unverified without live-session evidence"
    ),
}

_UNVERIFIED_CONNECTOR_NOTES: dict[tuple[str, str], str] = {
    (
        "cursor",
        "skills",
    ): (
        "local project/user Cursor, Agents, Claude, and Codex skill roots plus "
        "nested project Cursor/Agents roots are scanned recursively and without "
        "following aliases; multi-root, cloud, team/private, marketplace, and "
        "dynamic plugin skill activation require official-client evidence"
    ),
    (
        "cursor",
        "plugins",
    ): (
        "only the documented local plugin directory is inspectable; marketplace, "
        "team/private, cloud, and dynamically registered plugins are unverified"
    ),
    (
        "cursor",
        "mcp",
    ): (
        "project and user mcp.json candidates are retained without inventing a "
        "same-name winner; extension-registered dynamic servers, cloud/team "
        "sources, multi-root activation, and the effective runtime selection are unverified"
    ),
    (
        "cursor",
        "agents",
    ): (
        "project/user .cursor, .claude, and .codex subagent files are inventoried "
        "with documented scope precedence; multi-root, cloud, team/private, "
        "marketplace/dynamic, and runtime-only subagents are unverified"
    ),
    (
        "cursor",
        "rules",
    ): (
        "local .cursor/rules/**/*.mdc and root/nested AGENTS.md are inventoried; "
        "user UI rules, team/private rules, cloud state, multi-root activation, "
        "and effective runtime ordering are unverified"
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
    * amp        — static plugin metadata and ``createAgent({name})`` calls
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
        return _agents_from_cursor_dirs(
            connector_paths.agent_dirs(
                name,
                workspace_dir=_connector_workspace_dir(cfg),
            )
        )
    if name == "antigravity":
        return _agents_from_antigravity_dirs(_antigravity_agent_dirs(_connector_workspace_dir(cfg)))
    if name == "amp":
        return _agents_from_amp_plugins(cfg)
    return []


def _rules_for_connector(connector: str, cfg: Config) -> list[dict[str, Any]]:
    """Enumerate documented local rule/instruction files without evaluating them."""
    normalized = connector_paths.normalize(connector)
    if normalized == "hermes":
        soul = os.path.join(connector_paths.hermes_home(), "SOUL.md")
        try:
            info = os.lstat(soul)
        except OSError:
            return []
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            return []
        return [
            {
                "id": "SOUL.md",
                "name": "SOUL.md",
                "source": soul,
                "kind": "identity",
                "scope": "default-profile",
                "activation_source": "HERMES_HOME/SOUL.md",
                "activation_verified": False,
            }
        ]
    if normalized == "antigravity":
        return _antigravity_rules(cfg)
    if normalized == "copilot":
        return _copilot_instruction_rules(_connector_workspace_dir(cfg))
    if normalized == "cursor":
        return _cursor_rules_from_workspace(_connector_workspace_dir(cfg))
    if normalized == "windsurf":
        workspace = _connector_workspace_dir(cfg)
        rows: list[dict[str, Any]] = []
        for source in connector_paths.windsurf_rule_files(workspace):
            folded_parts = [part.casefold() for part in Path(source).parts]
            filename = os.path.basename(source)
            filename_folded = filename.casefold()
            if filename_folded == "global_rules.md":
                kind = "global-rule"
                source_format = "user-global"
            elif filename_folded == "agents.md":
                kind = "agents-md"
                source_format = "directory-scoped"
            elif filename_folded == ".windsurfrules":
                kind = "legacy-rule"
                source_format = "legacy-single-file"
            elif ".devin" in folded_parts:
                kind = "rule"
                source_format = "preferred-devin"
            elif ".windsurf" in folded_parts:
                kind = "legacy-rule"
                source_format = "legacy-windsurf"
            else:
                kind = "global-rule"
                source_format = "user-global"

            identity = source
            if workspace:
                try:
                    relative = os.path.relpath(source, workspace)
                except ValueError:
                    relative = source
                if relative != os.pardir and not relative.startswith(os.pardir + os.sep):
                    identity = relative
            rows.append(
                {
                    "id": identity.replace(os.sep, "/"),
                    "name": filename,
                    "source": source,
                    "scope": "user" if source_format == "user-global" else "workspace",
                    "kind": kind,
                    "source_format": source_format,
                    "discovery_only": True,
                    "activation_verified": False,
                }
            )
        return rows
    if normalized != "codex":
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


_COPILOT_INSTRUCTION_FILE_LIMIT = 2048
_COPILOT_INSTRUCTION_DIR_LIMIT = 1024
_COPILOT_INSTRUCTION_BYTES = 1024 * 1024
_COPILOT_IMPORT_DEPTH = 8
_COPILOT_CUSTOM_DIR_LIMIT = 32


def _extend_copilot_candidates(
    target: list[tuple[str, str, str, str]],
    additions: list[tuple[str, str, str, str]],
) -> None:
    remaining = _COPILOT_INSTRUCTION_FILE_LIMIT - len(target)
    if remaining > 0:
        target.extend(additions[:remaining])


def _copilot_instruction_rules(workspace: str) -> list[dict[str, Any]]:
    """Inventory Copilot's documented local instruction cascade.

    Copilot combines applicable instruction files and documents no general
    winner. Rows therefore expose collisions instead of manufacturing a
    precedence order. Runtime trust, active-file matching, session toggles,
    managed policy, and remote instructions remain explicitly unverified.
    """

    candidates: list[tuple[str, str, str, str]] = []
    home = connector_paths.copilot_home()
    candidates.append((os.path.join(home, "copilot-instructions.md"), "user", "general", home))
    _extend_copilot_candidates(
        candidates,
        _copilot_recursive_instruction_candidates(
            os.path.join(home, "instructions"),
            suffix=".instructions.md",
            scope="user",
            kind="path-specific",
        )
    )

    ancestors = connector_paths._copilot_workspace_ancestors(workspace) if workspace else []
    if ancestors:
        repository = ancestors[-1]
        # General files are loaded at the repository root, current workspace,
        # and intermediate directories. Root-to-workspace order is only for
        # deterministic output; it does not imply semantic priority.
        for root in reversed(ancestors):
            for relative in (
                os.path.join(".github", "copilot-instructions.md"),
                "AGENTS.md",
                "CLAUDE.md",
                os.path.join(".claude", "CLAUDE.md"),
                "GEMINI.md",
            ):
                if len(candidates) < _COPILOT_INSTRUCTION_FILE_LIMIT:
                    candidates.append(
                        (os.path.join(root, relative), "project", "general", repository)
                    )
        _extend_copilot_candidates(
            candidates,
            _copilot_recursive_instruction_candidates(
                repository,
                scope="project",
                kind="general",
                general_names=True,
            )
        )
        modular_roots = [os.path.join(repository, ".github", "instructions")]
        current_modular = os.path.join(ancestors[0], ".github", "instructions")
        if os.path.normcase(current_modular) != os.path.normcase(modular_roots[0]):
            modular_roots.append(current_modular)
        for root in modular_roots:
            _extend_copilot_candidates(
                candidates,
                _copilot_recursive_instruction_candidates(
                    root,
                    suffix=".instructions.md",
                    scope="project",
                    kind="path-specific",
                )
            )
        intermediate_roots = {
            os.path.normcase(os.path.abspath(root)) for root in ancestors[1:-1]
        }
        for candidate in _copilot_recursive_instruction_candidates(
            repository,
            suffix=".instructions.md",
            scope="project",
            kind="path-specific",
        ):
            owner = _copilot_modular_instruction_owner(candidate[0], repository)
            if owner is None or os.path.normcase(owner) in intermediate_roots:
                continue
            if len(candidates) < _COPILOT_INSTRUCTION_FILE_LIMIT:
                candidates.append(candidate)

    custom_roots = os.environ.get("COPILOT_CUSTOM_INSTRUCTIONS_DIRS", "").split(",")
    for raw in custom_roots[:_COPILOT_CUSTOM_DIR_LIMIT]:
        custom = os.path.expanduser(_expand(raw.strip()))
        if not custom:
            continue
        if not os.path.isabs(custom):
            if not workspace:
                continue
            custom = os.path.join(workspace, custom)
        custom = os.path.abspath(custom)
        if len(candidates) < _COPILOT_INSTRUCTION_FILE_LIMIT:
            candidates.append((os.path.join(custom, "AGENTS.md"), "custom", "general", custom))
        _extend_copilot_candidates(
            candidates,
            _copilot_recursive_instruction_candidates(
                custom,
                suffix=".instructions.md",
                scope="custom",
                kind="path-specific",
            )
        )

    rows: list[dict[str, Any]] = []
    seen_paths: set[str] = set()
    seen_general_content: set[str] = set()
    pending = list(candidates)
    import_depth: dict[str, int] = {}
    while pending and len(rows) < _COPILOT_INSTRUCTION_FILE_LIMIT:
        path, scope, kind, allowed_root = pending.pop(0)
        key = os.path.normcase(os.path.abspath(path))
        if key in seen_paths:
            continue
        seen_paths.add(key)
        payload = _read_copilot_instruction(path, allowed_root)
        if payload is None:
            continue
        digest = hashlib.sha256(payload).hexdigest()
        if kind == "general":
            if digest in seen_general_content:
                continue
            seen_general_content.add(digest)
        row = {
            "id": os.path.basename(path),
            "name": os.path.basename(path),
            "source": os.path.abspath(path),
            "kind": kind,
            "scope": scope,
            "content_sha256": digest,
            "precedence": "combined-no-general-precedence",
            "activation_verified": False,
            "activation_state": "declared-unverified",
            "no_follow_verified": True,
        }
        rows.append(row)

        depth = import_depth.get(key, 0)
        import_capable = kind == "import" or os.path.basename(path).casefold() in {
            "copilot-instructions.md",
            "agents.md",
            "claude.md",
        }
        if depth >= _COPILOT_IMPORT_DEPTH or kind == "path-specific" or not import_capable:
            continue
        remaining = _COPILOT_INSTRUCTION_FILE_LIMIT - len(rows) - len(pending)
        for imported in _copilot_instruction_imports(
            payload,
            os.path.dirname(path),
            limit=max(remaining, 0),
        ):
            imported_key = os.path.normcase(os.path.abspath(imported))
            if imported_key not in seen_paths:
                import_depth[imported_key] = depth + 1
                pending.append((imported, scope, "import", allowed_root))

    by_name: dict[str, int] = {}
    for row in rows:
        key = str(row["name"]).casefold()
        by_name[key] = by_name.get(key, 0) + 1
    for row in rows:
        row["collision"] = by_name[str(row["name"]).casefold()] > 1
    return rows


def _copilot_recursive_instruction_candidates(
    root: str,
    *,
    suffix: str = "",
    scope: str,
    kind: str,
    general_names: bool = False,
) -> list[tuple[str, str, str, str]]:
    try:
        connector_paths.reject_reparse_path(root)
        root_info = os.stat(root, follow_symlinks=False)
    except OSError:
        return []
    if not stat.S_ISDIR(root_info.st_mode):
        return []
    rows: list[tuple[str, str, str, str]] = []
    pending = [root]
    visited = 0
    while pending and visited < _COPILOT_INSTRUCTION_DIR_LIMIT:
        current = pending.pop(0)
        visited += 1
        directory_budget = max(
            _COPILOT_INSTRUCTION_DIR_LIMIT - visited - len(pending),
            0,
        )
        file_budget = max(_COPILOT_INSTRUCTION_FILE_LIMIT - len(rows), 0)
        try:
            connector_paths.reject_reparse_path(current)
            before = os.stat(current, follow_symlinks=False)
            if not stat.S_ISDIR(before.st_mode):
                continue
            with os.scandir(current) as iterator:
                directory_entries = heapq.nsmallest(
                    directory_budget,
                    (entry for entry in iterator if _copilot_entry_is_directory(entry)),
                    key=lambda item: item.name.casefold(),
                )
            with os.scandir(current) as iterator:
                file_entries = heapq.nsmallest(
                    file_budget,
                    (
                        entry
                        for entry in iterator
                        if _copilot_entry_is_instruction_file(
                            entry,
                            current=current,
                            suffix=suffix,
                            general_names=general_names,
                        )
                    ),
                    key=lambda item: item.name.casefold(),
                )
        except OSError:
            continue
        child_dirs: list[str] = []
        child_files: list[tuple[str, str, str, str]] = []
        for entry in directory_entries:
            if entry.name.casefold() == ".git":
                continue
            try:
                info = entry.stat(follow_symlinks=False)
            except OSError:
                continue
            if entry.is_symlink():
                continue
            if stat.S_ISDIR(info.st_mode):
                child_dirs.append(entry.path)
        for entry in file_entries:
            try:
                info = entry.stat(follow_symlinks=False)
            except OSError:
                continue
            if not entry.is_symlink() and stat.S_ISREG(info.st_mode):
                child_files.append((entry.path, scope, kind, root))
        try:
            connector_paths.reject_reparse_path(current)
            after = os.stat(current, follow_symlinks=False)
        except OSError:
            continue
        before_identity = (
            before.st_dev,
            before.st_ino,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if before_identity != after_identity:
            continue
        pending.extend(child_dirs)
        rows.extend(child_files)
        if len(rows) >= _COPILOT_INSTRUCTION_FILE_LIMIT:
            return rows[:_COPILOT_INSTRUCTION_FILE_LIMIT]
    return rows


def _copilot_entry_is_directory(entry: os.DirEntry[str]) -> bool:
    try:
        return (
            entry.name.casefold() != ".git"
            and not entry.is_symlink()
            and stat.S_ISDIR(entry.stat(follow_symlinks=False).st_mode)
        )
    except OSError:
        return False


def _copilot_entry_is_instruction_file(
    entry: os.DirEntry[str],
    *,
    current: str,
    suffix: str,
    general_names: bool,
) -> bool:
    try:
        if entry.is_symlink() or not stat.S_ISREG(entry.stat(follow_symlinks=False).st_mode):
            return False
    except OSError:
        return False
    name = entry.name.casefold()
    return bool(
        (
            general_names
            and (
                name in {"agents.md", "claude.md", "gemini.md"}
                or (
                    name == "copilot-instructions.md"
                    and os.path.basename(current).casefold() == ".github"
                )
            )
        )
        or (suffix and name.endswith(suffix))
    )


def _read_copilot_instruction(path: str, allowed_root: str) -> bytes | None:
    absolute = os.path.abspath(path)
    root = os.path.abspath(allowed_root)
    try:
        if os.path.normcase(os.path.commonpath((absolute, root))) != os.path.normcase(root):
            return None
        real_absolute = os.path.realpath(absolute)
        real_root = os.path.realpath(root)
        if os.path.normcase(os.path.commonpath((real_absolute, real_root))) != os.path.normcase(
            real_root
        ):
            return None
        connector_paths.reject_reparse_path(absolute)
        return connector_paths._read_bounded_stable_file(
            absolute,
            max_bytes=_COPILOT_INSTRUCTION_BYTES,
        )
    except (OSError, ValueError):
        return None


def _copilot_modular_instruction_owner(path: str, repository: str) -> str | None:
    """Return the directory owning a ``.github/instructions`` tree."""

    try:
        relative = os.path.relpath(os.path.abspath(path), os.path.abspath(repository))
    except ValueError:
        return None
    if relative == os.pardir or relative.startswith(os.pardir + os.sep):
        return None
    parts = relative.split(os.sep)
    for index in range(len(parts) - 2):
        if parts[index].casefold() == ".github" and parts[index + 1].casefold() == "instructions":
            owner_parts = parts[:index]
            return os.path.abspath(os.path.join(repository, *owner_parts))
    return None


def _copilot_instruction_imports(payload: bytes, parent: str, *, limit: int) -> list[str]:
    try:
        text = payload.decode("utf-8-sig")
    except UnicodeDecodeError:
        return []
    out: list[str] = []
    if limit <= 0:
        return out
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("@"):
            continue
        raw = stripped[1:].strip().strip("'\"")
        if not raw or "://" in raw or os.path.isabs(raw) or raw.startswith("~"):
            continue
        out.append(os.path.abspath(os.path.join(parent, raw)))
        if len(out) >= limit:
            break
    return out


def _antigravity_rules(cfg: Config) -> list[dict[str, Any]]:
    """Inventory bounded, stable Antigravity rule bytes from documented roots."""

    workspace = _connector_workspace_dir(cfg)
    rows: list[dict[str, Any]] = []

    def add_file(path: str, *, scope: str, kind: str, rule_id: str | None = None) -> None:
        if len(rows) >= _ANTIGRAVITY_RULE_INVENTORY_MAX_FILES:
            return
        try:
            payload = connector_paths._read_bounded_stable_file(
                path,
                max_bytes=_ANTIGRAVITY_RULE_FILE_MAX_BYTES,
            )
        except OSError:
            return
        filename = os.path.basename(path)
        rows.append(
            {
                "id": rule_id or os.path.splitext(filename)[0],
                "name": filename,
                "source": os.path.abspath(path),
                "kind": kind,
                "scope": scope,
                "trust_required": scope in {"project", "plugin"},
                "size_bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )

    add_file(
        os.path.join(os.path.expanduser("~"), ".gemini", "GEMINI.md"),
        scope="user",
        kind="instruction-rule",
        rule_id="GEMINI",
    )

    if workspace:
        for rules_dir, kind in (
            (os.path.join(workspace, ".agents", "rules"), "instruction-rule"),
            (os.path.join(workspace, ".agent", "rules"), "legacy-instruction-rule"),
        ):
            for entry in _safe_bounded_directory_entries(rules_dir) or ():
                if entry.lower().endswith(".md"):
                    add_file(os.path.join(rules_dir, entry), scope="project", kind=kind)

    for plugin_dir in connector_paths.plugin_dirs("antigravity", workspace_dir=workspace):
        for plugin_name in _safe_bounded_directory_entries(plugin_dir) or ():
            plugin_root = os.path.join(plugin_dir, plugin_name)
            rules_dir = os.path.join(plugin_root, "rules")
            for entry in _safe_bounded_directory_entries(rules_dir) or ():
                if not entry.lower().endswith(".md"):
                    continue
                add_file(
                    os.path.join(rules_dir, entry),
                    scope="plugin",
                    kind="plugin-rule",
                    rule_id=f"{plugin_name}:{os.path.splitext(entry)[0]}",
                )

    return rows


def _tools_for_connector(connector: str, cfg: Config) -> list[dict[str, Any]]:
    """Per-connector tool enumeration.

    * claudecode — connector-home ``settings.json`` ``tools`` field
    * codex      — connector-home ``config.toml`` ``[tools]`` table
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
        return _tools_from_codex_config(
            os.path.join(connector_paths.connector_home(name), "config.toml"),
        )
    if name == "zeptoclaw":
        return _tools_from_zeptoclaw_json(
            os.path.join(home, ".zeptoclaw", "agents.json"),
        )
    if name == "opencode":
        return []
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
        candidates = [os.path.join(connector_home, "memories")]
    elif name == "zeptoclaw":
        candidates = [os.path.join(home, ".zeptoclaw", "memory")]
    elif name == "hermes":
        hermes_home = connector_paths.hermes_home()
        memories = os.path.join(hermes_home, "memories")
        rows: list[dict[str, Any]] = []
        files: list[str] = []
        if os.path.isdir(memories) and not is_symlink(memories):
            for filename in ("MEMORY.md", "USER.md"):
                path = os.path.join(memories, filename)
                try:
                    info = os.lstat(path)
                except OSError:
                    continue
                if stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode):
                    files.append(path)
        rows.append(
            {
                "id": "builtin",
                "name": memories,
                "source": memories,
                "kind": "builtin-files",
                "files": files,
                "entry_count": len(files),
                "activation_source": "HERMES_HOME/memories",
                "activation_verified": False,
            }
        )
        document, _error = connector_paths._read_hermes_config_bounded()
        memory_config = document.get("memory") if isinstance(document, dict) else None
        provider = memory_config.get("provider") if isinstance(memory_config, dict) else None
        if isinstance(provider, str) and provider.strip() and provider.strip().casefold() not in {"builtin", "none"}:
            provider_name = provider.strip()
            provider_source = ""
            for plugin_root in connector_paths.plugin_dirs("hermes"):
                for candidate in (
                    os.path.join(plugin_root, "memory", provider_name),
                    os.path.join(plugin_root, provider_name),
                ):
                    if os.path.isdir(candidate) and not is_symlink(candidate):
                        provider_source = candidate
                        break
                if provider_source:
                    break
            rows.append(
                {
                    "id": provider_name,
                    "name": provider_name,
                    "source": provider_source or connector_paths.hermes_config_path(),
                    "kind": "memory-provider",
                    "configured": True,
                    "activation_source": "config.yaml:memory.provider",
                    "activation_verified": False,
                }
            )
        return rows
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


def _agents_from_cursor_dirs(agent_dirs: list[str]) -> list[dict[str, Any]]:
    """Retain Cursor subagent custody while expressing documented precedence."""

    home = os.path.abspath(os.path.expanduser("~"))
    user_roots = {
        os.path.normcase(os.path.abspath(os.path.join(home, family, "agents")))
        for family in (".cursor", ".claude", ".codex")
    }
    rows: list[dict[str, Any]] = []
    selected: dict[str, dict[str, Any]] = {}
    for agents_dir in agent_dirs:
        normalized_dir = os.path.normcase(os.path.abspath(agents_dir))
        scope = "user" if normalized_dir in user_roots else "project"
        family = os.path.basename(os.path.dirname(os.path.normpath(agents_dir))).casefold()
        for row in _agents_from_md_dir(agents_dir):
            row["scope"] = scope
            row["source_family"] = family
            identity = os.path.normcase(str(row["id"]))
            prior = selected.get(identity)
            if prior is None:
                row["selection_state"] = "documented-candidate"
                selected[identity] = row
            else:
                prior_scope = str(prior.get("scope") or "")
                prior_family = str(prior.get("source_family") or "")
                if prior_scope == "project" and scope == "user":
                    row["shadowed"] = True
                    row["selection_state"] = "documented-shadowed"
                elif prior_scope == scope and prior_family == ".cursor":
                    row["shadowed"] = True
                    row["selection_state"] = "documented-shadowed"
                elif prior_scope == scope and family == ".cursor":
                    prior["shadowed"] = True
                    prior["selection_state"] = "documented-shadowed"
                    row["selection_state"] = "documented-candidate"
                    selected[identity] = row
                else:
                    # Cursor documents .cursor over compatibility roots, but
                    # does not define a Claude-vs-Codex tie breaker.
                    prior["activation_verified"] = False
                    prior["selection_state"] = "unverified-compatibility-conflict"
                    row["activation_verified"] = False
                    row["selection_state"] = "unverified-compatibility-conflict"
            rows.append(row)
    return rows


def _cursor_rules_from_workspace(workspace: str) -> list[dict[str, Any]]:
    if not workspace or not connector_paths._cursor_walkable_directory(workspace):
        return []
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    rules_root = os.path.join(workspace, ".cursor", "rules")
    for current, _dirs, files in _bounded_cursor_walk(rules_root):
        for name in files:
            if not name.casefold().endswith(".mdc"):
                continue
            source = os.path.join(current, name)
            if not _cursor_regular_file(source):
                continue
            key = os.path.normcase(os.path.abspath(source))
            if key in seen:
                continue
            seen.add(key)
            rows.append(
                {
                    "id": os.path.relpath(source, rules_root),
                    "name": name,
                    "source": source,
                    "kind": "cursor-rule",
                    "scope": "project",
                }
            )
    for current, _dirs, files in _bounded_cursor_walk(workspace):
        for name in files:
            if name != "AGENTS.md":
                continue
            source = os.path.join(current, name)
            if not _cursor_regular_file(source):
                continue
            key = os.path.normcase(os.path.abspath(source))
            if key in seen:
                continue
            seen.add(key)
            rows.append(
                {
                    "id": os.path.relpath(source, workspace),
                    "name": name,
                    "source": source,
                    "kind": "agents-instructions",
                    "scope": "project",
                }
            )
    return rows


def _bounded_cursor_walk(root: str):
    if not connector_paths._cursor_walkable_directory(root):
        return
    visited = 0
    for current, dirs, files in os.walk(root, topdown=True, followlinks=False):
        safe_dirs: list[str] = []
        for name in sorted(dirs, key=str.casefold):
            if name == ".git":
                continue
            candidate = os.path.join(current, name)
            if connector_paths._cursor_walkable_directory(candidate):
                safe_dirs.append(name)
        dirs[:] = safe_dirs
        visited += 1
        if visited > connector_paths._CURSOR_DISCOVERY_DIR_LIMIT:
            dirs[:] = []
            break
        yield current, dirs, sorted(files, key=str.casefold)


def _cursor_regular_file(path: str) -> bool:
    try:
        connector_paths.reject_reparse_path(path)
        info = os.stat(path, follow_symlinks=False)
    except OSError:
        return False
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return (
        stat.S_ISREG(info.st_mode)
        and not stat.S_ISLNK(info.st_mode)
        and not bool(getattr(info, "st_file_attributes", 0) & reparse_flag)
    )


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


def _safe_bounded_directory_entries(
    path: str,
    *,
    max_entries: int = _ANTIGRAVITY_RULE_DIRECTORY_MAX_ENTRIES,
) -> list[str] | None:
    """List one stable real directory, refusing rather than truncating overflow."""

    try:
        connector_paths.reject_reparse_path(path)
        before = os.stat(path, follow_symlinks=False)
        if not stat.S_ISDIR(before.st_mode):
            return None
        entries: list[str] = []
        with os.scandir(path) as iterator:
            for entry in iterator:
                entries.append(entry.name)
                if len(entries) > max_entries:
                    return None
        connector_paths.reject_reparse_path(path)
        after = os.stat(path, follow_symlinks=False)
        if not stat.S_ISDIR(after.st_mode) or not os.path.samestat(before, after):
            return None
        return sorted(entries, key=str.casefold)
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


_AMP_AGENT_MODE_RE = re.compile(
    r"^[ \t]*//[ \t]*@amp-agent-mode[ \t]+(?P<metadata>\{[^\r\n]*\})[ \t]*\r?$",
    re.MULTILINE,
)
_AMP_CREATE_AGENT_CALL_RE = re.compile(
    r"\bcreateAgent[ \t\r\n]*\([ \t\r\n]*\{",
)
_AMP_REGISTER_AGENT_MODE_CALL_RE = re.compile(
    r"\bregisterAgentMode[ \t\r\n]*\([ \t\r\n]*\{",
)
_AMP_AGENT_NAME_RE = re.compile(r"[A-Za-z0-9_. -]{1,128}")
_AMP_AGENT_MODE_MAX_CHARS = 24
_AMP_AGENT_OBJECT_MAX_CHARS = 65_536


def _mask_ts_for_amp_agent_discovery(source: str) -> tuple[str, set[int]]:
    """Mask TS comments/string contents while preserving offsets and quotes.

    Amp plugin inventory is intentionally static: TypeScript is never imported
    or executed. This bounded lexical pass makes call detection ignore examples
    embedded in comments, quoted strings, and template literals. It also
    records real ``//`` token offsets so the intentionally comment-based
    ``@amp-agent-mode`` annotation can be distinguished from string content.
    """

    masked = list(source)
    line_comment_starts: set[int] = set()
    index = 0
    source_len = len(source)

    def _blank(position: int) -> None:
        if source[position] not in "\r\n":
            masked[position] = " "

    while index < source_len:
        current = source[index]
        following = source[index + 1] if index + 1 < source_len else ""
        if current == "/" and following == "/":
            line_comment_starts.add(index)
            _blank(index)
            _blank(index + 1)
            index += 2
            while index < source_len and source[index] not in "\r\n":
                _blank(index)
                index += 1
            continue
        if current == "/" and following == "*":
            _blank(index)
            _blank(index + 1)
            index += 2
            while index < source_len:
                if source[index] == "*" and index + 1 < source_len and source[index + 1] == "/":
                    _blank(index)
                    _blank(index + 1)
                    index += 2
                    break
                _blank(index)
                index += 1
            continue
        if current not in {"'", '"', "`"}:
            index += 1
            continue

        quote = current
        # Keep only the delimiters. The masked content cannot manufacture
        # identifiers, braces, or calls, while the retained delimiters let the
        # property parser locate a literal value in the original source.
        index += 1
        while index < source_len:
            char = source[index]
            if char == "\\":
                _blank(index)
                if index + 1 < source_len:
                    _blank(index + 1)
                index += 2
                continue
            if char == quote:
                index += 1
                break
            _blank(index)
            index += 1

    return "".join(masked), line_comment_starts


def _skip_masked_whitespace(masked: str, index: int, limit: int) -> int:
    while index < limit and masked[index].isspace():
        index += 1
    return index


def _matching_amp_agent_object(masked: str, opening: int) -> int:
    """Return the matching top-level ``}``, bounded to one call object."""

    depth = 0
    limit = min(len(masked), opening + _AMP_AGENT_OBJECT_MAX_CHARS)
    for index in range(opening, limit):
        if masked[index] == "{":
            depth += 1
        elif masked[index] == "}":
            depth -= 1
            if depth == 0:
                return index
    return -1


def _plain_ts_string_literal(source: str, start: int, limit: int) -> str:
    """Return a plain single/double-quoted literal, rejecting escapes."""

    if start >= limit or source[start] not in {"'", '"'}:
        return ""
    quote = source[start]
    chars: list[str] = []
    for index in range(start + 1, limit):
        char = source[index]
        if char == quote:
            return "".join(chars)
        if char == "\\" or char in "\r\n":
            return ""
        chars.append(char)
        if len(chars) > 128:
            return ""
    return ""


def _amp_literal_properties_from_object(
    source: str,
    masked: str,
    opening: int,
    closing: int,
    property_names: tuple[str, ...],
) -> dict[str, str]:
    """Extract requested top-level properties when their values are literals."""

    values: dict[str, str] = {}
    depth = 1
    index = opening + 1
    while index < closing:
        char = masked[index]
        if char == "{":
            depth += 1
            index += 1
            continue
        if char == "}":
            depth -= 1
            index += 1
            continue
        if depth != 1:
            index += 1
            continue
        matched_property = ""
        for property_name in property_names:
            if not masked.startswith(property_name, index):
                continue
            before = masked[index - 1] if index > opening + 1 else ""
            after_index = index + len(property_name)
            after = masked[after_index] if after_index < closing else ""
            if (before and (before.isalnum() or before in "_$")) or (
                after and (after.isalnum() or after in "_$")
            ):
                continue
            matched_property = property_name
            break
        if not matched_property:
            index += 1
            continue
        after_index = index + len(matched_property)
        value_index = _skip_masked_whitespace(masked, after_index, closing)
        if value_index >= closing or masked[value_index] != ":":
            index = after_index
            continue
        value_index = _skip_masked_whitespace(masked, value_index + 1, closing)
        literal = _plain_ts_string_literal(source, value_index, closing)
        if literal and matched_property not in values:
            values[matched_property] = literal
        index = value_index + 1
    return values


def _amp_call_object_ranges(masked: str, call_pattern: re.Pattern[str]) -> list[tuple[int, int]]:
    """Return bounded object ranges for real calls matched in lexical code."""

    ranges: list[tuple[int, int]] = []
    for match in call_pattern.finditer(masked):
        opening = match.end() - 1
        closing = _matching_amp_agent_object(masked, opening)
        if closing < 0:
            continue
        after = _skip_masked_whitespace(masked, closing + 1, len(masked))
        if after < len(masked) and masked[after] == ")":
            ranges.append((opening, closing))
    return ranges


def _amp_assigned_agent_variable(masked: str, call_start: int) -> str:
    """Return the local variable assigned one ``createAgent`` call, if plain."""

    prefix = masked[max(0, call_start - 512) : call_start]
    match = re.search(
        r"(?:^|[;{}\r\n])[ \t]*"
        r"(?:const|let|var)[ \t\r\n]+"
        r"(?P<variable>[A-Za-z_$][A-Za-z0-9_$]*)[ \t\r\n]*=[ \t\r\n]*"
        r"(?:amp[ \t\r\n]*(?:\.[ \t\r\n]*experimental[ \t\r\n]*)?\.[ \t\r\n]*)?$",
        prefix,
    )
    return match.group("variable") if match else ""


def _amp_invocation_has_parent_thread(masked: str, variable: str, start: int) -> bool:
    """Return whether a later agent invocation is tied to a parent thread."""

    invocation = re.compile(
        rf"\b{re.escape(variable)}[ \t\r\n]*\.[ \t\r\n]*"
        r"(?:run|createThread)[ \t\r\n]*\(",
    )
    for match in invocation.finditer(masked, start):
        opening = match.end() - 1
        depth = 0
        limit = min(len(masked), opening + _AMP_AGENT_OBJECT_MAX_CHARS)
        closing = -1
        for index in range(opening, limit):
            if masked[index] == "(":
                depth += 1
            elif masked[index] == ")":
                depth -= 1
                if depth == 0:
                    closing = index
                    break
        if closing >= 0 and re.search(
            r"\bparentThreadID\b",
            masked[opening + 1 : closing],
        ):
            return True
    return False


def _amp_custom_agent_definitions(source: str, masked: str) -> list[tuple[str, str]]:
    """Find literal custom agents and conservatively classify subagent use.

    ``createAgent`` is shared by Amp custom modes and independently spawned
    agents, so the call alone is not evidence that a subagent exists. Report
    ``custom-agent`` by default and upgrade to ``subagent`` only when a later
    ``run`` or ``createThread`` invocation is explicitly tied to a parent via
    ``parentThreadID``. Standalone/background commands can use the same methods
    without forming a delegation edge. Comments and strings remain masked.
    """

    agents: list[tuple[str, str]] = []
    for match in _AMP_CREATE_AGENT_CALL_RE.finditer(masked):
        opening = match.end() - 1
        closing = _matching_amp_agent_object(masked, opening)
        if closing < 0:
            continue
        after = _skip_masked_whitespace(masked, closing + 1, len(masked))
        if after >= len(masked) or masked[after] != ")":
            continue
        properties = _amp_literal_properties_from_object(
            source,
            masked,
            opening,
            closing,
            ("name",),
        )
        name = properties.get("name", "")
        if not _AMP_AGENT_NAME_RE.fullmatch(name):
            continue
        kind = "custom-agent"
        variable = _amp_assigned_agent_variable(masked, match.start())
        if variable and _amp_invocation_has_parent_thread(masked, variable, after + 1):
            kind = "subagent"
        agents.append((name, kind))
    return agents


def _amp_create_agent_names(source: str, masked: str) -> list[str]:
    """Compatibility projection of statically discovered custom-agent names."""

    return [name for name, _kind in _amp_custom_agent_definitions(source, masked)]


def _amp_registered_agent_modes(source: str, masked: str) -> list[tuple[str, str]]:
    """Find official literal ``registerAgentMode({key, label})`` calls."""

    modes: list[tuple[str, str]] = []
    for opening, closing in _amp_call_object_ranges(masked, _AMP_REGISTER_AGENT_MODE_CALL_RE):
        properties = _amp_literal_properties_from_object(
            source,
            masked,
            opening,
            closing,
            ("key", "label"),
        )
        key = properties.get("key", "").strip()
        label = properties.get("label", "").strip()
        if (
            key
            and label
            and len(key) <= _AMP_AGENT_MODE_MAX_CHARS
            and len(label) <= _AMP_AGENT_MODE_MAX_CHARS
        ):
            modes.append((key, label))
    return modes


def _agents_from_amp_plugins(cfg: Config) -> list[dict[str, Any]]:
    """Statically inventory Amp custom modes/subagents without executing TS."""

    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for plugin_root in cfg.plugin_dirs("amp"):
        for plugin in discover_plugin_directories(plugin_root, connector="amp"):
            if not os.path.isfile(plugin.path):
                continue
            source = read_amp_plugin_source(plugin.path)
            if not source:
                continue
            masked_source, line_comment_starts = _mask_ts_for_amp_agent_discovery(source)
            source_ids: set[str] = set()

            def _record_mode(key: str, label: str) -> None:
                identity = key.casefold()
                if identity in seen:
                    return
                seen.add(identity)
                source_ids.add(identity)
                rows.append(
                    {
                        "id": key,
                        "name": label,
                        "source": plugin.path,
                        "kind": "agent-mode",
                        "plugin": plugin.id,
                        "mode_key": key,
                    }
                )

            # Official Amp surface. The lexical/object parser only accepts
            # literal top-level key/label properties from executable code.
            for key, label in _amp_registered_agent_modes(source, masked_source):
                _record_mode(key, label)

            # Optional compatibility fallback for static plugins that expose
            # inventory metadata but cannot call registerAgentMode directly.
            for match in _AMP_AGENT_MODE_RE.finditer(source):
                comment_start = source.find("//", match.start(), match.end())
                if comment_start not in line_comment_starts:
                    continue
                try:
                    metadata = json.loads(match.group("metadata"))
                except (TypeError, ValueError):
                    continue
                if not isinstance(metadata, dict):
                    continue
                key = str(metadata.get("key") or "").strip()
                label = str(metadata.get("label") or "").strip()
                if (
                    not key
                    or not label
                    or len(key) > _AMP_AGENT_MODE_MAX_CHARS
                    or len(label) > _AMP_AGENT_MODE_MAX_CHARS
                ):
                    continue
                _record_mode(key, label)

            for agent_name, kind in _amp_custom_agent_definitions(source, masked_source):
                identity = agent_name.casefold()
                if not agent_name or identity in seen or identity in source_ids:
                    continue
                seen.add(identity)
                rows.append(
                    {
                        "id": agent_name,
                        "name": agent_name,
                        "source": plugin.path,
                        "kind": kind,
                        "plugin": plugin.id,
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
    rows: list[dict[str, Any]] = []
    for path in connector_paths._opencode_config_paths(workspace):  # type: ignore[attr-defined]
        rows.extend(_tools_from_opencode_config(path))
    rows.extend(
        _tools_from_script_dirs(
            _opencode_tool_dirs(workspace),
            kind="custom-tool",
            extensions=(".js", ".mjs", ".cjs", ".ts", ".mts", ".cts"),
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
            os.path.join(workspace_dir, ".opencode", "tools") if workspace_dir else "",
            os.path.join(home, ".config", "opencode", "tools"),
            os.path.join(os.path.expanduser(custom), "tools") if custom else "",
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


def _tools_from_opencode_config(path: str) -> list[dict[str, Any]]:
    data = connector_paths._load_json_or_jsonc(path)  # type: ignore[attr-defined]
    if not isinstance(data, dict):
        return []
    raw_tools = data.get("tool")
    if raw_tools is None:
        raw_tools = data.get("tools")
    if not isinstance(raw_tools, dict):
        return []
    rows: list[dict[str, Any]] = []
    for tool_id, body in raw_tools.items():
        if isinstance(body, dict):
            rows.append(
                {
                    "id": str(tool_id),
                    "name": str(body.get("name") or tool_id),
                    "description": str(body.get("description", "")),
                    "source": path,
                    "kind": "config-tool",
                }
            )
        else:
            rows.append(
                {
                    "id": str(tool_id),
                    "name": str(tool_id),
                    "source": path,
                    "kind": "config-tool",
                }
            )
    return rows


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
        if connector == "amp" and cat_key == "agents":
            # Amp custom agents/modes have a supported static plugin-source
            # adapter. An empty result means none are installed, not that the
            # capability is unsupported.
            continue
        result = results.get(cat_key)
        if result is None or result.error is not None:
            continue
        partial_status = (
            InventoryCapabilityStatus.UNVERIFIED
            if partial_connector == "windsurf"
            else InventoryCapabilityStatus.UNSUPPORTED
        )
        limitations.append(
            {
                "connector": connector,
                "category": cat_key,
                "status": partial_status,
                "reason": note,
            }
        )
    for (partial_connector, cat_key), note in _UNVERIFIED_CONNECTOR_NOTES.items():
        if partial_connector != connector or cat_key not in cats:
            continue
        result = results.get(cat_key)
        if result is None or result.error is not None:
            continue
        limitations.append(
            {
                "connector": connector,
                "category": cat_key,
                "status": InventoryCapabilityStatus.UNVERIFIED,
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
    if connector_paths.normalize(connector) == "hermes":
        hermes_notes = {
            "skills": (
                "default-profile HERMES_HOME/skills and existing skills.external_dirs are inventoried; "
                "named/multiplex profiles and session/project-conditional skill sources are unsupported or unverified"
            ),
            "plugins": (
                "default-profile user, vendor bundled/Nix override, and official Hermes-venv entry-point metadata are "
                "inventoried with config-derived activation provenance; runtime activation and project plugins "
                "conditional on the Hermes process CWD plus HERMES_ENABLE_PROJECT_PLUGINS remain unverified"
            ),
            "rules": (
                "default-profile SOUL.md is inventoried as identity; project AGENTS.md, CLAUDE.md, .hermes.md, and "
                ".cursorrules depend on the Hermes session CWD and remain unverified"
            ),
            "memory": (
                "default-profile MEMORY.md/USER.md and configured memory.provider are inventoried; provider-owned "
                "external state requires loading the provider and remains unverified"
            ),
        }
        for category, reason in hermes_notes.items():
            if category in cats:
                limitations.append(
                    {
                        "connector": connector,
                        "category": category,
                        "status": InventoryCapabilityStatus.UNVERIFIED,
                        "reason": reason,
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
        "live": connector_paths.normalize(connector) != "hermes",
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
    if connector_paths.normalize(connector) == "hermes":
        out["support_status"] = "supported"
        out["release_channel"] = "supported"
        out["profile_scope"] = "default-single-profile"
    _attach_connector_paths(out, cfg, connector)
    _sync_legacy_connector_paths(out)
    out["summary"] = _build_summary(out)
    return out


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
            if (
                normalized_connector == "copilot"
                and os.path.basename(os.path.normpath(skill_dir)).casefold() == "commands"
            ):
                row.update(
                    {
                        "kind": "command",
                        "precedence": "after-all-agent-skills",
                        "activation_verified": False,
                        "activation_state": "alternative-skill-unverified",
                    }
                )
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


def _read_hermes_plugin_manifest(path: str) -> dict[str, Any] | None:
    try:
        info = os.lstat(path)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_size > 256 * 1024:
            return None
        descriptor = open_regular_file_no_follow(path)
        with os.fdopen(descriptor, encoding="utf-8") as handle:
            document = yaml.safe_load(handle) or {}
    except (OSError, yaml.YAMLError):
        return None
    return document if isinstance(document, dict) else None


def _hermes_bounded_scandir(path: str, limit: int) -> list[os.DirEntry[str]]:
    entries: list[os.DirEntry[str]] = []
    with os.scandir(path) as iterator:
        for entry in iterator:
            entries.append(entry)
            if len(entries) >= limit:
                break
    return entries


def _hermes_manifest_rows(
    root: str,
    source: str,
    *,
    skip_top_level: frozenset[str] = frozenset(),
) -> list[dict[str, Any]]:
    if not os.path.isdir(root) or is_symlink(root):
        return []
    rows: list[dict[str, Any]] = []
    visited = 0
    try:
        first_level = sorted(_hermes_bounded_scandir(root, 512), key=lambda item: item.name.casefold())
    except OSError:
        return []
    for first in first_level:
        if visited >= 512:
            break
        if first.name in skip_top_level:
            continue
        try:
            if not first.is_dir(follow_symlinks=False):
                continue
        except OSError:
            continue
        visited += 1
        direct_manifest = os.path.join(first.path, "plugin.yaml")
        if _read_hermes_plugin_manifest(direct_manifest) is not None:
            candidates = [(first.name, first.path)]
        else:
            candidates = []
        try:
            children = (
                []
                if candidates
                else sorted(_hermes_bounded_scandir(first.path, 512 - visited), key=lambda item: item.name.casefold())
            )
        except OSError:
            children = []
        for child in children:
            if visited >= 512:
                break
            try:
                if child.is_dir(follow_symlinks=False):
                    candidates.append((f"{first.name}/{child.name}", child.path))
                    visited += 1
            except OSError:
                continue
        for key, directory in candidates:
            manifest_path = os.path.join(directory, "plugin.yaml")
            manifest = _read_hermes_plugin_manifest(manifest_path)
            if manifest is None:
                continue
            rows.append(
                {
                    "id": key,
                    "name": str(manifest.get("name") or os.path.basename(directory)),
                    "version": str(manifest.get("version") or ""),
                    "description": str(manifest.get("description") or ""),
                    "kind": str(manifest.get("kind") or "standalone"),
                    "source_kind": source,
                    "source": directory,
                    "manifest": manifest_path,
                }
            )
    return rows


def _hermes_pip_entry_points() -> list[tuple[Any, str]]:
    """Read plugin metadata from the official Hermes venv without executing it."""

    install_root = os.path.join(connector_paths.hermes_home(), "hermes-agent")
    site_packages: list[str] = []
    for venv_name in ("venv", ".venv"):
        venv_root = os.path.join(install_root, venv_name)
        windows_site = os.path.join(venv_root, "Lib", "site-packages")
        if os.path.isdir(windows_site) and not is_symlink(windows_site):
            site_packages.append(windows_site)
        unix_lib = os.path.join(venv_root, "lib")
        try:
            versions = _hermes_bounded_scandir(unix_lib, 16)
        except OSError:
            versions = []
        for version in versions:
            try:
                if not version.name.startswith("python") or not version.is_dir(follow_symlinks=False):
                    continue
            except OSError:
                continue
            candidate = os.path.join(version.path, "site-packages")
            if os.path.isdir(candidate) and not is_symlink(candidate):
                site_packages.append(candidate)

    rows: list[tuple[Any, str]] = []
    if site_packages:
        try:
            distributions = importlib.metadata.distributions(path=list(dict.fromkeys(site_packages)))
            for distribution_index, distribution in enumerate(distributions):
                if distribution_index >= 2048:
                    break
                version = str(getattr(distribution, "version", "") or "")
                for entry in getattr(distribution, "entry_points", ()):
                    if getattr(entry, "group", "") == "hermes_agent.plugins":
                        rows.append((entry, version))
                        if len(rows) >= 512:
                            return rows
        except Exception:  # noqa: BLE001 - corrupt installed metadata is an inventory gap.
            return rows
        return rows

    # Advanced -NoVenv/source installs can deliberately share the current
    # interpreter. Only consult its metadata when hermes_cli is import-visible;
    # DefenseClaw's unrelated environment must not be presented as Hermes.
    try:
        hermes_spec = importlib.util.find_spec("hermes_cli")
    except (ImportError, AttributeError, ValueError):
        hermes_spec = None
    if hermes_spec is None:
        return rows
    try:
        entry_points = importlib.metadata.entry_points()
        if hasattr(entry_points, "select"):
            selected = entry_points.select(group="hermes_agent.plugins")
        elif isinstance(entry_points, dict):
            selected = entry_points.get("hermes_agent.plugins", [])
        else:
            selected = [entry for entry in entry_points if entry.group == "hermes_agent.plugins"]
    except Exception:  # noqa: BLE001 - metadata corruption is an inventory gap.
        return rows
    for entry in list(selected)[:512]:
        distribution = getattr(entry, "dist", None)
        rows.append((entry, str(getattr(distribution, "version", "") or "")))
    return rows


def _enumerate_hermes_plugins() -> list[dict[str, Any]]:
    """Mirror v0.19's bounded default-profile plugin source and activation order."""

    home = connector_paths.hermes_home()
    user_root = os.path.join(home, "plugins")
    roots = connector_paths.plugin_dirs("hermes")
    bundled_roots = [root for root in roots if os.path.normcase(root) != os.path.normcase(user_root)]
    discovered: list[dict[str, Any]] = []
    for root in bundled_roots:
        source = "bundled-nix" if (os.environ.get("HERMES_BUNDLED_PLUGINS") or "").strip() else "bundled"
        discovered.extend(
            _hermes_manifest_rows(
                root,
                source,
                skip_top_level=frozenset({"memory", "context_engine", "platforms", "model-providers"}),
            )
        )
        discovered.extend(_hermes_manifest_rows(os.path.join(root, "platforms"), source))
    discovered.extend(_hermes_manifest_rows(user_root, "user"))

    for entry, version in _hermes_pip_entry_points():
        discovered.append(
            {
                "id": str(entry.name),
                "name": str(entry.name),
                "version": version,
                "description": "",
                "kind": "standalone",
                "source_kind": "entrypoint",
                "source": str(entry.value),
                "manifest": "",
            }
        )

    # v0.19 resolves collisions in scan order: user beats bundled and the
    # later entry-point source beats both. Preserve the final winner by ID.
    winners: dict[str, dict[str, Any]] = {}
    for row in discovered:
        winners[str(row["id"])] = row

    document, _error = connector_paths._read_hermes_config_bounded()
    plugins_config = document.get("plugins") if isinstance(document, dict) else None
    enabled_raw = plugins_config.get("enabled") if isinstance(plugins_config, dict) else None
    disabled_raw = plugins_config.get("disabled") if isinstance(plugins_config, dict) else None
    enabled = {str(item) for item in enabled_raw} if isinstance(enabled_raw, list) else set()
    disabled = {str(item) for item in disabled_raw} if isinstance(disabled_raw, list) else set()

    rows: list[dict[str, Any]] = []
    for key in sorted(winners, key=str.casefold):
        row = winners[key]
        name = str(row.get("name") or key)
        kind = str(row.get("kind") or "standalone")
        source_kind = str(row.get("source_kind") or "")
        if key in disabled or name in disabled:
            configured = False
            activation_source = "config.yaml:plugins.disabled"
        elif kind == "exclusive":
            configured = False
            activation_source = "provider-selection-required"
        elif kind == "model-provider":
            configured = True
            activation_source = "vendor model-provider discovery"
        elif source_kind.startswith("bundled") and kind in {"backend", "platform"}:
            configured = True
            activation_source = "vendor bundled auto/deferred activation"
        else:
            configured = key in enabled or name in enabled
            activation_source = "config.yaml:plugins.enabled" if configured else "vendor opt-in default"
        row.update(
            {
                "enabled": configured,
                "activation_status": "configured" if configured else "inactive",
                "activation_source": activation_source,
                "activation_verified": False,
            }
        )
        rows.append(row)
    return rows


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
    if connector_paths.normalize(connector or cfg.active_connector()) == "hermes":
        return _enumerate_hermes_plugins()
    rows: list[dict[str, Any]] = []
    seen: dict[str, str] = {}
    resolved_connector = connector or cfg.active_connector()
    workspace_dir = _connector_workspace_dir(cfg)
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
    entries = cfg.mcp_servers(connector)
    cursor_names: dict[str, int] = {}
    if connector_paths.normalize(resolved) == "cursor":
        for entry in entries:
            identity = os.path.normcase(entry.name)
            cursor_names[identity] = cursor_names.get(identity, 0) + 1
    for entry in entries:
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
        if connector_paths.normalize(resolved) == "cursor":
            row["activation_verified"] = False
            row["activation_state"] = "unverified-dynamic-selection"
            if cursor_names.get(os.path.normcase(entry.name), 0) > 1:
                row["selection_conflict"] = True
                row["activation_state"] = "unverified-same-name-scope-conflict"
        rows.append(row)
    return rows
