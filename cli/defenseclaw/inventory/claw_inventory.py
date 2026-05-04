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

Indexes: Skills, Plugins, MCP servers, Agents/sub-agents, Tools, Model providers, Memory.

Commands are dispatched in parallel via ``ThreadPoolExecutor`` and deduplicated
(e.g. ``plugins list`` is fetched once even though three categories use it).
"""

from __future__ import annotations

import json
import os
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from typing import Any, NamedTuple

from defenseclaw.config import Config, SkillActionsConfig, _expand
from defenseclaw.models import ActionEntry, Finding, ScanResult

INVENTORY_VERSION = 3

ALL_CATEGORIES: frozenset[str] = frozenset(
    ["skills", "plugins", "mcp", "agents", "tools", "models", "memory"]
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


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_claw_aibom(
    cfg: Config,
    *,
    live: bool = True,
    categories: set[str] | None = None,
) -> dict[str, Any]:
    """Collect a connector-agnostic agent-framework inventory.

    Dispatches via :meth:`Config.active_connector`. For OpenClaw —
    the historical default — *live=True* shells out to ``openclaw …
    --json`` commands in parallel; for Codex / Claude Code / ZeptoClaw
    we walk the filesystem under :func:`connector_paths.skill_dirs`,
    :func:`connector_paths.plugin_dirs`, and
    :func:`connector_paths.mcp_servers`.

    *categories* restricts which sections are collected (default: all).
    *live=False* always returns the disk-only shape (no subprocess
    calls, no filesystem walk).
    """
    cats = _resolve_categories(categories)
    connector = cfg.active_connector()
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
        "claw_mode": cfg.claw.mode,
        "live": live,
        "skills": _parse_skills(cache.get("skills_list")) if "skills" in cats else [],
        "plugins": _parse_plugins(cache.get("plugins_list")) if "plugins" in cats else [],
        "mcp": _parse_mcp(cache.get("mcp_list")) if "mcp" in cats else [],
        "agents": (
            _parse_agents(cache.get("agents_list"), cache.get("config_agents"))
            if "agents" in cats
            else []
        ),
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
    }
    out["summary"] = _build_summary(out)
    return out


def claw_aibom_to_scan_result(inv: dict[str, Any], cfg: Config) -> ScanResult:
    """One INFO finding per category so audit logging stays compact."""
    target = _expand(cfg.claw.config_file)
    ts = datetime.now(timezone.utc)
    category_labels = [
        ("skills", "Skills"),
        ("plugins", "Plugins"),
        ("mcp", "MCP servers"),
        ("agents", "Agents / sub-agents"),
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
            "blocked": 0, "allowed": 0, "rejected": 0,
            "warning": 0, "clean": 0, "unscanned": 0,
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
                item, target_type, candidates, scan_entry, action_entry, cfg,
            )
            verdict, detail = _admission_verdict(
                pe, target_type, policy_name,
                scan_entry, action_entry,
                fallback_actions,
                policy_dir=policy_dir,
                source_path=source_path,
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


def _admission_verdict(
    pe: Any,
    target_type: str,
    name: str,
    scan_entry: dict[str, Any] | None,
    action_entry: ActionEntry | None,
    skill_actions: SkillActionsConfig,
    policy_dir: str = "",
    source_path: str = "",
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

    if action_entry is not None and action_entry.source_path:
        return action_entry.source_path

    for key in ("path", "baseDir", "filePath", "scan_target", "url", "command"):
        raw = item.get(key)
        if raw:
            return str(raw)

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
        if alias and (
            plugin_name.startswith("@")
            or alias.endswith("-plugin")
            or alias.endswith("-provider")
        ):
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

    console.print()
    console.print(f"[bold]OpenClaw AIBOM[/bold]  (source: {mode})")
    console.print(f"  Config:    {inv.get('openclaw_config', '')}")
    console.print(f"  Claw home: {inv.get('claw_home', '')}")
    console.print(f"  Mode:      {inv.get('claw_mode', '')}")
    console.print()

    _render_summary(console, inv)
    console.print()

    if not summary_only:
        _render_skills(console, inv.get("skills", []))
        _render_plugins(console, inv.get("plugins", []))
        _render_mcp(console, inv.get("mcp", []))
        _render_agents(console, inv.get("agents", []))
        _render_tools(console, inv.get("tools", []))
        _render_models(console, inv.get("model_providers", []))
        _render_memory(console, inv.get("memory", []))

    _render_errors(console, inv.get("errors", []))


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
        "tools": {"count": len(inv.get("tools", []))},
        "model_providers": {"count": len(inv.get("model_providers", []))},
        "memory": {"count": len(inv.get("memory", []))},
    }
    total = sum(c["count"] for c in cats.values())
    return {
        "total_items": total,
        **cats,
        "errors": len(inv.get("errors", [])),
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
        blocked_count = sum(
            1 for s in ineligible if s.get("policy_verdict") == "blocked"
        )
        parts = ["missing deps"]
        if blocked_count:
            parts.append(f"{blocked_count} blocked by policy")
        console.print(
            f"  [dim]+ {len(ineligible)} ineligible skills "
            f"({', '.join(parts)})[/dim]"
        )
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
        blocked_count = sum(
            1 for p in disabled if p.get("policy_verdict") == "blocked"
        )
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
        for ch in ('{', '['):
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
        futures = {
            pool.submit(_run_openclaw, *_COMMANDS[key]): key
            for key in needed
            if key in _COMMANDS
        }
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
        for field in ("toolNames", "providerIds", "hookNames",
                       "channelIds", "cliCommands", "services"):
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
            rows.append({
                "id": a.get("id", ""),
                "model": a.get("model", ""),
                "workspace": a.get("workspace", ""),
                "is_default": a.get("isDefault", False),
                "bindings": a.get("bindings", 0),
            })

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
        rows.append({
            "id": "_config",
            "source": "models status",
            "default_model": raw_status.get("defaultModel") or raw_status.get("resolvedDefault", ""),
            "fallbacks": raw_status.get("fallbacks", []),
            "allowed": raw_status.get("allowed", []),
            "config_path": raw_status.get("configPath", ""),
        })
        auth = raw_status.get("auth", {})
        if isinstance(auth, dict):
            for prov in auth.get("providers", []):
                if isinstance(prov, dict):
                    rows.append({
                        "id": prov.get("provider", ""),
                        "source": "auth",
                        "status": prov.get("status", ""),
                    })
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
                    rows.append({
                        "id": pid,
                        "source": f"plugin:{p.get('id', '')}",
                        "enabled": p.get("enabled", False),
                        "status": p.get("status", ""),
                    })

    if isinstance(raw_models, dict):
        for m in raw_models.get("models", []):
            if not isinstance(m, dict):
                continue
            rows.append({
                "id": m.get("key", ""),
                "name": m.get("name", ""),
                "source": "models list",
                "available": m.get("available", False),
                "local": m.get("local", False),
                "input": m.get("input", ""),
                "context_window": m.get("contextWindow", 0),
            })

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
# as empty lists with a clear "errors" entry pointing the reader at
# the connector-specific surface that owns that concept.

_FILESYSTEM_ONLY_CONNECTOR_NOTES: dict[str, str] = {
    "agents": "agents are not a first-class concept on this connector",
    "tools": "tool registry is owned by each plugin's manifest",
    "models": "model providers are configured inside the framework",
    "memory": "memory backend is private to the framework",
}


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

    * claudecode — ``~/.claude/agents/*.md`` (sub-agent prompt files)
    * codex      — ``~/.codex/agents/*`` (when present)
    * zeptoclaw  — ``~/.zeptoclaw/agents.json`` array
    * geminicli  — ``.gemini/agents`` and ``~/.gemini/agents``
    * copilot    — ``.github/agents`` and ``~/.copilot/agents``
    """
    home = os.path.expanduser("~")
    name = (connector or "").lower()
    if name == "claudecode":
        return _agents_from_md_dir(os.path.join(home, ".claude", "agents"))
    if name == "codex":
        return _agents_from_md_dir(os.path.join(home, ".codex", "agents"))
    if name == "zeptoclaw":
        return _agents_from_zeptoclaw_json(
            os.path.join(home, ".zeptoclaw", "agents.json"),
        )
    if name == "geminicli":
        return _agents_from_md_dirs([
            os.path.join(os.getcwd(), ".gemini", "agents"),
            os.path.join(home, ".gemini", "agents"),
        ])
    if name == "copilot":
        return _agents_from_md_dirs([
            os.path.join(os.getcwd(), ".github", "agents"),
            os.path.join(home, ".copilot", "agents"),
        ])
    return []


def _tools_for_connector(connector: str, cfg: Config) -> list[dict[str, Any]]:
    """Per-connector tool enumeration.

    * claudecode — ``~/.claude/settings.json`` ``tools`` field
    * codex      — ``~/.codex/config.toml`` ``[tools]`` table
    * zeptoclaw  — ``~/.zeptoclaw/agents.json`` (tools are inline)
    """
    home = os.path.expanduser("~")
    name = (connector or "").lower()
    if name == "claudecode":
        return _tools_from_claude_settings(
            os.path.join(home, ".claude", "settings.json"),
        )
    if name == "codex":
        return _tools_from_codex_config(
            os.path.join(home, ".codex", "config.toml"),
        )
    if name == "zeptoclaw":
        return _tools_from_zeptoclaw_json(
            os.path.join(home, ".zeptoclaw", "agents.json"),
        )
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
            "ANTHROPIC_BASE_URL", "ANTHROPIC_API_KEY", default_provider="anthropic",
            default_base_url="https://api.anthropic.com",
        )
    if name == "codex":
        return _providers_from_env(
            "OPENAI_BASE_URL", "OPENAI_API_KEY", default_provider="openai",
            default_base_url="https://api.openai.com/v1",
        )
    if name == "zeptoclaw":
        return _providers_from_zeptoclaw_config(
            os.path.join(home, ".zeptoclaw", "config.json"),
        )
    return []


def _memory_for_connector(connector: str, cfg: Config) -> list[dict[str, Any]]:
    """Per-connector memory backend enumeration.

    Memory backends are rarely declarative across these frameworks;
    the conservative shape is "report the directory if present".
    """
    home = os.path.expanduser("~")
    name = (connector or "").lower()
    candidates: list[str] = []
    if name == "claudecode":
        candidates = [os.path.join(home, ".claude", "memory")]
    elif name == "codex":
        candidates = [
            os.path.join(home, ".codex", "memory"),
            os.path.join(home, ".codex", "history"),
        ]
    elif name == "zeptoclaw":
        candidates = [os.path.join(home, ".zeptoclaw", "memory")]
    else:
        return []

    rows: list[dict[str, Any]] = []
    for path in candidates:
        if not os.path.isdir(path):
            continue
        try:
            entry_count = sum(1 for _ in os.scandir(path))
        except OSError:
            entry_count = 0
        rows.append({
            "id": os.path.basename(path) or path,
            "name": path,
            "source": path,
            "kind": "filesystem",
            "entry_count": entry_count,
        })
    return rows


# --- adapter helpers -------------------------------------------------------


def _agents_from_md_dir(agents_dir: str) -> list[dict[str, Any]]:
    """Each *.md (or *.txt) file under *agents_dir* is one agent."""
    if not os.path.isdir(agents_dir):
        return []
    rows: list[dict[str, Any]] = []
    try:
        entries = sorted(os.listdir(agents_dir))
    except OSError:
        return []
    for entry in entries:
        full = os.path.join(agents_dir, entry)
        if not os.path.isfile(full):
            continue
        if not entry.endswith((".md", ".txt", ".json", ".yaml", ".yml")):
            continue
        agent_id = os.path.splitext(entry)[0]
        rows.append({
            "id": agent_id,
            "name": agent_id,
            "source": full,
            "kind": "subagent",
        })
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
        rows.append({
            "id": str(agent_id),
            "name": str(item.get("name") or agent_id),
            "description": str(item.get("description", "")),
            "source": path,
            "kind": "agent",
        })
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
                rows.append({
                    "id": str(tool_id),
                    "name": str(item.get("name") or tool_id),
                    "description": str(item.get("description", "")),
                    "source": path,
                })
    elif isinstance(tools, dict):
        for tool_id, item in tools.items():
            if isinstance(item, dict):
                rows.append({
                    "id": str(tool_id),
                    "name": str(item.get("name") or tool_id),
                    "description": str(item.get("description", "")),
                    "source": path,
                })
    return rows


def _tools_from_codex_config(path: str) -> list[dict[str, Any]]:
    """Codex's ``[tools]`` table — TOML."""
    if not os.path.isfile(path):
        return []
    try:
        # Python 3.11+: tomllib in stdlib. Earlier we'd need tomli;
        # the project pins 3.12 so this is safe.
        import tomllib

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
        rows.append({
            "id": str(tool_id),
            "name": str(body.get("name") or tool_id),
            "description": str(body.get("description", "")),
            "source": path,
        })
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
            rows.append({
                "id": str(tid),
                "name": str(tool.get("name") or tid),
                "description": str(tool.get("description", "")),
                "source": path,
            })
    return rows


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
    return [{
        "id": default_provider,
        "name": default_provider,
        "base_url": base_url,
        "api_key_present": has_key,
        "source": f"env:{base_url_var}",
    }]


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
        rows.append({
            "id": str(pid),
            "name": str(body.get("name") or pid),
            "base_url": str(body.get("api_base") or ""),
            # Don't echo the key. Reporting "present/absent" is the
            # only safe inventory signal.
            "api_key_present": bool(body.get("api_key")),
            "source": path,
        })
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
    errors: list[dict[str, str]] = []

    skills: list[dict[str, Any]] = []
    if "skills" in cats:
        skills = _enumerate_skills_filesystem(cfg)

    plugins: list[dict[str, Any]] = []
    if "plugins" in cats:
        plugins = _enumerate_plugins_filesystem(cfg)

    mcps: list[dict[str, Any]] = []
    if "mcp" in cats:
        mcps = _enumerate_mcp_filesystem(cfg)

    # Plan C7: dispatch into per-connector adapters for the four
    # categories that the CLI shellout used to own. When an adapter
    # returns an empty list we still emit the informational note so
    # operators see *why* a category is empty (no agent dir, no env
    # var set, etc.).
    agents = _agents_for_connector(connector, cfg) if "agents" in cats else []
    tools = _tools_for_connector(connector, cfg) if "tools" in cats else []
    model_providers = (
        _model_providers_for_connector(connector, cfg) if "models" in cats else []
    )
    memory = _memory_for_connector(connector, cfg) if "memory" in cats else []

    # Populate "errors" with informational notes for categories that
    # don't translate to non-OpenClaw connectors. This keeps the
    # output schema stable while telling operators why those buckets
    # are empty.
    _fs_only_results = {
        "agents": agents,
        "tools": tools,
        "models": model_providers,
        "memory": memory,
    }
    for cat_key, note in _FILESYSTEM_ONLY_CONNECTOR_NOTES.items():
        if cat_key not in cats:
            continue
        # Only attach the "informational" note when the adapter
        # actually returned no rows; if the adapter found rows we
        # don't want to confuse operators with "agents are not a
        # first-class concept" alongside a populated agents list.
        if _fs_only_results.get(cat_key):
            continue
        errors.append({
            "command": f"{connector}:{cat_key}",
            "error": note,
        })

    out: dict[str, Any] = {
        "version": INVENTORY_VERSION,
        "generated_at": now,
        "connector": connector,
        "openclaw_config": _expand(cfg.claw.config_file),
        "claw_home": cfg.claw_home_dir(),
        "claw_mode": cfg.claw.mode,
        "live": True,
        "skills": skills,
        "plugins": plugins,
        "mcp": mcps,
        "agents": agents,
        "tools": tools,
        "model_providers": model_providers,
        "memory": memory,
        "errors": errors,
    }
    out["summary"] = _build_summary(out)
    return out


def _enumerate_skills_filesystem(cfg: Config) -> list[dict[str, Any]]:
    """Walk every directory in ``cfg.skill_dirs()`` and emit one row
    per immediate subdirectory.

    A skill is treated as the directory itself; its ``id`` is the
    basename. ``eligible`` is True if the directory contains at
    least one of: SKILL.md, skill.json, README.md (matches the
    discovery contract used by the connector-specific OTel
    component scanner).
    """
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for skill_dir in cfg.skill_dirs():
        if not os.path.isdir(skill_dir):
            continue
        try:
            entries = os.listdir(skill_dir)
        except OSError:
            continue
        for entry in sorted(entries):
            full = os.path.join(skill_dir, entry)
            if not os.path.isdir(full):
                continue
            if entry in seen:
                continue
            seen.add(entry)
            row: dict[str, Any] = {
                "id": entry,
                "source": skill_dir,
                "eligible": _skill_dir_is_eligible(full),
                "enabled": True,
                "bundled": False,
                "path": full,
            }
            description = _read_skill_description(full)
            if description:
                row["description"] = description
            rows.append(row)
    return rows


def _skill_dir_is_eligible(path: str) -> bool:
    for marker in ("SKILL.md", "skill.json", "README.md"):
        if os.path.isfile(os.path.join(path, marker)):
            return True
    return False


def _read_skill_description(path: str) -> str:
    """Return the first non-empty line of SKILL.md / README.md, if any.

    Bounded to 2 KiB so we don't accidentally slurp a multi-MB README
    into the inventory dict.
    """
    for marker in ("SKILL.md", "README.md"):
        marker_path = os.path.join(path, marker)
        if not os.path.isfile(marker_path):
            continue
        try:
            with open(marker_path, encoding="utf-8", errors="replace") as f:
                text = f.read(2048)
        except OSError:
            continue
        for line in text.splitlines():
            stripped = line.strip().lstrip("#").strip()
            if stripped:
                return stripped[:200]
    return ""


def _enumerate_plugins_filesystem(cfg: Config) -> list[dict[str, Any]]:
    """One row per plugin directory under ``cfg.plugin_dirs()``.

    A plugin is treated as a directory containing one of the
    documented manifest names (matches plugin_scanner._MANIFEST_CANDIDATES
    after S2.3): package.json, manifest.json, plugin.json,
    openclaw.plugin.json, .codex-plugin/plugin.json,
    .claude-plugin/plugin.json.
    """
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for plugin_dir in cfg.plugin_dirs():
        if not os.path.isdir(plugin_dir):
            continue
        try:
            entries = os.listdir(plugin_dir)
        except OSError:
            continue
        for entry in sorted(entries):
            if entry == "cache":
                # Codex / ZeptoClaw use a "cache" sibling for transient
                # downloads; not a plugin in its own right.
                continue
            full = os.path.join(plugin_dir, entry)
            if not os.path.isdir(full):
                continue
            if entry in seen:
                continue
            seen.add(entry)
            manifest = _detect_plugin_manifest(full)
            row: dict[str, Any] = {
                "id": entry,
                "name": entry,
                "version": "",
                "origin": plugin_dir,
                "enabled": True,
                "status": "loaded" if manifest else "no-manifest",
                "path": full,
            }
            if manifest:
                row["manifest"] = manifest
            rows.append(row)
    return rows


_PLUGIN_MANIFEST_FILES: tuple[str, ...] = (
    "package.json",
    "manifest.json",
    "plugin.json",
    "openclaw.plugin.json",
    os.path.join(".codex-plugin", "plugin.json"),
    os.path.join(".claude-plugin", "plugin.json"),
)


def _detect_plugin_manifest(plugin_root: str) -> str:
    for rel in _PLUGIN_MANIFEST_FILES:
        candidate = os.path.join(plugin_root, rel)
        if os.path.isfile(candidate):
            return rel
    return ""


def _enumerate_mcp_filesystem(cfg: Config) -> list[dict[str, Any]]:
    """Read MCP servers via the connector-aware
    :meth:`Config.mcp_servers` helper and convert
    :class:`MCPServerEntry` rows into the inventory dict shape used by
    the OpenClaw CLI parser.
    """
    rows: list[dict[str, Any]] = []
    for entry in cfg.mcp_servers():
        row: dict[str, Any] = {
            "id": entry.name,
            "source": f"{cfg.active_connector()} mcp registry",
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
        rows.append(row)
    return rows
