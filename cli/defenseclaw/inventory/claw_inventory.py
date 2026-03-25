"""Build a live OpenClaw bill-of-materials by querying the ``openclaw`` CLI.

Indexes: Skills, Plugins, MCP servers, Agents/sub-agents, Tools, Model providers, Memory.

Commands are dispatched in parallel via ``ThreadPoolExecutor`` and deduplicated
(e.g. ``plugins list`` is fetched once even though three categories use it).
"""

from __future__ import annotations

import json
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from typing import Any, NamedTuple

from defenseclaw.config import Config, _expand
from defenseclaw.models import Finding, ScanResult

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
    """Collect the OpenClaw inventory.

    When *live* is True (default), runs ``openclaw … --json`` commands in
    parallel and merges results.  Use *categories* to restrict which sections
    are collected (default: all).
    """
    cats = _resolve_categories(categories)
    claw_home = cfg.claw_home_dir()
    now = datetime.now(timezone.utc).isoformat()

    if live:
        cache, errors = _fetch_all(_needed_commands(cats))
    else:
        cache, errors = {}, []

    out: dict[str, Any] = {
        "version": INVENTORY_VERSION,
        "generated_at": now,
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
    n_loaded = sum(1 for p in plugins if p.get("enabled"))
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
    table.add_row("Skills", str(sk.get("count", 0)), f"{sk.get('eligible', 0)} eligible")
    pl = data.get("plugins", {})
    table.add_row(
        "Plugins",
        str(pl.get("count", 0)),
        f"{pl.get('loaded', 0)} loaded, {pl.get('disabled', 0)} disabled",
    )
    table.add_row("MCP servers", str(data.get("mcp", {}).get("count", 0)))
    table.add_row("Agents", str(data.get("agents", {}).get("count", 0)))
    table.add_row("Tools", str(data.get("tools", {}).get("count", 0)))
    table.add_row("Model providers", str(data.get("model_providers", {}).get("count", 0)))
    table.add_row("Memory stores", str(data.get("memory", {}).get("count", 0)))
    console.print(table)


def _render_skills(console: Any, skills: list[dict[str, Any]]) -> None:
    if not skills:
        console.print("[dim]Skills: none[/dim]")
        return

    from rich.table import Table

    eligible = [s for s in skills if s.get("eligible")]
    ineligible = [s for s in skills if not s.get("eligible")]

    if eligible:
        table = Table(title=f"Skills — eligible ({len(eligible)})")
        table.add_column("Name", style="green bold")
        table.add_column("Source")
        table.add_column("Description", max_width=60)
        for s in eligible:
            table.add_row(
                s.get("id", ""),
                s.get("source", ""),
                _trunc(s.get("description", ""), 60),
            )
        console.print(table)

    if ineligible:
        console.print(
            f"  [dim]+ {len(ineligible)} ineligible skills "
            f"(missing deps)[/dim]"
        )
    console.print()


def _render_plugins(console: Any, plugins: list[dict[str, Any]]) -> None:
    if not plugins:
        console.print("[dim]Plugins: none[/dim]")
        return

    from rich.table import Table

    loaded = [p for p in plugins if p.get("enabled")]
    disabled = [p for p in plugins if not p.get("enabled")]

    table = Table(title=f"Plugins — loaded ({len(loaded)})")
    table.add_column("ID", style="bold")
    table.add_column("Origin")
    table.add_column("Providers")
    table.add_column("Tools")
    for p in loaded:
        provs = ", ".join(p.get("providerIds", []))
        tools = ", ".join(p.get("toolNames", []))
        table.add_row(p.get("id", ""), p.get("origin", ""), provs or "-", tools or "-")
    console.print(table)

    if disabled:
        names = ", ".join(p.get("id", "") for p in disabled[:10])
        suffix = f" … +{len(disabled) - 10} more" if len(disabled) > 10 else ""
        console.print(f"  [dim]+ {len(disabled)} disabled: {names}{suffix}[/dim]")
    console.print()


def _render_mcp(console: Any, mcps: list[dict[str, Any]]) -> None:
    if not mcps:
        console.print("[dim]MCP servers: none configured[/dim]\n")
        return

    from rich.table import Table

    table = Table(title=f"MCP Servers ({len(mcps)})")
    table.add_column("Name", style="bold")
    table.add_column("Transport")
    table.add_column("Command / URL")
    table.add_column("Env keys")
    for m in mcps:
        cmd_or_url = m.get("command") or m.get("url", "")
        if m.get("args"):
            cmd_or_url += " " + " ".join(str(a) for a in m["args"][:3])
        table.add_row(
            m.get("id", ""),
            m.get("transport", "stdio"),
            _trunc(cmd_or_url, 50),
            ", ".join(m.get("env_keys", [])) or "-",
        )
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
        proc = subprocess.run(
            ["openclaw", *args, "--json"],
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

    for stream in (proc.stdout, proc.stderr):
        text = stream.strip()
        if not text:
            continue
        try:
            return _CmdResult(data=json.loads(text), error=None, command=cmd_str)
        except json.JSONDecodeError:
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
        servers = raw.get("servers") or raw.get("mcpServers", {})
        if isinstance(servers, dict):
            rows: list[dict[str, Any]] = []
            for name, spec in servers.items():
                row: dict[str, Any] = {"id": str(name), "source": "openclaw mcp list"}
                if isinstance(spec, dict):
                    if spec.get("command"):
                        row["command"] = spec["command"]
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
