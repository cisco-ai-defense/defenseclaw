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

"""defenseclaw skill — Manage skills: scan, block, allow, list, disable, enable,
quarantine, restore, info, install.

Mirrors internal/cli/skill.go.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from typing import Any

import click

from defenseclaw.commands import compute_verdict as _compute_verdict
from defenseclaw.context import AppContext, pass_ctx


@click.group()
def skill() -> None:
    """Manage OpenClaw skills — search, install, scan, block, allow, disable, enable, quarantine, restore."""


# ---------------------------------------------------------------------------
# skill search
# ---------------------------------------------------------------------------

@skill.command()
@click.argument("query")
@click.option("--json", "as_json", is_flag=True, help="Output results as JSON")
@pass_ctx
def search(app: AppContext, query: str, as_json: bool) -> None:
    """Search the ClawHub skill registry.

    Delegates to ``npx clawhub search <query>`` and displays results.

    \b
    Examples:
      defenseclaw skill search wiki
      defenseclaw skill search database --json
    """
    try:
        result = subprocess.run(
            ["npx", "clawhub", "search", query],
            capture_output=True, text=True, timeout=30,
        )
    except FileNotFoundError:
        click.echo("error: npx not found — install Node.js to use clawhub search", err=True)
        raise SystemExit(1)
    except subprocess.TimeoutExpired:
        click.echo("error: clawhub search timed out", err=True)
        raise SystemExit(1)

    if result.returncode != 0:
        stderr = result.stderr.strip()
        click.echo(f"error: clawhub search failed: {stderr or 'unknown error'}", err=True)
        raise SystemExit(1)

    output = result.stdout.strip()
    if not output:
        click.echo(f"No skills found matching {query!r}")
        return

    if as_json:
        rows = []
        for line in output.splitlines():
            parts = line.split(None, 2)
            if len(parts) >= 2:
                name = parts[0]
                score = ""
                description = parts[1] if len(parts) >= 2 else ""
                if description.startswith("(") and description.endswith(")"):
                    score = description
                    description = ""
                elif len(parts) >= 3:
                    description = parts[1]
                    score = parts[2] if len(parts) >= 3 else ""
                rows.append({"name": name, "description": description, "score": score.strip("()")})
        click.echo(json.dumps(rows, indent=2))
        return

    click.echo(output)


# ---------------------------------------------------------------------------
# OpenClaw helpers — sidecar API first, local `openclaw` binary as fallback
# ---------------------------------------------------------------------------

def _run_openclaw(*args: str) -> str | None:
    """Run an openclaw CLI command and return the JSON body, or None on failure.

    OpenClaw may write JSON to stdout or stderr (and stderr may contain
    Node.js warnings around the JSON).  We try both streams, falling back
    to substring extraction when the whole stream isn't valid JSON.
    """
    try:
        from defenseclaw.config import openclaw_bin, openclaw_cmd_prefix
        prefix = openclaw_cmd_prefix()
        result = subprocess.run(
            [*prefix, openclaw_bin(), *args],
            capture_output=True, text=True, timeout=30,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None

    if result.returncode != 0:
        return None

    for stream in (result.stdout, result.stderr):
        text = (stream or "").strip()
        if not text:
            continue
        # Fast path: entire stream is valid JSON
        try:
            json.loads(text)
            return text
        except json.JSONDecodeError:
            pass
        # Slow path: find the first { or [ and try from there
        for ch in ("{", "["):
            idx = text.find(ch)
            if idx < 0:
                continue
            candidate = text[idx:]
            try:
                json.loads(candidate)
                return candidate
            except json.JSONDecodeError:
                pass
    return None


def _api_bind_host(app: AppContext) -> str:
    """Resolve the API bind address, mirroring sidecar.runAPI in Go.

    In standalone sandbox mode with a non-localhost guardrail host,
    the Go gateway binds to guardrail.host (the bridge IP) instead
    of 127.0.0.1.
    """
    if app.cfg.openshell.is_standalone() and app.cfg.guardrail.host not in ("", "localhost"):
        return app.cfg.guardrail.host
    return "127.0.0.1"


def _sidecar_client(app: AppContext):
    """Build an OrchestratorClient from the app's gateway config."""
    from defenseclaw.gateway import OrchestratorClient

    return OrchestratorClient(
        host=_api_bind_host(app),
        port=app.cfg.gateway.api_port,
        token=app.cfg.gateway.resolved_token(),
    )


def _list_skills_via_sidecar(app: AppContext) -> dict[str, Any] | None:
    """Fetch skills from the sidecar REST API (GET /skills)."""
    try:
        data = _sidecar_client(app).list_skills()
        if isinstance(data, dict):
            return data
        return None
    except Exception:
        return None


def _list_openclaw_skills_full(app: AppContext | None = None) -> dict[str, Any] | None:
    """Get the full skill list — tries sidecar API first, then local binary."""
    if app is not None:
        result = _list_skills_via_sidecar(app)
        if result is not None:
            return result

    out = _run_openclaw("skills", "list", "--json")
    if out is None:
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return None


def _get_openclaw_skill_info(name: str, app: AppContext | None = None) -> dict[str, Any] | None:
    """Get info for a single skill — tries sidecar first, then local binary."""
    if app is not None:
        full = _list_skills_via_sidecar(app)
        if full is not None:
            for s in full.get("skills", []):
                if s.get("name") == name:
                    return s

    out = _run_openclaw("skills", "info", name, "--json")
    if out is None:
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return None


# ---------------------------------------------------------------------------
# Scan map / actions map builders (mirror Go buildSkillScanMap / buildSkillActionsMap)
# ---------------------------------------------------------------------------

def _build_scan_map(store) -> dict[str, dict[str, Any]]:
    """Build a map of skill-name -> latest scan entry from the DB."""
    scan_map: dict[str, dict[str, Any]] = {}
    if store is None:
        return scan_map
    try:
        latest = store.latest_scans_by_scanner("skill-scanner")
    except Exception:
        return scan_map
    for ls in latest:
        name = os.path.basename(ls["target"])
        finding_count = ls["finding_count"]
        scan_map[name] = {
            "target": ls["target"],
            "clean": finding_count == 0,
            "max_severity": ls["max_severity"] if finding_count > 0 else "CLEAN",
            "total_findings": finding_count,
        }
    return scan_map


def _build_actions_map(store) -> dict[str, Any]:
    """Build a map of skill-name -> ActionEntry from the DB."""
    from defenseclaw.models import ActionEntry
    actions_map: dict[str, ActionEntry] = {}
    if store is None:
        return actions_map
    try:
        entries = store.list_actions_by_type("skill")
    except Exception:
        return actions_map
    for e in entries:
        actions_map[e.target_name] = e
    return actions_map


# ---------------------------------------------------------------------------
# skill list
# ---------------------------------------------------------------------------

def _skill_status(s: dict[str, Any]) -> str:
    if s.get("disabled"):
        return "disabled"
    if s.get("blockedByAllowlist"):
        return "blocked"
    if s.get("eligible"):
        return "active"
    return "inactive"


def _skill_status_display(
    s: dict[str, Any],
    action_entry: Any = None,
    scan_entry: dict[str, Any] | None = None,
) -> str:
    if s.get("disabled"):
        return "✗ disabled"
    if s.get("blockedByAllowlist"):
        return "✗ blocked"
    if action_entry and not action_entry.actions.is_empty():
        a = action_entry.actions
        if a.file == "quarantine":
            return "✗ quarantined"
        if a.install == "block":
            return "✗ blocked"
        if a.runtime == "disable":
            return "✗ disabled"
        if a.install == "allow":
            return "✓ allowed"
    if scan_entry:
        sev = scan_entry.get("max_severity", "CLEAN")
        if sev in ("CRITICAL", "HIGH"):
            return "✗ rejected"
        if sev in ("MEDIUM", "LOW"):
            return "⚠ warning"
    if s.get("eligible"):
        return "✓ ready"
    if s.get("source") in ("enforcement", "scan-history"):
        return "✗ removed"
    return "✗ missing"


def _skill_display_name(s: dict[str, Any]) -> str:
    emoji = (s.get("emoji", "") or "").strip()
    name = s.get("name", "")

    # Different terminals still render emoji widths a little differently,
    # so lead with the actual skill name and keep the icon as a suffix.
    if not emoji:
        return name

    return f"{name} {emoji}"


@skill.command("list")
@click.option("--json", "as_json", is_flag=True, help="Output merged skill list as JSON")
@pass_ctx
def list_skills(app: AppContext, as_json: bool) -> None:
    """List all OpenClaw skills with their latest scan severity."""

    oc_list = _list_openclaw_skills_full(app)
    skills = oc_list.get("skills", []) if oc_list else []

    scan_map = _build_scan_map(app.store)
    actions_map = _build_actions_map(app.store)

    if not skills and not actions_map and not scan_map:
        click.echo("No skills found. Is openclaw installed?")
        return

    known_names = {s.get("name", "") for s in skills}

    for name, ae in actions_map.items():
        if name not in known_names:
            skills.append({
                "name": name,
                "description": "",
                "emoji": "",
                "eligible": False,
                "disabled": ae.actions.runtime == "disable",
                "blockedByAllowlist": False,
                "source": "enforcement",
                "bundled": False,
                "homepage": "",
            })
            known_names.add(name)

    for name in scan_map:
        if name not in known_names:
            skills.append({
                "name": name,
                "description": "",
                "emoji": "",
                "eligible": False,
                "disabled": False,
                "blockedByAllowlist": False,
                "source": "scan-history",
                "bundled": False,
                "homepage": "",
            })
            known_names.add(name)

    if as_json:
        _print_skill_list_json(skills, scan_map, actions_map)
        return

    _print_skill_list_table(skills, scan_map, actions_map)

    from defenseclaw.commands import hint
    hint("Scan all skills:  defenseclaw skill scan all")


def _print_skill_list_json(
    skills: list[dict[str, Any]],
    scan_map: dict[str, dict[str, Any]],
    actions_map: dict[str, Any],
) -> None:
    items = []
    for s in skills:
        name = s.get("name", "")
        item: dict[str, Any] = {
            "name": name,
            "description": s.get("description", ""),
            "source": s.get("source", ""),
            "status": _skill_status(s),
            "eligible": s.get("eligible", False),
            "disabled": s.get("disabled", False),
            "bundled": s.get("bundled", False),
        }
        hp = s.get("homepage", "")
        if hp:
            item["homepage"] = hp
        if name in scan_map:
            item["scan"] = scan_map[name]
        if name in actions_map:
            ae = actions_map[name]
            if not ae.actions.is_empty():
                item["actions"] = ae.actions.to_dict()
        verdict_label, _ = _compute_verdict(actions_map.get(name), scan_map.get(name))
        item["verdict"] = verdict_label
        items.append(item)
    click.echo(json.dumps(items, indent=2, default=str))


def _print_skill_list_table(
    skills: list[dict[str, Any]],
    scan_map: dict[str, dict[str, Any]],
    actions_map: dict[str, Any],
) -> None:
    from rich.console import Console
    from rich.table import Table

    ready_count = sum(
        1 for s in skills if s.get("eligible") and not s.get("disabled")
    )

    console = Console()
    table = Table(title=f"Skills ({ready_count}/{len(skills)} ready)")
    table.add_column("Status", style="bold", no_wrap=True)
    table.add_column("Skill", no_wrap=True, overflow="ellipsis", max_width=24)
    table.add_column("Description", no_wrap=True, overflow="ellipsis", max_width=34)
    table.add_column("Source", no_wrap=True, overflow="ellipsis", max_width=18)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Verdict", no_wrap=True)
    table.add_column("Actions", no_wrap=True, overflow="ellipsis", max_width=18)

    for s in skills:
        name = s.get("name", "")
        display_name = _skill_display_name(s)
        status_display = _skill_status_display(s, actions_map.get(name), scan_map.get(name))
        desc = s.get("description", "")
        source = s.get("source", "")

        severity = "-"
        sev_style = ""
        if name in scan_map:
            severity = scan_map[name]["max_severity"]
            sev_style = {
                "CRITICAL": "bold red",
                "HIGH": "red",
                "MEDIUM": "yellow",
                "LOW": "cyan",
                "CLEAN": "green",
            }.get(severity, "")

        actions_str = "-"
        if name in actions_map:
            actions_str = actions_map[name].actions.summary()

        verdict_label, verdict_style = _compute_verdict(
            actions_map.get(name), scan_map.get(name),
        )

        status_style = ""
        if "✗" in status_display:
            status_style = "red"
        elif "✓" in status_display:
            status_style = "green"

        table.add_row(
            f"[{status_style}]{status_display}[/{status_style}]" if status_style else status_display,
            display_name,
            desc,
            source,
            f"[{sev_style}]{severity}[/{sev_style}]" if sev_style else severity,
            f"[{verdict_style}]{verdict_label}[/{verdict_style}]" if verdict_style else verdict_label,
            actions_str,
        )

    console.print(table)


# ---------------------------------------------------------------------------
# skill scan
# ---------------------------------------------------------------------------

@skill.command()
@click.argument("target", required=False)
@click.option("--json", "as_json", is_flag=True, help="Output scan results as JSON")
@click.option("--path", "scan_path", default="", help="Override skill directory path")
@click.option("--remote", is_flag=True, help="Scan via sidecar API (for skills on a remote host)")
@click.option("--all", "scan_all", is_flag=True, help="Scan all configured skills")
@click.option(
    "--action", is_flag=True, default=False,
    help="Apply enforcement actions (quarantine/block/disable) based on findings",
)
@pass_ctx
def scan(
    app: AppContext,
    target: str | None,
    as_json: bool,
    scan_path: str,
    remote: bool,
    scan_all: bool,
    action: bool,
) -> None:
    """Scan a skill by name, path, URL, or 'all' for all configured skills.

    Uses the native cisco-ai-skill-scanner SDK for local scans.

    Remote scanning (--remote):
      When the sidecar runs on a remote host (e.g. via SSM port-forward),
      pass --remote to send the scan request to the sidecar API instead of
      running the scanner locally.

    URL targets (fetch-to-temp):
      Pass an https:// URL or clawhub:// URI to download a skill package
      to a temp directory, scan it locally, then clean up. This lets you
      pre-screen skills before installing them.

      Examples:
        defenseclaw skill scan https://example.com/skills/my-skill.tar.gz
        defenseclaw skill scan clawhub://my-skill@1.2.3
    """
    from defenseclaw.enforce import PolicyEngine
    from defenseclaw.scanner.skill import SkillScannerWrapper

    if action and remote:
        click.echo(
            "error: --action is not supported with --remote; enforcement "
            "actions (quarantine/block/disable) require local file access",
            err=True,
        )
        raise SystemExit(1)

    # URL target → fetch-to-temp scan (Option 3)
    if scan_all and target not in (None, "all"):
        click.echo("error: provide either TARGET or --all, not both", err=True)
        raise SystemExit(2)

    if target and _is_url_target(target):
        if action:
            click.echo(
                "error: --action is not supported with URL targets; "
                "URL scans are pre-screening only",
                err=True,
            )
            raise SystemExit(1)
        _scan_from_url(app, target, as_json)
        return

    scanner = SkillScannerWrapper(app.cfg.scanners.skill_scanner, app.cfg.inspect_llm, app.cfg.cisco_ai_defense)

    if scan_all or target == "all":
        if remote:
            _scan_all_remote(app, as_json)
        else:
            _scan_all(app, scanner, as_json, enforce=action)
        return

    if not target:
        raise click.UsageError("Missing argument 'TARGET'.")

    # Resolve scan directory
    scan_dir = scan_path
    if not scan_dir:
        info = _get_openclaw_skill_info(target, app)
        if info and info.get("baseDir"):
            scan_dir = info["baseDir"]
        else:
            resolved = _resolve_path(app, target)
            if resolved:
                scan_dir = resolved

    if not scan_dir and not remote:
        click.echo(f"error: could not resolve skill {target!r} — use --path to specify manually", err=True)
        raise SystemExit(1)

    name = os.path.basename(scan_dir) if scan_dir else target

    # --remote: delegate scan to sidecar API — skip local policy checks
    # since enforcement runs on the remote host.
    if remote:
        _scan_via_sidecar(app, target=scan_dir or target, name=name, as_json=as_json)
        return

    pe = PolicyEngine(app.store)

    if pe.is_blocked("skill", name):
        click.echo(f"BLOCKED: {name} — remove from block list first", err=True)
        raise SystemExit(2)

    if pe.is_allowed("skill", name):
        click.echo(f"ALLOWED (skip scan): {name}")
        return

    if not as_json:
        click.echo(f"[scan] skill-scanner -> {scan_dir}")

    try:
        result = scanner.scan(scan_dir)
    except Exception as exc:
        click.echo(f"error: scan failed: {exc}", err=True)
        raise SystemExit(1)

    if app.logger:
        app.logger.log_scan(result)

    if as_json:
        click.echo(result.to_json())
    else:
        _print_result(name, result)
        from defenseclaw.commands import hint
        if result.is_clean():
            hint("Scan MCP servers:  defenseclaw mcp scan --all")
        else:
            hint(
                f"Block this skill:  defenseclaw skill block {name}",
                "View alerts:       defenseclaw alerts",
            )

    if not result.is_clean() and action:
        _apply_scan_enforcement(app, pe, name, scan_dir, result)


def _apply_scan_enforcement(
    app: AppContext,
    pe,
    skill_name: str,
    skill_path: str,
    result,
) -> None:
    """Apply configured skill_actions policy based on scan severity.

    Allow-listed skills are exempt from auto-enforcement — only a manual
    ``skill block`` can override an allow entry.
    """
    from defenseclaw.enforce.admission import evaluate_admission

    decision = evaluate_admission(
        pe,
        policy_dir=app.cfg.policy_dir,
        target_type="skill",
        name=skill_name,
        source_path=skill_path,
        scan_result=result,
        fallback_actions=app.cfg.skill_actions,
    )

    if decision.verdict == "allowed":
        click.echo(f"[scan] {skill_name!r} is allow-listed — skipping auto-enforcement")
        return

    from defenseclaw.enforce.skill_enforcer import SkillEnforcer

    sev = result.max_severity()
    action_cfg = decision.action

    if action_cfg.file == "none" and action_cfg.runtime != "disable" and action_cfg.install == "none":
        return

    enforcement_reason = f"post-scan: {len(result.findings)} findings, max={sev}"
    applied_actions: list[str] = []

    if action_cfg.file == "quarantine":
        pe.set_source_path("skill", skill_name, skill_path)
        se = SkillEnforcer(app.cfg.quarantine_dir)
        dest = se.quarantine(skill_name, skill_path)
        if dest:
            applied_actions.append(f"quarantined to {dest}")
            pe.quarantine("skill", skill_name, enforcement_reason)
        else:
            click.echo(f"[scan] quarantine failed for {skill_name!r}", err=True)

    if action_cfg.runtime == "disable":
        try:
            client = _sidecar_client(app)
            client.disable_skill(skill_name)
            applied_actions.append("disabled via gateway")
            pe.disable("skill", skill_name, enforcement_reason)
        except Exception:
            click.echo(f"[scan] gateway disable failed for {skill_name!r} — skipping runtime disable", err=True)

    if action_cfg.install == "block":
        pe.block("skill", skill_name, enforcement_reason)
        applied_actions.append("added to block list")

    if applied_actions:
        actions_str = ", ".join(applied_actions)
        click.echo(f"[scan] enforcement: {skill_name!r}: {actions_str}")
        if app.logger:
            detail = f"severity={sev} findings={len(result.findings)}"
            app.logger.log_action("scan-enforced", skill_name, f"{detail}; {actions_str}")


def _enable_skill_via_gateway(app: AppContext, skill_name: str) -> bool:
    """Best-effort runtime re-enable; returns True only on confirmed success."""
    client = _sidecar_client(app)
    try:
        resp = client.enable_skill(skill_name)
    except Exception as exc:
        click.echo(f"error: gateway enable failed: {exc}", err=True)
        return False

    if resp.get("status") != "enabled":
        click.echo(f"error: gateway returned unexpected response: {resp}", err=True)
        return False
    return True


def _scan_all(app: AppContext, scanner, as_json: bool, *, enforce: bool = False) -> None:
    from defenseclaw.enforce import PolicyEngine

    oc_list = _list_openclaw_skills_full(app)
    if oc_list and oc_list.get("skills"):
        skill_names = [s["name"] for s in oc_list["skills"]]
    else:
        skill_names = []

    pe = PolicyEngine(app.store)
    verdicts = []

    if skill_names:
        if not as_json:
            click.echo(f"[scan] found {len(skill_names)} skills to scan\n")
        for name in skill_names:
            info = _get_openclaw_skill_info(name, app)
            if not info or not info.get("baseDir"):
                click.echo(f"[scan] warning: no baseDir for {name}", err=True)
                continue
            base_dir = info["baseDir"]
            if not as_json:
                click.echo(f"[scan] skill-scanner -> {base_dir}")
            try:
                result = scanner.scan(base_dir)
                if app.logger:
                    app.logger.log_scan(result)
                verdicts.append({"name": name, "result": result})
                if as_json:
                    click.echo(result.to_json())
                else:
                    _print_result(name, result)
                    click.echo()
                if not result.is_clean() and enforce:
                    _apply_scan_enforcement(app, pe, name, base_dir, result)
            except Exception as exc:
                click.echo(f"[scan] error scanning {name}: {exc}", err=True)
    else:
        # Fall back to directory scan
        dirs = app.cfg.skill_dirs()
        for skill_dir in dirs:
            if not os.path.isdir(skill_dir):
                continue
            for entry in sorted(os.listdir(skill_dir)):
                path = os.path.join(skill_dir, entry)
                if not os.path.isdir(path):
                    continue
                if not as_json:
                    click.echo(f"[scan] skill-scanner -> {path}")
                try:
                    result = scanner.scan(path)
                    if app.logger:
                        app.logger.log_scan(result)
                    verdicts.append({"name": entry, "result": result})
                    if as_json:
                        click.echo(result.to_json())
                    else:
                        _print_result(entry, result)
                        click.echo()
                    if not result.is_clean() and enforce:
                        _apply_scan_enforcement(app, pe, entry, path, result)
                except Exception as exc:
                    click.echo(f"  Error: {exc}")

        if not verdicts:
            click.echo("No skills found in configured directories:")
            for d in (dirs if dirs else []):
                click.echo(f"  {d}")
            return

    if not as_json and verdicts:
        clean = sum(1 for v in verdicts if v["result"].is_clean())
        rejected = sum(
            1 for v in verdicts
            if not v["result"].is_clean()
            and (app.cfg.skill_actions.should_disable(v["result"].max_severity())
                 or app.cfg.skill_actions.should_quarantine(v["result"].max_severity()))
        )
        warnings = len(verdicts) - clean - rejected
        click.echo(f"Summary: {clean} clean, {warnings} warnings, {rejected} rejected")
        from defenseclaw.commands import hint
        if rejected:
            hint("View alerts:       defenseclaw alerts")
        else:
            hint("Scan MCP servers:  defenseclaw mcp scan --all")


def _resolve_path(app: AppContext, target: str) -> str | None:
    """Resolve a skill name or path to an actual directory."""
    if os.path.isdir(target):
        return target
    for candidate in app.cfg.installed_skill_candidates(target):
        if os.path.isdir(candidate):
            return candidate
    return None


# ---------------------------------------------------------------------------
# Option 2: Remote scan via sidecar API
# ---------------------------------------------------------------------------

def _scan_via_sidecar(app: AppContext, target: str, name: str, as_json: bool) -> None:
    """Send a scan request to the sidecar REST API (POST /v1/skill/scan).

    Used when DefenseClaw sidecar runs on a remote host and the CLI connects
    via SSM port-forward or direct network access.
    """
    client = _sidecar_client(app)

    if not as_json:
        click.echo(f"[scan] remote skill-scanner via sidecar -> {target}")

    try:
        data = client.scan_skill(target=target, name=name)
    except Exception as exc:
        click.echo(f"error: remote scan failed: {exc}", err=True)
        raise SystemExit(1)

    if as_json:
        click.echo(json.dumps(data, indent=2, default=str))
        return

    findings = data.get("findings") or data.get("Findings") or []
    max_sev = data.get("max_severity", "INFO")
    click.echo(f"  Skill:    {name}")
    click.echo(f"  Target:   {target} (remote)")
    click.echo(f"  Findings: {len(findings)}")

    if not findings:
        click.secho("  Verdict:  CLEAN", fg="green")
    else:
        color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow"}.get(max_sev, "white")
        sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        counts = {}
        for f in findings:
            s = f.get("severity") or f.get("Severity") or "INFO"
            counts[s] = counts.get(s, 0) + 1
        breakdown = ", ".join(
            f"{counts[s]} {s.lower()}" for s in sev_order if s in counts
        )
        click.secho(f"  Verdict:  {max_sev} ({breakdown})", fg=color)
        click.echo()
        for f in findings:
            sev = f.get("severity") or f.get("Severity") or "INFO"
            title = f.get("title") or f.get("Title") or ""
            sev_color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan"}.get(sev, "white")
            click.secho(f"    [{sev}]", fg=sev_color, nl=False)
            click.echo(f" {title}")


def _scan_all_remote(app: AppContext, as_json: bool) -> None:
    """Scan all skills via the sidecar API."""
    oc_list = _list_openclaw_skills_full(app)
    if not oc_list or not oc_list.get("skills"):
        click.echo("No skills found via sidecar.")
        return

    for s in oc_list["skills"]:
        name = s.get("name", "")
        base_dir = s.get("baseDir") or s.get("filePath") or ""
        if not base_dir:
            click.echo(f"[scan] warning: no path for {name}", err=True)
            continue
        _scan_via_sidecar(app, target=base_dir, name=name, as_json=as_json)
        if not as_json:
            click.echo()


# ---------------------------------------------------------------------------
# Option 3: Fetch-to-temp scan (URL / registry targets)
# ---------------------------------------------------------------------------

def _is_url_target(target: str) -> bool:
    """Check if the target is a URL or registry reference."""
    return target.startswith("https://") or target.startswith("http://") or target.startswith("clawhub://")


def _scan_from_url(app: AppContext, url: str, as_json: bool) -> None:
    """Fetch a skill and scan locally, then clean up.

    Supports two schemes:
      clawhub://name[@version]  — uses `npx clawhub install` into a temp dir
      https://...               — downloads a .tar.gz or .zip archive
    """
    if url.startswith("clawhub://"):
        _scan_from_clawhub(app, url, as_json)
    else:
        _scan_from_http(app, url, as_json)


def _scan_from_clawhub(app: AppContext, uri: str, as_json: bool) -> None:
    """Download a skill from the npm registry, scan locally, then clean up.

    Skills are bundled inside the 'openclaw' npm package at skills/<name>/.
    Flow: fetch openclaw tarball from npm → extract skills/<name>/ → scan → delete.
    """
    import shutil
    import tempfile

    import requests

    from defenseclaw.scanner.skill import SkillScannerWrapper

    name, _version = _parse_clawhub_uri(uri)
    if not name:
        click.echo(f"error: invalid clawhub URI: {uri}", err=True)
        raise SystemExit(1)

    if not as_json:
        click.echo(f"[scan] fetching skill {name!r} from openclaw registry ...")

    # Get the tarball URL from npm
    try:
        meta = requests.get("https://registry.npmjs.org/openclaw/latest", timeout=30).json()
        tarball_url = meta.get("dist", {}).get("tarball")
    except requests.RequestException as exc:
        click.echo(f"error: npm registry lookup failed: {exc}", err=True)
        raise SystemExit(1)

    if not tarball_url:
        click.echo("error: could not resolve openclaw tarball URL from npm", err=True)
        raise SystemExit(1)

    if not as_json:
        click.echo(f"[scan] downloading {tarball_url}")

    tmpdir = tempfile.mkdtemp(prefix="defenseclaw-clawhub-")
    try:
        resp = requests.get(tarball_url, timeout=120, stream=True)
        resp.raise_for_status()

        archive_path = os.path.join(tmpdir, "openclaw.tgz")
        with open(archive_path, "wb") as f:
            for chunk in resp.iter_content(chunk_size=65536):
                f.write(chunk)

        if not as_json:
            size_mb = os.path.getsize(archive_path) / (1024 * 1024)
            click.echo(f"[scan] downloaded {size_mb:.1f} MB, extracting skill {name!r} ...")

        skill_prefix = f"package/skills/{name}/"
        skill_dir = os.path.join(tmpdir, "skill")
        os.makedirs(skill_dir, exist_ok=True)

        if not as_json:
            click.echo(
                f"[scan] extracting prefix={skill_prefix!r} → {skill_dir!s}"
            )
        _safe_tar_extract(archive_path, skill_dir, skill_prefix, strip=3)

        os.unlink(archive_path)  # free disk immediately

        found = bool(os.listdir(skill_dir))
        if not as_json and found:
            click.echo(f"[scan] extracted entries in skill_dir: {os.listdir(skill_dir)!r}")

        if not found:
            click.echo(f"error: skill {name!r} not found in openclaw package", err=True)
            raise SystemExit(1)

        if not as_json:
            click.echo(f"[scan] skill-scanner -> {skill_dir}")

        scanner = SkillScannerWrapper(app.cfg.scanners.skill_scanner, app.cfg.inspect_llm, app.cfg.cisco_ai_defense)
        result = scanner.scan(skill_dir)

        if app.logger:
            app.logger.log_scan(result)

        if as_json:
            click.echo(result.to_json())
        else:
            _print_result(name, result)

    except requests.RequestException as exc:
        click.echo(f"error: download failed: {exc}", err=True)
        raise SystemExit(1)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
        if not as_json:
            click.echo("[scan] cleaned up temporary files")


def _scan_from_http(app: AppContext, url: str, as_json: bool) -> None:
    """Download a skill archive from HTTP(S), extract, scan, then clean up."""
    import shutil
    import tarfile
    import tempfile
    import zipfile

    import requests

    from defenseclaw.scanner.skill import SkillScannerWrapper

    if not as_json:
        click.echo(f"[scan] fetching skill from {url}")

    tmpdir = tempfile.mkdtemp(prefix="defenseclaw-skill-")
    try:
        resp = requests.get(url, timeout=60, stream=True)
        resp.raise_for_status()

        download_path = os.path.join(tmpdir, "download")
        with open(download_path, "wb") as f:
            for chunk in resp.iter_content(chunk_size=8192):
                f.write(chunk)

        extract_dir = os.path.join(tmpdir, "skill")
        os.makedirs(extract_dir, exist_ok=True)

        if tarfile.is_tarfile(download_path):
            if not as_json:
                click.echo(f"[scan] tarfile: extracting {download_path!s} -> {extract_dir!s}")
            with tarfile.open(download_path) as tf:
                members = tf.getnames()
                if not as_json:
                    n = len(members)
                    preview = members[:20]
                    more = f" ... ({n} total)" if n > 20 else ""
                    click.echo(f"[scan] tarfile: members={n} first={preview!r}{more}")
                tf.extractall(extract_dir, filter="data")
            if not as_json:
                click.echo(f"[scan] tarfile: extractall done -> listing={os.listdir(extract_dir)!r}")
        elif zipfile.is_zipfile(download_path):
            with zipfile.ZipFile(download_path) as zf:
                safe_root = os.path.realpath(extract_dir)
                for member in zf.infolist():
                    member_path = os.path.realpath(
                        os.path.join(extract_dir, member.filename),
                    )
                    if not member_path.startswith(safe_root + os.sep) and member_path != safe_root:
                        click.echo(f"error: zip contains path-traversal entry: {member.filename}", err=True)
                        raise SystemExit(1)
                zf.extractall(extract_dir)
        else:
            click.echo("error: unsupported archive format (expected .tar.gz or .zip)", err=True)
            raise SystemExit(1)

        entries = os.listdir(extract_dir)
        skill_dir = extract_dir
        if len(entries) == 1:
            single = os.path.join(extract_dir, entries[0])
            if os.path.isdir(single):
                skill_dir = single

        name = os.path.basename(skill_dir)
        if not as_json:
            click.echo(f"[scan] skill-scanner -> {skill_dir} (fetched)")

        scanner = SkillScannerWrapper(app.cfg.scanners.skill_scanner, app.cfg.inspect_llm, app.cfg.cisco_ai_defense)
        result = scanner.scan(skill_dir)

        if app.logger:
            app.logger.log_scan(result)

        if as_json:
            click.echo(result.to_json())
        else:
            _print_result(name, result)

    except requests.RequestException as exc:
        click.echo(f"error: download failed: {exc}", err=True)
        raise SystemExit(1)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


_CLAWHUB_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$")


def _parse_clawhub_uri(uri: str) -> tuple[str, str | None]:
    """Parse clawhub://name[@version] → (name, version or None).

    Names are restricted to alphanumeric, dots, hyphens, and underscores
    to prevent path traversal when used in tar extraction prefixes.
    """
    path = uri.removeprefix("clawhub://")
    if not path:
        return ("", None)

    version: str | None = None
    if "@" in path:
        name, version = path.split("@", 1)
    else:
        name = path

    if not _CLAWHUB_NAME_RE.match(name):
        return ("", None)
    return (name, version)


def _safe_tar_extract(
    archive_path: str, dest_dir: str, prefix: str, *, strip: int = 0
) -> None:
    """Extract members under *prefix* from a tar archive into *dest_dir*.

    Each member name is validated after stripping *strip* leading path
    components to prevent path traversal (``..`` segments, absolute paths,
    or symlinks escaping *dest_dir*).
    """
    import tarfile

    real_dest = os.path.realpath(dest_dir)
    with tarfile.open(archive_path, "r:gz") as tf:
        for member in tf.getmembers():
            if not member.name.startswith(prefix):
                continue
            if member.issym() or member.islnk():
                continue

            parts = member.name.split("/")
            if len(parts) <= strip:
                continue
            stripped = os.path.join(*parts[strip:])
            target = os.path.realpath(os.path.join(dest_dir, stripped))
            if not (target == real_dest or target.startswith(real_dest + os.sep)):
                continue
            if ".." in stripped.split(os.sep):
                continue

            member_copy = tarfile.TarInfo(name=stripped)
            member_copy.size = member.size
            member_copy.mode = 0o644 if not member.isdir() else 0o755

            if member.isdir():
                os.makedirs(target, exist_ok=True)
            elif member.isfile():
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with tf.extractfile(member) as src:
                    if src is None:
                        continue
                    with open(target, "wb") as dst:
                        while True:
                            chunk = src.read(65536)
                            if not chunk:
                                break
                            dst.write(chunk)


def _print_result(name: str, result) -> None:
    click.echo(f"  Skill:    {name}")
    click.echo(f"  Target:   {result.target}")
    click.echo(f"  Duration: {result.duration.total_seconds():.2f}s")
    click.echo(f"  Findings: {len(result.findings)}")

    if result.is_clean():
        click.secho("  Verdict:  CLEAN", fg="green")
    else:
        sev = result.max_severity()
        color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow"}.get(sev, "white")
        sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        counts = {}
        for f in result.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        breakdown = ", ".join(
            f"{counts[s]} {s.lower()}" for s in sev_order if s in counts
        )
        click.secho(f"  Verdict:  {sev} ({breakdown})", fg=color)
        click.echo()
        for f in result.findings:
            sev_color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan"}.get(f.severity, "white")
            click.secho(f"    [{f.severity}]", fg=sev_color, nl=False)
            click.echo(f" {f.title}")
            if f.location:
                click.echo(f"      Location: {f.location}")
            if f.description:
                desc = f.description[:120] + "..." if len(f.description) > 120 else f.description
                click.echo(f"      {desc}")
            if f.remediation:
                click.echo(f"      Fix: {f.remediation}")


# ---------------------------------------------------------------------------
# skill block
# ---------------------------------------------------------------------------

@skill.command()
@click.argument("name")
@click.option("--reason", default="", help="Reason for blocking")
@pass_ctx
def block(app: AppContext, name: str, reason: str) -> None:
    """Add a skill to the install block list.

    Blocked skills are rejected by 'skill install' before any scan.
    Does not affect already-running skills — use 'skill disable' or
    'skill quarantine' for that.
    """
    from defenseclaw.enforce import PolicyEngine

    skill_name = os.path.basename(name)
    pe = PolicyEngine(app.store)

    if not reason:
        reason = "manual block via CLI"

    pe.block("skill", skill_name, reason)
    skill_path = _resolve_path(app, skill_name)
    if skill_path:
        pe.set_source_path("skill", skill_name, skill_path)
    click.secho(f"[skill] {skill_name!r} added to block list", fg="red")

    if app.logger:
        app.logger.log_action("skill-block", skill_name, f"reason={reason}")

    from defenseclaw.commands import hint
    hint(f"Unblock later:  defenseclaw skill unblock {skill_name}")


# ---------------------------------------------------------------------------
# skill unblock
# ---------------------------------------------------------------------------

@skill.command()
@click.argument("name")
@pass_ctx
def unblock(app: AppContext, name: str) -> None:
    """Remove a skill from the block list and clear all enforcement state.

    Clears block, quarantine, and disable actions without adding to the
    allow list — the skill will go through normal scanning on next install.

    To also restore quarantined files, run 'skill restore' after unblocking.
    """
    from defenseclaw.enforce import PolicyEngine

    skill_name = os.path.basename(name)
    pe = PolicyEngine(app.store)

    has_state = (
        pe.is_blocked("skill", skill_name)
        or pe.is_quarantined("skill", skill_name)
        or app.store.has_action("skill", skill_name, "runtime", "disable")
    )
    if not has_state:
        click.echo(f"[skill] {skill_name!r} has no enforcement state to clear")
        return

    entry = pe.get_action("skill", skill_name)
    saved_path = entry.source_path if entry else ""
    runtime_disabled = bool(entry and entry.actions.runtime == "disable")

    runtime_cleared = True
    if runtime_disabled:
        runtime_cleared = _enable_skill_via_gateway(app, skill_name)

    if runtime_cleared:
        pe.remove_action("skill", skill_name)
        click.secho(f"[skill] {skill_name!r} all enforcement state cleared (block/quarantine/disable)", fg="green")
    else:
        pe.unblock("skill", skill_name)
        pe.clear_quarantine("skill", skill_name)
        click.secho(
            f"[skill] {skill_name!r} install/file enforcement cleared; "
            "runtime disable remains until the gateway is reachable",
            fg="yellow",
        )
    if saved_path:
        restore_hint = f"--path \"{saved_path}\""
    else:
        restore_hint = "--path <original-dir>"
    click.echo(
        f"  Tip: if files are quarantined, run "
        f"'defenseclaw skill restore {skill_name} {restore_hint}'"
    )

    if app.logger:
        app.logger.log_action("skill-unblock", skill_name, "manual unblock via CLI")


# ---------------------------------------------------------------------------
# skill allow
# ---------------------------------------------------------------------------

@skill.command()
@click.argument("name")
@click.option("--reason", default="", help="Reason for allowing")
@pass_ctx
def allow(app: AppContext, name: str, reason: str) -> None:
    """Add a skill to the install allow list.

    Allow-listed skills skip the scan gate during install.
    Adding a skill also removes it from the block list.
    """
    from defenseclaw.enforce import PolicyEngine

    skill_name = os.path.basename(name)
    pe = PolicyEngine(app.store)

    if not reason:
        reason = "manual allow via CLI"

    entry = pe.get_action("skill", skill_name)
    runtime_disabled = bool(entry and entry.actions.runtime == "disable")
    runtime_cleared = True
    if runtime_disabled:
        runtime_cleared = _enable_skill_via_gateway(app, skill_name)

    if runtime_cleared:
        pe.allow("skill", skill_name, reason)
    else:
        app.store.set_action_field("skill", skill_name, "install", "allow", reason)

    skill_path = _resolve_path(app, skill_name)
    if skill_path:
        pe.set_source_path("skill", skill_name, skill_path)
    if runtime_cleared:
        click.secho(f"[skill] {skill_name!r} added to allow list", fg="green")
    else:
        click.secho(
            f"[skill] {skill_name!r} added to allow list; runtime disable remains until the gateway is reachable",
            fg="yellow",
        )

    if app.logger:
        app.logger.log_action("skill-allow", skill_name, f"reason={reason}")


# ---------------------------------------------------------------------------
# skill disable (runtime, via gateway RPC)
# ---------------------------------------------------------------------------

@skill.command()
@click.argument("name")
@click.option("--reason", default="", help="Reason for disabling")
@pass_ctx
def disable(app: AppContext, name: str, reason: str) -> None:
    """Disable a skill at runtime via the OpenClaw gateway.

    Sends a skills.update RPC to prevent the agent from using the skill's
    tools until re-enabled. This is runtime-only — it does not block install
    or quarantine files.

    Requires the gateway to be running.
    """
    from defenseclaw.enforce import PolicyEngine
    skill_name = os.path.basename(name)

    client = _sidecar_client(app)
    try:
        client.disable_skill(skill_name)
    except Exception as exc:
        click.echo(f"error: gateway disable failed: {exc}", err=True)
        raise SystemExit(1)

    click.echo(f'[skill] {skill_name!r} disabled via gateway RPC')

    if not reason:
        reason = "manual disable via CLI"

    pe = PolicyEngine(app.store)
    pe.disable("skill", skill_name, reason)

    if app.logger:
        app.logger.log_action("skill-disable", skill_name, f"reason={reason}")


# ---------------------------------------------------------------------------
# skill enable (runtime, via gateway RPC)
# ---------------------------------------------------------------------------

@skill.command()
@click.argument("name")
@pass_ctx
def enable(app: AppContext, name: str) -> None:
    """Enable a previously disabled skill via the OpenClaw gateway.

    This is a runtime-only action.
    """
    from defenseclaw.enforce import PolicyEngine

    skill_name = os.path.basename(name)

    client = _sidecar_client(app)
    try:
        client.enable_skill(skill_name)
    except Exception as exc:
        click.echo(f"error: gateway enable failed: {exc}", err=True)
        raise SystemExit(1)

    click.echo(f'[skill] {skill_name!r} enabled via gateway RPC')

    pe = PolicyEngine(app.store)
    pe.enable("skill", skill_name)

    if app.logger:
        app.logger.log_action("skill-enable", skill_name, "re-enabled via CLI")


# ---------------------------------------------------------------------------
# skill quarantine
# ---------------------------------------------------------------------------

@skill.command()
@click.argument("name")
@click.option("--reason", default="", help="Reason for quarantine")
@pass_ctx
def quarantine(app: AppContext, name: str, reason: str) -> None:
    """Quarantine a skill's files to the quarantine area.

    Moves the skill's directory to ~/.defenseclaw/quarantine/skills/ and records
    the action. The skill can be restored with 'skill restore'.
    """
    from defenseclaw.enforce import PolicyEngine
    from defenseclaw.enforce.skill_enforcer import SkillEnforcer

    skill_name = os.path.basename(name)
    if not skill_name or ".." in name:
        click.echo(f"error: invalid skill name {name!r}", err=True)
        raise SystemExit(1)

    if os.path.isabs(name):
        # Validate absolute paths resolve inside a configured skill directory
        real = os.path.realpath(name)
        allowed_roots = [os.path.realpath(c) for c in app.cfg.skill_dirs()]
        if any(real == root for root in allowed_roots):
            click.echo(
                f"error: path {name!r} must point to a specific skill directory, not the skill root",
                err=True,
            )
            raise SystemExit(1)
        if not any(real.startswith(root + os.sep) for root in allowed_roots):
            click.echo(
                f"error: path {name!r} is not inside a configured skill directory\n"
                f"  Allowed roots: {', '.join(allowed_roots)}",
                err=True,
            )
            raise SystemExit(1)
        skill_path: str | None = real
    else:
        skill_path = _resolve_path(app, skill_name)

    if not skill_path:
        click.echo(f"error: could not locate skill {skill_name!r} — provide an absolute path", err=True)
        raise SystemExit(1)

    se = SkillEnforcer(app.cfg.quarantine_dir)
    dest = se.quarantine(skill_name, skill_path)
    if dest is None:
        click.echo(f"error: skill path does not exist: {skill_path}", err=True)
        raise SystemExit(1)

    click.echo(f'[skill] {skill_name!r} quarantined to {dest}')

    if not reason:
        reason = "manual quarantine via CLI"

    pe = PolicyEngine(app.store)
    pe.quarantine("skill", skill_name, reason)
    pe.set_source_path("skill", skill_name, skill_path)

    if app.logger:
        app.logger.log_action("skill-quarantine", skill_name, f"reason={reason}, dest={dest}")


# ---------------------------------------------------------------------------
# skill restore
# ---------------------------------------------------------------------------

@skill.command()
@click.argument("name")
@click.option("--path", "restore_path", default="", help="Override restore destination (defaults to original path)")
@pass_ctx
def restore(app: AppContext, name: str, restore_path: str) -> None:
    """Restore a quarantined skill to its original location.

    By default restores to the original path recorded during quarantine.
    Use --path to override the restore destination.
    """
    from defenseclaw.enforce import PolicyEngine
    from defenseclaw.enforce.skill_enforcer import SkillEnforcer

    skill_name = os.path.basename(name)

    se = SkillEnforcer(app.cfg.quarantine_dir)
    if not se.is_quarantined(skill_name):
        click.echo(f"error: {skill_name!r} is not quarantined", err=True)
        raise SystemExit(1)

    pe = PolicyEngine(app.store)

    if not restore_path:
        entry = pe.get_action("skill", skill_name)
        if entry is None or not entry.source_path:
            click.echo(
                f"error: no stored path for {skill_name!r} — use --path to specify restore destination",
                err=True,
            )
            raise SystemExit(1)
        restore_path = entry.source_path

    allowed_roots = app.cfg.skill_dirs() if hasattr(app.cfg, "skill_dirs") and callable(app.cfg.skill_dirs) else None
    real_restore = os.path.realpath(restore_path)
    if allowed_roots:
        if not any(
            real_restore.startswith(os.path.realpath(r) + os.sep) or real_restore == os.path.realpath(r)
            for r in allowed_roots
        ):
            click.echo(
                "error: restore path must be within configured skill directories",
                err=True,
            )
            raise SystemExit(1)

    if not se.restore(skill_name, restore_path, allowed_roots=allowed_roots):
        click.echo(f"error: restore failed for {skill_name!r}", err=True)
        raise SystemExit(1)

    click.echo(f'[skill] {skill_name!r} restored to {restore_path}')

    pe.clear_quarantine("skill", skill_name)
    pe.set_source_path("skill", skill_name, restore_path)

    if app.logger:
        app.logger.log_action("skill-restore", skill_name, f"restored to {restore_path}")


# ---------------------------------------------------------------------------
# skill info
# ---------------------------------------------------------------------------

@skill.command()
@click.argument("name")
@click.option("--json", "as_json", is_flag=True, help="Output skill info as JSON")
@pass_ctx
def info(app: AppContext, name: str, as_json: bool) -> None:
    """Show detailed information about a skill.

    Displays merged skill metadata from OpenClaw, latest scan results from the
    DefenseClaw audit database, and enforcement actions.
    """
    skill_name = os.path.basename(name)

    info_map = _get_openclaw_skill_info(skill_name, app)
    if info_map is None:
        info_map = {"name": skill_name}

    scan_map = _build_scan_map(app.store)
    if skill_name in scan_map:
        info_map["scan"] = scan_map[skill_name]

    actions_map = _build_actions_map(app.store)
    if skill_name in actions_map:
        ae = actions_map[skill_name]
        if not ae.actions.is_empty():
            info_map["actions"] = ae.actions.to_dict()

    if as_json:
        click.echo(json.dumps(info_map, indent=2, default=str))
        return

    # Text output
    click.echo(f"Skill:       {info_map.get('name', skill_name)}")
    if info_map.get("description"):
        click.echo(f"Description: {info_map['description']}")
    if info_map.get("source"):
        click.echo(f"Source:      {info_map['source']}")
    if info_map.get("baseDir"):
        click.echo(f"Path:        {info_map['baseDir']}")
    if info_map.get("filePath"):
        click.echo(f"File:        {info_map['filePath']}")
    click.echo(f"Eligible:    {info_map.get('eligible', False)}")
    click.echo(f"Bundled:     {info_map.get('bundled', False)}")
    if info_map.get("homepage"):
        click.echo(f"Homepage:    {info_map['homepage']}")

    scan_data = info_map.get("scan")
    if scan_data:
        click.echo()
        click.echo("Last Scan:")
        if scan_data.get("clean"):
            click.secho("  Verdict:  CLEAN", fg="green")
        else:
            n = scan_data.get("total_findings", 0)
            sev = scan_data.get("max_severity", "INFO")
            click.echo(f"  Verdict:  {n} {sev} findings")
        click.echo(f"  Target:   {scan_data.get('target', '')}")

    actions_data = info_map.get("actions")
    if actions_data:
        from defenseclaw.models import ActionState
        state = ActionState.from_dict(actions_data)
        if not state.is_empty():
            click.echo()
            click.echo(f"Actions:     {state.summary()}")


# ---------------------------------------------------------------------------
# skill install
# ---------------------------------------------------------------------------

@skill.command()
@click.argument("name")
@click.option("--force", is_flag=True, help="Force install (overwrites existing)")
@click.option("--action", "take_action", is_flag=True, help="Apply skill_actions policy based on scan severity")
@pass_ctx
def install(app: AppContext, name: str, force: bool, take_action: bool) -> None:
    """Install and scan an OpenClaw skill via clawhub.

    By default, install only runs the scan and reports findings — no enforcement
    actions are taken. Pass --action to apply the configured skill_actions policy
    (quarantine, disable, block) based on scan severity.

    Use --force to overwrite an existing skill.
    """
    from defenseclaw.enforce import PolicyEngine
    from defenseclaw.enforce.admission import evaluate_admission
    from defenseclaw.enforce.skill_enforcer import SkillEnforcer
    from defenseclaw.scanner.skill import SkillScannerWrapper

    skill_name = os.path.basename(name)
    pe = PolicyEngine(app.store)

    pre_decision = evaluate_admission(
        pe,
        policy_dir=app.cfg.policy_dir,
        target_type="skill",
        name=skill_name,
        source_path=name,
        fallback_actions=app.cfg.skill_actions,
    )

    if pre_decision.verdict == "blocked":
        if app.logger:
            app.logger.log_action("install-rejected", skill_name, "reason=blocked")
        click.echo(
            f"error: skill {skill_name!r} is on the block list"
            f" — run 'defenseclaw skill allow {skill_name}' to unblock",
            err=True,
        )
        raise SystemExit(1)

    if pre_decision.verdict == "allowed":
        if pre_decision.source == "scan-disabled":
            click.echo(f"[install] policy allows {skill_name!r} without scan")
        else:
            click.echo(f"[install] {skill_name!r} is on the allow list — skipping scan")
        if app.logger:
            app.logger.log_action("install-allowed", skill_name, "reason=allow-listed")
        _run_clawhub_install(skill_name, force)
        return

    # Install via clawhub
    click.echo(f"[install] installing {skill_name!r} via clawhub...")
    _run_clawhub_install(skill_name, force)

    # Locate and scan
    skill_path = _resolve_path(app, skill_name)
    if not skill_path:
        click.echo("[install] warning: could not locate installed skill for scan", err=True)
        return

    click.echo(f"[install] scanning {skill_path}...")
    scanner = SkillScannerWrapper(app.cfg.scanners.skill_scanner, app.cfg.inspect_llm, app.cfg.cisco_ai_defense)
    try:
        result = scanner.scan(skill_path)
    except Exception as exc:
        click.echo(f"error: scan failed: {exc}", err=True)
        raise SystemExit(1)

    if app.logger:
        app.logger.log_scan(result)

    _print_result(skill_name, result)

    post_decision = evaluate_admission(
        pe,
        policy_dir=app.cfg.policy_dir,
        target_type="skill",
        name=skill_name,
        source_path=skill_path,
        scan_result=result,
        fallback_actions=app.cfg.skill_actions,
    )

    if post_decision.verdict == "allowed":
        click.echo(f"[install] {skill_name!r} became allow-listed — skipping post-scan enforcement")
        if app.logger:
            app.logger.log_action("install-allowed", skill_name, "reason=allow-listed-post-scan")
        return

    if post_decision.verdict == "clean":
        click.echo(f"[install] {skill_name!r} installed and clean")
        if app.logger:
            app.logger.log_action("install-clean", skill_name, "verdict=clean")
        return

    sev = result.max_severity()
    detail = f"severity={sev} findings={len(result.findings)}"

    if not take_action:
        click.echo(
            f"[install] {len(result.findings)} {sev} findings in {skill_name!r} "
            f"(no action taken — pass --action to enforce)"
        )
        if app.logger:
            app.logger.log_action("install-warning", skill_name, detail)
        return

    # --action: apply configured skill_actions policy
    action_cfg = post_decision.action
    enforcement_reason = f"post-install scan: {len(result.findings)} findings, max={sev}"
    applied_actions: list[str] = []

    if action_cfg.file == "quarantine":
        se = SkillEnforcer(app.cfg.quarantine_dir)
        dest = se.quarantine(skill_name, skill_path)
        if dest:
            applied_actions.append(f"quarantined to {dest}")
            pe.quarantine("skill", skill_name, enforcement_reason)
        else:
            click.echo("[install] quarantine failed", err=True)

    if action_cfg.runtime == "disable":
        client = _sidecar_client(app)
        try:
            client.disable_skill(skill_name)
            applied_actions.append("disabled via gateway")
            pe.disable("skill", skill_name, enforcement_reason)
        except Exception as exc:
            click.echo(f"[install] gateway disable failed: {exc}", err=True)

    if action_cfg.install == "block":
        pe.block("skill", skill_name, enforcement_reason)
        applied_actions.append("added to block list")

    if action_cfg.install == "allow":
        pe.allow("skill", skill_name, enforcement_reason)
        applied_actions.append("added to allow list")

    pe.set_source_path("skill", skill_name, skill_path)

    if applied_actions:
        actions_str = ", ".join(applied_actions)
        click.echo(f"[install] {skill_name!r}: {actions_str} ({detail})")
        if app.logger:
            app.logger.log_action("install-enforced", skill_name, f"{detail}; {actions_str}")
        click.echo(f"error: skill {skill_name!r} had {sev} findings — actions applied: {actions_str}", err=True)
        raise SystemExit(1)

    click.echo(f"[install] warning: {len(result.findings)} {sev} findings in {skill_name!r}")
    if app.logger:
        app.logger.log_action("install-warning", skill_name, detail)


def _run_clawhub_install(skill_name: str, force: bool) -> None:
    args = ["npx", "clawhub", "install", skill_name]
    if force:
        args.append("--force")
    try:
        subprocess.run(args, check=True, timeout=300)
    except subprocess.TimeoutExpired:
        click.echo("error: clawhub install timed out after 300s", err=True)
        raise SystemExit(1)
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        click.echo(f"error: clawhub install failed: {exc}", err=True)
        raise SystemExit(1)
