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

"""defenseclaw plugin — Manage plugins: install, list, remove, scan, block,
allow, disable, enable, quarantine, restore, info.

Mirrors the skill CLI governance commands for plugins.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from typing import Any

import click

from defenseclaw.commands import compute_verdict as _compute_verdict
from defenseclaw.context import AppContext, pass_ctx


def _api_bind_host(app: AppContext) -> str:
    """Resolve the API bind address, mirroring sidecar.runAPI in Go."""
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


@click.group()
def plugin() -> None:
    """Manage DefenseClaw plugins — install, list, remove, scan, block, allow, disable, enable, quarantine, restore."""


@plugin.command()
@click.argument("name_or_path")
@click.option("--json", "as_json", is_flag=True, help="Output scan results as JSON")
@click.option("--policy", "policy_name", default="", help="Scan policy: default, strict, permissive, or path to YAML")
@click.option("--profile", type=click.Choice(["default", "strict"]), default=None,
              help="Scan profile (overrides policy profile)")
@click.option("--use-llm", is_flag=True, help="Enable LLM-based semantic analysis (uses skill_scanner LLM config)")
@click.option("--llm-model", default="", help="LLM model override (e.g. claude-sonnet-4-20250514, gpt-4)")
@click.option("--llm-provider", default="", help="LLM provider hint (anthropic, openai, ollama, etc.)")
@click.option("--llm-consensus-runs", default=0, type=int, help="Number of LLM consensus runs (default: 1)")
@click.option("--enable-meta/--no-meta", default=True, help="Enable/disable meta analyzer (default: enabled)")
@click.option("--lenient", is_flag=True, help="Suppress low-confidence findings (sets min_confidence=0.5)")
@pass_ctx
def scan(
    app: AppContext,
    name_or_path: str,
    as_json: bool,
    policy_name: str,
    profile: str | None,
    use_llm: bool,
    llm_model: str,
    llm_provider: str,
    llm_consensus_runs: int,
    enable_meta: bool,
    lenient: bool,
) -> None:
    """Scan a plugin directory for security issues.

    Uses defenseclaw-plugin-scanner to check for dangerous permissions,
    install scripts, credential theft, obfuscation, and supply chain risks.

    LLM analysis uses the same configuration as the skill scanner
    (reads from config.yaml: inspect_llm).

    Examples:\n
      defenseclaw plugin scan my-plugin\n
      defenseclaw plugin scan my-plugin --policy strict\n
      defenseclaw plugin scan my-plugin --use-llm\n
      defenseclaw plugin scan my-plugin --use-llm --llm-model gpt-4\n
      defenseclaw plugin scan my-plugin --policy ~/.defenseclaw/policies/custom.yaml\n
      defenseclaw plugin scan /path/to/plugin --profile strict --lenient
    """
    from defenseclaw.scanner.plugin import PluginScannerWrapper

    scan_dir = _resolve_plugin_dir(name_or_path, app.cfg.plugin_dir)
    if not scan_dir:
        click.echo(f"error: plugin not found: {name_or_path}", err=True)
        click.echo("  Provide a path, a DefenseClaw plugin name, or an OpenClaw plugin name.", err=True)
        raise SystemExit(1)

    # Build scan options from CLI flags + config
    scan_options = _build_scan_options(
        app, policy_name, profile, use_llm, llm_model, llm_provider,
        llm_consensus_runs, enable_meta, lenient,
    )

    # Route the unified LLM config (top-level ``llm:`` + any
    # ``scanners.plugin.llm:`` overrides) into the wrapper. The
    # wrapper layers per-call CLI flags on top before dispatching.
    scanner = PluginScannerWrapper(llm=app.cfg.resolve_llm("scanners.plugin"))
    if not as_json:
        flags = []
        if policy_name:
            flags.append(f"policy={policy_name}")
        if use_llm:
            model = llm_model or scan_options.get("llm_model", "")
            flags.append(f"llm={model}")
        if profile:
            flags.append(f"profile={profile}")
        flag_str = f" ({', '.join(flags)})" if flags else ""
        click.echo(f"[plugin] scanning {scan_dir}{flag_str}...")

    try:
        result = scanner.scan(scan_dir, **scan_options)
    except SystemExit:
        raise
    except Exception as exc:
        click.echo(f"error: scan failed: {exc}", err=True)
        raise SystemExit(1)

    if app.logger:
        app.logger.log_scan(result)

    if as_json:
        click.echo(result.to_json())
    elif result.is_clean():
        click.secho(f"  Plugin: {os.path.basename(scan_dir)}", bold=True)
        click.secho("  Verdict: CLEAN", fg="green")
    else:
        sev = result.max_severity()
        color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow"}.get(sev, "white")
        click.secho(f"  Plugin:   {os.path.basename(scan_dir)}", bold=True)
        click.echo(f"  Duration: {result.duration.total_seconds():.2f}s")
        click.secho(f"  Verdict:  {sev} ({len(result.findings)} findings)", fg=color)
        click.echo()
        for f in result.findings:
            sev_color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan"}.get(f.severity, "white")
            click.secho(f"    [{f.severity}]", fg=sev_color, nl=False)
            click.echo(f" {f.title}")
            if f.location:
                click.echo(f"      Location: {f.location}")
            if f.remediation:
                click.echo(f"      Fix: {f.remediation}")


def _build_scan_options(
    app: AppContext,
    policy_name: str,
    profile: str | None,
    use_llm: bool,
    llm_model: str,
    llm_provider: str,
    llm_consensus_runs: int,
    enable_meta: bool,
    lenient: bool,
) -> dict:
    """Build ``PluginScannerWrapper.scan`` kwargs from CLI flags.

    LLM defaults (model, api_key, base_url, provider) come from the
    unified :class:`LLMConfig` — resolved at ``scanners.plugin`` and
    threaded in via ``PluginScannerWrapper(llm=...)``. This function
    only forwards the per-invocation knobs the operator set on this
    particular command line. Any field left at its default ("", 0)
    falls through to the unified config.
    """
    opts: dict = {}

    if policy_name:
        opts["policy"] = policy_name
    if profile:
        opts["profile"] = profile

    if use_llm:
        opts["use_llm"] = True
        if llm_model:
            opts["llm_model"] = llm_model
        if llm_provider:
            opts["llm_provider"] = llm_provider
        if llm_consensus_runs > 0:
            opts["llm_consensus_runs"] = llm_consensus_runs

    if not enable_meta:
        opts["disable_meta"] = True

    if lenient:
        opts["lenient"] = True

    return opts


@plugin.command()
@click.argument("name_or_path")
@click.option("--force", is_flag=True, help="Force install (overwrites existing)")
@click.option("--action", "take_action", is_flag=True, help="Apply plugin_actions policy based on scan severity")
@pass_ctx
def install(app: AppContext, name_or_path: str, force: bool, take_action: bool) -> None:
    """Install a plugin from a local path, npm registry, clawhub, or URL.

    Supports four source types (auto-detected):

    \b
      Local directory   defenseclaw plugin install /path/to/plugin
      npm package       defenseclaw plugin install @openclasw/voice-call
      clawhub URI       defenseclaw plugin install clawhub://voice-call
      HTTP(S) URL       defenseclaw plugin install https://example.com/plugin.tgz

    After downloading, the plugin is scanned for security issues. Pass --action
    to apply the configured plugin_actions policy (quarantine, disable, block)
    based on scan severity. Use --force to overwrite an existing plugin.
    """
    import tempfile

    from defenseclaw.enforce import PolicyEngine
    from defenseclaw.enforce.admission import evaluate_admission
    from defenseclaw.enforce.plugin_enforcer import PluginEnforcer
    from defenseclaw.registry import (
        RegistryError,
        SourceType,
        detect_source,
        fetch_from_clawhub,
        fetch_from_url,
        fetch_npm_package,
    )
    from defenseclaw.scanner.plugin import PluginScannerWrapper

    plugin_dir = app.cfg.plugin_dir
    os.makedirs(plugin_dir, exist_ok=True)

    source = detect_source(name_or_path)
    pe = PolicyEngine(app.store)

    # --- Resolve plugin name early for policy checks ---
    if source == SourceType.LOCAL:
        plugin_name = os.path.basename(name_or_path.rstrip("/"))
    elif source == SourceType.CLAWHUB:
        from defenseclaw.registry import parse_clawhub_uri
        plugin_name, _ = parse_clawhub_uri(name_or_path)
    elif source == SourceType.NPM:
        plugin_name = name_or_path.rsplit("/", 1)[-1] if "/" in name_or_path else name_or_path
    else:
        plugin_name = ""

    pre_decision = None
    if plugin_name:
        pre_install_source = name_or_path if source == SourceType.LOCAL else ""
        pre_decision = evaluate_admission(
            pe,
            policy_dir=app.cfg.policy_dir,
            target_type="plugin",
            name=plugin_name,
            source_path=pre_install_source,
            fallback_actions=app.cfg.plugin_actions,
        )

    # --- Block list check ---
    if pre_decision is not None and pre_decision.verdict == "blocked":
        if app.logger:
            app.logger.log_action("install-rejected", plugin_name, "reason=blocked")
        click.echo(
            f"error: plugin {plugin_name!r} is on the block list"
            f" — run 'defenseclaw plugin allow {plugin_name}' to unblock",
            err=True,
        )
        raise SystemExit(1)

    # --- Manual/policy allow check (skip scan) ---
    allowed = pre_decision is not None and pre_decision.verdict == "allowed"
    if allowed:
        if pre_decision is not None and pre_decision.source == "scan-disabled":
            click.echo(f"[install] policy allows {plugin_name!r} without scan")
        else:
            click.echo(f"[install] {plugin_name!r} is on the allow list — skipping scan")
        if app.logger:
            app.logger.log_action("install-allowed", plugin_name, "reason=allow-listed")

    # --- Fetch plugin ---
    tmpdir: str | None = None
    source_path: str

    if source == SourceType.LOCAL:
        if not os.path.isdir(name_or_path):
            click.echo(f"error: directory not found: {name_or_path}", err=True)
            raise SystemExit(1)
        source_path = name_or_path
    else:
        tmpdir = tempfile.mkdtemp(prefix="dclaw-plugin-fetch-")
        try:
            if source == SourceType.NPM:
                click.echo(f"[install] fetching {name_or_path!r} from npm registry...")
                source_path = fetch_npm_package(name_or_path, tmpdir)
            elif source == SourceType.CLAWHUB:
                click.echo(f"[install] fetching {name_or_path!r} from clawhub...")
                source_path = fetch_from_clawhub(name_or_path, tmpdir, plugin_name=plugin_name)
            else:
                click.echo(f"[install] downloading from {name_or_path}...")
                source_path = fetch_from_url(name_or_path, tmpdir)
        except RegistryError as exc:
            click.echo(f"error: {exc}", err=True)
            shutil.rmtree(tmpdir, ignore_errors=True)
            raise SystemExit(1)

        if not plugin_name:
            plugin_name = os.path.basename(source_path)

    try:
        # --- Duplicate check ---
        dest = os.path.join(plugin_dir, plugin_name)
        if os.path.exists(dest):
            if not force:
                click.echo(f"Plugin already installed: {plugin_name}")
                click.echo(f"  Remove first with: defenseclaw plugin remove {plugin_name}")
                click.echo("  Or pass --force to overwrite")
                raise SystemExit(1)
            shutil.rmtree(dest)

        # --- Scan (unless allow-listed) ---
        if not allowed:
            click.echo(f"[install] scanning {source_path}...")
            scanner = PluginScannerWrapper(llm=app.cfg.resolve_llm("scanners.plugin"))
            try:
                result = scanner.scan(source_path)
            except Exception as exc:
                click.echo(f"error: scan failed: {exc}", err=True)
                raise SystemExit(1)

            if app.logger:
                app.logger.log_scan(result)

            _print_install_result(plugin_name, result)

            if result.is_clean():
                click.echo(f"[install] {plugin_name!r} is clean")
                if app.logger:
                    app.logger.log_action("install-clean", plugin_name, "verdict=clean")
            else:
                sev = result.max_severity()
                detail = f"severity={sev} findings={len(result.findings)}"
                provenance_path = source_path if source == SourceType.LOCAL else ""
                post_decision = evaluate_admission(
                    pe,
                    policy_dir=app.cfg.policy_dir,
                    target_type="plugin",
                    name=plugin_name,
                    source_path=provenance_path,
                    scan_result=result,
                    fallback_actions=app.cfg.plugin_actions,
                )

                if post_decision.verdict == "allowed":
                    click.echo(f"[install] {plugin_name!r} became allow-listed — skipping post-scan enforcement")
                    if app.logger:
                        app.logger.log_action("install-allowed", plugin_name, "reason=allow-listed-post-scan")
                elif not take_action:
                    click.echo(
                        f"[install] {len(result.findings)} {sev} findings in {plugin_name!r} "
                        f"(no action taken — pass --action to enforce)"
                    )
                    if app.logger:
                        app.logger.log_action("install-warning", plugin_name, detail)
                else:
                    action_cfg = post_decision.action
                    enforcement_reason = f"post-install scan: {len(result.findings)} findings, max={sev}"
                    applied_actions: list[str] = []

                    if action_cfg.file == "quarantine":
                        se = PluginEnforcer(app.cfg.quarantine_dir)
                        q_dest = se.quarantine(plugin_name, source_path)
                        if q_dest:
                            applied_actions.append(f"quarantined to {q_dest}")
                            pe.quarantine("plugin", plugin_name, enforcement_reason)
                        else:
                            click.echo("[install] quarantine failed", err=True)

                    if action_cfg.runtime == "disable":
                        client = _sidecar_client(app)
                        try:
                            client.disable_plugin(plugin_name)
                            applied_actions.append("disabled via gateway")
                            pe.disable("plugin", plugin_name, enforcement_reason)
                        except Exception as exc:
                            click.echo(f"[install] gateway disable failed: {exc}", err=True)

                    if action_cfg.install == "block":
                        pe.block("plugin", plugin_name, enforcement_reason)
                        applied_actions.append("added to block list")

                    if action_cfg.install == "allow":
                        pe.allow("plugin", plugin_name, enforcement_reason)
                        applied_actions.append("added to allow list")

                    if applied_actions:
                        actions_str = ", ".join(applied_actions)
                        click.echo(f"[install] {plugin_name!r}: {actions_str} ({detail})")
                        if app.logger:
                            app.logger.log_action("install-enforced", plugin_name, f"{detail}; {actions_str}")
                        click.echo(
                            f"error: plugin {plugin_name!r} had {sev} findings — actions applied: {actions_str}",
                            err=True,
                        )
                        raise SystemExit(1)

                    click.echo(f"[install] warning: {len(result.findings)} {sev} findings in {plugin_name!r}")
                    if app.logger:
                        app.logger.log_action("install-warning", plugin_name, detail)

        # --- Copy to plugin_dir ---
        shutil.copytree(source_path, dest)
        pe.set_source_path("plugin", plugin_name, dest)
        click.echo(f"Installed plugin: {plugin_name}")
        if app.logger:
            app.logger.log_action("plugin-install", plugin_name, f"source={name_or_path}")

        from defenseclaw.commands import hint
        hint(
            "List plugins:      defenseclaw plugin list",
            "Restart gateway:   defenseclaw-gateway restart",
        )

    finally:
        if tmpdir:
            shutil.rmtree(tmpdir, ignore_errors=True)


def _print_install_result(name: str, result) -> None:
    """Print a compact summary of scan results during install."""
    if result.is_clean():
        return
    sev = result.max_severity()
    color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow"}.get(sev, "white")
    click.secho(f"  Plugin:   {name}", bold=True)
    click.echo(f"  Duration: {result.duration.total_seconds():.2f}s")
    click.secho(f"  Verdict:  {sev} ({len(result.findings)} findings)", fg=color)
    for f in result.findings:
        sev_color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan"}.get(f.severity, "white")
        click.secho(f"    [{f.severity}]", fg=sev_color, nl=False)
        click.echo(f" {f.title}")


@plugin.command("list")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
@pass_ctx
def list_plugins(app: AppContext, as_json: bool) -> None:
    """List installed plugins (DefenseClaw + OpenClaw) with scan severity."""
    plugins = _merge_all_plugins(app.cfg.plugin_dir)
    scan_map = _build_plugin_scan_map(app.store)
    actions_map = _build_plugin_actions_map(app.store)

    if not plugins and not scan_map:
        click.echo("No plugins found. Is openclaw installed?")
        return

    known_ids = {p["id"] for p in plugins}
    for scan_id in scan_map:
        if scan_id not in known_ids:
            plugins.append({
                "id": scan_id,
                "name": scan_id,
                "description": "",
                "version": "",
                "origin": "scan-history",
                "enabled": False,
                "source": "scan-history",
            })
            known_ids.add(scan_id)

    if as_json:
        _print_plugin_list_json(plugins, scan_map, actions_map)
        return

    _print_plugin_list_table(plugins, scan_map, actions_map)

    from defenseclaw.commands import hint
    hint("Scan a plugin:  defenseclaw plugin scan <name>")


def _merge_all_plugins(plugin_dir: str) -> list[dict[str, Any]]:
    """Build a unified plugin list from DefenseClaw + OpenClaw sources.

    Each entry carries both ``id`` (directory basename, matches scan DB
    targets) and ``name`` (human-readable display name from OpenClaw).
    """
    plugins: list[dict[str, Any]] = []

    for dir_name in _list_defenseclaw_plugins(plugin_dir):
        plugins.append({
            "id": dir_name,
            "name": dir_name,
            "description": "",
            "version": "",
            "origin": "local",
            "enabled": True,
            "source": "defenseclaw",
        })

    for p in _list_openclaw_plugins():
        plugins.append({
            "id": p.get("id", ""),
            "name": p.get("name") or p.get("id", "unknown"),
            "description": p.get("description", ""),
            "version": p.get("version", ""),
            "origin": p.get("origin", ""),
            "enabled": p.get("enabled", False),
            "source": "openclaw",
        })

    return plugins




def _plugin_status(p: dict[str, Any]) -> str:
    if not p.get("enabled"):
        return "disabled"
    return "enabled"


def _plugin_status_display(p: dict[str, Any], action_entry: Any = None) -> str:
    if action_entry and not action_entry.actions.is_empty():
        a = action_entry.actions
        if a.file == "quarantine":
            return "\u2717 quarantined"
        if a.install == "block":
            return "\u2717 blocked"
        if a.runtime == "disable":
            return "\u2717 disabled"
    if p.get("enabled"):
        return "\u2713 enabled"
    return "\u2717 disabled"


def _print_plugin_list_json(
    plugins: list[dict[str, Any]],
    scan_map: dict[str, dict[str, Any]],
    actions_map: dict[str, Any],
) -> None:
    items = []
    for p in plugins:
        pid = p["id"]
        item: dict[str, Any] = {
            "id": pid,
            "name": p["name"],
            "description": p.get("description", ""),
            "version": p.get("version", ""),
            "origin": p.get("origin", ""),
            "source": p.get("source", ""),
            "status": _plugin_status(p),
            "enabled": p.get("enabled", False),
        }
        if pid in scan_map:
            item["scan"] = scan_map[pid]
        if pid in actions_map:
            ae = actions_map[pid]
            if not ae.actions.is_empty():
                item["actions"] = ae.actions.to_dict()
        verdict_label, _ = _compute_verdict(actions_map.get(pid), scan_map.get(pid))
        item["verdict"] = verdict_label
        items.append(item)
    click.echo(json.dumps(items, indent=2, default=str))


def _print_plugin_list_table(
    plugins: list[dict[str, Any]],
    scan_map: dict[str, dict[str, Any]],
    actions_map: dict[str, Any],
) -> None:
    from rich.console import Console
    from rich.table import Table

    enabled_count = sum(1 for p in plugins if p.get("enabled"))

    console = Console()
    table = Table(title=f"Plugins ({enabled_count}/{len(plugins)} enabled)")
    table.add_column("Status", style="bold")
    table.add_column("ID")
    table.add_column("Plugin")
    table.add_column("Description", max_width=50)
    table.add_column("Origin")
    table.add_column("Severity")
    table.add_column("Verdict")
    table.add_column("Actions")

    for p in plugins:
        pid = p["id"]
        name = p["name"]
        status_display = _plugin_status_display(p, actions_map.get(pid))
        desc = p.get("description", "")

        origin = p.get("origin", "") or p.get("source", "")

        severity = "-"
        sev_style = ""
        if pid in scan_map:
            severity = scan_map[pid]["max_severity"]
            sev_style = {
                "CRITICAL": "bold red",
                "HIGH": "red",
                "MEDIUM": "yellow",
                "LOW": "cyan",
                "CLEAN": "green",
            }.get(severity, "")

        actions_str = "-"
        if pid in actions_map:
            actions_str = actions_map[pid].actions.summary()

        verdict_label, verdict_style = _compute_verdict(
            actions_map.get(pid), scan_map.get(pid),
        )

        status_style = ""
        if "\u2717" in status_display:
            status_style = "red"
        elif "\u2713" in status_display:
            status_style = "green"

        table.add_row(
            f"[{status_style}]{status_display}[/{status_style}]" if status_style else status_display,
            pid,
            name,
            desc[:50] + "\u2026" if len(desc) > 50 else desc,
            origin,
            f"[{sev_style}]{severity}[/{sev_style}]" if sev_style else severity,
            f"[{verdict_style}]{verdict_label}[/{verdict_style}]" if verdict_style else verdict_label,
            actions_str,
        )

    console.print(table)


def _resolve_plugin_dir(name_or_path: str, plugin_dir: str) -> str | None:
    """Resolve a plugin name or path to a directory on disk.

    Resolution order:
      1. Literal path (already a directory)
      2. Subdirectory under DefenseClaw's plugin_dir
      3. OpenClaw plugin by name (``openclaw plugins info <name> --json``)
    """
    if os.path.isdir(name_or_path):
        return name_or_path

    candidate = os.path.join(plugin_dir, name_or_path)
    if os.path.isdir(candidate):
        return candidate

    for lookup in dict.fromkeys([name_or_path, name_or_path.lower()]):
        info = _get_openclaw_plugin_info(lookup)
        if info:
            root = info.get("rootDir") or info.get("source", "")
            if root:
                if os.path.isdir(root):
                    return root
                # source is a file — walk up to find the plugin root
                # (directory containing package.json or openclaw.plugin.json)
                check = os.path.dirname(root)
                while check and check != os.path.dirname(check):
                    if any(os.path.isfile(os.path.join(check, m))
                           for m in ("package.json", "openclaw.plugin.json")):
                        return check
                    check = os.path.dirname(check)
            break

    return None


def _get_openclaw_plugin_info(name: str) -> dict | None:
    """Run ``openclaw plugins info <name> --json`` and return the plugin dict."""
    try:
        from defenseclaw.config import openclaw_bin, openclaw_cmd_prefix
        prefix = openclaw_cmd_prefix()
        proc = subprocess.run(
            [*prefix, openclaw_bin(), "plugins", "info", name, "--json"],
            capture_output=True, text=True, timeout=15,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None

    if proc.returncode != 0:
        return None

    for stream in (proc.stdout, proc.stderr):
        text = (stream or "").strip()
        if not text:
            continue
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            idx = text.find("{")
            if idx < 0:
                continue
            try:
                data = json.loads(text[idx:])
            except (json.JSONDecodeError, ValueError):
                continue

        if isinstance(data, dict):
            return data.get("plugin", data)

    return None


def _resolve_openclaw_plugin_id(name: str) -> str:
    """Resolve a user-provided plugin name to the actual OpenClaw plugin ID.

    Handles formats like ``@openclaw/xai-plugin`` → ``xai``,
    ``xai-plugin`` → ``xai``, or returns the name unchanged if already valid.
    """
    bare = name
    if "/" in bare:
        bare = bare.rsplit("/", 1)[-1]

    candidates = [bare]
    for suffix in ("-plugin", "-provider"):
        if bare.endswith(suffix):
            candidates.append(bare[: -len(suffix)])

    plugins = _list_openclaw_plugins()
    ids = {p.get("id", "") for p in plugins}
    names_to_id = {p.get("name", ""): p.get("id", "") for p in plugins}

    for c in candidates:
        if c in ids:
            return c
        if c in names_to_id:
            return names_to_id[c]

    return bare


def _plugin_runtime_candidates(name: str) -> list[str]:
    bare = os.path.basename(name)
    candidates: list[str] = []
    for candidate in (bare, _resolve_openclaw_plugin_id(name)):
        if candidate and candidate not in candidates:
            candidates.append(candidate)
    for suffix in ("-plugin", "-provider"):
        if bare.endswith(suffix):
            stripped = bare[: -len(suffix)]
            if stripped and stripped not in candidates:
                candidates.append(stripped)
    return candidates


def _enable_plugin_via_gateway(app: AppContext, plugin_name: str) -> bool:
    """Best-effort runtime re-enable; returns True only on confirmed success."""
    client = _sidecar_client(app)
    try:
        resp = client.enable_plugin(plugin_name)
    except Exception as exc:
        click.echo(f"error: gateway enable failed: {exc}", err=True)
        return False

    if resp.get("status") != "enabled":
        click.echo(f"error: gateway returned unexpected response: {resp}", err=True)
        return False
    return True


def _list_defenseclaw_plugins(plugin_dir: str) -> list[str]:
    """Return sorted list of DefenseClaw plugin directory names."""
    if not os.path.isdir(plugin_dir):
        return []
    return sorted(
        e for e in os.listdir(plugin_dir)
        if os.path.isdir(os.path.join(plugin_dir, e))
    )


def _list_openclaw_plugins() -> list[dict]:
    """Query ``openclaw plugins list --json`` for the active OpenClaw plugins."""
    try:
        from defenseclaw.config import openclaw_bin, openclaw_cmd_prefix
        prefix = openclaw_cmd_prefix()
        proc = subprocess.run(
            [*prefix, openclaw_bin(), "plugins", "list", "--json"],
            capture_output=True, text=True, timeout=15,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []

    if proc.returncode != 0:
        return []

    for stream in (proc.stdout, proc.stderr):
        text = (stream or "").strip()
        if not text:
            continue
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            idx = text.find("{")
            if idx < 0:
                idx = text.find("[")
            if idx < 0:
                continue
            try:
                data = json.loads(text[idx:])
            except (json.JSONDecodeError, ValueError):
                continue

        if isinstance(data, dict):
            plugins = data.get("plugins", [])
        elif isinstance(data, list):
            plugins = data
        else:
            continue

        return [p for p in plugins if isinstance(p, dict)]

    return []


@plugin.command()
@click.argument("name")
@pass_ctx
def remove(app: AppContext, name: str) -> None:
    """Remove an installed plugin."""
    plugin_dir = app.cfg.plugin_dir
    safe_name = os.path.basename(name)
    if not safe_name or safe_name in (".", ".."):
        click.echo(f"Invalid plugin name: {name}", err=True)
        raise SystemExit(1)

    path = os.path.realpath(os.path.join(plugin_dir, safe_name))
    if not path.startswith(os.path.realpath(plugin_dir) + os.sep):
        click.echo(f"Invalid plugin name: {name}", err=True)
        raise SystemExit(1)

    if not os.path.isdir(path):
        click.echo(f"Plugin not found: {safe_name}")
        return

    shutil.rmtree(path)
    click.echo(f"Removed plugin: {safe_name}")
    if app.logger:
        app.logger.log_action("plugin-remove", safe_name, "")

    from defenseclaw.commands import hint
    hint("Restart gateway to apply:  defenseclaw-gateway restart")


# ---------------------------------------------------------------------------
# plugin block
# ---------------------------------------------------------------------------

@plugin.command()
@click.argument("name")
@click.option("--reason", default="", help="Reason for blocking")
@pass_ctx
def block(app: AppContext, name: str, reason: str) -> None:
    """Add a plugin to the install block list.

    Blocked plugins are rejected by the admission gate before any scan.
    Does not affect already-installed plugins — use 'plugin disable' or
    'plugin quarantine' for that.
    """
    from defenseclaw.enforce import PolicyEngine

    plugin_name = os.path.basename(name)
    pe = PolicyEngine(app.store)

    if not reason:
        reason = "manual block via CLI"

    pe.block("plugin", plugin_name, reason)
    plugin_path = _resolve_plugin_path(app, plugin_name)
    if plugin_path:
        pe.set_source_path("plugin", plugin_name, plugin_path)
    click.secho(f"[plugin] {plugin_name!r} added to block list", fg="red")

    if app.logger:
        app.logger.log_action("plugin-block", plugin_name, f"reason={reason}")


# ---------------------------------------------------------------------------
# plugin allow
# ---------------------------------------------------------------------------

@plugin.command()
@click.argument("name")
@click.option("--reason", default="", help="Reason for allowing")
@pass_ctx
def allow(app: AppContext, name: str, reason: str) -> None:
    """Add a plugin to the install allow list.

    Allow-listed plugins skip the scan gate during install.
    Adding a plugin also removes it from the block list.
    """
    from defenseclaw.enforce import PolicyEngine

    plugin_name = os.path.basename(name)
    runtime_name = plugin_name
    pe = PolicyEngine(app.store)

    if not reason:
        reason = "manual allow via CLI"

    entry = pe.get_action("plugin", plugin_name)
    runtime_entry = entry
    for candidate in _plugin_runtime_candidates(name):
        resolved_entry = pe.get_action("plugin", candidate)
        if resolved_entry is not None and resolved_entry.actions.runtime == "disable":
            runtime_entry = resolved_entry
            runtime_name = candidate
            break
    runtime_disabled = bool(runtime_entry and runtime_entry.actions.runtime == "disable")
    runtime_cleared = True
    if runtime_disabled:
        runtime_cleared = _enable_plugin_via_gateway(app, runtime_name)
        if runtime_cleared and runtime_name != plugin_name:
            pe.enable("plugin", runtime_name)

    if runtime_cleared:
        pe.allow("plugin", plugin_name, reason)
    else:
        app.store.set_action_field("plugin", plugin_name, "install", "allow", reason)

    plugin_path = _resolve_plugin_path(app, plugin_name)
    if plugin_path:
        pe.set_source_path("plugin", plugin_name, plugin_path)
    if runtime_cleared:
        click.secho(f"[plugin] {plugin_name!r} added to allow list", fg="green")
    else:
        click.secho(
            f"[plugin] {plugin_name!r} added to allow list; runtime disable remains until the gateway is reachable",
            fg="yellow",
        )

    if app.logger:
        app.logger.log_action("plugin-allow", plugin_name, f"reason={reason}")


# ---------------------------------------------------------------------------
# plugin disable (runtime, via gateway RPC)
# ---------------------------------------------------------------------------

@plugin.command()
@click.argument("name")
@click.option("--reason", default="", help="Reason for disabling")
@pass_ctx
def disable(app: AppContext, name: str, reason: str) -> None:
    """Disable a plugin at runtime via the OpenClaw gateway.

    Sends an RPC to prevent the agent from using the plugin until
    re-enabled. This is runtime-only — it does not block install or
    quarantine files.

    Requires the gateway to be running.
    """
    from defenseclaw.enforce import PolicyEngine

    plugin_name = _resolve_openclaw_plugin_id(name)

    client = _sidecar_client(app)
    try:
        resp = client.disable_plugin(plugin_name)
    except Exception as exc:
        click.echo(f"error: gateway disable failed: {exc}", err=True)
        raise SystemExit(1)

    if resp.get("status") != "disabled":
        click.echo(f"error: gateway returned unexpected response: {resp}", err=True)
        raise SystemExit(1)

    click.echo(f"[plugin] {plugin_name!r} disabled via gateway RPC")

    if not reason:
        reason = "manual disable via CLI"

    pe = PolicyEngine(app.store)
    pe.disable("plugin", plugin_name, reason)

    if app.logger:
        app.logger.log_action("plugin-disable", plugin_name, f"reason={reason}")


# ---------------------------------------------------------------------------
# plugin enable (runtime, via gateway RPC)
# ---------------------------------------------------------------------------

@plugin.command()
@click.argument("name")
@pass_ctx
def enable(app: AppContext, name: str) -> None:
    """Enable a previously disabled plugin via the OpenClaw gateway.

    This is a runtime-only action.
    """
    from defenseclaw.enforce import PolicyEngine

    plugin_name = _resolve_openclaw_plugin_id(name)

    client = _sidecar_client(app)
    try:
        resp = client.enable_plugin(plugin_name)
    except Exception as exc:
        click.echo(f"error: gateway enable failed: {exc}", err=True)
        raise SystemExit(1)

    if resp.get("status") != "enabled":
        click.echo(f"error: gateway returned unexpected response: {resp}", err=True)
        raise SystemExit(1)

    click.echo(f"[plugin] {plugin_name!r} enabled via gateway RPC")

    pe = PolicyEngine(app.store)
    pe.enable("plugin", plugin_name)

    if app.logger:
        app.logger.log_action("plugin-enable", plugin_name, "re-enabled via CLI")


# ---------------------------------------------------------------------------
# plugin quarantine
# ---------------------------------------------------------------------------

@plugin.command()
@click.argument("name")
@click.option("--reason", default="", help="Reason for quarantine")
@pass_ctx
def quarantine(app: AppContext, name: str, reason: str) -> None:
    """Quarantine a plugin's files to the quarantine area.

    Moves the plugin's directory to ~/.defenseclaw/quarantine/plugins/ and
    records the action. The plugin can be restored with 'plugin restore'.
    """
    from defenseclaw.enforce import PolicyEngine
    from defenseclaw.enforce.plugin_enforcer import PluginEnforcer

    plugin_name = os.path.basename(name)
    plugin_dir = app.cfg.plugin_dir

    if os.path.isabs(name):
        real_path = os.path.realpath(name)
        real_plugin_dir = os.path.realpath(plugin_dir)
        if not real_path.startswith(real_plugin_dir + os.sep):
            click.echo(f"error: path must be within plugin directory {plugin_dir}", err=True)
            raise SystemExit(1)
        plugin_path = real_path
    else:
        plugin_path = _resolve_plugin_path(app, plugin_name)

    if not plugin_path:
        click.echo(f"error: could not locate plugin {plugin_name!r}", err=True)
        raise SystemExit(1)

    pe_enforcer = PluginEnforcer(app.cfg.quarantine_dir)
    dest = pe_enforcer.quarantine(plugin_name, plugin_path)
    if dest is None:
        click.echo(f"error: plugin path does not exist: {plugin_path}", err=True)
        raise SystemExit(1)

    click.echo(f"[plugin] {plugin_name!r} quarantined to {dest}")

    if not reason:
        reason = "manual quarantine via CLI"

    pe = PolicyEngine(app.store)
    pe.quarantine("plugin", plugin_name, reason)
    pe.set_source_path("plugin", plugin_name, plugin_path)

    if app.logger:
        app.logger.log_action("plugin-quarantine", plugin_name, f"reason={reason}, dest={dest}")


# ---------------------------------------------------------------------------
# plugin restore
# ---------------------------------------------------------------------------

@plugin.command()
@click.argument("name")
@click.option("--path", "restore_path", default="", help="Override restore destination (defaults to original path)")
@pass_ctx
def restore(app: AppContext, name: str, restore_path: str) -> None:
    """Restore a quarantined plugin to its original location.

    By default restores to the original path recorded during quarantine.
    Use --path to override the restore destination.
    """
    from defenseclaw.enforce import PolicyEngine
    from defenseclaw.enforce.plugin_enforcer import PluginEnforcer

    plugin_name = os.path.basename(name)

    pe_enforcer = PluginEnforcer(app.cfg.quarantine_dir)
    if not pe_enforcer.is_quarantined(plugin_name):
        click.echo(f"error: {plugin_name!r} is not quarantined", err=True)
        raise SystemExit(1)

    pe = PolicyEngine(app.store)
    plugin_dir = app.cfg.plugin_dir

    if not restore_path:
        entry = pe.get_action("plugin", plugin_name)
        if entry is None or not entry.source_path:
            click.echo(
                f"error: no stored path for {plugin_name!r} — use --path to specify restore destination",
                err=True,
            )
            raise SystemExit(1)
        restore_path = entry.source_path

    real_restore = os.path.realpath(restore_path)
    real_plugin_dir = os.path.realpath(plugin_dir)
    if not real_restore.startswith(real_plugin_dir + os.sep) and real_restore != real_plugin_dir:
        click.echo(f"error: restore path must be within plugin directory {plugin_dir}", err=True)
        raise SystemExit(1)

    if not pe_enforcer.restore(plugin_name, restore_path):
        click.echo(f"error: restore failed for {plugin_name!r}", err=True)
        raise SystemExit(1)

    click.echo(f"[plugin] {plugin_name!r} restored to {restore_path}")

    pe.clear_quarantine("plugin", plugin_name)
    pe.set_source_path("plugin", plugin_name, restore_path)

    if app.logger:
        app.logger.log_action("plugin-restore", plugin_name, f"restored to {restore_path}")


# ---------------------------------------------------------------------------
# plugin info
# ---------------------------------------------------------------------------

@plugin.command()
@click.argument("name")
@click.option("--json", "as_json", is_flag=True, help="Output plugin info as JSON")
@pass_ctx
def info(app: AppContext, name: str, as_json: bool) -> None:
    """Show detailed information about a plugin.

    Displays plugin metadata, latest scan results from the DefenseClaw
    audit database, and enforcement actions.
    """
    plugin_name = os.path.basename(name)
    plugin_dir = app.cfg.plugin_dir

    info_map: dict = {"name": plugin_name}

    # Check if installed
    candidate = os.path.join(plugin_dir, plugin_name)
    if os.path.isdir(candidate):
        info_map["installed"] = True
        info_map["path"] = candidate
        # Try to read package.json for metadata
        pkg_json = os.path.join(candidate, "package.json")
        if os.path.isfile(pkg_json):
            try:
                with open(pkg_json) as f:
                    pkg = json.load(f)
                info_map["version"] = pkg.get("version", "")
                info_map["description"] = pkg.get("description", "")
            except (OSError, json.JSONDecodeError):
                pass
    else:
        info_map["installed"] = False

    # Scan results
    scan_map = _build_plugin_scan_map(app.store)
    if plugin_name in scan_map:
        info_map["scan"] = scan_map[plugin_name]

    # Enforcement actions
    actions_map = _build_plugin_actions_map(app.store)
    if plugin_name in actions_map:
        ae = actions_map[plugin_name]
        if not ae.actions.is_empty():
            info_map["actions"] = ae.actions.to_dict()

    # Quarantine status
    from defenseclaw.enforce.plugin_enforcer import PluginEnforcer
    pe_enforcer = PluginEnforcer(app.cfg.quarantine_dir)
    info_map["quarantined"] = pe_enforcer.is_quarantined(plugin_name)

    if as_json:
        click.echo(json.dumps(info_map, indent=2, default=str))
        return

    click.echo(f"Plugin:      {info_map['name']}")
    if info_map.get("description"):
        click.echo(f"Description: {info_map['description']}")
    if info_map.get("version"):
        click.echo(f"Version:     {info_map['version']}")
    if info_map.get("path"):
        click.echo(f"Path:        {info_map['path']}")
    click.echo(f"Installed:   {info_map['installed']}")
    click.echo(f"Quarantined: {info_map['quarantined']}")

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
# Helpers
# ---------------------------------------------------------------------------

def _resolve_plugin_path(app: AppContext, plugin_name: str) -> str | None:
    """Resolve a plugin name to its installed directory path."""
    plugin_dir = app.cfg.plugin_dir
    candidate = os.path.join(plugin_dir, plugin_name)
    if os.path.isdir(candidate):
        return candidate
    return None


def _build_plugin_scan_map(store) -> dict:
    """Build a map of plugin-name -> latest scan entry from the DB."""
    scan_map: dict = {}
    if store is None:
        return scan_map
    try:
        latest = store.latest_scans_by_scanner("plugin-scanner")
    except Exception as exc:
        click.echo(f"warning: failed to load plugin scan data: {exc}", err=True)
        return scan_map
    for ls in latest:
        name = os.path.basename(ls["target"])
        scan_map[name] = {
            "target": ls["target"],
            "clean": ls["finding_count"] == 0,
            "max_severity": ls["max_severity"] or "INFO",
            "total_findings": ls["finding_count"],
        }
    return scan_map


def _build_plugin_actions_map(store) -> dict:
    """Build a map of plugin-name -> ActionEntry from the DB."""
    actions_map: dict = {}
    if store is None:
        return actions_map
    try:
        entries = store.list_actions_by_type("plugin")
    except Exception as exc:
        click.echo(f"warning: failed to load plugin actions data: {exc}", err=True)
        return actions_map
    for e in entries:
        actions_map[e.target_name] = e
    return actions_map
