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
import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import click

from defenseclaw import connector_paths, ux
from defenseclaw.commands import compute_verdict as _compute_verdict
from defenseclaw.commands._audit_notice import note_asset_policy_observed, saved_change_audit
from defenseclaw.commands._scan_ui import record_scan as _record_scan
from defenseclaw.context import AppContext, pass_ctx
from defenseclaw.enforce import asset_lists
from defenseclaw.inventory.plugin_directories import (
    PluginInstallClaims,
    PluginRegistryCache,
    PluginRegistryProbe,
    PluginRegistryState,
    discover_plugin_directories,
    plugin_directory_entries,
    probe_claude_plugin_registry,
)
from defenseclaw.inventory.plugin_identity import (
    PluginIdentityError,
    canonical_plugin_id,
    enumerate_physical_identities,
    filesystem_identity_key,
    is_link_or_reparse,
    resolve_plugin_identity,
    validate_plugin_id,
)

if TYPE_CHECKING:
    from defenseclaw.scanner.rulepack import RulePackOverlayCache


def _api_bind_host(app: AppContext) -> str:
    """Resolve the host to dial for the sidecar API (config.APIBindHost in Go)."""
    from defenseclaw.gateway import gateway_api_client_host

    return gateway_api_client_host(app.cfg)


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
    """Manage DefenseClaw plugins — install, list, remove, scan, block, allow, disable, enable, quarantine, restore.

    Multi-connector: plugins are tracked per connector. With no --connector,
    commands that operate on plugin copies run across configured connectors
    where the plugin or plugin directory applies. Pass --connector X to narrow to one
    connector. Policy commands that create unscoped entries say so in their own
    help.
    """


@plugin.command()
@click.argument("name_or_path", required=False)
@click.option("--json", "as_json", is_flag=True, help="Output scan results as JSON")
@click.option("--policy", "policy_name", default="", help="Scan policy: default, strict, permissive, or path to YAML")
@click.option(
    "--profile", type=click.Choice(["default", "strict"]), default=None, help="Scan profile (overrides policy profile)"
)
@click.option("--all", "scan_all", is_flag=True, help="Scan every installed plugin across configured connectors")
@click.option(
    "--use-llm/--no-llm",
    "use_llm",
    default=None,
    help=(
        "Run the LLM semantic analyzer in addition to the static scanner. "
        "Default (auto): on whenever a model is configured for scanners.plugin, "
        "off otherwise. The LLM lane degrades loudly (never silent-clean) if no "
        "model resolves or the backend is unreachable."
    ),
)
@click.option("--llm-model", default="", help="LLM model override (e.g. claude-sonnet-4-20250514, gpt-4)")
@click.option("--llm-provider", default="", help="LLM provider hint (anthropic, openai, ollama, etc.)")
@click.option("--llm-consensus-runs", default=0, type=int, help="Number of LLM consensus runs (default: 1)")
@click.option("--enable-meta/--no-meta", default=True, help="Enable/disable meta analyzer (default: enabled)")
@click.option(
    "--include-self",
    is_flag=True,
    help="Include exact first-party DefenseClaw artifacts (excluded by default)",
)
@click.option("--lenient", is_flag=True, help="Suppress low-confidence findings (sets min_confidence=0.5)")
@click.option(
    "--connector",
    "connector_flag",
    default="",
    help=(
        "Scan a specific connector's plugins. "
        "Default: bare names scan every matching configured connector copy; "
        "no target/--all scans configured connectors. Use --connector "
        "<name> to narrow."
    ),
)
@pass_ctx
def scan(
    app: AppContext,
    name_or_path: str | None,
    as_json: bool,
    policy_name: str,
    profile: str | None,
    scan_all: bool,
    use_llm: bool | None,
    llm_model: str,
    llm_provider: str,
    llm_consensus_runs: int,
    enable_meta: bool,
    include_self: bool,
    lenient: bool,
    connector_flag: str,
) -> None:
    """Scan a plugin directory for security issues.

    Uses defenseclaw-plugin-scanner to check for dangerous permissions,
    install scripts, credential theft, obfuscation, and supply chain risks.

    LLM analysis uses the same configuration as the skill scanner
    (reads from config.yaml: inspect_llm).

    \b
    Examples:
      defenseclaw plugin scan my-plugin
      defenseclaw plugin scan --all
      defenseclaw plugin scan my-plugin --policy strict
      defenseclaw plugin scan my-plugin --use-llm
      defenseclaw plugin scan my-plugin --no-llm
      defenseclaw plugin scan my-plugin --use-llm --llm-model gpt-4
      defenseclaw plugin scan my-plugin --policy ~/.defenseclaw/policies/custom.yaml
      defenseclaw plugin scan /path/to/plugin --profile strict --lenient
      defenseclaw plugin scan ~/.defenseclaw/extensions/defenseclaw --include-self
    """
    from defenseclaw import ux
    from defenseclaw.scanner.plugin import PluginScannerWrapper
    from defenseclaw.scanner.rulepack import maybe_wrap

    # P-C: accept a literal ``all`` argument (parity with skill/mcp scan),
    # treat a missing target as "scan configured plugins", and reject
    # TARGET + --all together.
    if scan_all and name_or_path not in (None, "all"):
        click.echo("error: provide either a plugin name/path or --all, not both", err=True)
        raise SystemExit(2)
    if scan_all or name_or_path == "all" or not name_or_path:
        _scan_all_plugins(
            app,
            as_json,
            policy_name,
            profile,
            use_llm,
            llm_model,
            llm_provider,
            llm_consensus_runs,
            enable_meta,
            include_self,
            lenient,
            connector_flag,
        )
        return

    # Build scan options from CLI flags + config
    scan_options = _build_scan_options(
        app,
        policy_name,
        profile,
        use_llm,
        llm_model,
        llm_provider,
        llm_consensus_runs,
        enable_meta,
        include_self,
        lenient,
    )

    # Route the unified LLM config (top-level ``llm:`` + any
    # ``scanners.plugin.llm:`` overrides) into the wrapper. The
    # wrapper layers per-call CLI flags on top before dispatching.
    scanner = PluginScannerWrapper(llm=app.cfg.resolve_llm("scanners.plugin"))

    matches: list[_PluginMatch] = []
    registry_cache: PluginRegistryCache = {}
    hermes_match = _hermes_listed_plugin(app, name_or_path, connector_flag, require_active=True)
    if hermes_match is not None and hermes_match[1]:
        matches = [_PluginMatch("hermes", hermes_match[1], plugin_id=hermes_match[0])]
    elif _looks_like_explicit_path(name_or_path):
        from defenseclaw.commands import resolve_list_connector

        connector = resolve_list_connector(app, connector_flag)
        adhoc = False
        if not connector_flag:
            # Without --connector, name the connector whose plugin root holds
            # the path rather than the first active one. A folder no connector
            # root holds is an ad-hoc path scan (GAP-1640): it is still scanned
            # with the active connector's policy, but not attributed to it.
            owner = _connector_for_plugin_path(app, name_or_path)
            adhoc = not owner
            connector = owner or connector
        scan_dir = _resolve_plugin_dir(
            name_or_path,
            app.cfg.plugin_dir,
            connector,
            _plugin_roots_for_connector(app, connector),
            registry_cache=registry_cache,
        )
        if scan_dir and not adhoc and _is_bridge_plugin_root(app, connector, scan_dir):
            matches = [
                _PluginMatch(connector, entry.path, plugin_id=entry.id)
                for entry in discover_plugin_directories(
                    scan_dir,
                    connector=connector,
                    registry_cache=registry_cache,
                )
            ]
            if not matches:
                _report_empty_bridge_plugin_root(scan_dir, connector, as_json=as_json)
                return
        elif scan_dir:
            # GAP-1697: report a Hermes plugin under the id plugin list shows.
            plugin_id = (
                _hermes_plugin_id_for_path(scan_dir) if connector_paths.normalize(connector) == "hermes" else ""
            )
            matches = [_PluginMatch(connector, scan_dir, adhoc=adhoc, plugin_id=plugin_id)]
    else:
        if connector_flag:
            from defenseclaw.commands import resolve_list_connector

            discovery_connectors = [resolve_list_connector(app, connector_flag)]
        else:
            discovery_connectors = _active_plugin_connectors(app)
        discovery = _plugin_registry_probes(
            app,
            discovery_connectors,
            registry_cache=registry_cache,
        )
        _fail_on_plugin_registry_errors(discovery, as_json=as_json)
        matches = _plugin_match_dir_scopes(
            app,
            name_or_path,
            connector_flag,
            registry_cache=registry_cache,
        )
        if not matches:
            # OpenClaw can report a plugin root via its CLI even when the
            # directory is outside our configured filesystem roots.
            from defenseclaw.commands import resolve_list_connector

            connector = resolve_list_connector(app, connector_flag)
            scan_dir = _resolve_plugin_dir(
                name_or_path,
                app.cfg.plugin_dir,
                connector,
                _plugin_roots_for_connector(app, connector),
                registry_cache=registry_cache,
            )
            if scan_dir:
                matches = [_PluginMatch(connector, scan_dir)]
        if not matches and not connector_flag:
            # A bare nested Hermes name (``ddgs``) when no connector is named.
            hermes_match = _hermes_listed_plugin(app, name_or_path, "hermes", require_active=True)
            if hermes_match is not None and hermes_match[1]:
                matches = [_PluginMatch("hermes", hermes_match[1], plugin_id=hermes_match[0])]

    _refuse_managed_bridge_action(
        app,
        name_or_path,
        connector_flag,
        action="scan",
    )
    for _connector, scan_dir in matches:
        bridge = _managed_bridge_connector(scan_dir)
        if bridge:
            _raise_managed_bridge_refusal("scan", bridge)

    if not matches:
        scope = f" for connector {connector_flag!r}" if connector_flag else " across configured connectors"
        click.echo(f"error: plugin not found: {name_or_path}{scope}", err=True)
        click.echo("  Provide a path, a DefenseClaw plugin name, or a connector plugin name.", err=True)
        raise SystemExit(1)

    if len(matches) == 1 and _looks_like_explicit_path(name_or_path):
        _refuse_plugin_folder_of_plugins(matches[0].path, connector=matches[0].connector)

    pack_cache: RulePackOverlayCache = {}
    for idx, match in enumerate(matches):
        connector, scan_dir = match
        if len(matches) > 1 and not as_json:
            if idx:
                click.echo()
            instance = _plugin_instance_label(
                match.plugin_id or name_or_path,
                match.scope,
                match.project_path,
            )
            ux.echo(
                ux._style(
                    f"── connector: {connector}; plugin: {instance} ──",
                    fg="cyan",
                )
            )
        _scan_one_plugin_dir(
            app,
            maybe_wrap(
                scanner,
                app.cfg,
                connector,
                pack_cache=pack_cache,
            ),
            scan_dir=scan_dir,
            connector=connector,
            as_json=as_json,
            scan_options=scan_options,
            policy_name=policy_name,
            use_llm=use_llm,
            llm_model=llm_model,
            profile=profile,
            scope=match.scope,
            project_path=match.project_path,
            plugin_id=match.plugin_id,
            adhoc=match.adhoc,
        )


def _is_bridge_plugin_root(app: AppContext, connector: str, path: str) -> bool:
    """GAP-2099: *path* is an Amp/OpenCode plugin root, which can hold our bridge."""
    connector = connector_paths.normalize(connector)
    if connector not in _MANAGED_BRIDGES or not os.path.isdir(path):
        return False
    real = os.path.normcase(os.path.realpath(path))
    return any(
        real == os.path.normcase(os.path.realpath(root))
        for root in _plugin_roots_for_connector(app, connector, include_legacy=False)
    )


def _report_empty_bridge_plugin_root(path: str, connector: str, *, as_json: bool) -> None:
    connector = connector_paths.normalize(connector)
    if as_json:
        click.echo(json.dumps({"connector": connector, "results": [], "error": "no_plugin_targets"}, indent=2))
        return
    click.echo(f"No plugins found to scan in {path} for connector={connector}.")
    label, filename = _MANAGED_BRIDGES[connector]
    if os.path.isfile(os.path.join(path, filename)):
        click.echo(
            f"  {filename} is DefenseClaw's own {label} bridge, so it is not scanned. "
            f"To stop guarding {label}, run: defenseclaw setup remove {connector}"
        )


def _has_plugin_manifest(path: str) -> bool:
    from defenseclaw.scanner.plugin_scanner.scanner import _MANIFEST_CANDIDATES

    return any(os.path.isfile(os.path.join(path, rel)) for rel, _label in _MANIFEST_CANDIDATES)


def _plugin_folder_children(path: str) -> list[str]:
    """Sub-folders holding a plugin manifest when *path* itself has none."""
    if not os.path.isdir(path) or _has_plugin_manifest(path):
        return []
    try:
        entries = sorted(os.scandir(path), key=lambda e: e.name)
    except OSError:
        return []
    return [
        e.name
        for e in entries
        if not e.name.startswith((".", "_"))
        and e.is_dir(follow_symlinks=False)
        and _has_plugin_manifest(e.path)
    ]


def _refuse_plugin_folder_of_plugins(path: str, *, connector: str = "") -> None:
    """GAP-1580: a folder of plugins (Hermes ``plugins/browser``) is not a plugin.

    Scanning it as one reported a BLOCKED HIGH "No plugin manifest found";
    say what it is and how to scan the plugins inside it instead.
    """
    children = _plugin_folder_children(path)
    if not children:
        return
    flag = f" --connector {connector}" if connector else ""
    click.echo(
        f"error: {path} is a folder of {len(children)} plugin(s), not a plugin "
        "(it has no plugin manifest).",
        err=True,
    )
    click.echo(f"  It holds: {', '.join(children)}", err=True)
    click.echo(
        f"  Scan one:  defenseclaw plugin scan {os.path.join(path, children[0])}",
        err=True,
    )
    click.echo(f"  Scan all:  defenseclaw plugin scan --all{flag}", err=True)
    raise SystemExit(2)


def _scan_one_plugin_dir(
    app: AppContext,
    scanner: Any,
    *,
    scan_dir: str,
    connector: str,
    as_json: bool,
    scan_options: dict[str, Any],
    policy_name: str,
    use_llm: bool | None,
    llm_model: str,
    profile: str | None,
    scope: str = "",
    project_path: str = "",
    plugin_id: str = "",
    adhoc: bool = False,
) -> None:
    from defenseclaw.commands import _scan_ui

    # S6.2 — surface the connector and the concrete category list before
    # kicking off the scan, so operators see what's being checked instead of
    # an opaque "[plugin] scanning..." line.
    ctx = _scan_ui.ScanContext.for_plugin(
        connector=connector,
        paths=[scan_dir],
        as_json=as_json,
        where=_scan_ui.WHERE_ADHOC_PATH if adhoc else "",
    )
    _scan_ui.render_preamble(ctx, target_count=1)
    if not as_json:
        flags = []
        if policy_name:
            flags.append(f"policy={policy_name}")
        if use_llm:
            model = llm_model or scan_options.get("llm_model", "")
            flags.append(f"llm={model}")
        if profile:
            flags.append(f"profile={profile}")
        if flags:
            click.echo(f"  Options: {', '.join(flags)}")

    try:
        result = scanner.scan(scan_dir, **scan_options)
    except SystemExit:
        raise
    except Exception as exc:
        click.echo(f"error: scan failed: {exc}", err=True)
        raise SystemExit(1)

    _record_scan(app.logger, result, connector=connector or None)

    if as_json:
        # Preserve the ScanResult keys automation already parses, while adding
        # connector metadata so scoped JSON callers need not infer it from paths.
        payload = json.loads(result.to_json())
        payload["connector"] = connector
        payload["target_metadata"] = _plugin_instance_metadata(
            connector=connector,
            path=result.target,
            scope=scope,
            project_path=project_path,
        )
        click.echo(json.dumps(payload, indent=2, default=str))
        return

    try:
        if (
            connector_paths.normalize(connector) in {"amp", "opencode"}
            and os.path.isfile(scan_dir)
            and scan_dir.casefold().endswith((".js", ".ts"))
        ):
            target_name = validate_plugin_id(os.path.splitext(os.path.basename(scan_dir))[0])
        else:
            target_name, _manifest = canonical_plugin_id(scan_dir)
    except PluginIdentityError as exc:
        raise click.ClickException(f"invalid plugin identity at {scan_dir}: {exc}") from exc
    if result.is_clean():
        _scan_ui.render_per_target_status(
            ctx,
            target=plugin_id or target_name,
            verdict=_scan_ui.VERDICT_CLEAN,
            findings=0,
        )
        _scan_ui.render_summary(
            ctx,
            clean=1,
            warning=0,
            blocked=0,
            errored=0,
            total=1,
            duration_ms=int(result.duration.total_seconds() * 1000),
        )
        return

    sev = result.max_severity()
    verdict, rejects = _plugin_scan_findings_verdict(
        app, result, name=plugin_id or target_name, path=scan_dir, connector=connector,
    )
    _scan_ui.render_per_target_status(
        ctx,
        target=plugin_id or target_name,
        verdict=verdict,
        detail=f"max severity: {sev}",
        findings=len(result.findings),
    )
    if rejects:
        _print_plugin_scan_policy(
            plugin_id or target_name, connector="" if adhoc else connector, installed=not adhoc,
        )
    click.echo()
    for f in result.findings:
        sev_color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan"}.get(f.severity, "white")
        click.secho(f"    [{f.severity}]", fg=sev_color, nl=False)
        click.echo(f" {f.title}")
        if f.location:
            click.echo(f"      Location: {f.location}")
        if f.remediation:
            click.echo(f"      Fix: {f.remediation}")
    _scan_ui.render_summary(
        ctx,
        clean=0,
        warning=0 if verdict == _scan_ui.VERDICT_BLOCKED else 1,
        blocked=1 if verdict == _scan_ui.VERDICT_BLOCKED else 0,
        errored=0,
        total=1,
        findings=len(result.findings),
        duration_ms=int(result.duration.total_seconds() * 1000),
    )


def _plugin_scan_findings_verdict(
    app: AppContext, result: Any, *, name: str, path: str, connector: str,
) -> tuple[str, bool]:
    """The scan line's verdict, and whether the policy rejects the plugin.

    BLOCKED (and the Summary's blocked=) only for a plugin that is on the
    block list, as in ``skill scan`` (GAP-1592): a scan blocks nothing, so a
    plugin the policy would refuse at install reads WARN and gets a
    "policy: rejected" line instead. A LOW-only plugin ("declares no
    permissions") is not rejected by the default policy (GAP-1413).
    """
    from defenseclaw.commands import _scan_ui

    sev = str(result.max_severity()).upper()
    try:
        from defenseclaw.enforce import PolicyEngine
        from defenseclaw.enforce.admission import evaluate_admission

        pe = PolicyEngine(app.store, app.cfg)
        try:
            if pe.is_blocked_for_connector("plugin", name, connector):
                return _scan_ui.VERDICT_BLOCKED, False
        except Exception:  # noqa: BLE001 - fall through to the policy check.
            pass
        decision = evaluate_admission(
            pe,
            config=app.cfg,
            target_type="plugin",
            name=name,
            source_path=path,
            scan_result=result,
            connector=connector,
        )
        blocks = decision.verdict != "allowed" and decision.action.install == "block"
    except Exception:  # noqa: BLE001 - an admission failure must not read as clean.
        blocks = True
    return (_scan_ui.VERDICT_INFO if sev == "INFO" else _scan_ui.VERDICT_WARN), blocks


def _print_plugin_scan_policy(name: str, *, connector: str = "", installed: bool = True) -> None:
    """Under a WARN line, say the policy rejects the plugin and how to act.

    Same shape as ``skill scan``'s "policy: rejected" line (GAP-1592).
    """
    flag = f" --connector {connector}" if connector else ""
    if installed:
        text = (
            "the policy refuses this plugin at install; the copy already "
            "installed still loads until you act."
        )
    else:
        text = "the policy would refuse this plugin at install."
    ux.echo(f"        policy: rejected — {text}")
    if installed:
        # GAP-2111: 'plugin block' only refuses new installs; quarantine moves
        # the installed copy out (plugin restore brings it back).
        click.echo(f"          Stop it: defenseclaw plugin quarantine {name}{flag}")
    else:
        click.echo(f"          Block it: defenseclaw plugin block {name}{flag}")


def _host_plugin_dirs(app: AppContext, connector: str) -> list[str]:
    """The target connector's own plugin dirs (P-B), empty on any failure."""
    try:
        if connector_paths.normalize(connector) != "opencode":
            return list(app.cfg.plugin_dirs(connector))
        workspace_resolver = getattr(app.cfg, "connector_workspace_dir", None)
        workspace = workspace_resolver() if callable(workspace_resolver) else ""
        claw = getattr(app.cfg, "claw", None)
        return connector_paths.plugin_inventory_dirs(
            connector,
            openclaw_home=getattr(claw, "home_dir", None),
            workspace_dir=workspace,
        )
    except Exception:  # noqa: BLE001 — managed-dir-only fallback.
        return []


def _active_plugin_connectors(app: AppContext) -> list[str]:
    cfg = app.cfg
    if hasattr(cfg, "active_connectors"):
        try:
            names = [
                n
                for n in cfg.active_connectors()
                if n
            ]
            if names:
                return names
        except Exception:  # noqa: BLE001 — fall back to the singular connector.
            pass
    if hasattr(cfg, "active_connector"):
        active = cfg.active_connector()
        if active:
            return [active]
    return ["openclaw"]


def _plugin_roots_for_connector(
    app: AppContext,
    connector: str,
    *,
    include_legacy: bool = True,
) -> list[str]:
    """Filesystem roots that can hold plugins for one connector.

    New installs target ``cfg.plugin_dirs(connector)``. The legacy
    DefenseClaw-managed ``plugin_dir`` remains readable for old local installs
    and tests, but only for the active/single-connector scope so it does not
    fabricate a copy on every peer in multi-connector info/quarantine flows.
    """
    roots: list[str] = []
    try:
        roots.extend(d for d in _host_plugin_dirs(app, connector) if d)
    except Exception:  # noqa: BLE001 — legacy root below may still work.
        pass

    if include_legacy and getattr(app.cfg, "plugin_dir", ""):
        active = app.cfg.active_connector() if hasattr(app.cfg, "active_connector") else "openclaw"
        active_connectors = _active_plugin_connectors(app)
        if len(active_connectors) <= 1 or connector == active:
            roots.append(app.cfg.plugin_dir)

    deduped: list[str] = []
    for root in roots:
        if root and root not in deduped:
            deduped.append(root)
    return deduped


def _all_active_plugin_dirs(app: AppContext) -> list[str]:
    roots: list[str] = []
    for connector in _active_plugin_connectors(app):
        for root in _plugin_roots_for_connector(app, connector):
            if root not in roots:
                roots.append(root)
    return roots


def _plugin_registry_probes(
    app: AppContext,
    connectors: list[str],
    *,
    registry_cache: PluginRegistryCache | None = None,
) -> dict[str, list[PluginRegistryProbe]]:
    """Probe authoritative connector registries without inventing sources."""

    discovered: dict[str, list[PluginRegistryProbe]] = {}
    cache = registry_cache if registry_cache is not None else {}
    for connector in connectors:
        probes: list[PluginRegistryProbe] = []
        seen: set[str] = set()
        for root in _plugin_roots_for_connector(
            app,
            connector,
            include_legacy=False,
        ):
            probe = probe_claude_plugin_registry(
                root,
                connector=connector,
                registry_cache=cache,
            )
            if probe is None:
                continue
            source_key = os.path.normcase(
                os.path.abspath(os.path.normpath(probe.source_path))
            )
            if source_key in seen:
                continue
            seen.add(source_key)
            probes.append(probe)
        discovered[connector] = probes
    return discovered


def _plugin_registry_diagnostics_json(
    diagnostics: dict[str, list[PluginRegistryProbe]],
) -> list[dict[str, Any]]:
    """Flatten connector probes into one deterministic JSON diagnostic list."""

    return [
        {"connector": connector, **probe.as_dict()}
        for connector in diagnostics
        for probe in diagnostics[connector]
    ]


def _render_plugin_registry_diagnostics(
    diagnostics: dict[str, list[PluginRegistryProbe]],
    *,
    failures_only: bool = False,
    force_stderr: bool = False,
    hide_missing: bool = False,
) -> None:
    """Render exact discovery source outcomes for human-facing commands."""

    for connector, probes in diagnostics.items():
        for probe in probes:
            if failures_only and not probe.failed:
                continue
            if probe.state == PluginRegistryState.MISSING:
                # GAP-2274: a missing installed_plugins.json only means the
                # agent has no plugins yet; say so plainly (or not at all).
                if not hide_missing:
                    click.echo(
                        f"{connector} has no installed plugins "
                        f"({probe.source_path} not found).",
                        err=force_stderr,
                    )
                continue
            if probe.state == PluginRegistryState.VALID and not probe.entries:
                # GAP-2317: an empty registry is the same normal "none yet".
                if not hide_missing:
                    click.echo(f"{connector} has no installed plugins.", err=force_stderr)
                continue
            suffix = f" ({probe.detail})" if probe.detail else ""
            ux.echo(
                "Plugin discovery source "
                f"[{connector}]: {probe.source_path} — {probe.state.value}; "
                f"entries={probe.entries}{suffix}",
                err=force_stderr or probe.failed,
            )


def _empty_plugin_registry_note(
    diagnostics: dict[str, list[PluginRegistryProbe]],
    connector: str,
) -> str | None:
    """Why the connector's plugin registry lists nothing, or None.

    A missing registry gives "(<path> not found)" (GAP-2290); a valid but
    empty one gives "" (GAP-2317).
    """

    for probe in diagnostics.get(connector) or []:
        if probe.state == PluginRegistryState.MISSING:
            return f"({probe.source_path} not found)"
        if probe.state == PluginRegistryState.VALID and not probe.entries:
            return ""
    return None


def _fail_on_plugin_registry_errors(
    diagnostics: dict[str, list[PluginRegistryProbe]],
    *,
    as_json: bool,
    preserve_json_array: bool = False,
) -> None:
    """Fail loudly when an existing authoritative registry was unusable."""

    failed = {
        connector: [probe for probe in probes if probe.failed]
        for connector, probes in diagnostics.items()
    }
    failed = {connector: probes for connector, probes in failed.items() if probes}
    if not failed:
        return
    if as_json:
        rendered = json.dumps(
            {
                "error": "plugin_discovery_failed",
                "discovery": _plugin_registry_diagnostics_json(failed),
            },
            indent=2,
        )
        if preserve_json_array:
            # ``plugin list --json`` has always exposed an array on stdout.
            # Keep diagnostics on stderr rather than changing that machine
            # contract merely because discovery produced no plugin rows.
            click.echo("[]")
            click.echo(rendered, err=True)
        else:
            click.echo(rendered)
    else:
        _render_plugin_registry_diagnostics(failed, failures_only=True)
        click.echo(
            "error: plugin discovery could not safely read every existing registry source",
            err=True,
        )
    raise SystemExit(1)


def _plugin_basename(target: str) -> str:
    name = target.rstrip("/\\")
    if "/" in name or "\\" in name:
        name = os.path.basename(name)
    return name.lstrip("@")


def _connector_for_plugin_path(
    app: AppContext,
    plugin_path: str,
    connector_hint: str = "",
) -> str:
    real_path = os.path.realpath(plugin_path)
    if connector_hint:
        return connector_hint
    for connector in _active_plugin_connectors(app):
        for root in _plugin_roots_for_connector(app, connector, include_legacy=False):
            real_root = os.path.realpath(root)
            if real_path == real_root or real_path.startswith(real_root + os.sep):
                return connector
    return ""


@dataclass(frozen=True)
class _PluginMatch:
    """Tuple-compatible scan match with Claude install provenance."""

    connector: str
    path: str
    scope: str = ""
    project_path: str = ""
    registry_source: str = ""
    plugin_id: str = ""
    # True for an explicit folder that no connector plugin root holds.
    adhoc: bool = False

    def __iter__(self):
        # Keep the established private helper contract for governance callers
        # that unpack ``(connector, path)`` while retaining scan metadata.
        yield self.connector
        yield self.path

    def __len__(self) -> int:
        return 2

    def __getitem__(self, index: int) -> str:
        return (self.connector, self.path)[index]


def _plugin_instance_metadata(
    *,
    connector: str,
    path: str,
    scope: str = "",
    project_path: str = "",
) -> dict[str, str]:
    metadata = {"connector": connector, "path": path}
    if scope:
        metadata["scope"] = scope
    if project_path:
        metadata["project_path"] = project_path
    return metadata


def _plugin_instance_label(plugin_id: str, scope: str, project_path: str) -> str:
    details: list[str] = []
    if scope:
        details.append(f"scope={scope}")
    if project_path:
        details.append(f"project={project_path}")
    return f"{plugin_id} ({', '.join(details)})" if details else plugin_id


def _plugin_match_dir_scopes(
    app: AppContext,
    target: str,
    connector: str = "",
    *,
    registry_cache: PluginRegistryCache | None = None,
) -> list[_PluginMatch]:
    """Every ``(connector, path)`` pair that contains a plugin target."""
    if _looks_like_explicit_path(target) and os.path.isdir(target):
        resolved = _resolve_connector_scope(app, connector)
        return [
            _PluginMatch(
                _connector_for_plugin_path(app, target, resolved),
                target,
            )
        ]

    name = _plugin_basename(target)
    try:
        name = validate_plugin_id(name)
    except PluginIdentityError as exc:
        raise click.ClickException(f"invalid plugin identity: {exc}") from exc

    def connector_matches(resolved: str) -> list[_PluginMatch]:
        found: list[_PluginMatch] = []
        claimed = PluginInstallClaims()
        try:
            for root in _plugin_roots_for_connector(app, resolved):
                key = filesystem_identity_key(name, root)
                root_matches = [
                    entry
                    for entry in discover_plugin_directories(
                        root,
                        connector=resolved,
                        registry_cache=registry_cache,
                        workspace_dir=app.cfg.connector_workspace_dir(),
                    )
                    if filesystem_identity_key(entry.id, root) == key
                ]
                for entry in root_matches:
                    if not claimed.add_directory(entry, root):
                        continue
                    found.append(
                        _PluginMatch(
                            connector=resolved,
                            path=entry.path,
                            plugin_id=entry.id,
                            scope=entry.scope,
                            project_path=entry.project_path,
                            registry_source=entry.registry_source,
                        )
                    )
        except PluginIdentityError as exc:
            raise click.ClickException(str(exc)) from exc
        return found

    if connector:
        resolved = _resolve_connector_scope(app, connector)
        return connector_matches(resolved)

    matches: list[_PluginMatch] = []
    seen_paths: set[tuple[str, str, str, bool]] = set()
    for c in _active_plugin_connectors(app):
        for match in connector_matches(c):
            dedupe_key = (
                os.path.normcase(os.path.realpath(match.path)),
                match.scope.casefold(),
                os.path.normcase(os.path.normpath(match.project_path)),
                bool(match.registry_source),
            )
            if dedupe_key not in seen_paths:
                matches.append(match)
                seen_paths.add(dedupe_key)
    return matches


_MANAGED_BRIDGES: dict[str, tuple[str, str]] = {
    "opencode": ("OpenCode", "defenseclaw.js"),
    "amp": ("Amp", "defenseclaw.ts"),
}


def _managed_bridge_path(connector: str) -> str:
    """Return the exact connector-owned bridge path for OpenCode or Amp."""

    try:
        if connector == "opencode":
            return os.path.abspath(connector_paths.connector_config_files("opencode")[0])
        if connector == "amp":
            return os.path.abspath(connector_paths.amp_policy_plugin_path())
    except (IndexError, OSError, ValueError):
        pass
    return ""


def _managed_bridge_connector(path: str) -> str:
    """Name the connector whose exact bridge *path* is, never a same-named sibling."""

    if not path:
        return ""
    try:
        target = os.path.normcase(os.path.abspath(path))
    except (OSError, ValueError):
        return ""
    for connector in _MANAGED_BRIDGES:
        managed = _managed_bridge_path(connector)
        if managed and target == os.path.normcase(managed):
            return connector
    return ""


def _raise_managed_bridge_refusal(action: str, connector: str) -> None:
    label, filename = _MANAGED_BRIDGES[connector]
    raise click.ClickException(
        f"refusing to {action} the managed {label} {filename} bridge; "
        "it is connector lifecycle configuration, not an operator plugin, "
        f"and {label} runs unguarded without it. To stop guarding {label}, "
        f"run: defenseclaw setup remove {connector}"
    )


def _refuse_managed_bridge_action(
    app: AppContext,
    target: str,
    connector: str,
    *,
    action: str,
) -> None:
    """Refuse lifecycle actions only when they resolve to our exact bridge."""

    if _looks_like_explicit_path(target):
        bridge = _managed_bridge_connector(target)
        if bridge:
            _raise_managed_bridge_refusal(action, bridge)
        return
    requested = os.path.splitext(os.path.basename(target))[0].casefold()
    if requested != "defenseclaw":
        return
    scoped = _normalize_runtime_connector(connector) if connector else ""
    connectors = [scoped] if scoped else _active_plugin_connectors(app)
    for bridge in _MANAGED_BRIDGES:
        if bridge not in connectors:
            continue
        # A project/user plugin with the same basename is an ordinary eligible
        # asset. Discovery excludes only the exact managed global bridge.
        if _plugin_match_dir_scopes(app, "defenseclaw", bridge):
            continue
        managed = _managed_bridge_path(bridge)
        if managed and os.path.isfile(managed):
            _raise_managed_bridge_refusal(action, bridge)


def _scan_all_plugins(
    app: AppContext,
    as_json: bool,
    policy_name: str,
    profile: str | None,
    use_llm: bool | None,
    llm_model: str,
    llm_provider: str,
    llm_consensus_runs: int,
    enable_meta: bool,
    include_self: bool,
    lenient: bool,
    connector_flag: str,
) -> None:
    """P-C: sweep every installed plugin across configured connectors.

    Mirrors ``skill scan --all`` / ``mcp scan --all``: an explicit
    ``--connector`` targets exactly one peer; otherwise a multi-connector
    install fans out across every configured connector (each under a
    ``── connector: c ──`` banner), and a single-connector install scans the
    one configured connector.
    """
    from defenseclaw import ux
    from defenseclaw.commands import _scan_ui, resolve_list_connectors
    from defenseclaw.scanner.plugin import PluginScannerWrapper
    from defenseclaw.scanner.rulepack import maybe_wrap

    connectors: list[str] = resolve_list_connectors(app, connector_flag)

    registry_cache: PluginRegistryCache = {}
    discovery = _plugin_registry_probes(
        app,
        connectors,
        registry_cache=registry_cache,
    )
    _fail_on_plugin_registry_errors(
        discovery,
        as_json=as_json,
        preserve_json_array=as_json,
    )

    scan_options = _build_scan_options(
        app,
        policy_name,
        profile,
        use_llm,
        llm_model,
        llm_provider,
        llm_consensus_runs,
        enable_meta,
        include_self,
        lenient,
    )
    scanner = PluginScannerWrapper(llm=app.cfg.resolve_llm("scanners.plugin"))
    pack_cache: RulePackOverlayCache = {}

    json_groups: list[dict[str, Any]] = []
    total_targets = 0
    for connector in connectors:
        connector_scanner = maybe_wrap(
            scanner,
            app.cfg,
            connector,
            pack_cache=pack_cache,
        )
        if len(connectors) > 1 and not as_json:
            ux.echo(ux._style(f"\n── connector: {connector} ──", fg="cyan"))

        plugins = _merge_all_plugins(
            app.cfg.plugin_dir,
            connector,
            cfg=app.cfg,
            registry_cache=registry_cache,
        )
        # Resolve each plugin id to a scannable artifact on disk (managed dir,
        # connector-owned dir, or Amp's documented direct ``*.ts`` file).
        # Skip phantom (scan-history / enforcement-only) rows with no artifact.
        host_dirs = _host_plugin_dirs(app, connector)
        targets: list[tuple[str, str, str, str]] = []
        for p in plugins:
            pid = p.get("id", "")
            if not pid:
                continue
            scan_dir = str(p.get("host_path") or "")
            direct_amp_plugin = (
                connector == "amp"
                and os.path.isfile(scan_dir)
                and scan_dir.casefold().endswith(".ts")
                and not is_link_or_reparse(scan_dir)
            )
            if not os.path.isdir(scan_dir) and not direct_amp_plugin:
                scan_dir = (
                    _resolve_plugin_dir(
                        pid,
                        app.cfg.plugin_dir,
                        connector,
                        host_dirs,
                        registry_cache=registry_cache,
                    )
                    or ""
                )
            if scan_dir:
                targets.append(
                    (
                        pid,
                        scan_dir,
                        str(p.get("scope") or ""),
                        str(p.get("project_path") or ""),
                    )
                )

        if not targets:
            if not as_json:
                _render_plugin_registry_diagnostics(
                    {connector: discovery.get(connector, [])},
                    hide_missing=True,
                )
                click.echo(f"No plugins found to scan for connector={connector}.")
            else:
                json_groups.append(
                    {
                        "connector": connector,
                        "results": [],
                        "discovery": [
                            probe.as_dict()
                            for probe in discovery.get(connector, [])
                        ],
                        "error": "no_plugin_targets",
                    }
                )
            continue
        total_targets += len(targets)

        ctx = _scan_ui.ScanContext.for_plugin(
            connector=connector,
            paths=[d for _, d, _, _ in targets],
            as_json=as_json,
        )
        _scan_ui.render_preamble(ctx, target_count=len(targets))

        clean = warned = blocked = errored = findings_total = 0
        # Summary time is the wall time of the sweep, not the sum of the
        # base scanner's durations (GAP-2070).
        sweep_started = time.monotonic()
        group_results: list[dict[str, Any]] = []
        # GAP-2643: overlap the LLM-bound scans; results keep their order.
        for (pid, scan_dir, scope, project_path), scan_result in _scan_ui.ordered_scans(
            lambda target: connector_scanner.scan(target[1], **scan_options),
            targets,
            workers=_scan_ui.scan_batch_workers(connector_scanner, **scan_options),
        ):
            try:
                result = scan_result()
            except Exception as exc:  # noqa: BLE001 — surface, keep sweeping.
                errored += 1
                if not as_json:
                    click.echo(f"  error: scan failed for {pid!r}: {exc}", err=True)
                continue
            _record_scan(app.logger, result, connector=connector or None)
            if as_json:
                payload = json.loads(result.to_json())
                payload["connector"] = connector
                payload["target_metadata"] = _plugin_instance_metadata(
                    connector=connector,
                    path=result.target,
                    scope=scope,
                    project_path=project_path,
                )
                group_results.append(payload)
                continue
            target_label = _plugin_instance_label(pid, scope, project_path)
            if result.is_clean():
                clean += 1
                _scan_ui.render_per_target_status(
                    ctx,
                    target=target_label,
                    verdict=_scan_ui.VERDICT_CLEAN,
                    findings=0,
                )
            else:
                findings_total += len(result.findings)
                verdict, rejects = _plugin_scan_findings_verdict(
                    app, result, name=pid, path=scan_dir, connector=connector,
                )
                if verdict == _scan_ui.VERDICT_BLOCKED:
                    blocked += 1
                else:
                    warned += 1
                _scan_ui.render_per_target_status(
                    ctx,
                    target=target_label,
                    verdict=verdict,
                    detail=f"max severity: {result.max_severity()}",
                    findings=len(result.findings),
                )
                if rejects:
                    _print_plugin_scan_policy(pid, connector=connector)
        if as_json:
            json_groups.append({"connector": connector, "results": group_results})
        else:
            _scan_ui.render_summary(
                ctx,
                clean=clean,
                warning=warned,
                blocked=blocked,
                errored=errored,
                total=len(targets),
                findings=findings_total,
                duration_ms=int((time.monotonic() - sweep_started) * 1000),
            )

    if as_json:
        click.echo(json.dumps(json_groups, indent=2, default=str))
    if total_targets == 0:
        if not as_json:
            click.echo(
                "No plugins found to scan across "
                f"{len(connectors)} connector(s)",
            )


def _build_scan_options(
    app: AppContext,
    policy_name: str,
    profile: str | None,
    use_llm: bool | None,
    llm_model: str,
    llm_provider: str,
    llm_consensus_runs: int,
    enable_meta: bool,
    include_self: bool,
    lenient: bool,
) -> dict:
    """Build ``PluginScannerWrapper.scan`` kwargs from CLI flags.

    LLM defaults (model, api_key, base_url, provider) come from the
    unified :class:`LLMConfig` — resolved at ``scanners.plugin`` and
    threaded in via ``PluginScannerWrapper(llm=...)``. This function
    only forwards the per-invocation knobs the operator set on this
    particular command line. Any field left at its default ("", 0)
    falls through to the unified config.

    P-F: ``use_llm`` is tri-state — ``None`` (auto: on when a model is
    configured), ``True`` (force on), ``False`` (force off). It is always
    forwarded so the wrapper can make the auto decision.
    """
    opts: dict = {"use_llm": use_llm}

    if policy_name:
        opts["policy"] = policy_name
    if profile:
        opts["profile"] = profile

    if use_llm:
        if llm_model:
            opts["llm_model"] = llm_model
        if llm_provider:
            opts["llm_provider"] = llm_provider
        if llm_consensus_runs > 0:
            opts["llm_consensus_runs"] = llm_consensus_runs

    if not enable_meta:
        opts["disable_meta"] = True

    if include_self:
        opts["include_self"] = True

    # A configured OpenClaw home can live outside ~/.openclaw. Pass only its
    # exact DefenseClaw leaf to the scanner's identity registry; never pass a
    # broad plugin parent or a name pattern.
    claw = getattr(app.cfg, "claw", None)
    openclaw_home = str(getattr(claw, "home_dir", "") or "").strip()
    if openclaw_home:
        opts["trusted_self_paths"] = (
            os.path.join(os.path.abspath(os.path.expanduser(openclaw_home)), "extensions", "defenseclaw"),
        )

    if lenient:
        opts["lenient"] = True

    return opts


@plugin.command()
@click.argument("name_or_path")
@click.option("--force", is_flag=True, help="Force install (overwrites existing)")
@click.option("--action", "take_action", is_flag=True, help="Apply the admission policy (admission.plugin)")
@click.option(
    "--connector",
    "connector_flag",
    default="",
    help=(
        "Install into one configured connector's plugin directory. "
        "Default: every configured connector that exposes a plugin directory."
    ),
)
@pass_ctx
def install(app: AppContext, name_or_path: str, force: bool, take_action: bool, connector_flag: str) -> None:
    """Install a plugin from a local path, npm registry, clawhub, or URL.

    Supports four source types (auto-detected):

    \b
      Local directory   defenseclaw plugin install /path/to/plugin
      npm package       defenseclaw plugin install @openclaw/voice-call
      clawhub URI       defenseclaw plugin install clawhub://voice-call
      HTTP(S) URL       defenseclaw plugin install https://example.com/plugin.tgz

    After downloading, the plugin is scanned for security issues. Pass --action
    to apply the configured admission policy (quarantine, disable, block)
    based on scan severity. Use --force to overwrite an existing plugin.

    With no ``--connector`` the source is materialized into every configured
    connector that exposes a plugin directory. ``--connector`` narrows both
    placement and admission/enforcement attribution to that peer.
    """
    import tempfile

    from defenseclaw.commands import resolve_list_connectors
    from defenseclaw.enforce import PolicyEngine
    from defenseclaw.registry import (
        RegistryError,
        SourceType,
        detect_source,
        fetch_from_clawhub,
        fetch_from_url,
        fetch_npm_package,
    )
    from defenseclaw.scanner.plugin import PluginScannerWrapper
    from defenseclaw.scanner.rulepack import maybe_wrap

    connectors = resolve_list_connectors(app, connector_flag)
    targets = _plugin_install_targets(
        app,
        connectors,
        explicit_connector=bool(connector_flag),
    )

    source = detect_source(name_or_path)
    pe = PolicyEngine(app.store, app.cfg)

    # Package/source names are fetch hints only.  Policy identity is read from
    # the materialized manifest below.
    fetch_hint = ""
    if source == SourceType.CLAWHUB:
        from defenseclaw.registry import parse_clawhub_uri

        fetch_hint, _ = parse_clawhub_uri(name_or_path)

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
                source_path = fetch_from_clawhub(name_or_path, tmpdir, plugin_name=fetch_hint)
            else:
                click.echo(f"[install] downloading from {name_or_path}...")
                source_path = fetch_from_url(name_or_path, tmpdir)
        except RegistryError as exc:
            click.echo(f"error: {exc}", err=True)
            shutil.rmtree(tmpdir, ignore_errors=True)
            raise SystemExit(1)
    try:
        try:
            _reject_linked_tree(source_path)
        except PluginIdentityError as exc:
            click.echo(f"error: unsafe plugin source: {exc}", err=True)
            raise SystemExit(1)
        _validate_connector_plugin_source(source_path, targets)
        try:
            plugin_name, _manifest = canonical_plugin_id(source_path)
            if not _manifest:
                raise PluginIdentityError(
                    "plugin source does not contain a supported manifest with a canonical identity"
                )
        except PluginIdentityError as exc:
            click.echo(f"error: invalid plugin identity: {exc}", err=True)
            raise SystemExit(1)

        pre_decisions = _check_plugin_pre_install_admission(
            app,
            pe,
            targets,
            plugin_name,
            source_path=source_path,
        )

        try:
            transaction = _PluginInstallTransaction.prepare(
                source_path,
                targets,
                plugin_name,
                force=force,
            )
        except PluginIdentityError as exc:
            click.echo(f"error: {exc}", err=True)
            raise SystemExit(1)

        click.echo(
            f"[install] installing {plugin_name!r} for "
            + ", ".join(f"connector={connector}" for connector, _root in targets)
            + "..."
        )
        try:
            installed_by_connector = transaction.commit()
        except (OSError, PluginIdentityError) as exc:
            transaction.rollback()
            click.echo(f"error: plugin install commit failed: {exc}", err=True)
            raise SystemExit(1)
        for connector, plugin_path in installed_by_connector.items():
            click.echo(f"[install] installed {plugin_name!r} -> {plugin_path} (connector={connector})")
            if app.logger:
                saved_change_audit(app.logger).log_action(
                    "plugin-install",
                    plugin_name,
                    f"source={name_or_path} connector={connector}",
                )

        scanner = PluginScannerWrapper(llm=app.cfg.resolve_llm("scanners.plugin"))
        pack_cache: RulePackOverlayCache = {}
        scan_results: dict[str, Any] = {}
        try:
            for connector, _install_root in targets:
                if pre_decisions[connector].verdict != "allowed":
                    plugin_path = installed_by_connector[connector]
                    connector_scanner = maybe_wrap(
                        scanner,
                        app.cfg,
                        connector,
                        pack_cache=pack_cache,
                    )
                    scan_results[connector] = connector_scanner.scan(plugin_path)
        except Exception as exc:
            transaction.rollback()
            click.echo(f"error: scan failed for connector={connector}: {exc}", err=True)
            raise SystemExit(1)

        deferred_enforcement_failure = False
        try:
            for connector, _install_root in targets:
                plugin_path = installed_by_connector[connector]
                pre_decision = pre_decisions[connector]
                if pre_decision.verdict == "allowed":
                    if pre_decision.source == "scan-disabled":
                        click.echo(f"[install] policy allows {plugin_name!r} without scan (connector={connector})")
                    else:
                        ux.echo(
                            f"[install] {plugin_name!r} is on the allow list for connector={connector} — skipping scan"
                        )
                    pe.set_source_path("plugin", plugin_name, plugin_path, connector)
                    if app.logger:
                        saved_change_audit(app.logger).log_action(
                            "install-allowed",
                            plugin_name,
                            f"reason=allow-listed connector={connector}",
                        )
                    continue

                deferred_enforcement_failure = (
                    _scan_installed_plugin_for_connector(
                        app,
                        pe,
                        scanner,
                        plugin_name,
                        plugin_path,
                        connector=connector,
                        take_action=take_action,
                        rollback=transaction.rollback,
                        scan_result=scan_results[connector],
                        defer_action_failure=len(targets) > 1,
                        defer_scan_log=True,
                    )
                    or deferred_enforcement_failure
                )
        except SystemExit:
            # Enforcement may intentionally move the new canonical copy into
            # quarantine.  Preserve that action, but discard replacement
            # backups.  All other failures restore the exact prior layout.
            if transaction.committed and any(not os.path.exists(path) for path in installed_by_connector.values()):
                transaction.finalize()
            else:
                transaction.rollback()
            raise

        if app.logger:
            for scanned_connector, result in scan_results.items():
                saved_change_audit(app.logger).log_scan(result, connector=scanned_connector)
        transaction.finalize()
        if deferred_enforcement_failure:
            raise SystemExit(1)

        click.echo(f"Installed plugin: {plugin_name}")
        installed_connectors = {_normalize_runtime_connector(c) for c, _root in targets}
        if "hermes" in installed_connectors:
            _echo_hermes_activation_note(plugin_name)
        if "claudecode" in installed_connectors:
            _echo_claudecode_install_note(
                source_path, plugin_name, only_claudecode=installed_connectors == {"claudecode"}
            )

        from defenseclaw.commands import hint

        # Only the OpenClaw gateway loads plugins at start; hook connectors
        # pick a plugin up in their own next session (GAP-1878). plugin list
        # does not show a Claude Code copy, so don't point there (GAP-2084).
        hints = []
        if installed_connectors != {"claudecode"}:
            hints.append("List plugins:      defenseclaw plugin list")
        if "openclaw" in installed_connectors:
            hints.append("Restart gateway:   defenseclaw-gateway restart")
        if hints:
            hint(*hints)

    finally:
        if tmpdir:
            shutil.rmtree(tmpdir, ignore_errors=True)


def _check_plugin_pre_install_admission(
    app: AppContext,
    pe: Any,
    targets: list[tuple[str, str]],
    plugin_name: str,
    *,
    source_path: str,
) -> dict[str, Any]:
    from defenseclaw.enforce.admission import evaluate_admission

    pre_decisions: dict[str, Any] = {}
    for connector, _install_root in targets:
        decision = evaluate_admission(
            pe,
            config=app.cfg,
            target_type="plugin",
            name=plugin_name,
            source_path=source_path,
            connector=connector,
            include_quarantine=True,
        )
        pre_decisions[connector] = decision

        if decision.verdict == "blocked":
            if app.logger:
                saved_change_audit(app.logger).log_action(
                    "install-rejected",
                    plugin_name,
                    f"reason=blocked connector={connector}",
                )
            ux.echo(
                f"error: plugin {plugin_name!r} is on the block list for "
                f"connector={connector} — run "
                f"'defenseclaw plugin unblock {plugin_name} --connector {connector}' "
                "to clear the block",
                err=True,
            )
            raise SystemExit(1)

        if decision.verdict == "rejected" and decision.source == "quarantine":
            if app.logger:
                saved_change_audit(app.logger).log_action(
                    "install-rejected",
                    plugin_name,
                    f"reason=quarantined connector={connector}",
                )
            ux.echo(
                f"error: plugin {plugin_name!r} is quarantined for "
                f"connector={connector} — release the quarantine before reinstalling",
                err=True,
            )
            raise SystemExit(1)

        note_asset_policy_observed(
            app.logger, decision, target_type="plugin", name=plugin_name, connector=connector,
        )

    return pre_decisions


def _plugin_install_targets(
    app: AppContext,
    connectors: list[str],
    *,
    explicit_connector: bool = False,
) -> list[tuple[str, str]]:
    """Return ``(connector, install_root)`` targets for plugin installs.

    Antigravity is a normal filesystem-backed target: its documented global
    plugin directory is returned by ``cfg.plugin_dirs("antigravity")`` just
    like Claude Code, Codex, and Hermes. Keep capability decisions in the path
    adapter instead of hard-coding connector exclusions here.
    """
    targets: list[tuple[str, str]] = []
    skipped: list[str] = []
    for connector in connectors:
        dirs = [d for d in app.cfg.plugin_dirs(connector) if d]
        if not dirs:
            skipped.append(connector)
            continue
        targets.append((connector, dirs[0]))

    if not targets:
        if explicit_connector and connectors:
            click.echo(
                f"error: connector {connectors[0]!r} does not expose a plugin install directory",
                err=True,
            )
        else:
            click.echo(
                "error: no configured connector exposes a plugin install directory",
                err=True,
            )
        raise SystemExit(1)

    for connector in skipped:
        click.echo(f"[install] skipping connector={connector}: no plugin install directory")
    return targets


def _validate_connector_plugin_source(
    source_path: str,
    targets: list[tuple[str, str]],
) -> None:
    """Fail before copying a bundle that Antigravity cannot load.

    Google's manual-install contract requires a regular root ``plugin.json``.
    The IDE permits an omitted ``name`` (directory-name fallback), while the
    CLI requires a restricted name. Accept their common contract: a JSON
    object marker, with a valid CLI-shaped name whenever one is supplied.
    """
    if not any(connector == "antigravity" for connector, _root in targets):
        return

    source_root = os.path.realpath(source_path)
    manifest_path = os.path.join(source_path, "plugin.json")
    manifest_real = os.path.realpath(manifest_path)
    if (
        manifest_real == source_root
        or not manifest_real.startswith(source_root + os.sep)
        or is_link_or_reparse(manifest_path)
        or not os.path.isfile(manifest_path)
    ):
        click.echo(
            "error: Antigravity plugins require a regular root plugin.json",
            err=True,
        )
        raise SystemExit(1)

    try:
        with open(manifest_path, encoding="utf-8") as fh:
            manifest = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        click.echo(f"error: invalid Antigravity plugin.json: {exc}", err=True)
        raise SystemExit(1) from exc
    if not isinstance(manifest, dict):
        click.echo("error: Antigravity plugin.json must contain a JSON object", err=True)
        raise SystemExit(1)

    declared_name = manifest.get("name")
    if declared_name is not None and (
        not isinstance(declared_name, str) or re.fullmatch(r"[A-Za-z0-9_-]+", declared_name) is None
    ):
        click.echo(
            "error: Antigravity plugin.json name must match [A-Za-z0-9_-]+",
            err=True,
        )
        raise SystemExit(1)


def _reject_linked_tree(source_path: str) -> None:
    """Reject links/reparse-like entries instead of copying their targets."""
    source_real = os.path.realpath(source_path)
    for current, dirs, files in os.walk(source_path, followlinks=False):
        current_real = os.path.realpath(current)
        if is_link_or_reparse(current) or not (
            current_real == source_real or current_real.startswith(source_real + os.sep)
        ):
            raise PluginIdentityError(f"plugin source contains an unsafe path: {current}")
        for name in [*dirs, *files]:
            candidate = os.path.join(current, name)
            if is_link_or_reparse(candidate):
                raise PluginIdentityError(f"plugin source contains a linked entry: {candidate}")


class _PluginInstallTransaction:
    """Stage every connector, then atomically swap with rollback backups."""

    def __init__(self, source_path: str, plugin_name: str) -> None:
        self.source_path = source_path
        self.plugin_name = plugin_name
        self.plans: list[dict[str, Any]] = []
        self.committed = False

    @classmethod
    def prepare(
        cls,
        source_path: str,
        targets: list[tuple[str, str]],
        plugin_name: str,
        *,
        force: bool,
    ) -> _PluginInstallTransaction:
        _reject_linked_tree(source_path)
        tx = cls(source_path, plugin_name)
        source_real = os.path.realpath(source_path)

        # Complete every read-only collision/path check before creating roots or
        # staging data for any connector.
        for connector, root in targets:
            root_real = os.path.realpath(root)
            destination = os.path.join(root, plugin_name)
            dest_real = os.path.realpath(destination)
            if dest_real == root_real or not dest_real.startswith(root_real + os.sep):
                raise PluginIdentityError(f"canonical destination escapes connector={connector} plugin root")
            identities = enumerate_physical_identities(root)
            key = filesystem_identity_key(plugin_name, root)
            aliases = [item.path for item in identities if filesystem_identity_key(item.plugin_id, root) == key]
            if source_real in {os.path.realpath(path) for path in aliases}:
                raise PluginIdentityError("refusing to replace or move the plugin source path")
            if aliases and not force:
                raise PluginIdentityError(
                    f"plugin {plugin_name!r} already exists for connector={connector} "
                    f"at {', '.join(aliases)}; pass --force to replace it"
                )
            tx.plans.append(
                {
                    "connector": connector,
                    "root": root,
                    "destination": destination,
                    "aliases": aliases,
                    "stage": "",
                    "backups": [],
                    "installed": False,
                }
            )

        try:
            for plan in tx.plans:
                os.makedirs(plan["root"], exist_ok=True)
                stage = os.path.join(plan["root"], f".dclaw-stage-{plugin_name}-{os.getpid()}")
                if os.path.lexists(stage):
                    raise PluginIdentityError(f"staging path already exists: {stage}")
                shutil.copytree(source_path, stage, symlinks=True)
                plan["stage"] = stage
                # Preserve links during the untrusted copy so they are never
                # dereferenced, then reject any link introduced after the
                # source preflight before the staged tree can be committed.
                _reject_linked_tree(stage)
        except Exception:
            tx.rollback()
            raise
        return tx

    def commit(self) -> dict[str, str]:
        installed: dict[str, str] = {}
        try:
            for plan in self.plans:
                # Revalidate at the mutation boundary in case the staged tree
                # changed after prepare() returned.
                _reject_linked_tree(plan["stage"])
                for index, existing in enumerate(plan["aliases"]):
                    backup = os.path.join(
                        plan["root"],
                        f".dclaw-backup-{self.plugin_name}-{os.getpid()}-{index}",
                    )
                    if os.path.lexists(backup):
                        raise PluginIdentityError(f"backup path already exists: {backup}")
                    os.replace(existing, backup)
                    plan["backups"].append((existing, backup))
                os.replace(plan["stage"], plan["destination"])
                plan["stage"] = ""
                plan["installed"] = True
                _reject_linked_tree(plan["destination"])
                installed[plan["connector"]] = plan["destination"]
            self.committed = True
            return installed
        except Exception:
            self.rollback()
            raise

    def rollback(self) -> None:
        for plan in reversed(self.plans):
            destination = plan["destination"]
            if plan["installed"]:
                if os.path.isdir(destination) and not os.path.islink(destination):
                    shutil.rmtree(destination, ignore_errors=True)
                plan["installed"] = False
            for original, backup in reversed(plan["backups"]):
                if os.path.exists(backup) and not os.path.exists(original):
                    os.replace(backup, original)
            plan["backups"] = []
            stage = plan["stage"]
            if stage and os.path.isdir(stage) and not os.path.islink(stage):
                shutil.rmtree(stage, ignore_errors=True)
                plan["stage"] = ""
        self.committed = False

    def finalize(self) -> None:
        for plan in self.plans:
            for _original, backup in plan["backups"]:
                if os.path.isdir(backup) and not os.path.islink(backup):
                    shutil.rmtree(backup)
            plan["backups"] = []


def _rollback_plugin_install_paths(paths: list[str]) -> None:
    seen: set[str] = set()
    for path in paths:
        if not path or path in seen:
            continue
        seen.add(path)
        try:
            if os.path.isdir(path) and not os.path.islink(path):
                shutil.rmtree(path)
        except OSError as exc:
            click.echo(
                f"[install] warning: could not remove partial install {path}: {exc}",
                err=True,
            )


def _scan_installed_plugin_for_connector(
    app: AppContext,
    pe: Any,
    scanner: Any,
    plugin_name: str,
    plugin_path: str,
    *,
    connector: str,
    take_action: bool,
    rollback: Any = None,
    scan_result: Any = None,
    defer_action_failure: bool = False,
    defer_scan_log: bool = False,
) -> bool:
    from defenseclaw.enforce.admission import evaluate_admission
    from defenseclaw.enforce.plugin_enforcer import PluginEnforcer

    click.echo(f"[install] scanning {plugin_path} (connector={connector})...")
    if scan_result is None:
        try:
            result = scanner.scan(plugin_path)
        except Exception as exc:
            if rollback:
                rollback()
            else:
                _rollback_plugin_install_paths([plugin_path])
            click.echo(
                f"error: scan failed for connector={connector}: {exc}",
                err=True,
            )
            raise SystemExit(1)
    else:
        result = scan_result

    _print_install_result(plugin_name, result)

    post_decision = evaluate_admission(
        pe,
        config=app.cfg,
        target_type="plugin",
        name=plugin_name,
        source_path=plugin_path,
        scan_result=result,
        connector=connector,
    )

    if post_decision.verdict == "allowed" and post_decision.source == "scan-allowed":
        # The admission action for the findings' severity is allow; nothing
        # is on an allow list, so this is installed like a clean plugin.
        if app.logger and not defer_scan_log:
            saved_change_audit(app.logger).log_scan(result, connector=connector)
        click.echo(
            f"[install] {plugin_name!r} installed: the admission policy allows its findings "
            f"({post_decision.reason}, connector={connector})"
        )
        pe.set_source_path("plugin", plugin_name, plugin_path, connector)
        if app.logger:
            saved_change_audit(app.logger).log_action(
                "install-allowed",
                plugin_name,
                f"reason=admission-action-allow connector={connector}",
            )
        return False

    if post_decision.verdict == "allowed":
        if app.logger and not defer_scan_log:
            saved_change_audit(app.logger).log_scan(result, connector=connector)
        ux.echo(
            f"[install] {plugin_name!r} became allow-listed for connector={connector} — skipping post-scan enforcement"
        )
        pe.set_source_path("plugin", plugin_name, plugin_path, connector)
        if app.logger:
            saved_change_audit(app.logger).log_action(
                "install-allowed",
                plugin_name,
                f"reason=allow-listed-post-scan connector={connector}",
            )
        return False

    if post_decision.verdict == "clean":
        if app.logger and not defer_scan_log:
            saved_change_audit(app.logger).log_scan(result, connector=connector)
        click.echo(f"[install] {plugin_name!r} installed and clean (connector={connector})")
        pe.set_source_path("plugin", plugin_name, plugin_path, connector)
        if app.logger:
            saved_change_audit(app.logger).log_action(
                "install-clean",
                plugin_name,
                f"verdict=clean connector={connector}",
            )
        return False

    sev = result.max_severity()
    detail = f"severity={sev} findings={len(result.findings)} connector={connector}"

    if not take_action:
        sev_norm = (sev or "").strip().upper()
        if sev_norm in {"HIGH", "CRITICAL"}:
            if rollback:
                rollback()
            else:
                _rollback_plugin_install_paths([plugin_path])
            ux.echo(
                f"error: refusing to install {plugin_name!r} for connector={connector} — "
                f"{len(result.findings)} {sev_norm} findings detected and "
                "--action was not passed. Run with --action to enforce, or "
                f"`defenseclaw plugin allow {plugin_name} --connector {connector}` "
                "to explicitly accept the risk.",
                err=True,
            )
            if app.logger:
                saved_change_audit(app.logger).log_action(
                    "install-rejected",
                    plugin_name,
                    f"{detail} result=refused reason=critical-without-action",
                )
            raise SystemExit(1)
        ux.echo(
            f"[install] {len(result.findings)} {sev} findings in {plugin_name!r} "
            f"(connector={connector}; no action taken — pass --action to enforce)"
        )
        if app.logger and not defer_scan_log:
            saved_change_audit(app.logger).log_scan(result, connector=connector)
        pe.set_source_path("plugin", plugin_name, plugin_path, connector)
        if app.logger:
            saved_change_audit(app.logger).log_action("install-warning", plugin_name, detail)
        return False

    action_cfg = post_decision.action
    if app.logger and not defer_scan_log:
        saved_change_audit(app.logger).log_scan(result, connector=connector)
    enforcement_reason = f"post-install scan: {len(result.findings)} findings, max={sev}"
    applied_actions: list[str] = []

    if action_cfg.file == "quarantine":
        pe.set_source_path("plugin", plugin_name, plugin_path, connector)
        se = PluginEnforcer(app.cfg.quarantine_dir)
        q_dest = se.quarantine(plugin_name, plugin_path, connector=connector)
        if q_dest:
            applied_actions.append(f"quarantined to {q_dest}")
            pe.quarantine_for_connector("plugin", plugin_name, connector, enforcement_reason)
        else:
            click.echo("[install] quarantine failed", err=True)

    if action_cfg.runtime == "disable":
        target_connector = _normalize_runtime_connector(connector)
        if target_connector == "openclaw":
            client = _sidecar_client(app)
            try:
                client.disable_plugin(plugin_name)
                applied_actions.append("disabled via gateway")
                pe.disable_for_connector("plugin", plugin_name, connector, enforcement_reason)
            except Exception as exc:
                click.echo(f"[install] gateway disable failed: {exc}", err=True)
        else:
            applied_actions.append(f"runtime disable recorded for connector={connector}")
            pe.disable_for_connector("plugin", plugin_name, connector, enforcement_reason)

    if action_cfg.install == "block":
        pe.record_scan_block("plugin", plugin_name, connector, enforcement_reason)
        applied_actions.append("added to block list")

    pe.set_source_path("plugin", plugin_name, plugin_path, connector)

    if applied_actions:
        actions_str = ", ".join(applied_actions)
        click.echo(f"[install] {plugin_name!r}: {actions_str} ({detail})")
        if app.logger:
            saved_change_audit(app.logger).log_action(
                "install-enforced",
                plugin_name,
                f"{detail}; {actions_str}",
            )
        ux.echo(
            f"error: plugin {plugin_name!r} had {sev} findings for "
            f"connector={connector} — actions applied: {actions_str}",
            err=True,
        )
        if defer_action_failure:
            return True
        raise SystemExit(1)

    click.echo(f"[install] warning: {len(result.findings)} {sev} findings in {plugin_name!r} (connector={connector})")
    pe.set_source_path("plugin", plugin_name, plugin_path, connector)
    if app.logger:
        saved_change_audit(app.logger).log_action("install-warning", plugin_name, detail)
    return False


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
@click.option(
    "--connector",
    "connector_flag",
    default="",
    help=(
        "List plugins for a specific configured connector. "
        "Default: every configured connector (on a single-connector install, "
        "just that one). Pass --connector <name> to narrow to one peer."
    ),
)
@pass_ctx
def list_plugins(app: AppContext, as_json: bool, connector_flag: str) -> None:
    """List installed plugins with scan severity.

    By default this lists every configured connector's plugins — each
    connector gets its own connector-tagged table — so the output reads
    the same whether one or many connectors are configured. ``--connector
    <name>`` narrows the listing to one configured peer.
    """
    from defenseclaw.commands import resolve_list_connectors

    connectors = resolve_list_connectors(app, connector_flag)
    registry_cache: PluginRegistryCache = {}
    discovery = _plugin_registry_probes(
        app,
        connectors,
        registry_cache=registry_cache,
    )
    _fail_on_plugin_registry_errors(
        discovery,
        as_json=as_json,
        preserve_json_array=as_json,
    )
    scan_map = _build_plugin_scan_map(app.store)
    # P-A: resolve the effective actions per connector (connector-scoped row
    # overrides unscoped) so each connector's table/card shows its own verdict.

    if as_json:
        if len(connectors) > 1:
            groups: list[dict[str, Any]] = []
            total_plugins = 0
            for connector in connectors:
                items = _plugin_list_json_items(
                    _collect_plugins_for_connector(
                        app,
                        connector,
                        scan_map,
                        registry_cache=registry_cache,
                    ),
                    _build_plugin_scan_map_for_connector(app, connector),
                    _build_plugin_actions_map(app.store, connector, app.cfg),
                    connector=connector,
                )
                _report_host_plugin_list_error(connector)
                total_plugins += len(items)
                groups.append({"connector": connector, "plugins": items})
            click.echo(json.dumps(groups, indent=2, default=str))
            if total_plugins == 0 and any(discovery.values()):
                _render_plugin_registry_diagnostics(
                    discovery,
                    force_stderr=True,
                )
        else:
            plugins = _collect_plugins_for_connector(
                app,
                connectors[0],
                scan_map,
                registry_cache=registry_cache,
            )
            items = _plugin_list_json_items(
                plugins,
                _build_plugin_scan_map_for_connector(app, connectors[0]),
                _build_plugin_actions_map(app.store, connectors[0], app.cfg),
                connector=connectors[0],
            )
            click.echo(json.dumps(items, indent=2, default=str))
            if _report_host_plugin_list_error(connectors[0]) and not items:
                raise SystemExit(1)
            if not items and discovery.get(connectors[0]):
                _render_plugin_registry_diagnostics(
                    discovery,
                    force_stderr=True,
                )
        return

    shown_any = False
    list_failed = False
    empty_connectors: list[str] = []
    for connector in connectors:
        plugins = _collect_plugins_for_connector(
            app,
            connector,
            scan_map,
            registry_cache=registry_cache,
        )
        list_error = _report_host_plugin_list_error(connector)
        if not plugins:
            empty_connectors.append(connector)
            if list_error:
                list_failed = True
                if len(connectors) > 1:
                    click.echo(f"Plugins (connector={connector}): could not list plugins")
                continue
            if len(connectors) > 1:
                # GAP-2290: a missing registry is the normal "none yet" case;
                # say it on this connector's own line.
                note = _empty_plugin_registry_note(discovery, connector)
                if note is not None:
                    click.echo(
                        f"Plugins (connector={connector}): no installed plugins {note}".rstrip()
                    )
                else:
                    click.echo(f"Plugins (connector={connector}): no plugins found")
            continue
        actions_map = _build_plugin_actions_map(app.store, connector, app.cfg)
        connector_scan_map = _build_plugin_scan_map_for_connector(app, connector)
        _print_plugin_list_table(plugins, connector_scan_map, actions_map, connector)
        shown_any = True

    if not shown_any:
        if list_failed and len(connectors) == 1:
            raise SystemExit(1)
        _render_plugin_registry_diagnostics(discovery, hide_missing=len(connectors) > 1)
        if len(connectors) == 1 and _empty_plugin_registry_note(discovery, connectors[0]) is None:
            # GAP-2368: no plugins is a normal state, not a broken install.
            roots = _plugin_roots_for_connector(app, connectors[0])
            checked = f" (checked: {', '.join(roots)})" if roots else ""
            click.echo(f"{connectors[0]} has no installed plugins{checked}.")
        return

    if shown_any:
        from defenseclaw.commands import hint

        hint("Scan a plugin:  defenseclaw plugin scan <name>")


def _report_host_plugin_list_error(connector: str) -> str:
    """Say on stderr why *connector*'s plugins could not be listed (GAP-2415)."""

    reason = _HOST_PLUGIN_LIST_ERRORS.pop(connector, "")
    if reason:
        click.echo(
            f"warning: could not list {connector} plugins: {reason}",
            err=True,
        )
    return reason


def _collect_plugins_for_connector(
    app: AppContext,
    connector: str,
    scan_map: dict[str, dict[str, Any]],
    *,
    registry_cache: PluginRegistryCache | None = None,
) -> list[dict[str, Any]]:
    """Build the merged plugin list for a single connector.

    OpenClaw-only audit-DB phantom (scan-history) rows are folded in just
    as the single-connector path did. Other connectors get only the
    connector-aware filesystem enumeration so OpenClaw plugins never leak
    into a Codex / Claude Code / ZeptoClaw view.
    """
    try:
        _assert_connector_plugin_identities_unambiguous(
            app,
            connector,
            registry_cache=registry_cache,
        )
        plugins = _merge_all_plugins(
            app.cfg.plugin_dir,
            connector,
            cfg=app.cfg,
            registry_cache=registry_cache,
        )
    except PluginIdentityError as exc:
        raise click.ClickException(str(exc)) from exc
    known_ids = {p["id"] for p in plugins}
    for pid, ae in sorted(_build_plugin_actions_map(app.store, connector, app.cfg).items()):
        if pid in known_ids or ae.actions.file != "quarantine":
            continue
        row = _quarantined_hermes_row(app, pid, ae, connector)
        if row is None or row["id"] in known_ids:
            row = {
                "id": pid,
                "name": pid,
                "description": "",
                "version": "",
                "origin": "enforcement",
                "enabled": False,
                "source": "enforcement",
            }
        plugins.append(row)
        known_ids.add(row["id"])
    if connector != "openclaw":
        return plugins
    for scan_id in scan_map:
        if scan_id not in known_ids:
            plugins.append(
                {
                    "id": scan_id,
                    "name": scan_id,
                    "description": "",
                    "version": "",
                    "origin": "scan-history",
                    "enabled": False,
                    "source": "scan-history",
                }
            )
            known_ids.add(scan_id)
    return plugins


def _quarantined_hermes_row(
    app: AppContext,
    action_id: str,
    entry: Any,
    connector: str,
) -> dict[str, Any] | None:
    """GAP-2265: the row a quarantined Hermes plugin had before quarantine.

    Quarantine is keyed by manifest id (``photon-platform``), but the list
    showed the folder id (``photon``). Rebuild that id and origin from the
    original path, and the name and description from the quarantined copy.
    """
    if connector != "hermes" or not entry.source_path:
        return None
    from defenseclaw.enforce.plugin_enforcer import PluginEnforcer
    from defenseclaw.inventory.claw_inventory import _read_hermes_plugin_manifest, hermes_listed_identity

    identity = hermes_listed_identity(entry.source_path)
    if identity is None:
        return None
    qpath = PluginEnforcer(app.cfg.quarantine_dir)._quarantine_path(action_id, connector)
    manifest = (_read_hermes_plugin_manifest(os.path.join(qpath, "plugin.yaml")) if qpath else None) or {}
    return {
        "id": identity[0],
        "name": str(manifest.get("name") or action_id),
        "description": str(manifest.get("description") or ""),
        "version": str(manifest.get("version") or ""),
        "origin": identity[1],
        "enabled": False,
        "source": "host:hermes",
        "action_id": action_id,
    }


def _row_action(p: dict[str, Any], actions_map: dict[str, Any]) -> Any:
    """The action entry for a list row (a quarantined row lists its old id)."""
    return actions_map.get(p.get("action_id") or p["id"])


def _plugin_actions_label(state: Any) -> str:
    """GAP-2199/GAP-2264: list and info say what an install block covers."""
    label = state.summary()
    if state.install == "block":
        label = label.replace("blocked", "install-blocked")
    return label


def _assert_connector_plugin_identities_unambiguous(
    app: AppContext,
    connector: str,
    *,
    registry_cache: PluginRegistryCache | None = None,
) -> None:
    """Preflight all configured roots without collapsing physical aliases."""
    if connector_paths.normalize(connector) == "hermes":
        # GAP-2463: Hermes lists its own plugin sources: category folders
        # (~/.hermes/plugins/platforms) are containers, not plugins, and a
        # user plugin overrides a bundled one with the same id.
        return
    claimed = PluginInstallClaims()
    for root in _plugin_roots_for_connector(app, connector):
        for entry in discover_plugin_directories(
            root,
            connector=connector,
            registry_cache=registry_cache,
            workspace_dir=app.cfg.connector_workspace_dir(),
        ):
            claimed.add_directory(entry, root)


def _merge_all_plugins(
    plugin_dir: str,
    connector: str = "",
    *,
    cfg: Any = None,
    registry_cache: PluginRegistryCache | None = None,
) -> list[dict[str, Any]]:
    """Build a unified plugin list from DefenseClaw + connector sources.

    Each entry carries both ``id`` (directory basename, matches scan DB
    targets) and ``name`` (human-readable display name).

    Plan C6: when *cfg* is provided AND the requested connector is not
    OpenClaw, host-agent plugins are enumerated via cfg.plugin_dirs()
    and tagged ``source: "host:<connector>"`` so the merged list
    distinguishes managed-by-DefenseClaw plugins from host-owned
    ones. cfg=None is supported for back-compat with existing tests
    that mock _list_openclaw_plugins directly.
    """
    plugins: list[dict[str, Any]] = []

    for dir_name in _list_defenseclaw_plugins(plugin_dir):
        plugins.append(
            {
                "id": dir_name,
                "name": dir_name,
                "description": "",
                "version": "",
                "origin": "local",
                "enabled": True,
                "source": "defenseclaw",
            }
        )

    for p in _list_openclaw_plugins(connector):
        plugins.append(
            {
                "id": p.get("id", ""),
                "name": p.get("name") or p.get("id", "unknown"),
                "description": p.get("description", ""),
                "version": p.get("version", ""),
                "origin": p.get("origin", ""),
                "enabled": p.get("enabled", False),
                "source": "openclaw",
            }
        )

    # Plan C6: matrix §5 — surface host-owned plugins for non-OpenClaw
    # connectors. We de-dup by id against DefenseClaw-managed plugins:
    # a DefenseClaw plugin with the same id wins (it's our copy).
    if cfg is not None:
        seen_ids = {str(p["id"]).casefold() for p in plugins}
        seen_registry_instances: set[tuple[str, str, str]] = set()
        for hp in _list_host_plugins(
            connector,
            cfg,
            registry_cache=registry_cache,
        ):
            plugin_key = str(hp["id"]).casefold()
            registry_source = str(hp.get("registry_source") or "")
            if registry_source:
                registry_key = (
                    plugin_key,
                    str(hp.get("scope") or "").casefold(),
                    os.path.normcase(
                        os.path.normpath(str(hp.get("project_path") or ""))
                    ),
                )
                if registry_key in seen_registry_instances:
                    continue
                seen_registry_instances.add(registry_key)
                plugins.append(hp)
                continue
            if plugin_key in seen_ids:
                continue
            seen_ids.add(plugin_key)
            plugins.append(hp)

    return plugins


def _plugin_status(p: dict[str, Any], action_entry: Any = None) -> str:
    if action_entry and not action_entry.actions.is_empty():
        a = action_entry.actions
        if a.file == "quarantine":
            return "quarantined"
        if a.install == "block":
            return "blocked"
        if a.runtime == "disable":
            return "disabled"
    if not p.get("enabled"):
        return "disabled"
    return "enabled"


def _plugin_status_display(p: dict[str, Any], action_entry: Any = None) -> str:
    if action_entry and not action_entry.actions.is_empty():
        a = action_entry.actions
        # GAP-2199: an install block leaves the installed copy loaded, so
        # it does not change the Status column (Actions shows it).
        if a.file == "quarantine":
            return "\u2717 quarantined"
        if a.runtime == "disable":
            return "\u2717 disabled"
    if p.get("enabled"):
        return "\u2713 enabled"
    return "\u2717 disabled"


def _plugin_effectively_enabled(p: dict[str, Any], action_entry: Any = None) -> bool:
    if action_entry and not action_entry.actions.is_empty():
        a = action_entry.actions
        if a.file == "quarantine" or a.runtime == "disable":
            return False
    return bool(p.get("enabled"))


def _plugin_list_json_items(
    plugins: list[dict[str, Any]],
    scan_map: dict[str, dict[str, Any]],
    actions_map: dict[str, Any],
    connector: str = "",
) -> list[dict[str, Any]]:
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
            "status": _plugin_status(p, _row_action(p, actions_map)),
            "enabled": _plugin_effectively_enabled(p, _row_action(p, actions_map)),
        }
        if connector:
            item["connector"] = connector
        for field in (
            "scope",
            "project_path",
            "registry",
            "registry_source",
            "host_path",
            "manifest",
            "cached",
        ):
            value = p.get(field)
            if value not in (None, "", False):
                item[field] = value
        if pid in scan_map:
            item["scan"] = scan_map[pid]
        ae = _row_action(p, actions_map)
        if ae is not None and not ae.actions.is_empty():
            item["actions"] = ae.actions.to_dict()
        verdict_label, _ = _compute_verdict(ae, scan_map.get(pid))
        item["verdict"] = verdict_label
        items.append(item)
    return items


def _print_plugin_list_table(
    plugins: list[dict[str, Any]],
    scan_map: dict[str, dict[str, Any]],
    actions_map: dict[str, Any],
    connector: str = "",
) -> None:
    from rich.console import Console

    from defenseclaw.commands import list_scope_title

    enabled_count = sum(1 for p in plugins if _plugin_effectively_enabled(p, _row_action(p, actions_map)))

    detail = f"({enabled_count}/{len(plugins)} enabled)"
    title = list_scope_title("Plugins", connector, detail) if connector else f"Plugins {detail}"
    console = Console()
    rows: list[dict[str, str]] = []

    for p in plugins:
        pid = p["id"]
        name = p["name"]
        action_entry = _row_action(p, actions_map)
        status_display = _plugin_status_display(p, action_entry)
        # GAP-2202: YAML folded descriptions end in (or hold) newlines.
        desc = " ".join(str(p.get("description") or "").split())

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
        verdict_action = action_entry
        if action_entry is not None:
            state = action_entry.actions
            actions_str = _plugin_actions_label(state)
            # GAP-2199: keep the scan verdict when nothing stops the installed copy.
            # GAP-2293: a quarantine shows in Status and Actions; Verdict keeps
            # the last scan verdict, as ``plugin info`` does.
            if state.file == "quarantine" or (state.install == "block" and state.runtime != "disable"):
                verdict_action = None

        verdict_label, verdict_style = _compute_verdict(
            verdict_action,
            scan_map.get(pid),
        )

        status_style = ""
        if "\u2717" in status_display:
            status_style = "red"
        elif "\u2713" in status_display:
            status_style = "green"

        rows.append(
            {
                "Status": f"[{status_style}]{status_display}[/{status_style}]" if status_style else status_display,
                "ID": pid,
                "Plugin": name,
                "Description": desc,
                "Origin": origin,
                "Severity": f"[{sev_style}]{severity}[/{sev_style}]" if sev_style else severity,
                "Verdict": f"[{verdict_style}]{verdict_label}[/{verdict_style}]" if verdict_style else verdict_label,
                "Actions": actions_str,
            }
        )

    table, hidden = _fit_plugin_list_table(console, title, rows)
    console.print(table)
    if hidden:
        # GAP-2348: the command sits on its own line, so a wrap never splits it.
        console.print(f"[dim]Hidden to fit: {', '.join(hidden)}.[/dim]")
        console.print("[dim]See: defenseclaw plugin info <id>[/dim]")


# GAP-2292: the column order, and which columns may be hidden (first to last)
# when the terminal is too narrow for one line per row.
_PLUGIN_LIST_COLUMNS = ("Status", "ID", "Plugin", "Description", "Origin", "Severity", "Verdict", "Actions")
# GAP-2333/GAP-2334: Actions hides last, and is named in "Hidden to fit",
# instead of being squeezed to "quarantin…" or to a zero-width column.
_PLUGIN_LIST_OPTIONAL = ("Description", "Origin", "Plugin", "Actions")
_PLUGIN_LIST_DESC_MAX = 50
_PLUGIN_LIST_DESC_MIN = 16


def _fit_plugin_list_table(console: Any, title: str, rows: list[dict[str, str]]) -> tuple[Any, list[str]]:
    """Build the plugin table so each row fits on one terminal line.

    Rich never shrinks a ``no_wrap`` column, so a fixed-width Description
    squeezed Status, ID and Verdict to "…" on 80/120-column terminals
    (GAP-2292). Instead the Description narrows first, then Description,
    Origin, Plugin and Actions are hidden in that order. Returns (table, hidden).
    """
    from rich.cells import cell_len
    from rich.measure import Measurement
    from rich.table import Table

    def build(hidden: tuple[str, ...], desc_width: int) -> Any:
        table = Table(title=title)
        for col in _PLUGIN_LIST_COLUMNS:
            if col in hidden:
                continue
            if col == "Description":
                table.add_column(col, max_width=desc_width, no_wrap=True, overflow="ellipsis")
            elif col in ("Plugin", "Origin"):
                table.add_column(col)
            elif col == "ID":
                # GAP-2333: when even the required columns overflow, a long ID
                # folds onto a second line rather than squeezing Status/Verdict.
                table.add_column(col, overflow="fold")
            else:
                table.add_column(col, no_wrap=True, style="bold" if col == "Status" else "")
        for row in rows:
            table.add_row(*(row[col] for col in _PLUGIN_LIST_COLUMNS if col not in hidden))
        return table

    width = console.width
    wide = console.options.update_width(10_000)

    def natural(table: Any) -> int:
        return Measurement.get(console, wide, table).maximum

    table = build((), _PLUGIN_LIST_DESC_MAX)
    excess = natural(table) - width
    if excess <= 0:
        return table, []
    desc_width = min(
        _PLUGIN_LIST_DESC_MAX,
        max([len("Description")] + [cell_len(row["Description"]) for row in rows]),
    )
    if desc_width - excess >= _PLUGIN_LIST_DESC_MIN:
        return build((), desc_width - excess), []
    has_desc = any(row["Description"] for row in rows)
    for count in range(1, len(_PLUGIN_LIST_OPTIONAL) + 1):
        hidden = _PLUGIN_LIST_OPTIONAL[:count]
        table = build(hidden, _PLUGIN_LIST_DESC_MAX)
        if natural(table) <= width or count == len(_PLUGIN_LIST_OPTIONAL):
            break
    if natural(table) > width:
        # GAP-2364: even Status, ID, Severity and Verdict overflow, and a
        # squeezed ID broke mid-word ("whatsap" / "p"). List each plugin
        # with its whole ID on its own line instead.
        table = _stacked_plugin_list(title, rows)
    return table, [col for col in hidden if col != "Description" or has_desc]


def _stacked_plugin_list(title: str, rows: list[dict[str, str]]) -> Any:
    """One block per plugin: the whole ID, then Status, Severity and Verdict."""
    from rich.console import Group
    from rich.text import Text

    legend = Text("ID, then Status \u00b7 Severity \u00b7 Verdict", style="dim")
    parts: list[Any] = [Text(title, style="italic"), legend]
    for row in rows:
        parts.append(Text(row["ID"], style="bold", overflow="fold"))
        parts.append(Text.from_markup(f"  {row['Status']} \u00b7 {row['Severity']} \u00b7 {row['Verdict']}"))
    return Group(*parts)


def _looks_like_explicit_path(value: str) -> bool:
    """Return ``True`` when ``value`` clearly looks like a filesystem
    path the operator typed deliberately, rather than a bare plugin
    name.

    A path qualifies when:

      * It is absolute (``/foo/bar``, ``C:\\plugins\\foo`` on
        Windows, etc.).
      * It contains the OS path separator (``./local-plugin``,
        ``../sibling-plugin``, ``some/dir``).
      * On platforms with an alternate separator (``os.altsep`` —
        Windows ``/``), the alternate separator counts too.

    A bare token like ``"my-plugin"`` does NOT qualify, even if it
    coincidentally matches a directory in the current working
    directory. That's the entire point of this helper: we don't want
    plugin resolution to depend on the operator's cwd.
    """
    if not value:
        return False
    if os.path.isabs(value):
        return True
    if os.sep in value:
        return True
    if os.altsep and os.altsep in value:
        return True
    return False


def _resolve_plugin_dir(
    name_or_path: str,
    plugin_dir: str,
    connector: str = "",
    search_dirs: list[str] | None = None,
    *,
    registry_cache: PluginRegistryCache | None = None,
) -> str | None:
    """Resolve a plugin name or path to a scannable artifact on disk.

    Resolution order:
      1. Literal path (a directory, direct Amp ``.ts`` plugin, or direct
         OpenCode ``.js``/``.ts`` plugin) — only
         when the input clearly looks like a path (absolute, or contains a path
         separator). A bare token like ``my-plugin`` is intentionally
         NOT treated as a relative path here, even if a directory of
         that name happens to exist in the current working directory:
         operators run this command from anywhere, and a bare name
         must always resolve via plugin lookup, not via cwd-relative
         coincidence. Otherwise running the command from a workspace
         that contains a same-named folder silently mis-resolves to
         the local folder and skips the OpenClaw / DefenseClaw lookup
         entirely.
      2. Subdirectory under DefenseClaw's plugin_dir
      3. P-B: the target connector's own plugin dirs (``search_dirs`` =
         ``cfg.plugin_dirs(connector)``) so a host-owned plugin that
         ``plugin list --connector X`` shows can also be scanned. This
         mirrors ``info()`` so list/scan/info agree across peers.
      4. Connector plugin by name (openclaw CLI or filesystem)
    """
    if _looks_like_explicit_path(name_or_path) and (
        os.path.isdir(name_or_path)
        or (
            connector_paths.normalize(connector) in {"amp", "opencode"}
            and os.path.isfile(name_or_path)
            and name_or_path.casefold().endswith(
                (".ts",)
                if connector_paths.normalize(connector) == "amp"
                else (".js", ".ts")
            )
            and not is_link_or_reparse(name_or_path)
        )
    ):
        return name_or_path
    if _looks_like_explicit_path(name_or_path):
        return None

    try:
        managed = resolve_plugin_identity(plugin_dir, name_or_path)
    except PluginIdentityError as exc:
        raise click.ClickException(str(exc)) from exc
    if managed is not None:
        return managed.path

    for d in search_dirs or []:
        requested = name_or_path.casefold()
        try:
            discovered_entries = discover_plugin_directories(
                d,
                connector=connector,
                registry_cache=registry_cache,
            )
        except PluginIdentityError as exc:
            raise click.ClickException(str(exc)) from exc
        for discovered in discovered_entries:
            if requested in {discovered.id.casefold(), discovered.name.casefold()}:
                return discovered.path

    for lookup in dict.fromkeys([name_or_path, name_or_path.lower()]):
        info = _get_openclaw_plugin_info(lookup, connector)
        if info:
            root = info.get("rootDir") or info.get("source", "")
            if root:
                if os.path.isdir(root):
                    return root
                # source is a file — walk up to find the plugin root
                # (directory containing package.json or openclaw.plugin.json)
                check = os.path.dirname(root)
                while check and check != os.path.dirname(check):
                    if any(os.path.isfile(os.path.join(check, m)) for m in ("package.json", "openclaw.plugin.json")):
                        return check
                    check = os.path.dirname(check)
            break

    return None


def _get_openclaw_plugin_info(name: str, connector: str = "") -> dict | None:
    """Get plugin info — uses openclaw CLI for OpenClaw, filesystem for others."""
    if connector in ("", "openclaw"):
        try:
            from defenseclaw.config import openclaw_bin
            proc = subprocess.run(
                [openclaw_bin(), "plugins", "info", name, "--json"],
                capture_output=True,
                text=True,
                timeout=15,
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

    return None


def _resolve_openclaw_plugin_id(name: str, connector: str = "") -> str:
    """Resolve a user-provided plugin name to the actual plugin ID.

    Handles formats like ``@openclaw/xai-plugin`` -> ``xai``,
    ``xai-plugin`` -> ``xai``, or returns the name unchanged if already valid.
    """
    bare = name
    if "/" in bare:
        bare = bare.rsplit("/", 1)[-1]

    candidates = [bare]
    for suffix in ("-plugin", "-provider"):
        if bare.endswith(suffix):
            candidates.append(bare[: -len(suffix)])

    plugins = _list_openclaw_plugins(connector)
    ids = {p.get("id", "") for p in plugins}
    names_to_id = {p.get("name", ""): p.get("id", "") for p in plugins}

    for c in candidates:
        if c in ids:
            return c
        if c in names_to_id:
            return names_to_id[c]

    return bare


def _plugin_runtime_candidates(name: str, connector: str = "") -> list[str]:
    bare = os.path.basename(name)
    candidates: list[str] = []
    for candidate in (bare, _resolve_openclaw_plugin_id(name, connector)):
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
    return [entry for entry, _path in plugin_directory_entries(plugin_dir)]


# _HOST_PLUGIN_MANIFEST_FILES — plan C6 / matrix #3. Each host agent
# declares a plugin via one of these manifest filenames inside the
# plugin directory. We try each in order; the first hit wins. Keep
# this list narrow — adding a globbed extension here invites both
# false positives (treating a config file as a plugin) and DoS
# (large directory walks during ``plugin list``).
_HOST_PLUGIN_MANIFEST_FILES = (
    os.path.join(".codex-plugin", "plugin.json"),
    "plugin.json",
    "plugin.yaml",
    "plugin.yml",
    "package.json",
    "manifest.json",
)


def _read_host_plugin_manifest(plugin_path: str) -> dict[str, Any] | None:
    """Try each known manifest filename inside *plugin_path*.

    Returns a dict with at least ``id`` populated, or None if no
    manifest exists. We never raise on a malformed manifest — a
    broken plugin should not break ``defenseclaw plugin list`` for
    the rest of the host's plugins.
    """
    for fname in _HOST_PLUGIN_MANIFEST_FILES:
        manifest_path = os.path.join(plugin_path, fname)
        if not os.path.isfile(manifest_path):
            continue
        try:
            with open(manifest_path, encoding="utf-8") as fh:
                if fname.endswith((".yaml", ".yml")):
                    import yaml as _yaml

                    raw = _yaml.safe_load(fh) or {}
                else:
                    raw = json.load(fh)
        except (OSError, ValueError):
            continue
        if not isinstance(raw, dict):
            continue
        return raw
    return None


def _scan_plugin_dir(
    host_dir: str,
    connector: str,
    *,
    registry_cache: PluginRegistryCache | None = None,
    workspace_dir: str = "",
) -> list[dict[str, Any]]:
    """Discover *host_dir* and emit one dict per installed plugin.

    Ordinary host-agent roots remain one-level and non-recursive so nested
    dependencies cannot become phantom plugins. Connector-specific discovery
    owns exact registry/cache layouts, including Claude marketplace versions
    and manifest-bearing skills-directory plugins.
    """
    out: list[dict[str, Any]] = []
    for discovered in discover_plugin_directories(
        host_dir,
        connector=connector,
        registry_cache=registry_cache,
        workspace_dir=workspace_dir,
    ):
        entry = discovered.id
        plugin_path = discovered.path
        manifest = _read_host_plugin_manifest(plugin_path) or {}
        plugin_id = manifest.get("id") or manifest.get("name") or entry
        plugin_name = manifest.get("name") or discovered.name or plugin_id
        row = {
            "id": str(plugin_id),
            "name": str(plugin_name),
            "description": str(manifest.get("description") or discovered.description),
            "version": str(manifest.get("version") or discovered.version),
            "origin": str(manifest.get("origin") or discovered.origin or "host"),
            "enabled": (discovered.enabled if discovered.cached else bool(manifest.get("enabled", True))),
            # Provenance label per plan C6 — the merged list MUST
            # disambiguate "managed by DefenseClaw" from "owned by the
            # host agent" so policy hooks (block/quarantine) only
            # touch the right side.
            "source": f"host:{connector}",
            "host_path": plugin_path,
        }
        if discovered.manifest:
            row["manifest"] = discovered.manifest
        if discovered.registry:
            row["registry"] = discovered.registry
        if discovered.cached:
            row["cached"] = True
            row["activation_verified"] = discovered.activation_verified
        if discovered.scope:
            row["scope"] = discovered.scope
        if discovered.project_path:
            row["project_path"] = discovered.project_path
        if discovered.registry_source:
            row["registry_source"] = discovered.registry_source
        if discovered.logical_id and discovered.logical_id != discovered.id:
            row["logical_id"] = discovered.logical_id
        out.append(row)
    return out


def _hermes_plugin_off_id(plugin_name: str) -> str:
    """Return the Hermes plugin id when Hermes itself has it off, else ''."""
    try:
        from defenseclaw.inventory.claw_inventory import _enumerate_hermes_plugins

        rows = _enumerate_hermes_plugins()
    except Exception:
        return ""
    for row in rows:
        plugin_id = str(row.get("id") or "")
        if plugin_name in (plugin_id, str(row.get("name") or "")):
            return "" if row.get("enabled") else plugin_id
    return ""


def _echo_claudecode_install_note(source_path: str, plugin_name: str, *, only_claudecode: bool = True) -> None:
    """Say that Claude Code will not load a copied plugin (GAP-2084).

    Claude Code loads only plugins it installed from a marketplace (listed in
    installed_plugins.json), so the copy in its plugin cache is scanned but
    neither loaded nor shown by plugin list.
    """
    click.secho(
        "  Claude Code loads only plugins installed from a marketplace, so it will not load "
        "this copy and plugin list will not show it.",
        fg="yellow",
    )
    if not os.path.isfile(os.path.join(source_path, ".claude-plugin", "plugin.json")):
        click.echo("  This folder is not a Claude Code plugin: it has no .claude-plugin/plugin.json.")
    click.echo(
        "  To use a Claude Code plugin, run /plugin marketplace add <marketplace folder or repo>, "
        "then /plugin install <name>@<marketplace> in Claude Code."
    )
    # A bare remove deletes every connector's copy (GAP-2152).
    scope = " --connector claudecode" if only_claudecode else ""
    click.echo(f"  Remove this copy: defenseclaw plugin remove {plugin_name}{scope}")


def _echo_hermes_activation_note(plugin_name: str) -> None:
    """Explain Hermes' own opt-in next to DefenseClaw's runtime state (GAP-1878)."""
    plugin_id = _hermes_plugin_off_id(plugin_name)
    if plugin_id:
        click.echo(
            f"  Hermes keeps {plugin_id!r} off until you enable it there, so plugin list shows "
            f"it disabled. DefenseClaw does not change that setting; run: hermes plugins enable {plugin_id}"
        )


def _list_hermes_plugins() -> list[dict[str, Any]]:
    """Hermes plugins with the activation state Hermes itself applies.

    Uses the same enumeration as the AIBOM, so ``plugin list`` and
    ``aibom scan`` count the same plugins with the same enabled state
    instead of listing the category folders under hermes-agent/plugins.
    """
    from defenseclaw.inventory.claw_inventory import _enumerate_hermes_plugins

    rows: list[dict[str, Any]] = []
    for row in _enumerate_hermes_plugins():
        source = str(row.get("source") or "")
        is_path = row.get("source_kind") != "entrypoint" and os.path.isabs(source)
        rows.append(
            {
                "id": str(row["id"]),
                "name": str(row.get("name") or row["id"]),
                "description": str(row.get("description") or ""),
                "version": str(row.get("version") or ""),
                "origin": str(row.get("source_kind") or "host"),
                "enabled": bool(row.get("enabled")),
                "source": "host:hermes",
                "host_path": source if is_path else "",
            }
        )
    return rows


def _list_host_plugins(
    connector: str,
    cfg,
    *,
    registry_cache: PluginRegistryCache | None = None,
) -> list[dict[str, Any]]:
    """Enumerate host-agent-owned plugins for the requested connector.

    Plan C6: matrix §5 marks zeptoclaw / claudecode / codex as ⚠️ for
    ``plugin list`` because the host's own plugin directory was
    silently skipped. This pulls each entry through cfg.plugin_dirs(),
    which is already connector-aware (see config.plugin_dirs() →
    connector_paths.plugin_dirs()), and tags each result with
    ``source: "host:<connector>"`` so the merged list keeps
    provenance even when the host directory contains plugins with
    the same id as a DefenseClaw-managed one.
    """
    name = (connector or "").lower()
    if name in ("", "openclaw"):
        # OpenClaw has its own enumeration path via the openclaw
        # binary (see _list_openclaw_plugins). Don't double-count.
        return []
    if name == "copilot":
        workspace_resolver = getattr(cfg, "connector_workspace_dir", None)
        workspace_dir = workspace_resolver() if callable(workspace_resolver) else ""
        return _list_copilot_plugins(
            data_dir=getattr(cfg, "data_dir", None),
            workspace_dir=workspace_dir,
        )
    if name == "hermes":
        hermes_rows = _list_hermes_plugins()
        if hermes_rows:
            return hermes_rows
    workspace_resolver = getattr(cfg, "connector_workspace_dir", None)
    workspace_dir = workspace_resolver() if callable(workspace_resolver) else ""
    try:
        if name == "opencode":
            claw = getattr(cfg, "claw", None)
            dirs = connector_paths.plugin_inventory_dirs(
                connector,
                openclaw_home=getattr(claw, "home_dir", None),
                workspace_dir=workspace_dir,
            )
        else:
            dirs = cfg.plugin_dirs(connector)
    except Exception:
        return []
    out: list[dict[str, Any]] = []
    claimed = PluginInstallClaims()
    for d in dirs:
        for entry in _scan_plugin_dir(
            d,
            name,
            registry_cache=registry_cache,
            workspace_dir=workspace_dir,
        ):
            if not claimed.add(
                str(entry["id"]),
                str(entry.get("host_path") or ""),
                d,
                registry_source=str(entry.get("registry_source") or ""),
                scope=str(entry.get("scope") or ""),
                project_path=str(entry.get("project_path") or ""),
            ):
                continue
            out.append(entry)
    if name == "opencode":
        from defenseclaw.inventory.claw_inventory import _opencode_config_plugin_rows

        seen_ids = {str(entry["id"]).casefold() for entry in out}
        for configured in _opencode_config_plugin_rows(workspace_dir):
            pid = str(configured["id"])
            identity = pid.casefold()
            if identity in seen_ids:
                continue
            seen_ids.add(identity)
            out.append(
                {
                    "id": pid,
                    "name": str(configured["name"]),
                    "description": "",
                    "version": "",
                    "origin": str(configured["origin"]),
                    "enabled": True,
                    "source": "host:opencode:config",
                    "configuration_only": True,
                }
            )
    return out


def _trusted_copilot_binary(
    data_dir: str | os.PathLike[str] | None = None,
) -> str:
    """Resolve Copilot through the passive inventory's executable trust gate."""
    from defenseclaw.inventory.agent_discovery import (
        _SPECS,
        _binary_candidates_for_agent,
        _is_trusted_binary_path,
    )

    spec = _SPECS["copilot"]
    for candidate in _binary_candidates_for_agent("copilot", spec):
        if _is_trusted_binary_path(candidate, data_dir=data_dir):
            return candidate
    return ""


def _untrusted_copilot_binary() -> str:
    """Return the first Copilot on PATH that the trust gate refused, if any."""
    from defenseclaw.inventory.agent_discovery import _SPECS, _binary_candidates_for_agent

    return next(iter(_binary_candidates_for_agent("copilot", _SPECS["copilot"])), "")


# GAP-2415: Copilot CLI 1.0.90 rejects the older ``plugins list --kind
# plugin`` form; ``plugin list --json`` is the supported read-only command.
# The older form stays as a fallback for earlier Copilot CLIs.
_COPILOT_PLUGIN_LIST_ARGVS: tuple[tuple[str, ...], ...] = (
    ("plugin", "list", "--json"),
    ("plugins", "list", "--kind", "plugin", "--json"),
)

# Why a host plugin lister could not list plugins, by connector, so
# ``plugin list`` says so instead of claiming there are none (GAP-2415).
_HOST_PLUGIN_LIST_ERRORS: dict[str, str] = {}


def _copilot_list_failure(argv: tuple[str, ...], proc: Any) -> str:
    detail = ""
    for stream in (getattr(proc, "stderr", ""), getattr(proc, "stdout", "")):
        lines = [ln.strip() for ln in str(stream or "").splitlines() if ln.strip()]
        if lines:
            detail = lines[0][:200]
            break
    msg = f"`copilot {' '.join(argv)}` exited {proc.returncode}"
    return f"{msg}: {detail}" if detail else msg


def _list_copilot_plugins(
    *,
    data_dir: str | os.PathLike[str] | None = None,
    workspace_dir: str | os.PathLike[str] | None = None,
) -> list[dict[str, Any]]:
    """List declared plugins in the exact trusted lifecycle context.

    Copilot runs in the pinned connector workspace, or in the user's home
    directory when none is pinned (the default config; GAP-2415). Every
    gate that stops the listing records why in ``_HOST_PLUGIN_LIST_ERRORS``
    so ``plugin list`` never reports a skipped listing as "no plugins".
    """

    _HOST_PLUGIN_LIST_ERRORS.pop("copilot", None)

    def _fail(reason: str) -> list[dict[str, Any]]:
        _HOST_PLUGIN_LIST_ERRORS["copilot"] = reason
        return []

    workspace = str(workspace_dir or "")
    if not workspace:
        workspace = os.path.realpath(os.path.expanduser("~"))
    if (
        workspace.strip() != workspace
        or not os.path.isabs(workspace)
        or os.path.normpath(workspace) != workspace
    ):
        return _fail(f"workspace {workspace!r} is not a normalized absolute path (claw.workspace_dir)")
    try:
        connector_paths.reject_reparse_path(workspace)
        before = os.stat(workspace, follow_symlinks=False)
        if not os.path.isdir(workspace):
            return _fail(f"workspace {workspace} is not a directory (claw.workspace_dir)")
        if data_dir:
            data_real = os.path.realpath(os.path.abspath(str(data_dir)))
            workspace_real = os.path.realpath(workspace)
            if os.path.normcase(os.path.commonpath((workspace_real, data_real))) == os.path.normcase(
                data_real
            ):
                return _fail(f"workspace {workspace} is inside the DefenseClaw data directory")
    except (OSError, ValueError) as exc:
        return _fail(f"workspace {workspace} is not usable: {exc}")

    copilot = _trusted_copilot_binary(data_dir)
    if not copilot:
        found = _untrusted_copilot_binary()
        if found:
            return _fail(
                f"copilot at {found} is not in a trusted location; add its install "
                "prefix to ai_discovery.trusted_binary_prefixes"
            )
        return []
    try:
        bound_home = connector_paths.copilot_home()
    except ValueError as exc:
        return _fail(f"COPILOT_HOME is not usable: {exc}")
    env = os.environ.copy()
    env["COPILOT_HOME"] = bound_home
    proc = None
    failure = ""
    for argv in _COPILOT_PLUGIN_LIST_ARGVS:
        try:
            proc = subprocess.run(
                [copilot, *argv],
                capture_output=True,
                text=True,
                timeout=15,
                cwd=workspace,
                env=env,
            )
        except subprocess.TimeoutExpired:
            failure = failure or f"`copilot {' '.join(argv)}` timed out after 15s"
            proc = None
            break
        except OSError as exc:
            failure = failure or f"could not run copilot: {exc}"
            proc = None
            break
        if proc.returncode == 0:
            break
        failure = failure or _copilot_list_failure(argv, proc)
        proc = None
    if proc is None:
        _HOST_PLUGIN_LIST_ERRORS["copilot"] = failure
        return []
    try:
        after = os.stat(workspace, follow_symlinks=False)
    except OSError as exc:
        return _fail(f"workspace {workspace} is not usable: {exc}")
    def _identity(st: os.stat_result) -> tuple[int, ...]:
        # Home (the unpinned fallback) gets routine entry churn from other
        # programs, so only its identity is compared there.
        if workspace_dir:
            return (st.st_dev, st.st_ino, st.st_mtime_ns, st.st_ctime_ns)
        return (st.st_dev, st.st_ino)

    if _identity(before) != _identity(after):
        return _fail(f"workspace {workspace} changed while copilot was listing plugins")
    try:
        if (proc.stdout or "").strip():
            json.loads(proc.stdout)
    except json.JSONDecodeError:
        _HOST_PLUGIN_LIST_ERRORS["copilot"] = "copilot printed output that is not JSON"
        return []
    plugins = _parse_plugin_list_json(proc.stdout)
    out: list[dict[str, Any]] = []
    for p in plugins:
        pid = str(p.get("id") or "").strip()
        if not pid:
            # Copilot CLI 1.0.90 rows carry name + marketplace; Copilot
            # addresses an installed plugin as <name>@<marketplace>.
            base = str(p.get("name") or "").strip()
            market = str(p.get("marketplace") or "").strip()
            pid = f"{base}@{market}" if base and market else base
        if not pid:
            continue
        out.append(
            {
                "id": pid,
                "name": str(p.get("name") or pid),
                "version": str(p.get("version") or ""),
                "enabled": p.get("enabled", True),
                "activation_verified": False,
                "activation_state": "semantic-activation-unverified",
                "source": "host:copilot",
                "path": "",
            }
        )
    return out


def _parse_plugin_list_json(text: str) -> list[dict[str, Any]]:
    text = (text or "").strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    if isinstance(data, dict):
        plugins = data.get("plugins", data.get("items", []))
    else:
        plugins = data
    if not isinstance(plugins, list):
        return []
    return [p for p in plugins if isinstance(p, dict)]


def _list_openclaw_plugins(connector: str = "") -> list[dict]:
    """Query plugins from the requested connector.

    For OpenClaw, shells out to ``openclaw plugins list --json``.
    For other connectors, returns an empty list (plugins are discovered
    from the filesystem via ``cfg.plugin_dirs()`` in ``_merge_all_plugins``).
    """
    if connector not in ("", "openclaw"):
        return []

    try:
        from defenseclaw.config import openclaw_bin
        proc = subprocess.run(
            [openclaw_bin(), "plugins", "list", "--json"],
            capture_output=True,
            text=True,
            timeout=15,
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


def _claude_known_marketplaces(plugins_root: str) -> set[str]:
    """Lower-cased marketplace names from Claude Code's known_marketplaces.json."""
    try:
        with open(os.path.join(plugins_root, "known_marketplaces.json"), encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return set()
    return {str(key).casefold() for key in data} if isinstance(data, dict) else set()


def _install_root_copies(
    app: AppContext,
    name: str,
    connectors: list[str],
    known_paths: list[str],
) -> list[tuple[str, str]]:
    """Copies ``plugin install`` put directly in a connector's install root.

    GAP-2152: install copies the folder to ``<root>/<name>`` (Claude Code
    and Codex: their plugin cache) and refuses a reinstall while it is
    there, but discovery reads only the marketplace layout, so remove never
    found it. Marketplace folders (named in known_marketplaces.json or
    holding a discovered plugin) are skipped.
    """
    known = [os.path.realpath(path) for path in known_paths]
    found: list[tuple[str, str]] = []
    for connector in connectors:
        # Only the root install writes to (see _plugin_install_targets).
        try:
            roots = [d for d in app.cfg.plugin_dirs(connector) if d][:1]
        except Exception:  # noqa: BLE001 — no install root, nothing to find.
            roots = []
        for root in roots:
            try:
                identities = enumerate_physical_identities(root)
                discovered = discover_plugin_directories(
                    root,
                    connector=connector,
                    workspace_dir=app.cfg.connector_workspace_dir(),
                )
            except (OSError, PluginIdentityError):
                continue
            busy = known + [os.path.realpath(entry.path) for entry in discovered]
            marketplaces = _claude_known_marketplaces(os.path.dirname(os.path.normpath(root)))
            key = filesystem_identity_key(name, root)
            for item in identities:
                if filesystem_identity_key(item.plugin_id, root) != key:
                    continue
                if os.path.basename(item.path).casefold() in marketplaces:
                    continue
                real = os.path.realpath(item.path)
                if any(path == real or path.startswith(real + os.sep) for path in busy):
                    continue
                found.append((connector, item.path))
                known.append(real)
    return found


@plugin.command()
@click.argument("name")
@click.option(
    "--connector",
    "connector_flag",
    default="",
    help=(
        "Remove from one configured connector's plugin dirs. "
        "Default: remove matching copies across every configured connector."
    ),
)
@pass_ctx
def remove(app: AppContext, name: str, connector_flag: str) -> None:
    """Remove an installed plugin.

    Bare removes matching copies across every configured connector; ``--connector
    <name>`` narrows removal to that peer's plugin dirs. The legacy
    DefenseClaw-managed plugin dir is removed only for bare operations (or a
    single-connector install), because it is shared rather than peer-owned.
    """
    from defenseclaw.commands import resolve_list_connectors

    try:
        safe_name = (
            canonical_plugin_id(name)[0]
            if _looks_like_explicit_path(name) and os.path.isdir(name)
            else validate_plugin_id(os.path.basename(name))
        )
    except PluginIdentityError:
        click.echo(f"Invalid plugin name: {name}", err=True)
        raise SystemExit(1)

    connectors = resolve_list_connectors(app, connector_flag)
    scoped = bool(connector_flag and connector_flag.strip())
    _refuse_managed_bridge_action(
        app,
        name,
        connectors[0] if scoped and connectors else "",
        action="remove",
    )

    removed: list[tuple[str, str]] = []
    if scoped:
        candidates = _plugin_match_dir_scopes(app, safe_name, connectors[0])
    else:
        candidates = _plugin_match_dir_scopes(app, safe_name)
    candidates = [
        *[(match.connector, match.path) for match in candidates],
        *_install_root_copies(
            app,
            safe_name,
            [connectors[0]] if scoped and connectors else _active_plugin_connectors(app),
            [match.path for match in candidates],
        ),
    ]
    for connector, candidate in candidates:
        if is_link_or_reparse(candidate):
            raise click.ClickException(f"refusing to remove linked plugin path: {candidate}")
        # Amp and OpenCode direct plugins are single source files.
        if os.path.isfile(candidate):
            os.remove(candidate)
        else:
            shutil.rmtree(candidate)
        removed.append((connector, candidate))

    if not removed:
        click.echo(f"error: plugin not found: {safe_name}", err=True)
        raise SystemExit(1)

    for connector, path in removed:
        suffix = f" (connector={connector})" if connector else ""
        click.echo(f"[plugin] {safe_name!r} removed from {path}{suffix}")

    if app.logger:
        connector_detail = f"connector={connectors[0]}" if scoped and connectors else "connector=all"
        saved_change_audit(app.logger).log_action(
            "plugin-remove",
            safe_name,
            connector_detail,
        )

    from defenseclaw.commands import hint

    # Like install: only the OpenClaw gateway loads plugins at start; a hook
    # connector stops loading the plugin in its own next session (GAP-1969).
    hints = ["List plugins:      defenseclaw plugin list"]
    if any(_normalize_runtime_connector(connector) == "openclaw" for connector, _path in removed):
        hints.append("Restart gateway:   defenseclaw-gateway restart")
    hint(*hints)


# ---------------------------------------------------------------------------
# plugin block / allow / disable / enable / quarantine / restore / remove
#
# P-A: these accept ``--connector`` to scope policy. Bare verb writes an
# unscoped entry that applies across connectors; ``--connector <name>``
# narrows the entry to one peer. The connector dimension lives in the audit
# store's per-connector column (the SK-4/N2 foundation) via the
# PolicyEngine ``*_for_connector`` methods; reads resolve most-specific-wins
# (connector entry, then unscoped). Runtime honoring is at the admission gate
# (enforce/admission.py threads the connector into its block/allow/quarantine
# check), not CLI-only. Mirrors the ``mcp`` N2 commands.
# ---------------------------------------------------------------------------

_CONNECTOR_SCOPE_HELP = (
    "Scope to one connector. Default: create an unscoped policy entry "
    "that applies across connectors. "
    "Pass --connector <name> to narrow to that peer."
)
_CONNECTOR_RUNTIME_SCOPE_HELP = "Scope to one connector. Default: matching plugin copies across configured connectors."


def _resolve_connector_scope(app: AppContext, connector_flag: str) -> str:
    """Validate a connector-scoped plugin policy flag.

    Bare policy commands intentionally write an unscoped row. A supplied
    connector must be configured, so typos cannot create inert policy state.
    """
    if not connector_flag:
        return ""
    from defenseclaw.commands import resolve_list_connector

    return resolve_list_connector(app, connector_flag)


def _hermes_plugin_id_for_path(scan_dir: str) -> str:
    """The id ``plugin list --connector hermes`` shows for a plugin folder, or ""."""
    try:
        rows = _list_hermes_plugins()
    except Exception:  # noqa: BLE001 - fall back to the manifest name.
        return ""
    real = os.path.realpath(scan_dir)
    for row in rows:
        host = row.get("host_path") or ""
        if host and os.path.realpath(host) == real:
            return str(row["id"])
    return ""


def _hermes_listed_plugin(
    app: AppContext,
    name: str,
    connector: str,
    *,
    require_active: bool = False,
) -> tuple[str, str] | None:
    """Map a Hermes plugin, as ``plugin list`` shows it, to ``(id, directory)``.

    Hermes nests most plugins in category folders, so the list shows ids like
    ``web/ddgs`` or ``cron_providers/chronos``. With ``--connector hermes``
    the listed id, the manifest name, the last id segment or the folder path
    (``platforms/a2a``) is accepted
    (refused when it names more than one plugin, like ``xai``). Without a
    connector only a nested listed id is mapped, so bare names keep their
    meaning for the other connectors. Returns ``None`` when nothing matches.
    """
    wanted = (name or "").strip().strip("/\\")
    if not wanted:
        return None
    if connector:
        if connector_paths.normalize(connector) != "hermes":
            return None
        if require_active and "hermes" not in _active_plugin_connectors(app):
            return None
        nested_only = False
    else:
        if "/" not in wanted or "hermes" not in _active_plugin_connectors(app):
            return None
        nested_only = True
    try:
        rows = _list_hermes_plugins()
    except Exception:  # noqa: BLE001 - fall back to the generic resolvers.
        return None
    for row in rows:
        if row["id"] == wanted:
            return row["id"], row.get("host_path") or ""
    if nested_only:
        return None
    # The folder path under plugins/ (``platforms/a2a``) names the plugin too.
    suffix = os.sep + os.path.normpath(wanted)
    hits = {
        row["id"]: row.get("host_path") or ""
        for row in rows
        if wanted in (row.get("name"), row["id"].rsplit("/", 1)[-1])
        or ("/" in wanted and os.path.normpath(row.get("host_path") or "").endswith(suffix))
    }
    if len(hits) > 1:
        raise click.ClickException(
            f"{wanted!r} matches several Hermes plugins: {', '.join(sorted(hits))}. "
            "Use the ID that 'defenseclaw plugin list --connector hermes' shows."
        )
    if hits:
        plugin_id, path = next(iter(hits.items()))
        return plugin_id, path
    return None


def _policy_plugin_target(app: AppContext, name: str, connector: str) -> tuple[str, str | None]:
    """Return the policy key and directory for a block/allow/unblock target.

    Hermes plugins are keyed by the id ``plugin list`` shows, so the row
    reflects the action; everything else keeps the validated plugin id.
    """
    hermes = _hermes_listed_plugin(app, name, connector)
    if hermes is not None:
        plugin_id, path = hermes
        try:
            for segment in plugin_id.split("/"):
                validate_plugin_id(segment)
        except PluginIdentityError as exc:
            raise click.ClickException(f"invalid plugin identity: {exc}") from exc
        return plugin_id, path or None
    return _validated_plugin_argument(name), None


def _validated_plugin_argument(name: str) -> str:
    """Validate lifecycle identity without laundering traversal via basename."""
    try:
        if "/" in name and not os.path.isabs(name):
            name = _resolve_openclaw_plugin_id(name, "openclaw")
        return validate_plugin_id(name)
    except PluginIdentityError as exc:
        raise click.ClickException(f"invalid plugin identity: {exc}") from exc


def _resolve_plugin_quarantine_restore_scopes(
    app: AppContext,
    pe: Any,
    plugin_name: str,
    connector_flag: str,
) -> list[tuple[str, Any | None]]:
    """Resolve which quarantine rows a plugin restore command should use."""
    if connector_flag:
        connector = _resolve_connector_scope(app, connector_flag)
        return [(connector, pe.get_action("plugin", plugin_name, connector))]

    matches: list[tuple[str, Any]] = []
    global_entry = pe.get_action("plugin", plugin_name)
    if global_entry is not None and global_entry.actions.file == "quarantine":
        matches.append(("", global_entry))

    active_order = {c: i for i, c in enumerate(_active_plugin_connectors(app))}
    seen_connectors: set[str] = set()
    for entry in pe.list_by_type("plugin"):
        c = entry.connector
        if not c or c in seen_connectors:
            continue
        seen_connectors.add(c)
        scoped_entry = pe.get_action("plugin", plugin_name, c)
        if scoped_entry is not None and scoped_entry.actions.file == "quarantine":
            matches.append((c, scoped_entry))

    if matches:
        return sorted(matches, key=lambda item: active_order.get(item[0], len(active_order)))
    return [("", global_entry)]


def _quarantined_plugin_alias(pe: Any, name: str, connector: str) -> str:
    """Map a listed name (folder or nested id) to its quarantine key.

    GAP-2163: quarantine is keyed by manifest ID, but Hermes lists the folder
    (``photon`` for ``platforms/photon`` with manifest ``photon-platform``).
    Returns the key only when exactly one quarantined plugin matches.
    """
    wanted = os.path.normpath((name or "").strip().strip("/\\"))
    if not wanted or wanted in (".", ".."):
        return ""
    hits = {
        entry.target_name
        for entry in pe.list_by_type("plugin")
        if entry.actions.file == "quarantine"
        and entry.source_path
        and (not connector or entry.connector == connector)
        and (os.sep + os.path.normpath(entry.source_path)).endswith(os.sep + wanted)
    }
    return next(iter(hits)) if len(hits) == 1 else ""


def _hermes_listed_id(path: str, connector: str) -> str:
    """The id 'plugin list' shows for a Hermes plugin folder, or "" (GAP-2308)."""
    if not path or not connector or connector_paths.normalize(connector) != "hermes":
        return ""
    from defenseclaw.inventory.claw_inventory import hermes_listed_identity

    identity = hermes_listed_identity(path)
    return identity[0] if identity else ""


def _plugin_label(listed: str, key: str) -> str:
    """``'photon' (photon-platform)`` when the listed id and quarantine key differ."""
    return f"{listed!r} ({key})" if listed and listed != key else repr(key)


def _plugin_policy_fanout_connectors(
    app: AppContext,
    pe: Any,
    plugin_name: str,
) -> list[str]:
    """Connectors where a bare plugin policy command should apply.

    The set includes installed matching connector copies plus any connector
    that already has scoped enforcement for the plugin, so bare allow/unblock
    can clean stale connector-scoped rows even after a copy was removed.
    """
    active_order = {
        _normalize_runtime_connector(connector): idx for idx, connector in enumerate(_active_plugin_connectors(app))
    }
    seen: set[str] = set()
    connectors: list[str] = []

    def add(connector: str) -> None:
        normalized = _normalize_runtime_connector(connector)
        if not normalized or normalized in seen:
            return
        seen.add(normalized)
        connectors.append(normalized)

    for connector, _path in _plugin_match_dir_scopes(app, plugin_name):
        add(connector)

    if pe is not None:
        for entry in pe.list_by_type("plugin"):
            if entry.target_name == plugin_name and entry.connector:
                add(entry.connector)

    return sorted(connectors, key=lambda c: active_order.get(c, len(active_order)))


def _plugin_has_connector_enforcement(
    app: AppContext,
    plugin_name: str,
    connector: str,
) -> bool:
    if app.store is None:
        return False
    return (
        asset_lists.has_entry(app.cfg, app.store, "plugin", plugin_name, connector, "block")
        or asset_lists.has_entry(app.cfg, app.store, "plugin", plugin_name, connector, "allow")
        or app.store.has_action("plugin", plugin_name, "file", "quarantine", connector)
        or app.store.has_action("plugin", plugin_name, "runtime", "disable", connector)
        or app.store.has_action("plugin", plugin_name, "runtime", "enable", connector)
    )


def _plugin_copies_disabled(app: AppContext, plugin_name: str, connector: str) -> bool:
    """True when every listed copy of *plugin_name* in scope is off (GAP-2313)."""
    states: list[bool] = []
    for c in [connector] if connector else _active_plugin_connectors(app):
        try:
            rows = _merge_all_plugins(app.cfg.plugin_dir, c, cfg=app.cfg)
        except Exception:  # noqa: BLE001 - keep the generic "still loads" note.
            return False
        actions_map = _build_plugin_actions_map(app.store, c, app.cfg)
        states.extend(
            _plugin_effectively_enabled(p, _row_action(p, actions_map))
            for p in rows
            if plugin_name in (p.get("id"), p.get("name"))
        )
    return bool(states) and not any(states)


@plugin.command()
@click.argument("name")
@click.option("--reason", default="", help="Reason for blocking")
@click.option("--connector", "connector_flag", default="", help=_CONNECTOR_SCOPE_HELP)
@pass_ctx
@asset_lists.refuse_on_managed_device("plugin", asset_lists.OP_BLOCK)
def block(app: AppContext, name: str, reason: str, connector_flag: str) -> None:
    """Add a plugin to the install block list.

    Blocked plugins are rejected by the admission gate before any scan.
    Does not affect already-installed plugins — use 'plugin disable' or
    'plugin quarantine' for that.

    Bare ``plugin block <name>`` creates an unscoped block entry;
    ``--connector <name>`` narrows the block to one peer.
    """
    from defenseclaw.enforce import PolicyEngine

    name = asset_lists.policy_rule_name("plugin", name)
    connector = _resolve_connector_scope(app, connector_flag)
    _refuse_managed_bridge_action(
        app,
        name,
        connector,
        action="block",
    )
    plugin_name, hermes_path = _policy_plugin_target(app, name, connector)
    pe = PolicyEngine(app.store, app.cfg)

    if not reason:
        reason = "manual block via CLI"

    if connector:
        if pe.is_blocked_for_connector("plugin", plugin_name, connector):
            if app.store and asset_lists.has_entry(app.cfg, app.store, "plugin", plugin_name, connector, "block"):
                click.echo(f"Already blocked for {connector}: {plugin_name}")
            else:
                click.echo(f"Already blocked by unscoped policy (covers {connector}): {plugin_name}")
            return
        pe.block_for_connector("plugin", plugin_name, connector, reason)
        plugin_path = hermes_path or _resolve_plugin_path(app, plugin_name, connector)
        if plugin_path:
            pe.set_source_path("plugin", plugin_name, plugin_path, connector)
        click.secho(f"[plugin] Blocked {plugin_name!r} ({connector}).", fg="red")
    else:
        pe.block("plugin", plugin_name, reason)
        plugin_path = hermes_path or _resolve_plugin_path(app, plugin_name)
        if plugin_path:
            pe.set_source_path("plugin", plugin_name, plugin_path)
        click.secho(f"[plugin] Blocked {plugin_name!r} (every connector).", fg="red")

    installed = bool(plugin_path or _plugin_match_dir_scopes(app, plugin_name, connector))
    if installed and _plugin_copies_disabled(app, plugin_name, connector):
        # GAP-2313: a disabled copy does not load; don't tell the user it does.
        click.secho(
            "  The installed copy is disabled, so it does not load; new installs are refused.",
            fg="yellow",
        )
    elif installed:
        flag = f" --connector {connector}" if connector else ""
        click.secho(
            "  The installed copy still loads: block only refuses new installs.\n"
            f"  To stop it: defenseclaw plugin quarantine {plugin_name}{flag}",
            fg="yellow",
        )

    if app.logger:
        saved_change_audit(app.logger).log_action(
            "plugin-block",
            plugin_name,
            f"reason={reason} connector={connector}",
        )


# ---------------------------------------------------------------------------
# plugin unblock
# ---------------------------------------------------------------------------

# GAP-2049: unblock removes DefenseClaw's own allow/block/quarantine/disable
# entries; the agent's own enabled/disabled setting is left as it was.
_PLUGIN_UNBLOCK_NOTE = "  DefenseClaw no longer overrides it; it keeps the on/off setting from the agent's own config."


def _plugin_only_allow_entry(app: AppContext, pe, plugin_name: str, connector: str) -> bool:
    """True when the only state at this exact scope is an allow entry."""
    if app.store is None:
        return False
    if connector:
        restrictive = (
            asset_lists.has_entry(app.cfg, app.store, "plugin", plugin_name, connector, "block")
            or app.store.has_action("plugin", plugin_name, "file", "quarantine", connector)
            or app.store.has_action("plugin", plugin_name, "runtime", "disable", connector)
        )
        allowed = asset_lists.has_entry(app.cfg, app.store, "plugin", plugin_name, connector, "allow")
    else:
        restrictive = (
            pe.is_blocked("plugin", plugin_name)
            or pe.is_quarantined("plugin", plugin_name)
            or app.store.has_action("plugin", plugin_name, "runtime", "disable")
        )
        allowed = pe.is_allowed("plugin", plugin_name)
    return allowed and not restrictive


def _plugin_unblock_line(plugin_name: str, connector: str, only_allow: bool) -> str:
    # GAP-2273: same wording as mcp unblock (GAP-2225).
    scope = f" ({connector})" if connector else " (every connector)"
    if only_allow:
        return f"[plugin] Removed the allow entry for {plugin_name!r}{scope}."
    return f"[plugin] Unblocked {plugin_name!r}{scope}."


def _plugin_unblock_followup(plugin_name: str, connector: str, all_only_allow: bool) -> None:
    import shlex

    if not all_only_allow:
        click.echo(_PLUGIN_UNBLOCK_NOTE)
        return
    cmd = f"defenseclaw plugin scan {shlex.quote(plugin_name)}"
    if connector:
        cmd += f" --connector {connector}"
    click.echo("  Its scan verdict applies again.")
    click.echo(f"  To scan it now, run: {cmd}")


@plugin.command()
@click.argument("name")
@click.option(
    "--connector",
    "connector_flag",
    default="",
    help=(
        "Scope to one connector. Default: clear matching connector copies and unscoped state. "
        "Pass --connector <name> to clear only that peer's per-connector state; "
        "an unscoped block stays in force."
    ),
)
@pass_ctx
@asset_lists.refuse_on_managed_device("plugin", asset_lists.OP_UNBLOCK)
def unblock(app: AppContext, name: str, connector_flag: str) -> None:
    """Remove plugin enforcement state without adding an allow entry."""
    from defenseclaw.enforce import PolicyEngine

    connector = _resolve_connector_scope(app, connector_flag)
    plugin_name, _hermes_path = _policy_plugin_target(app, name, connector)
    pe = PolicyEngine(app.store, app.cfg)
    if connector:
        has_state = bool(app.store) and (
            asset_lists.has_entry(app.cfg, app.store, "plugin", plugin_name, connector, "block")
            or asset_lists.has_entry(app.cfg, app.store, "plugin", plugin_name, connector, "allow")
            or app.store.has_action("plugin", plugin_name, "file", "quarantine", connector)
            or app.store.has_action("plugin", plugin_name, "runtime", "disable", connector)
        )
        if not has_state:
            click.echo(f"[plugin] {plugin_name!r} has no enforcement state to clear for {connector}")
            return
        only_allow = _plugin_only_allow_entry(app, pe, plugin_name, connector)
        pe.remove_action_for_connector("plugin", plugin_name, connector)
        click.secho(_plugin_unblock_line(plugin_name, connector, only_allow), fg="green")
        _plugin_unblock_followup(plugin_name, connector, only_allow)
        if app.logger:
            saved_change_audit(app.logger).log_action(
                "plugin-unblock",
                plugin_name,
                f"manual unblock via CLI connector={connector}",
            )
        return

    targets = _plugin_policy_fanout_connectors(app, pe, plugin_name)
    has_unscoped_state = bool(app.store) and (
        pe.is_blocked("plugin", plugin_name)
        or pe.is_allowed("plugin", plugin_name)
        or pe.is_quarantined("plugin", plugin_name)
        or app.store.has_action("plugin", plugin_name, "runtime", "disable")
        or app.store.has_action("plugin", plugin_name, "runtime", "enable")
    )
    has_scoped_state = any(
        _plugin_has_connector_enforcement(app, plugin_name, target_connector) for target_connector in targets
    )
    if targets and (has_unscoped_state or has_scoped_state):
        # GAP-2085: name only the scopes that held state, like skill unblock.
        owners = [
            target_connector
            for target_connector in targets
            if _plugin_has_connector_enforcement(app, plugin_name, target_connector)
        ]
        scopes = list(owners) + ([""] if has_unscoped_state else [])
        only_allow = {
            scope: _plugin_only_allow_entry(app, pe, plugin_name, scope) for scope in scopes
        }
        for target_connector in targets:
            pe.remove_action_for_connector("plugin", plugin_name, target_connector)
        if has_unscoped_state:
            pe.remove_action("plugin", plugin_name)
        for scope in scopes:
            click.secho(_plugin_unblock_line(plugin_name, scope, only_allow[scope]), fg="green")
        only_one = len(owners) == 1 and not has_unscoped_state
        _plugin_unblock_followup(
            plugin_name,
            owners[0] if only_one else "",
            bool(scopes) and all(only_allow.values()),
        )
        if app.logger:
            saved_change_audit(app.logger).log_action(
                "plugin-unblock",
                plugin_name,
                "manual unblock via CLI connector=all",
            )
        return

    has_state = bool(app.store) and (
        pe.is_blocked("plugin", plugin_name)
        or pe.is_allowed("plugin", plugin_name)
        or pe.is_quarantined("plugin", plugin_name)
        or app.store.has_action("plugin", plugin_name, "runtime", "disable")
    )
    if not has_state:
        click.echo(f"[plugin] {plugin_name!r} has no enforcement state to clear")
        return

    only_allow = _plugin_only_allow_entry(app, pe, plugin_name, "")
    pe.remove_action("plugin", plugin_name)
    click.secho(_plugin_unblock_line(plugin_name, "", only_allow), fg="green")
    _plugin_unblock_followup(plugin_name, "", only_allow)
    if app.logger:
        saved_change_audit(app.logger).log_action("plugin-unblock", plugin_name, "manual unblock via CLI")


# ---------------------------------------------------------------------------
# plugin allow
# ---------------------------------------------------------------------------


@plugin.command()
@click.argument("name")
@click.option("--reason", default="", help="Reason for allowing")
@click.option("--connector", "connector_flag", default="", help=_CONNECTOR_SCOPE_HELP)
@pass_ctx
@asset_lists.refuse_on_managed_device("plugin", asset_lists.OP_ALLOW)
def allow(app: AppContext, name: str, reason: str, connector_flag: str) -> None:
    """Add a plugin to the install allow list.

    Allow-listed plugins skip the scan gate during install.
    Adding a plugin also removes it from the block list.

    Bare ``plugin allow <name>`` allows matching configured connector copies;
    ``--connector <name>`` narrows the allow to one peer.
    """
    from defenseclaw.enforce import PolicyEngine

    name = asset_lists.policy_rule_name("plugin", name)
    # P-A connector-scoped allow: write the narrowed entry and clear residual
    # file/runtime state for that peer. The gateway runtime-enable dance below
    # is for the unscoped/OpenClaw runtime lane and stays on the bare path.
    connector_scope = _resolve_connector_scope(app, connector_flag)
    plugin_name, hermes_path = _policy_plugin_target(app, name, connector_scope)
    runtime_name = plugin_name
    pe = PolicyEngine(app.store, app.cfg)

    if not reason:
        reason = "manual allow via CLI"

    if connector_scope:
        if pe.is_allowed_for_connector("plugin", plugin_name, connector_scope):
            if app.store and asset_lists.has_entry(app.cfg, app.store, "plugin", plugin_name, connector_scope, "allow"):
                click.echo(f"Already allowed for {connector_scope}: {plugin_name}")
            else:
                click.echo(f"Already allowed by unscoped policy (covers {connector_scope}): {plugin_name}")
            return
        plugin_path = hermes_path or _resolve_plugin_path(app, plugin_name, connector_scope)
        pe.allow_for_connector("plugin", plugin_name, connector_scope, reason, plugin_path or "")
        if plugin_path:
            pe.set_source_path("plugin", plugin_name, plugin_path, connector_scope)
        click.secho(f"[plugin] Allowed {plugin_name!r} ({connector_scope}).", fg="green")
        if app.logger:
            saved_change_audit(app.logger).log_action(
                "plugin-allow",
                plugin_name,
                f"reason={reason} connector={connector_scope}",
            )
        return

    connector = (
        app.cfg.active_connector()
        if hasattr(app.cfg, "active_connector")
        else getattr(getattr(app.cfg, "guardrail", None), "connector", "")
    )
    connector = _normalize_runtime_connector(connector)
    targets = _plugin_policy_fanout_connectors(app, pe, plugin_name)
    if targets and (len(_active_plugin_connectors(app)) > 1 or connector != "openclaw"):
        for target_connector in targets:
            plugin_path = _resolve_plugin_path(app, plugin_name, target_connector)
            pe.allow_for_connector("plugin", plugin_name, target_connector, reason, plugin_path or "")
            if plugin_path:
                pe.set_source_path("plugin", plugin_name, plugin_path, target_connector)
            click.secho(f"[plugin] Allowed {plugin_name!r} ({target_connector}).", fg="green")
        if app.store and pe.get_action("plugin", plugin_name) is not None:
            pe.remove_action("plugin", plugin_name)
        if app.logger:
            saved_change_audit(app.logger).log_action(
                "plugin-allow",
                plugin_name,
                f"reason={reason} connector=all",
            )
        return

    entry = pe.get_action("plugin", plugin_name)
    runtime_entry = entry
    for candidate in _plugin_runtime_candidates(name, connector):
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

    plugin_path = _resolve_plugin_path(app, plugin_name)
    pe.allow("plugin", plugin_name, reason, plugin_path or "", clear_journal=runtime_cleared)
    if plugin_path:
        pe.set_source_path("plugin", plugin_name, plugin_path)
    if runtime_cleared:
        click.secho(f"[plugin] Allowed {plugin_name!r} (every connector).", fg="green")
    else:
        click.secho(
            f"[plugin] Allowed {plugin_name!r} (every connector); "
            "runtime disable remains until the gateway is reachable.",
            fg="yellow",
        )

    if app.logger:
        saved_change_audit(app.logger).log_action("plugin-allow", plugin_name, f"reason={reason}")


# ---------------------------------------------------------------------------
# plugin disable (runtime, via gateway RPC)
# ---------------------------------------------------------------------------

_PLUGIN_RUNTIME_PROBE_CONNECTORS = {"claudecode"}


def _normalize_runtime_connector(connector: str) -> str:
    from defenseclaw import connector_paths

    return connector_paths.normalize(connector or "openclaw")


def _plugin_runtime_probe_enforced(connector: str) -> bool:
    return _normalize_runtime_connector(connector) in _PLUGIN_RUNTIME_PROBE_CONNECTORS


def _warn_plugin_runtime_disable_advisory(plugin_name: str, connector: str, scoped: bool) -> None:
    scope = f"connector={connector}"
    click.secho(
        f"warning: plugin runtime disable is advisory for {scope}; that connector "
        "does not emit plugin runtime events DefenseClaw can gate. Use "
        f"'defenseclaw plugin quarantine {plugin_name}"
        + (f" --connector {connector}" if scoped else "")
        + "' for hard enforcement on that peer.",
        fg="yellow",
    )


@plugin.command()
@click.argument("name")
@click.option("--reason", default="", help="Reason for disabling")
@click.option("--connector", "connector_flag", default="", help=_CONNECTOR_RUNTIME_SCOPE_HELP)
@pass_ctx
def disable(app: AppContext, name: str, reason: str, connector_flag: str) -> None:
    """Disable a plugin at runtime.

    OpenClaw uses the gateway RPC. Hook connectors store a runtime-disable
    policy row that the hook runtime gate enforces when that connector emits
    plugin runtime events. This is runtime-only — it does not block install or
    quarantine files.

    Bare records a runtime-disable row for every matching configured connector copy;
    ``--connector <name>`` narrows the runtime-disable record to that peer.
    """
    from defenseclaw.commands import resolve_list_connector
    from defenseclaw.enforce import PolicyEngine

    connector = _normalize_runtime_connector(resolve_list_connector(app, connector_flag))
    _refuse_managed_bridge_action(
        app,
        name,
        connector,
        action="disable",
    )
    plugin_name = (
        _resolve_openclaw_plugin_id(name, connector) if connector == "openclaw" else _validated_plugin_argument(name)
    )
    if connector_flag and connector != "openclaw":
        _plugin_match_dir_scopes(app, plugin_name, connector)

    if not reason:
        reason = "manual disable via CLI"

    pe = PolicyEngine(app.store, app.cfg)
    if not connector_flag and (len(_active_plugin_connectors(app)) > 1 or connector != "openclaw"):
        targets = _plugin_match_dir_scopes(app, plugin_name)
        if not targets:
            click.echo(
                f"error: plugin not found: {plugin_name} across configured connectors",
                err=True,
            )
            raise SystemExit(1)
        seen_connectors: set[str] = set()
        for target_connector, _path in targets:
            target_connector = _normalize_runtime_connector(target_connector)
            if target_connector in seen_connectors:
                continue
            seen_connectors.add(target_connector)
            pe.disable_for_connector("plugin", plugin_name, target_connector, reason)
            click.echo(f"[plugin] {plugin_name!r} runtime disable recorded (connector={target_connector})")
            if _plugin_runtime_probe_enforced(target_connector):
                click.echo(f"  Enforced by hook runtime gate for connector={target_connector}.")
            else:
                _warn_plugin_runtime_disable_advisory(plugin_name, target_connector, True)
        if app.logger:
            saved_change_audit(app.logger).log_action(
                "plugin-disable",
                plugin_name,
                f"reason={reason} connector=all",
            )
        return

    if connector == "openclaw":
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
    elif connector_flag:
        click.echo(f"[plugin] {plugin_name!r} runtime disable recorded (connector={connector})")
        if _plugin_runtime_probe_enforced(connector):
            click.echo(f"  Enforced by hook runtime gate for connector={connector}.")
        else:
            _warn_plugin_runtime_disable_advisory(plugin_name, connector, True)
    else:
        click.echo(f"[plugin] {plugin_name!r} runtime disable recorded as unscoped policy")
        if _plugin_runtime_probe_enforced(connector):
            click.echo("  Enforced by hook runtime gates for connectors that emit plugin events.")
        else:
            _warn_plugin_runtime_disable_advisory(plugin_name, connector, False)

    if connector_flag:
        pe.disable_for_connector("plugin", plugin_name, connector, reason)
    else:
        pe.disable("plugin", plugin_name, reason)

    if app.logger:
        saved_change_audit(app.logger).log_action(
            "plugin-disable",
            plugin_name,
            f"reason={reason} connector={connector_flag}",
        )


# ---------------------------------------------------------------------------
# plugin enable (runtime, via gateway RPC)
# ---------------------------------------------------------------------------


@plugin.command()
@click.argument("name")
@click.option("--connector", "connector_flag", default="", help=_CONNECTOR_RUNTIME_SCOPE_HELP)
@pass_ctx
def enable(app: AppContext, name: str, connector_flag: str) -> None:
    """Enable a previously disabled plugin.

    This is a runtime-only action. Bare clears runtime-disable rows for every
    matching configured connector copy; ``--connector <name>`` narrows the clear to
    that peer.
    """
    from defenseclaw.commands import resolve_list_connector
    from defenseclaw.enforce import PolicyEngine

    connector = _normalize_runtime_connector(resolve_list_connector(app, connector_flag))
    plugin_name = (
        _resolve_openclaw_plugin_id(name, connector) if connector == "openclaw" else _validated_plugin_argument(name)
    )
    if connector_flag and connector != "openclaw":
        _plugin_match_dir_scopes(app, plugin_name, connector)

    pe = PolicyEngine(app.store, app.cfg)
    if not connector_flag and (len(_active_plugin_connectors(app)) > 1 or connector != "openclaw"):
        targets = _plugin_match_dir_scopes(app, plugin_name)
        if not targets:
            click.echo(
                f"error: plugin not found: {plugin_name} across configured connectors",
                err=True,
            )
            raise SystemExit(1)
        seen_connectors: set[str] = set()
        for target_connector, _path in targets:
            target_connector = _normalize_runtime_connector(target_connector)
            if target_connector in seen_connectors:
                continue
            seen_connectors.add(target_connector)
            pe.enable_for_connector("plugin", plugin_name, target_connector)
            click.echo(f"[plugin] {plugin_name!r} runtime disable cleared (connector={target_connector})")
            if target_connector == "hermes":
                _echo_hermes_activation_note(plugin_name)
        pe.enable("plugin", plugin_name)
        if app.logger:
            saved_change_audit(app.logger).log_action(
                "plugin-enable",
                plugin_name,
                "re-enabled via CLI connector=all",
            )
        return

    if connector == "openclaw":
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
    elif connector_flag:
        click.echo(f"[plugin] {plugin_name!r} runtime disable cleared (connector={connector})")
        if connector == "hermes":
            _echo_hermes_activation_note(plugin_name)
    else:
        click.echo(f"[plugin] {plugin_name!r} unscoped runtime disable cleared")

    if connector_flag:
        pe.enable_for_connector("plugin", plugin_name, connector)
        if app.store and app.store.has_action("plugin", plugin_name, "runtime", "disable"):
            app.store.set_action_field(
                "plugin",
                plugin_name,
                "runtime",
                "enable",
                "manual scoped enable via CLI; overrides unscoped runtime disable",
                connector,
            )
    else:
        pe.enable("plugin", plugin_name)

    if app.logger:
        saved_change_audit(app.logger).log_action(
            "plugin-enable",
            plugin_name,
            f"re-enabled via CLI connector={connector_flag}",
        )


# ---------------------------------------------------------------------------
# plugin quarantine
# ---------------------------------------------------------------------------


@plugin.command()
@click.argument("name")
@click.option("--reason", default="", help="Reason for quarantine")
@click.option("--connector", "connector_flag", default="", help=_CONNECTOR_SCOPE_HELP)
@pass_ctx
def quarantine(app: AppContext, name: str, reason: str, connector_flag: str) -> None:
    """Quarantine a plugin's files to the quarantine area.

    Moves matching plugin directories to ~/.defenseclaw/quarantine/plugins/
    and records the action. The plugin can be restored with 'plugin restore'.

    On a multi-connector install a bare plugin name quarantines every matching
    copy across configured connectors; pass ``--connector`` to scope the operation
    to one connector.
    """
    from defenseclaw.enforce import PolicyEngine
    from defenseclaw.enforce.plugin_enforcer import PluginEnforcer

    resolved_connector = _resolve_connector_scope(app, connector_flag)
    _refuse_managed_bridge_action(
        app,
        name,
        resolved_connector,
        action="quarantine",
    )
    try:
        plugin_name = (
            canonical_plugin_id(name)[0]
            if os.path.isabs(name) and os.path.isdir(name)
            else validate_plugin_id(os.path.basename(name))
        )
    except PluginIdentityError:
        click.echo(f"error: invalid plugin name {name!r}", err=True)
        raise SystemExit(1)

    pe_enforcer = PluginEnforcer(app.cfg.quarantine_dir)
    scope_roots = (
        _plugin_roots_for_connector(app, resolved_connector) if resolved_connector else _all_active_plugin_dirs(app)
    )

    if os.path.isabs(name):
        real_path = os.path.realpath(name)
        allowed_roots = [os.path.realpath(root) for root in scope_roots]
        if any(real_path == root for root in allowed_roots):
            click.echo(
                f"error: path {name!r} must point to a specific plugin directory, not the plugin root",
                err=True,
            )
            raise SystemExit(1)
        if not any(real_path.startswith(root + os.sep) for root in allowed_roots):
            click.echo(
                f"error: path {name!r} is not inside a configured plugin directory\n"
                f"  Allowed roots: {', '.join(allowed_roots)}",
                err=True,
            )
            raise SystemExit(1)
        targets = [
            (
                resolved_connector or _connector_for_plugin_path(app, real_path),
                real_path,
            )
        ]
    else:
        targets = _plugin_match_dir_scopes(app, plugin_name, connector_flag)
        if not targets:
            # GAP-2163: Hermes nests plugins (bundled ``platforms/photon``);
            # accept the id, manifest name or folder 'plugin list' shows.
            hermes = _hermes_listed_plugin(app, name, resolved_connector)
            if hermes is not None and hermes[1] and os.path.isdir(hermes[1]):
                try:
                    plugin_name = canonical_plugin_id(hermes[1])[0]
                except PluginIdentityError as exc:
                    raise click.ClickException(f"invalid plugin identity: {exc}") from exc
                targets = [("hermes", hermes[1])]

    if not targets:
        if not reason:
            reason = "manual quarantine via CLI"
        pe = PolicyEngine(app.store, app.cfg)
        quarantined_connectors = (
            [resolved_connector]
            if resolved_connector and pe_enforcer.is_quarantined(plugin_name, resolved_connector)
            else [c for c in _active_plugin_connectors(app) if pe_enforcer.is_quarantined(plugin_name, c)]
        )
        if quarantined_connectors:
            for target_connector in quarantined_connectors:
                pe.quarantine_for_connector("plugin", plugin_name, target_connector, reason)
                click.echo(f"[plugin] {plugin_name!r} is already quarantined (connector={target_connector})")
            return
        click.echo(f"error: could not locate plugin {plugin_name!r}", err=True)
        raise SystemExit(1)

    if not reason:
        reason = "manual quarantine via CLI"
    pe = PolicyEngine(app.store, app.cfg)

    for target_connector, plugin_path in targets:
        dest = pe_enforcer.quarantine(
            plugin_name,
            plugin_path,
            connector=target_connector,
        )
        if dest is None:
            click.echo(f"error: plugin path does not exist: {plugin_path}", err=True)
            raise SystemExit(1)

        suffix = f" (connector={target_connector})" if target_connector else ""
        listed = _hermes_listed_id(plugin_path, target_connector)
        click.echo(f"[plugin] {_plugin_label(listed, plugin_name)} quarantined to {dest}{suffix}")

        if target_connector:
            pe.quarantine_for_connector("plugin", plugin_name, target_connector, reason)
            pe.set_source_path("plugin", plugin_name, plugin_path, target_connector)
        else:
            pe.quarantine("plugin", plugin_name, reason)
            pe.set_source_path("plugin", plugin_name, plugin_path)

        if app.logger:
            saved_change_audit(app.logger).log_action(
                "plugin-quarantine",
                listed or plugin_name,
                f"reason={reason}, dest={dest} connector={target_connector}"
                + (f" quarantine_id={plugin_name}" if listed and listed != plugin_name else ""),
            )


# ---------------------------------------------------------------------------
# plugin restore
# ---------------------------------------------------------------------------


@plugin.command()
@click.argument("name")
@click.option("--path", "restore_path", default="", help="Override restore destination (defaults to original path)")
@click.option("--connector", "connector_flag", default="", help=_CONNECTOR_SCOPE_HELP)
@pass_ctx
def restore(app: AppContext, name: str, restore_path: str, connector_flag: str) -> None:
    """Restore a quarantined plugin to its original location.

    By default restores to the original path recorded during quarantine.
    Use --path to override the restore destination. Bare restore restores every
    configured connector-scoped quarantine copy; pass ``--connector`` to narrow to
    one connector.
    """
    from defenseclaw.enforce import PolicyEngine
    from defenseclaw.enforce.plugin_enforcer import PluginEnforcer

    plugin_name = _validated_plugin_argument(name)

    pe = PolicyEngine(app.store, app.cfg)
    alias_scope = _resolve_connector_scope(app, connector_flag) if connector_flag else ""
    if "/" in name.strip("/\\"):
        # GAP-2464: "web/x" names the category plugin itself, not a flat "x".
        plugin_name = _quarantined_plugin_alias(pe, name, alias_scope) or plugin_name
    targets = _resolve_plugin_quarantine_restore_scopes(
        app,
        pe,
        plugin_name,
        connector_flag,
    )
    if restore_path and len(targets) > 1:
        click.echo(
            "error: --path with multiple quarantined connector copies is ambiguous; "
            "pass --connector <name> to restore one copy to an explicit path",
            err=True,
        )
        raise SystemExit(1)

    pe_enforcer = PluginEnforcer(app.cfg.quarantine_dir)

    def quarantined_targets() -> list[tuple[str, Any, str]]:
        """(action scope, entry, connector folder holding the copy)."""
        scoped = {target_connector for target_connector, _ in targets}
        found = []
        for target_connector, entry in targets:
            slot = target_connector if pe_enforcer.is_quarantined(plugin_name, target_connector) else None
            if slot is None and not target_connector and entry is not None and entry.source_path:
                # GAP-2464: the gateway watcher records a global action but
                # keeps the copy under the connector it watches for.
                owner = _connector_for_plugin_path(app, entry.source_path)
                if owner and owner not in scoped and pe_enforcer.is_quarantined(plugin_name, owner):
                    slot = owner
            if slot is not None:
                found.append((target_connector, entry, slot))
        return found

    existing_targets = quarantined_targets()
    if not existing_targets:
        alias = _quarantined_plugin_alias(pe, name, alias_scope)
        if alias and alias != plugin_name:
            plugin_name = alias
            targets = _resolve_plugin_quarantine_restore_scopes(app, pe, plugin_name, connector_flag)
            existing_targets = quarantined_targets()
    if not existing_targets:
        click.echo(f"error: {plugin_name!r} is not quarantined", err=True)
        raise SystemExit(1)

    for resolved_connector, entry, slot_connector in existing_targets:
        target_restore_path = restore_path
        if not target_restore_path:
            if entry is None or not entry.source_path:
                ux.echo(
                    f"error: no stored path for {plugin_name!r}"
                    + (f" on connector={resolved_connector}" if resolved_connector else "")
                    + " — use --path to specify restore destination",
                    err=True,
                )
                raise SystemExit(1)
            target_restore_path = entry.source_path

        allowed_roots = (
            _plugin_roots_for_connector(app, resolved_connector) if resolved_connector else _all_active_plugin_dirs(app)
        )
        # GAP-2163/GAP-2164: restore to the recorded (or --path) location
        # as-is, so a folder named apart from its manifest ID (Hermes
        # ``platforms/photon``) and a single-file ``.js``/``.ts`` plugin come
        # back under their original name. An explicit configured root keeps
        # its documented "restore under this root" meaning.
        if any(os.path.realpath(target_restore_path) == os.path.realpath(root) for root in allowed_roots):
            original = os.path.basename(os.path.normpath(entry.source_path)) if entry and entry.source_path else ""
            target_restore_path = os.path.join(target_restore_path, original or plugin_name)
        real_restore = os.path.realpath(target_restore_path)
        if allowed_roots:
            if not any(
                real_restore == os.path.realpath(root) or real_restore.startswith(os.path.realpath(root) + os.sep)
                for root in allowed_roots
            ):
                click.echo(
                    "error: restore path must be within configured plugin directories",
                    err=True,
                )
                raise SystemExit(1)
        try:
            # A category plugin (web/x) has no root-level identity to collide
            # with; restore still refuses an existing destination.
            existing = [
                match
                for root in allowed_roots
                if "/" not in plugin_name and (match := resolve_plugin_identity(root, plugin_name)) is not None
            ]
        except PluginIdentityError as exc:
            raise click.ClickException(str(exc)) from exc
        if existing:
            raise click.ClickException(
                f"cannot restore plugin {plugin_name!r}: canonical identity already "
                f"exists at {', '.join(item.path for item in existing)}; remove the "
                "existing copy or choose the correct connector"
            )

        if not pe_enforcer.restore(
            plugin_name,
            target_restore_path,
            allowed_roots=allowed_roots,
            connector=slot_connector,
        ):
            click.echo(
                f"error: restore failed for {plugin_name!r}"
                + (f" on connector={resolved_connector}" if resolved_connector else ""),
                err=True,
            )
            raise SystemExit(1)

        suffix = f" (connector={resolved_connector})" if resolved_connector else ""
        listed = _hermes_listed_id(
            (entry.source_path if entry is not None else "") or target_restore_path,
            slot_connector,
        )
        click.echo(f"[plugin] {_plugin_label(listed, plugin_name)} restored to {target_restore_path}{suffix}")

        if resolved_connector:
            pe.clear_quarantine_for_connector("plugin", plugin_name, resolved_connector)
            pe.set_source_path("plugin", plugin_name, target_restore_path, resolved_connector)
        else:
            pe.clear_quarantine("plugin", plugin_name)
            pe.set_source_path("plugin", plugin_name, target_restore_path)

        if app.logger:
            saved_change_audit(app.logger).log_action(
                "plugin-restore",
                listed or plugin_name,
                f"restored to {target_restore_path} connector={resolved_connector}"
                + (f" quarantine_id={plugin_name}" if listed and listed != plugin_name else ""),
            )


# ---------------------------------------------------------------------------
# plugin info
# ---------------------------------------------------------------------------


@plugin.command()
@click.argument("name")
@click.option("--json", "as_json", is_flag=True, help="Output plugin info as JSON")
@click.option(
    "--connector",
    "connector_flag",
    default="",
    help="Inspect a specific connector's plugin (multi-connector installs)",
)
@pass_ctx
def info(app: AppContext, name: str, as_json: bool, connector_flag: str) -> None:
    """Show detailed information about a plugin.

    Displays plugin metadata, latest scan results from the DefenseClaw
    audit database, and enforcement actions.
    """
    if connector_flag:
        connector = _resolve_connector_scope(app, connector_flag)
        # GAP-1624: accept the ids and names 'plugin list' shows for nested
        # Hermes plugins (web/ddgs, a2a-platform), as 'plugin scan' does.
        plugin_name, _path = _policy_plugin_target(app, name, connector)
        card = _plugin_info_card(app, plugin_name, connector=connector)
        cards = [card] if card is not None else []
    else:
        plugin_name, _path = _policy_plugin_target(app, name, "")
        cards: list[dict[str, Any]] = []
        for connector in _active_plugin_connectors(app):
            card = _plugin_info_card(
                app,
                plugin_name,
                connector=connector,
                suppress_global_action_only=True,
            )
            if card is not None:
                cards.append(card)
        if not cards:
            fallback = _plugin_info_card(app, plugin_name)
            if fallback is not None and (
                fallback.get("installed") or fallback.get("scan") or fallback.get("quarantined")
            ):
                cards.append(fallback)

    if not cards:
        list_cmd = f"defenseclaw plugin list --connector {connector}" if connector_flag else "defenseclaw plugin list"
        click.echo(
            f"Error: plugin {name!r} not found. Run `{list_cmd}` to see installed plugins.",
            err=True,
        )
        raise SystemExit(1)

    if as_json:
        payload: Any = cards if len(cards) > 1 else cards[0]
        click.echo(json.dumps(payload, indent=2, default=str))
        return

    for idx, card in enumerate(cards):
        if idx:
            click.echo()
        _print_plugin_info_card(
            card,
            plugin_name,
            show_connector=bool(card.get("connector")),
        )


def _plugin_metadata_from_path(plugin_name: str, candidate: str) -> dict[str, Any]:
    info_map: dict[str, Any] = {
        "name": plugin_name,
        "installed": True,
        "path": candidate,
    }
    pkg_json = os.path.join(candidate, "package.json")
    if os.path.isfile(pkg_json):
        try:
            with open(pkg_json, encoding="utf-8") as f:
                pkg = json.load(f)
            info_map["version"] = pkg.get("version", "")
            info_map["description"] = pkg.get("description", "")
        except (OSError, json.JSONDecodeError):
            pass
    if not info_map.get("description"):
        # Hermes plugins describe themselves in plugin.yaml; info showed no
        # description while the TUI detail cut it off (GAP-2314).
        from defenseclaw.inventory.claw_inventory import _read_hermes_plugin_manifest

        manifest = _read_hermes_plugin_manifest(os.path.join(candidate, "plugin.yaml")) or {}
        if manifest.get("description"):
            info_map["description"] = " ".join(str(manifest["description"]).split())
        if manifest.get("version") and not info_map.get("version"):
            info_map["version"] = str(manifest["version"])
    return info_map


def _plugin_info_card(
    app: AppContext,
    plugin_name: str,
    *,
    connector: str = "",
    suppress_global_action_only: bool = False,
) -> dict[str, Any] | None:
    info_map: dict[str, Any] | None = None
    if connector:
        matches = _plugin_match_dir_scopes(app, plugin_name, connector)
        candidate = matches[0][1] if matches else ""
        if not candidate:
            # GAP-1592: Hermes nests plugins in category folders (bundled
            # ``platforms/photon``); find them the way 'plugin list' does so
            # info does not read "Installed: False" for a listed plugin.
            try:
                hermes_match = _hermes_listed_plugin(app, plugin_name, connector)
            except click.ClickException:
                hermes_match = None
            if hermes_match is not None and hermes_match[1] and os.path.exists(hermes_match[1]):
                # Key scan and policy rows by the listed id (GAP-1624).
                plugin_name, candidate = hermes_match
        if candidate:
            info_map = _plugin_metadata_from_path(plugin_name, candidate)
        else:
            oc_info = _get_openclaw_plugin_info(plugin_name, connector)
            oc_path = str(oc_info.get("rootDir") or oc_info.get("source") or "") if oc_info else ""
            if oc_path and os.path.isdir(oc_path):
                info_map = _plugin_metadata_from_path(plugin_name, oc_path)
                info_map.update(
                    {
                        "description": oc_info.get("description", info_map.get("description", "")),
                        "version": oc_info.get("version", info_map.get("version", "")),
                    }
                )
    else:
        candidate = _resolve_plugin_path(app, plugin_name)
        if candidate:
            info_map = _plugin_metadata_from_path(plugin_name, candidate)

    scan_entry = (
        _latest_plugin_scan_for_connector(app, plugin_name, connector)
        if connector
        else _build_plugin_scan_map(app.store).get(plugin_name)
    )
    actions_map = _build_plugin_actions_map(app.store, connector, app.cfg)
    scoped_action = None
    if suppress_global_action_only and connector and app.store is not None:
        try:
            scoped_action = app.store.get_action("plugin", plugin_name, connector)
        except Exception:
            scoped_action = None

    from defenseclaw.enforce.plugin_enforcer import PluginEnforcer

    pe_enforcer = PluginEnforcer(app.cfg.quarantine_dir)
    quarantined = pe_enforcer.is_quarantined(plugin_name, connector)
    action_name = plugin_name
    display_name = plugin_name
    if info_map is None and not quarantined and connector and app.store is not None:
        from defenseclaw.enforce import PolicyEngine

        alias = _quarantined_plugin_alias(PolicyEngine(app.store, app.cfg), plugin_name, connector)
        if alias and alias != plugin_name and pe_enforcer.is_quarantined(alias, connector):
            action_name = alias
            quarantined = True
            if scan_entry is None:
                scan_entry = _latest_plugin_scan_for_connector(app, alias, connector)
    if quarantined and connector:
        # GAP-2308: scans of a Hermes plugin are keyed by its listed id
        # (photon), its quarantine by the manifest name (photon-platform).
        q_entry = actions_map.get(action_name)
        listed = _hermes_listed_id(getattr(q_entry, "source_path", "") or "", connector)
        if listed and listed != action_name:
            if scan_entry is None:
                scan_entry = _latest_plugin_scan_for_connector(app, listed, connector)
            # GAP-2355: the header shows the id 'plugin list' shows, whichever
            # name was typed, as it does for the installed copy.
            display_name = listed

    if info_map is None:
        if (
            suppress_global_action_only
            and connector
            and plugin_name in actions_map
            and scoped_action is None
            and scan_entry is None
            and not quarantined
        ):
            return None
        if scan_entry is None and plugin_name not in actions_map and not quarantined:
            return None
        info_map = {"name": display_name, "installed": False}
    else:
        info_map = dict(info_map)

    if connector:
        info_map["connector"] = connector
    if scan_entry is not None:
        info_map["scan"] = scan_entry
    if action_name in actions_map:
        ae = actions_map[action_name]
        if not ae.actions.is_empty():
            info_map["actions"] = ae.actions.to_dict()
    if action_name != info_map["name"]:
        info_map["quarantine_id"] = action_name
    if quarantined:
        qpath = pe_enforcer._quarantine_path(action_name, connector)
        if qpath:
            info_map["quarantine_path"] = qpath
    info_map["quarantined"] = quarantined
    info_map.setdefault("installed", False)
    return info_map


_SCAN_SEVERITY_COLORS = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan"}


def _yes_no(value: Any) -> str:
    return "yes" if value else "no"


def _print_plugin_info_card(
    info_map: dict[str, Any],
    plugin_name: str,
    *,
    show_connector: bool = False,
) -> None:
    click.echo(f"Plugin:      {info_map.get('name', plugin_name)}")
    if show_connector and info_map.get("connector"):
        click.echo(f"Connector:   {info_map['connector']}")
    if info_map.get("description"):
        click.echo(f"Description: {info_map['description']}")
    if info_map.get("version"):
        click.echo(f"Version:     {info_map['version']}")
    if info_map.get("path"):
        click.echo(f"Path:        {info_map['path']}")
    click.echo(f"Installed:   {_yes_no(info_map.get('installed', False))}")
    click.echo(f"Quarantined: {_yes_no(info_map.get('quarantined', False))}")
    if info_map.get("quarantine_path"):
        click.echo(f"Quarantine:  {info_map['quarantine_path']}")

    scan_data = info_map.get("scan")
    if scan_data:
        click.echo()
        click.echo("Last Scan:")
        # GAP-2201: the same Verdict / Findings lines whatever the outcome.
        # GAP-1507: the count is the total and the severity the maximum;
        # "2 HIGH findings" read as two HIGH ones (same wording as skill info).
        n = scan_data.get("total_findings", 0)
        noun = "finding" if n == 1 else "findings"
        # GAP-2201: Verdict is the same word plugin list shows (clean,
        # warning, rejected); the severity belongs on the Findings line.
        if scan_data.get("clean"):
            click.secho("  Verdict:  clean", fg="green")
            click.echo("  Findings: 0 findings")
        else:
            sev = scan_data.get("max_severity", "INFO")
            verdict, _style = _compute_verdict(None, scan_data)
            if verdict == "-":
                verdict = str(sev).lower()
            click.secho(f"  Verdict:  {verdict}", fg=_SCAN_SEVERITY_COLORS.get(sev))
            click.echo(f"  Findings: {n} {noun} (max severity: {sev})")
        if scan_data.get("scanned_at"):
            click.echo(f"  Scanned:  {scan_data['scanned_at']}")
        click.echo(f"  Target:   {scan_data.get('target', '')}")

    actions_data = info_map.get("actions")
    if actions_data or info_map.get("connector"):
        from defenseclaw.models import ActionState

        state = ActionState.from_dict(actions_data)
        label = _plugin_actions_label(state)
        if state.install == "block" and state.file != "quarantine" and state.runtime != "disable":
            label += " (new installs are refused; the installed copy still loads)"
        click.echo()
        click.echo(f"Actions:     {label}")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _resolve_plugin_path(
    app: AppContext,
    plugin_name: str,
    connector: str = "",
) -> str | None:
    """Resolve a plugin name to its installed directory path.

    Searches the DefenseClaw-managed ``plugin_dir`` first, then — so a
    host-owned plugin's files can be quarantined/removed (P-A) — the target
    connector's own plugin dirs via ``cfg.plugin_dirs(connector)`` (mirrors
    ``info()``). ``connector=""`` keeps the legacy managed-dir-only behavior.
    """
    for _connector, candidate in _plugin_match_dir_scopes(app, plugin_name, connector):
        if os.path.isdir(candidate):
            return candidate
    return None


def _plugin_scan_payload_from_latest(ls: dict[str, Any]) -> dict[str, Any]:
    finding_count = ls["finding_count"]
    payload = {
        "target": ls["target"],
        "clean": finding_count == 0,
        "max_severity": ls["max_severity"] if finding_count > 0 else "CLEAN",
        "total_findings": finding_count,
    }
    scanned_at = _format_scan_time(ls.get("timestamp"))
    if scanned_at:
        payload["scanned_at"] = scanned_at
    return payload


def _format_scan_time(ts: Any) -> str:
    """GAP-2201: the scan time as 'YYYY-MM-DD HH:MM:SS UTC' (or "")."""
    from datetime import datetime, timezone

    if not isinstance(ts, datetime):
        return ""
    if ts.tzinfo is not None:
        ts = ts.astimezone(timezone.utc)
    return ts.strftime("%Y-%m-%d %H:%M:%S UTC")


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
        try:
            name, _manifest = canonical_plugin_id(ls["target"])
        except PluginIdentityError:
            name = os.path.basename(ls["target"])
        scan_map[name] = _plugin_scan_payload_from_latest(ls)
    return scan_map


def _build_plugin_scan_map_for_connector(app: AppContext, connector: str) -> dict:
    """Build plugin-name -> latest scan entry scoped to one connector's roots."""
    scan_map: dict[str, dict[str, Any]] = {}
    if app.store is None:
        return scan_map
    try:
        latest = app.store.latest_scans_by_scanner("plugin-scanner")
    except Exception as exc:
        click.echo(f"warning: failed to load plugin scan data: {exc}", err=True)
        return scan_map
    matches: dict[str, tuple[Any, dict[str, Any]]] = {}
    ids_by_path = _host_plugin_ids_by_path(app, connector)
    for ls in latest:
        name = _plugin_id_for_scan_target(app, connector, ls["target"], ids_by_path=ids_by_path)
        payload = _plugin_scan_payload_from_latest(ls)
        if connector and not _scan_entry_matches_plugin_connector(app, payload, connector):
            continue
        timestamp = ls.get("timestamp")
        current = matches.get(name)
        if current is None or timestamp > current[0]:
            matches[name] = (timestamp, payload)
    for name, (_timestamp, payload) in matches.items():
        scan_map[name] = payload
    return scan_map


def _host_plugin_ids_by_path(app: AppContext, connector: str) -> dict[str, str]:
    """Real host plugin path -> logical plugin ID; the first entry for a path wins.

    Enumerating host plugins parses every manifest (59 Hermes plugins take
    about half a second), so callers build this once per command instead of
    once per cached scan (GAP-1626).
    """
    ids: dict[str, str] = {}
    for plugin_entry in _list_host_plugins(connector, app.cfg):
        plugin_path = str(plugin_entry.get("host_path") or "")
        if not plugin_path:
            continue
        try:
            real_path = os.path.normcase(os.path.realpath(plugin_path))
        except (OSError, ValueError):
            continue
        ids.setdefault(real_path, str(plugin_entry.get("id") or ""))
    if (connector or "").lower() == "hermes" and app.store is not None:
        # GAP-2265: a quarantined Hermes plugin keeps its listed id and scan.
        from defenseclaw.inventory.claw_inventory import hermes_listed_identity

        try:
            entries = app.store.list_actions_by_type("plugin")
        except Exception:  # noqa: BLE001 - scan map stays best effort
            entries = []
        for entry in entries:
            if entry.actions.file != "quarantine" or not entry.source_path:
                continue
            if entry.connector not in ("", "hermes"):
                continue
            identity = hermes_listed_identity(entry.source_path)
            if identity:
                ids.setdefault(os.path.normcase(os.path.realpath(entry.source_path)), identity[0])
    return ids


def _plugin_id_for_scan_target(
    app: AppContext,
    connector: str,
    target: str,
    *,
    ids_by_path: dict[str, str] | None = None,
) -> str:
    """Map a concrete cached version directory back to its logical plugin ID."""
    try:
        real_target = os.path.normcase(os.path.realpath(target))
    except (OSError, ValueError):
        return os.path.basename(target)
    if ids_by_path is None:
        ids_by_path = _host_plugin_ids_by_path(app, connector)
    return ids_by_path.get(real_target) or os.path.basename(target)


def _scan_entry_matches_plugin_connector(
    app: AppContext,
    scan_data: dict[str, Any] | None,
    connector: str,
) -> bool:
    if not connector or not scan_data:
        return True
    target = str(scan_data.get("target") or "")
    if not target:
        return False
    real_target = os.path.realpath(target)
    roots = _plugin_roots_for_connector(app, connector)
    return any(
        real_target == os.path.realpath(root) or real_target.startswith(os.path.realpath(root) + os.sep)
        for root in roots
    )


def _latest_plugin_scan_for_connector(
    app: AppContext,
    plugin_name: str,
    connector: str,
) -> dict[str, Any] | None:
    if app.store is None:
        return None
    try:
        latest = app.store.latest_scans_by_scanner("plugin-scanner")
    except Exception:
        return None
    matches: list[tuple[Any, dict[str, Any]]] = []
    ids_by_path = _host_plugin_ids_by_path(app, connector)
    for ls in latest:
        if _plugin_id_for_scan_target(app, connector, ls["target"], ids_by_path=ids_by_path) != plugin_name:
            continue
        payload = _plugin_scan_payload_from_latest(ls)
        if connector and not _scan_entry_matches_plugin_connector(app, payload, connector):
            continue
        matches.append((ls.get("timestamp"), payload))
    if not matches:
        return None
    matches.sort(key=lambda item: item[0], reverse=True)
    return matches[0][1]


def _build_plugin_actions_map(store, connector: str = "", cfg=None) -> dict:
    """Build a map of plugin-name -> effective ActionEntry from the DB.

    Resolves most-specific-wins per name (P-A): the connector-scoped row
    overrides the unscoped row when ``connector`` is given, so each connector's
    table/card shows that connector's effective verdict. ``connector=""``
    returns only the unscoped rows (today's behavior).
    """
    actions_map: dict = {}
    if store is None:
        return actions_map
    try:
        entries = asset_lists.merge_operator_entries(store.list_actions_by_type("plugin"), cfg, "plugin")
    except Exception as exc:
        click.echo(f"warning: failed to load plugin actions data: {exc}", err=True)
        return actions_map
    # Global first, then overlay the connector-scoped rows so the override wins.
    # list_actions_by_type returns newest first, so keep the first row per
    # connector/name.
    for e in entries:
        if e.actions.is_empty():
            continue
        if e.connector == "" and e.target_name not in actions_map:
            actions_map[e.target_name] = e
    if connector:
        seen_scoped: set[str] = set()
        for e in entries:
            if e.actions.is_empty():
                continue
            if e.connector == connector and e.target_name not in seen_scoped:
                actions_map[e.target_name] = e
                seen_scoped.add(e.target_name)
    return actions_map
