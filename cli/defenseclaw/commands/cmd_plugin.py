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
@click.option("--profile", type=click.Choice(["default", "strict"]), default=None,
              help="Scan profile (overrides policy profile)")
@click.option("--all", "scan_all", is_flag=True, help="Scan every installed plugin across configured connectors")
@click.option(
    "--use-llm/--no-llm", "use_llm", default=None,
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
@click.option("--lenient", is_flag=True, help="Suppress low-confidence findings (sets min_confidence=0.5)")
@click.option(
    "--connector", "connector_flag", default="",
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
    lenient: bool,
    connector_flag: str,
) -> None:
    """Scan a plugin directory for security issues.

    Uses defenseclaw-plugin-scanner to check for dangerous permissions,
    install scripts, credential theft, obfuscation, and supply chain risks.

    LLM analysis uses the same configuration as the skill scanner
    (reads from config.yaml: inspect_llm).

    Examples:\n
      defenseclaw plugin scan my-plugin\n
      defenseclaw plugin scan --all\n
      defenseclaw plugin scan my-plugin --policy strict\n
      defenseclaw plugin scan my-plugin --use-llm\n
      defenseclaw plugin scan my-plugin --no-llm\n
      defenseclaw plugin scan my-plugin --use-llm --llm-model gpt-4\n
      defenseclaw plugin scan my-plugin --policy ~/.defenseclaw/policies/custom.yaml\n
      defenseclaw plugin scan /path/to/plugin --profile strict --lenient
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
            app, as_json, policy_name, profile, use_llm, llm_model,
            llm_provider, llm_consensus_runs, enable_meta, lenient, connector_flag,
        )
        return

    # Build scan options from CLI flags + config
    scan_options = _build_scan_options(
        app, policy_name, profile, use_llm, llm_model, llm_provider,
        llm_consensus_runs, enable_meta, lenient,
    )

    # Route the unified LLM config (top-level ``llm:`` + any
    # ``scanners.plugin.llm:`` overrides) into the wrapper. The
    # wrapper layers per-call CLI flags on top before dispatching.
    scanner = PluginScannerWrapper(llm=app.cfg.resolve_llm("scanners.plugin"))
    # R4: overlay the configured guardrail rule pack over the plugin source.
    # No-op when no rule_pack_dir is set.
    scanner = maybe_wrap(scanner, app.cfg)

    matches: list[tuple[str, str]] = []
    if _looks_like_explicit_path(name_or_path):
        from defenseclaw.commands import resolve_list_connector
        connector = resolve_list_connector(app, connector_flag)
        scan_dir = _resolve_plugin_dir(
            name_or_path,
            app.cfg.plugin_dir,
            connector,
            _plugin_roots_for_connector(app, connector),
        )
        if scan_dir:
            matches = [(connector, scan_dir)]
    else:
        matches = _plugin_match_dir_scopes(app, name_or_path, connector_flag)
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
            )
            if scan_dir:
                matches = [(connector, scan_dir)]

    if not matches:
        scope = (
            f" for connector {connector_flag!r}"
            if connector_flag
            else " across configured connectors"
        )
        click.echo(f"error: plugin not found: {name_or_path}{scope}", err=True)
        click.echo("  Provide a path, a DefenseClaw plugin name, or a connector plugin name.", err=True)
        raise SystemExit(1)

    for idx, (connector, scan_dir) in enumerate(matches):
        if len(matches) > 1 and not as_json:
            if idx:
                click.echo()
            click.echo(ux._style(f"── connector: {connector} ──", fg="cyan"))
        _scan_one_plugin_dir(
            app,
            scanner,
            scan_dir=scan_dir,
            connector=connector,
            as_json=as_json,
            scan_options=scan_options,
            policy_name=policy_name,
            use_llm=use_llm,
            llm_model=llm_model,
            profile=profile,
        )


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
) -> None:
    from defenseclaw.commands import _scan_ui

    # S6.2 — surface the connector and the concrete category list before
    # kicking off the scan, so operators see what's being checked instead of
    # an opaque "[plugin] scanning..." line.
    ctx = _scan_ui.ScanContext.for_plugin(
        connector=connector,
        paths=[scan_dir],
        as_json=as_json,
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

    if app.logger:
        app.logger.log_scan(result)

    if as_json:
        # Preserve the ScanResult keys automation already parses, while adding
        # connector metadata so scoped JSON callers need not infer it from paths.
        payload = json.loads(result.to_json())
        payload["connector"] = connector
        payload["target_metadata"] = {
            "connector": connector,
            "path": result.target,
        }
        click.echo(json.dumps(payload, indent=2, default=str))
        return

    target_name = os.path.basename(scan_dir)
    if result.is_clean():
        _scan_ui.render_per_target_status(
            ctx,
            target=target_name,
            verdict=_scan_ui.VERDICT_CLEAN,
            findings=0,
        )
        _scan_ui.render_summary(
            ctx,
            clean=1, blocked=0, errored=0, total=1,
            duration_ms=int(result.duration.total_seconds() * 1000),
        )
        return

    sev = result.max_severity()
    _scan_ui.render_per_target_status(
        ctx,
        target=target_name,
        verdict=_scan_ui.VERDICT_BLOCKED,
        detail=f"max severity: {sev}",
        findings=len(result.findings),
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
        blocked=1,
        errored=0,
        total=1,
        duration_ms=int(result.duration.total_seconds() * 1000),
    )


def _host_plugin_dirs(app: AppContext, connector: str) -> list[str]:
    """The target connector's own plugin dirs (P-B), empty on any failure."""
    try:
        return list(app.cfg.plugin_dirs(connector))
    except Exception:  # noqa: BLE001 — managed-dir-only fallback.
        return []


def _active_plugin_connectors(app: AppContext) -> list[str]:
    cfg = app.cfg
    if hasattr(cfg, "active_connectors"):
        try:
            names = [n for n in cfg.active_connectors() if n]
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
    app: AppContext, connector: str, *, include_legacy: bool = True,
) -> list[str]:
    """Filesystem roots that can hold plugins for one connector.

    New installs target ``cfg.plugin_dirs(connector)``. The legacy
    DefenseClaw-managed ``plugin_dir`` remains readable for old local installs
    and tests, but only for the active/single-connector scope so it does not
    fabricate a copy on every peer in multi-connector info/quarantine flows.
    """
    roots: list[str] = []
    try:
        roots.extend(d for d in app.cfg.plugin_dirs(connector) if d)
    except Exception:  # noqa: BLE001 — legacy root below may still work.
        pass

    if include_legacy and getattr(app.cfg, "plugin_dir", ""):
        active = (
            app.cfg.active_connector()
            if hasattr(app.cfg, "active_connector")
            else "openclaw"
        )
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


def _plugin_basename(target: str) -> str:
    name = target.rstrip("/\\")
    if "/" in name or "\\" in name:
        name = os.path.basename(name)
    return name.lstrip("@")


def _connector_for_plugin_path(
    app: AppContext, plugin_path: str, connector_hint: str = "",
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


def _plugin_match_dir_scopes(
    app: AppContext, target: str, connector: str = "",
) -> list[tuple[str, str]]:
    """Every ``(connector, path)`` pair that contains a plugin target."""
    if _looks_like_explicit_path(target) and os.path.isdir(target):
        resolved = _resolve_connector_scope(app, connector)
        return [(_connector_for_plugin_path(app, target, resolved), target)]

    name = _plugin_basename(target)
    if connector:
        resolved = _resolve_connector_scope(app, connector)
        scoped_matches: list[tuple[str, str]] = []
        for root in _plugin_roots_for_connector(app, resolved):
            candidate = os.path.join(root, name)
            if os.path.isdir(candidate) and (resolved, candidate) not in scoped_matches:
                scoped_matches.append((resolved, candidate))
        return scoped_matches

    matches: list[tuple[str, str]] = []
    seen_paths: set[str] = set()
    for c in _active_plugin_connectors(app):
        for root in _plugin_roots_for_connector(app, c):
            candidate = os.path.join(root, name)
            if os.path.isdir(candidate) and candidate not in seen_paths:
                matches.append((c, candidate))
                seen_paths.add(candidate)
    return matches


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
    from defenseclaw.commands import _scan_ui, resolve_list_connector
    from defenseclaw.scanner.plugin import PluginScannerWrapper
    from defenseclaw.scanner.rulepack import maybe_wrap

    if connector_flag:
        connectors: list[str] = [resolve_list_connector(app, connector_flag)]
    elif hasattr(app.cfg, "active_connectors") and len(app.cfg.active_connectors()) > 1:
        connectors = list(app.cfg.active_connectors())
    else:
        connectors = [resolve_list_connector(app, "")]

    scan_options = _build_scan_options(
        app, policy_name, profile, use_llm, llm_model, llm_provider,
        llm_consensus_runs, enable_meta, lenient,
    )
    scanner = PluginScannerWrapper(llm=app.cfg.resolve_llm("scanners.plugin"))
    scanner = maybe_wrap(scanner, app.cfg)

    json_groups: list[dict[str, Any]] = []
    for connector in connectors:
        if len(connectors) > 1 and not as_json:
            click.echo(ux._style(f"\n── connector: {connector} ──", fg="cyan"))

        plugins = _merge_all_plugins(app.cfg.plugin_dir, connector, cfg=app.cfg)
        # Resolve each plugin id to a directory on disk (managed dir or the
        # connector's own dirs). Skip phantom (scan-history / enforcement-only)
        # rows that have no files to scan.
        host_dirs = _host_plugin_dirs(app, connector)
        targets: list[tuple[str, str]] = []
        for p in plugins:
            pid = p.get("id", "")
            if not pid:
                continue
            scan_dir = _resolve_plugin_dir(pid, app.cfg.plugin_dir, connector, host_dirs)
            if scan_dir:
                targets.append((pid, scan_dir))

        if not targets:
            if not as_json:
                click.echo(f"No plugins found to scan for connector={connector}.")
            else:
                json_groups.append({"connector": connector, "results": []})
            continue

        ctx = _scan_ui.ScanContext.for_plugin(
            connector=connector,
            paths=[d for _, d in targets],
            as_json=as_json,
        )
        _scan_ui.render_preamble(ctx, target_count=len(targets))

        clean = blocked = errored = 0
        total_ms = 0
        group_results: list[dict[str, Any]] = []
        for pid, scan_dir in targets:
            try:
                result = scanner.scan(scan_dir, **scan_options)
            except Exception as exc:  # noqa: BLE001 — surface, keep sweeping.
                errored += 1
                if not as_json:
                    click.echo(f"  error: scan failed for {pid!r}: {exc}", err=True)
                continue
            if app.logger:
                app.logger.log_scan(result)
            total_ms += int(result.duration.total_seconds() * 1000)
            if as_json:
                group_results.append(json.loads(result.to_json()))
                continue
            if result.is_clean():
                clean += 1
                _scan_ui.render_per_target_status(
                    ctx, target=pid, verdict=_scan_ui.VERDICT_CLEAN, findings=0,
                )
            else:
                blocked += 1
                _scan_ui.render_per_target_status(
                    ctx,
                    target=pid,
                    verdict=_scan_ui.VERDICT_BLOCKED,
                    detail=f"max severity: {result.max_severity()}",
                    findings=len(result.findings),
                )
        if as_json:
            json_groups.append({"connector": connector, "results": group_results})
        else:
            _scan_ui.render_summary(
                ctx, clean=clean, blocked=blocked, errored=errored,
                total=len(targets), duration_ms=total_ms,
            )

    if as_json:
        click.echo(json.dumps(json_groups, indent=2, default=str))


def _build_scan_options(
    app: AppContext,
    policy_name: str,
    profile: str | None,
    use_llm: bool | None,
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

    if lenient:
        opts["lenient"] = True

    return opts


@plugin.command()
@click.argument("name_or_path")
@click.option("--force", is_flag=True, help="Force install (overwrites existing)")
@click.option("--action", "take_action", is_flag=True, help="Apply plugin_actions policy based on scan severity")
@click.option(
    "--connector", "connector_flag", default="",
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
      npm package       defenseclaw plugin install @openclasw/voice-call
      clawhub URI       defenseclaw plugin install clawhub://voice-call
      HTTP(S) URL       defenseclaw plugin install https://example.com/plugin.tgz

    After downloading, the plugin is scanned for security issues. Pass --action
    to apply the configured plugin_actions policy (quarantine, disable, block)
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
        app, connectors, explicit_connector=bool(connector_flag),
    )

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

    pre_decisions: dict[str, Any] = {}
    if plugin_name:
        pre_decisions = _check_plugin_pre_install_admission(
            app,
            pe,
            targets,
            plugin_name,
            source_path=name_or_path if source == SourceType.LOCAL else "",
        )

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
        # --- Validate the derived install name (F-0301) ---
        # plugin_name is a basename of operator-controlled input (local path /
        # npm spec / clawhub URI / extracted dir). Reject empty / dot /
        # traversal / separator names before any destructive operation.
        if (
            not plugin_name
            or plugin_name in (".", "..")
            or "/" in plugin_name
            or "\\" in plugin_name
            or os.sep in plugin_name
            or (os.altsep and os.altsep in plugin_name)
        ):
            click.echo(f"error: invalid plugin name: {plugin_name!r}", err=True)
            raise SystemExit(1)

        if not pre_decisions:
            pre_decisions = _check_plugin_pre_install_admission(
                app,
                pe,
                targets,
                plugin_name,
                source_path=source_path if source == SourceType.LOCAL else "",
            )

        click.echo(
            f"[install] installing {plugin_name!r} for "
            + ", ".join(f"connector={connector}" for connector, _root in targets)
            + "..."
        )
        installed_paths: list[str] = []
        installed_by_connector: dict[str, str] = {}
        for connector, install_root in targets:
            plugin_path = _copy_plugin_tree_to_connector(
                source_path, install_root, plugin_name, force=force,
            )
            installed_paths.append(plugin_path)
            installed_by_connector[connector] = plugin_path
            click.echo(
                f"[install] installed {plugin_name!r} -> {plugin_path} "
                f"(connector={connector})"
            )
            if app.logger:
                app.logger.log_action(
                    "plugin-install",
                    plugin_name,
                    f"source={name_or_path} connector={connector}",
                )

        scanner = PluginScannerWrapper(llm=app.cfg.resolve_llm("scanners.plugin"))
        scanner = maybe_wrap(scanner, app.cfg)
        for connector, _install_root in targets:
            plugin_path = installed_by_connector[connector]
            pre_decision = pre_decisions[connector]
            if pre_decision.verdict == "allowed":
                if pre_decision.source == "scan-disabled":
                    click.echo(
                        f"[install] policy allows {plugin_name!r} without scan "
                        f"(connector={connector})"
                    )
                else:
                    click.echo(
                        f"[install] {plugin_name!r} is on the allow list for "
                        f"connector={connector} — skipping scan"
                    )
                pe.set_source_path("plugin", plugin_name, plugin_path, connector)
                if app.logger:
                    app.logger.log_action(
                        "install-allowed",
                        plugin_name,
                        f"reason=allow-listed connector={connector}",
                    )
                continue

            _scan_installed_plugin_for_connector(
                app,
                pe,
                scanner,
                plugin_name,
                plugin_path,
                connector=connector,
                take_action=take_action,
                rollback_paths=installed_paths,
            )

        click.echo(f"Installed plugin: {plugin_name}")

        from defenseclaw.commands import hint
        hint(
            "List plugins:      defenseclaw plugin list",
            "Restart gateway:   defenseclaw-gateway restart",
        )

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
            policy_dir=app.cfg.policy_dir,
            target_type="plugin",
            name=plugin_name,
            source_path=source_path,
            fallback_actions=app.cfg.plugin_actions,
            connector=connector,
            asset_policy=app.cfg.asset_policy,
            include_quarantine=True,
        )
        pre_decisions[connector] = decision

        if decision.verdict == "blocked":
            if app.logger:
                app.logger.log_action(
                    "install-rejected",
                    plugin_name,
                    f"reason=blocked connector={connector}",
                )
            click.echo(
                f"error: plugin {plugin_name!r} is on the block list for "
                f"connector={connector} — run "
                f"'defenseclaw plugin allow {plugin_name} --connector {connector}' "
                "to unblock",
                err=True,
            )
            raise SystemExit(1)

        if decision.verdict == "rejected" and decision.source == "quarantine":
            if app.logger:
                app.logger.log_action(
                    "install-rejected",
                    plugin_name,
                    f"reason=quarantined connector={connector}",
                )
            click.echo(
                f"error: plugin {plugin_name!r} is quarantined for "
                f"connector={connector} — release the quarantine before reinstalling",
                err=True,
            )
            raise SystemExit(1)

    return pre_decisions


def _plugin_install_targets(
    app: AppContext, connectors: list[str], *, explicit_connector: bool = False,
) -> list[tuple[str, str]]:
    """Return ``(connector, install_root)`` targets for plugin installs."""
    targets: list[tuple[str, str]] = []
    skipped: list[str] = []
    for connector in connectors:
        if connector == "antigravity":
            skipped.append(connector)
            continue
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
        click.echo(
            f"[install] skipping connector={connector}: no plugin install directory"
        )
    return targets


def _copy_plugin_tree_to_connector(
    source_path: str, install_root: str, plugin_name: str, *, force: bool,
) -> str:
    target_path = os.path.join(install_root, plugin_name)
    real_root = os.path.realpath(install_root)
    real_target = os.path.realpath(target_path)
    if not (real_target != real_root and real_target.startswith(real_root + os.sep)):
        click.echo("error: resolved install path escapes the connector plugin directory", err=True)
        raise SystemExit(1)

    if os.path.realpath(source_path) == real_target:
        return target_path
    if os.path.exists(target_path):
        if not force:
            click.echo(
                f"error: plugin {plugin_name!r} already exists at {target_path}; "
                "pass --force to replace it",
                err=True,
            )
            raise SystemExit(1)
        shutil.rmtree(target_path)
    os.makedirs(install_root, exist_ok=True)
    shutil.copytree(source_path, target_path)
    return target_path


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
    rollback_paths: list[str] | None = None,
) -> None:
    from defenseclaw.enforce.admission import evaluate_admission
    from defenseclaw.enforce.plugin_enforcer import PluginEnforcer

    click.echo(f"[install] scanning {plugin_path} (connector={connector})...")
    try:
        result = scanner.scan(plugin_path)
    except Exception as exc:
        _rollback_plugin_install_paths(rollback_paths or [plugin_path])
        click.echo(
            f"error: scan failed for connector={connector}: {exc}",
            err=True,
        )
        raise SystemExit(1)

    if app.logger:
        app.logger.log_scan(result)

    _print_install_result(plugin_name, result)

    post_decision = evaluate_admission(
        pe,
        policy_dir=app.cfg.policy_dir,
        target_type="plugin",
        name=plugin_name,
        source_path=plugin_path,
        scan_result=result,
        fallback_actions=app.cfg.plugin_actions,
        connector=connector,
        asset_policy=app.cfg.asset_policy,
    )

    if post_decision.verdict == "allowed":
        click.echo(
            f"[install] {plugin_name!r} became allow-listed for "
            f"connector={connector} — skipping post-scan enforcement"
        )
        pe.set_source_path("plugin", plugin_name, plugin_path, connector)
        if app.logger:
            app.logger.log_action(
                "install-allowed",
                plugin_name,
                f"reason=allow-listed-post-scan connector={connector}",
            )
        return

    if post_decision.verdict == "clean":
        click.echo(f"[install] {plugin_name!r} installed and clean (connector={connector})")
        pe.set_source_path("plugin", plugin_name, plugin_path, connector)
        if app.logger:
            app.logger.log_action(
                "install-clean",
                plugin_name,
                f"verdict=clean connector={connector}",
            )
        return

    sev = result.max_severity()
    detail = f"severity={sev} findings={len(result.findings)} connector={connector}"

    if not take_action:
        sev_norm = (sev or "").strip().upper()
        if sev_norm in {"HIGH", "CRITICAL"}:
            _rollback_plugin_install_paths(rollback_paths or [plugin_path])
            click.echo(
                f"error: refusing to install {plugin_name!r} for connector={connector} — "
                f"{len(result.findings)} {sev_norm} findings detected and "
                "--action was not passed. Run with --action to enforce, or "
                f"`defenseclaw plugin allow {plugin_name} --connector {connector}` "
                "to explicitly accept the risk.",
                err=True,
            )
            if app.logger:
                app.logger.log_action(
                    "install-refused",
                    plugin_name,
                    f"{detail} reason=critical-without-action",
                )
            raise SystemExit(1)
        click.echo(
            f"[install] {len(result.findings)} {sev} findings in {plugin_name!r} "
            f"(connector={connector}; no action taken — pass --action to enforce)"
        )
        pe.set_source_path("plugin", plugin_name, plugin_path, connector)
        if app.logger:
            app.logger.log_action("install-warning", plugin_name, detail)
        return

    action_cfg = post_decision.action
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
        pe.block_for_connector("plugin", plugin_name, connector, enforcement_reason)
        applied_actions.append("added to block list")

    if action_cfg.install == "allow":
        pe.allow_for_connector("plugin", plugin_name, connector, enforcement_reason)
        applied_actions.append("added to allow list")

    pe.set_source_path("plugin", plugin_name, plugin_path, connector)

    if applied_actions:
        actions_str = ", ".join(applied_actions)
        click.echo(f"[install] {plugin_name!r}: {actions_str} ({detail})")
        if app.logger:
            app.logger.log_action(
                "install-enforced", plugin_name, f"{detail}; {actions_str}",
            )
        click.echo(
            f"error: plugin {plugin_name!r} had {sev} findings for "
            f"connector={connector} — actions applied: {actions_str}",
            err=True,
        )
        raise SystemExit(1)

    click.echo(
        f"[install] warning: {len(result.findings)} {sev} findings in "
        f"{plugin_name!r} (connector={connector})"
    )
    pe.set_source_path("plugin", plugin_name, plugin_path, connector)
    if app.logger:
        app.logger.log_action("install-warning", plugin_name, detail)


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

    By default this lists **every configured connector's** plugins — each
    connector gets its own connector-tagged table — so the output reads
    the same whether one or many connectors are configured. ``--connector
    <name>`` narrows the listing to one configured peer.
    """
    from defenseclaw.commands import resolve_list_connectors

    connectors = resolve_list_connectors(app, connector_flag)
    scan_map = _build_plugin_scan_map(app.store)
    # P-A: resolve the effective actions per connector (connector-scoped row
    # overrides unscoped) so each connector's table/card shows its own verdict.

    if as_json:
        if len(connectors) > 1:
            groups = [
                {
                    "connector": c,
                    "plugins": _plugin_list_json_items(
                        _collect_plugins_for_connector(app, c, scan_map),
                        _build_plugin_scan_map_for_connector(app, c),
                        _build_plugin_actions_map(app.store, c),
                        connector=c,
                    ),
                }
                for c in connectors
            ]
            click.echo(json.dumps(groups, indent=2, default=str))
        else:
            plugins = _collect_plugins_for_connector(app, connectors[0], scan_map)
            _print_plugin_list_json(
                plugins,
                _build_plugin_scan_map_for_connector(app, connectors[0]),
                _build_plugin_actions_map(app.store, connectors[0]),
                connector=connectors[0],
            )
        return

    shown_any = False
    empty_connectors: list[str] = []
    for connector in connectors:
        plugins = _collect_plugins_for_connector(app, connector, scan_map)
        if not plugins:
            empty_connectors.append(connector)
            if len(connectors) > 1:
                click.echo(f"Plugins (connector={connector}): no plugins found")
            continue
        actions_map = _build_plugin_actions_map(app.store, connector)
        connector_scan_map = _build_plugin_scan_map_for_connector(app, connector)
        _print_plugin_list_table(plugins, connector_scan_map, actions_map, connector)
        shown_any = True

    if not shown_any:
        if len(connectors) == 1:
            click.echo(
                f"No plugins found. Check your {connectors[0]} installation and plugin directories."
            )
        return

    if shown_any:
        from defenseclaw.commands import hint
        hint("Scan a plugin:  defenseclaw plugin scan <name>")


def _collect_plugins_for_connector(
    app: AppContext,
    connector: str,
    scan_map: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """Build the merged plugin list for a single connector.

    OpenClaw-only audit-DB phantom (scan-history) rows are folded in just
    as the single-connector path did. Other connectors get only the
    connector-aware filesystem enumeration so OpenClaw plugins never leak
    into a Codex / Claude Code / ZeptoClaw view.
    """
    plugins = _merge_all_plugins(app.cfg.plugin_dir, connector, cfg=app.cfg)
    known_ids = {p["id"] for p in plugins}
    for pid, ae in sorted(_build_plugin_actions_map(app.store, connector).items()):
        if pid in known_ids or ae.actions.file != "quarantine":
            continue
        plugins.append({
            "id": pid,
            "name": pid,
            "description": "",
            "version": "",
            "origin": "enforcement",
            "enabled": False,
            "source": "enforcement",
        })
        known_ids.add(pid)
    if connector != "openclaw":
        return plugins
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
    return plugins


def _merge_all_plugins(
    plugin_dir: str,
    connector: str = "",
    *,
    cfg: Any = None,
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
        plugins.append({
            "id": dir_name,
            "name": dir_name,
            "description": "",
            "version": "",
            "origin": "local",
            "enabled": True,
            "source": "defenseclaw",
        })

    for p in _list_openclaw_plugins(connector):
        plugins.append({
            "id": p.get("id", ""),
            "name": p.get("name") or p.get("id", "unknown"),
            "description": p.get("description", ""),
            "version": p.get("version", ""),
            "origin": p.get("origin", ""),
            "enabled": p.get("enabled", False),
            "source": "openclaw",
        })

    # Plan C6: matrix §5 — surface host-owned plugins for non-OpenClaw
    # connectors. We de-dup by id against DefenseClaw-managed plugins:
    # a DefenseClaw plugin with the same id wins (it's our copy).
    if cfg is not None:
        seen_ids = {p["id"] for p in plugins}
        for hp in _list_host_plugins(connector, cfg):
            if hp["id"] in seen_ids:
                continue
            seen_ids.add(hp["id"])
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
        if a.file == "quarantine":
            return "\u2717 quarantined"
        if a.install == "block":
            return "\u2717 blocked"
        if a.runtime == "disable":
            return "\u2717 disabled"
    if p.get("enabled"):
        return "\u2713 enabled"
    return "\u2717 disabled"


def _plugin_effectively_enabled(p: dict[str, Any], action_entry: Any = None) -> bool:
    if action_entry and not action_entry.actions.is_empty():
        a = action_entry.actions
        if a.file == "quarantine" or a.install == "block" or a.runtime == "disable":
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
            "status": _plugin_status(p, actions_map.get(pid)),
            "enabled": _plugin_effectively_enabled(p, actions_map.get(pid)),
        }
        if connector:
            item["connector"] = connector
        if pid in scan_map:
            item["scan"] = scan_map[pid]
        if pid in actions_map:
            ae = actions_map[pid]
            if not ae.actions.is_empty():
                item["actions"] = ae.actions.to_dict()
        verdict_label, _ = _compute_verdict(actions_map.get(pid), scan_map.get(pid))
        item["verdict"] = verdict_label
        items.append(item)
    return items


def _print_plugin_list_json(
    plugins: list[dict[str, Any]],
    scan_map: dict[str, dict[str, Any]],
    actions_map: dict[str, Any],
    connector: str = "",
) -> None:
    click.echo(json.dumps(
        _plugin_list_json_items(plugins, scan_map, actions_map, connector=connector),
        indent=2,
        default=str,
    ))


def _print_plugin_list_table(
    plugins: list[dict[str, Any]],
    scan_map: dict[str, dict[str, Any]],
    actions_map: dict[str, Any],
    connector: str = "",
) -> None:
    from rich.console import Console
    from rich.table import Table

    from defenseclaw.commands import list_scope_title

    enabled_count = sum(
        1 for p in plugins if _plugin_effectively_enabled(p, actions_map.get(p["id"]))
    )

    detail = f"({enabled_count}/{len(plugins)} enabled)"
    title = (
        list_scope_title("Plugins", connector, detail)
        if connector
        else f"Plugins {detail}"
    )
    console = Console()
    table = Table(title=title)
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
) -> str | None:
    """Resolve a plugin name or path to a directory on disk.

    Resolution order:
      1. Literal path (already a directory) — only when the input
         clearly looks like a path (absolute, or contains a path
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
    if _looks_like_explicit_path(name_or_path) and os.path.isdir(name_or_path):
        return name_or_path

    candidate = os.path.join(plugin_dir, name_or_path)
    if os.path.isdir(candidate):
        return candidate

    for d in search_dirs or []:
        host_candidate = os.path.join(d, name_or_path)
        if os.path.isdir(host_candidate):
            return host_candidate

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
                    if any(os.path.isfile(os.path.join(check, m))
                           for m in ("package.json", "openclaw.plugin.json")):
                        return check
                    check = os.path.dirname(check)
            break

    return None


def _get_openclaw_plugin_info(name: str, connector: str = "") -> dict | None:
    """Get plugin info — uses openclaw CLI for OpenClaw, filesystem for others."""
    if connector in ("", "openclaw"):
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
    if not os.path.isdir(plugin_dir):
        return []
    return sorted(
        e for e in os.listdir(plugin_dir)
        if os.path.isdir(os.path.join(plugin_dir, e))
    )


# _HOST_PLUGIN_MANIFEST_FILES — plan C6 / matrix #3. Each host agent
# declares a plugin via one of these manifest filenames inside the
# plugin directory. We try each in order; the first hit wins. Keep
# this list narrow — adding a globbed extension here invites both
# false positives (treating a config file as a plugin) and DoS
# (large directory walks during ``plugin list``).
_HOST_PLUGIN_MANIFEST_FILES = (
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
            with open(manifest_path) as fh:
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


def _scan_plugin_dir(host_dir: str, connector: str) -> list[dict[str, Any]]:
    """Walk one level under *host_dir* and emit one dict per plugin.

    Only one level — host-agent plugin directories are conventionally
    flat (``~/.claude/plugins/<name>/plugin.json``). Recursing risks
    picking up unrelated nested package.json files (e.g. a plugin's
    own node_modules tree).
    """
    if not os.path.isdir(host_dir):
        return []
    out: list[dict[str, Any]] = []
    try:
        entries = sorted(os.listdir(host_dir))
    except OSError:
        return []
    for entry in entries:
        # N6: host plugin dirs carry non-plugin siblings — a ``cache``
        # working dir (codex/zeptoclaw register ``…/plugins/cache``) and
        # dot-prefixed dirs (``.git`` and editor/OS cruft). Skip both so they
        # never surface as phantom plugin rows. The manifest stays optional
        # below, so genuinely manifest-less host plugins still list.
        if entry == "cache" or entry.startswith("."):
            continue
        plugin_path = os.path.join(host_dir, entry)
        if not os.path.isdir(plugin_path):
            continue
        manifest = _read_host_plugin_manifest(plugin_path) or {}
        plugin_id = manifest.get("id") or entry
        plugin_name = manifest.get("name") or plugin_id
        out.append({
            "id": str(plugin_id),
            "name": str(plugin_name),
            "description": str(manifest.get("description", "")),
            "version": str(manifest.get("version", "")),
            "origin": str(manifest.get("origin", "host")),
            "enabled": bool(manifest.get("enabled", True)),
            # Provenance label per plan C6 — the merged list MUST
            # disambiguate "managed by DefenseClaw" from "owned by the
            # host agent" so policy hooks (block/quarantine) only
            # touch the right side.
            "source": f"host:{connector}",
            "host_path": plugin_path,
        })
    return out


def _list_host_plugins(connector: str, cfg) -> list[dict[str, Any]]:
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
        return _list_copilot_plugins()
    try:
        dirs = cfg.plugin_dirs(connector)
    except Exception:
        return []
    out: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for d in dirs:
        for entry in _scan_plugin_dir(d, name):
            pid = entry["id"]
            if pid in seen_ids:
                # First occurrence wins. Two plugin dirs (e.g.
                # ``~/.claude/plugins`` + ``./.claude/plugins``) may
                # legitimately ship the same plugin id; we prefer the
                # earlier (typically user-scoped) source.
                continue
            seen_ids.add(pid)
            out.append(entry)
    return out


def _list_copilot_plugins() -> list[dict[str, Any]]:
    """Best-effort Copilot CLI plugin listing via documented CLI flow."""
    copilot = shutil.which("copilot")
    if not copilot:
        return []
    try:
        proc = subprocess.run(
            [copilot, "plugin", "list", "--json"],
            capture_output=True, text=True, timeout=15,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    if proc.returncode != 0:
        return []
    plugins = _parse_plugin_list_json(proc.stdout) or _parse_plugin_list_text(proc.stdout)
    out: list[dict[str, Any]] = []
    for p in plugins:
        pid = str(p.get("id") or p.get("name") or "").strip()
        if not pid:
            continue
        out.append({
            "id": pid,
            "name": str(p.get("name") or pid),
            "version": str(p.get("version") or ""),
            "enabled": p.get("enabled", True),
            "source": "host:copilot",
            "path": "",
        })
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


def _parse_plugin_list_text(text: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.lower().startswith(("name", "plugin")):
            continue
        name = line.split()[0]
        out.append({"id": name, "name": name})
    return out


def _list_openclaw_plugins(connector: str = "") -> list[dict]:
    """Query plugins from the requested connector.

    For OpenClaw, shells out to ``openclaw plugins list --json``.
    For other connectors, returns an empty list (plugins are discovered
    from the filesystem via ``cfg.plugin_dirs()`` in ``_merge_all_plugins``).
    """
    if connector not in ("", "openclaw"):
        return []

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
@click.option(
    "--connector", "connector_flag", default="",
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

    safe_name = os.path.basename(name)
    if not safe_name or safe_name in (".", ".."):
        click.echo(f"Invalid plugin name: {name}", err=True)
        raise SystemExit(1)

    connectors = resolve_list_connectors(app, connector_flag)
    scoped = bool(connector_flag and connector_flag.strip())

    roots: list[tuple[str, str]] = []
    include_legacy = not scoped or len(_active_plugin_connectors(app)) <= 1
    if include_legacy and getattr(app.cfg, "plugin_dir", ""):
        roots.append(("", app.cfg.plugin_dir))
    for connector in connectors:
        for root in _host_plugin_dirs(app, connector):
            roots.append((connector, root))

    removed: list[tuple[str, str]] = []
    seen_paths: set[str] = set()
    for connector, root in roots:
        if not root:
            continue
        real_root = os.path.realpath(root)
        candidate = os.path.realpath(os.path.join(root, safe_name))
        if candidate != real_root and not candidate.startswith(real_root + os.sep):
            continue
        if os.path.isdir(candidate):
            if candidate in seen_paths:
                continue
            shutil.rmtree(candidate)
            removed.append((connector, candidate))
            seen_paths.add(candidate)

    if not removed:
        click.echo(f"Plugin not found: {safe_name}")
        return

    for connector, path in removed:
        suffix = f" (connector={connector})" if connector else ""
        click.echo(f"[plugin] {safe_name!r} removed from {path}{suffix}")

    if app.logger:
        connector_detail = (
            f"connector={connectors[0]}" if scoped and connectors else "connector=all"
        )
        app.logger.log_action(
            "plugin-remove", safe_name, connector_detail,
        )

    from defenseclaw.commands import hint
    hint("Restart gateway to apply:  defenseclaw-gateway restart")


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
_CONNECTOR_RUNTIME_SCOPE_HELP = (
    "Scope to one connector. Default: matching plugin copies across configured connectors."
)


def _resolve_connector_scope(app: AppContext, connector_flag: str) -> str:
    """Validate a connector-scoped plugin policy flag.

    Bare policy commands intentionally write an unscoped row. A supplied
    connector must be configured, so typos cannot create inert policy state.
    """
    if not connector_flag:
        return ""
    from defenseclaw.commands import resolve_list_connector
    return resolve_list_connector(app, connector_flag)


def _resolve_plugin_quarantine_restore_scopes(
    app: AppContext, pe: Any, plugin_name: str, connector_flag: str,
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


def _plugin_policy_fanout_connectors(
    app: AppContext, pe: Any, plugin_name: str,
) -> list[str]:
    """Connectors where a bare plugin policy command should apply.

    The set includes installed matching connector copies plus any connector
    that already has scoped enforcement for the plugin, so bare allow/unblock
    can clean stale connector-scoped rows even after a copy was removed.
    """
    active_order = {
        _normalize_runtime_connector(connector): idx
        for idx, connector in enumerate(_active_plugin_connectors(app))
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
    app: AppContext, plugin_name: str, connector: str,
) -> bool:
    if app.store is None:
        return False
    return (
        app.store.has_action("plugin", plugin_name, "install", "block", connector)
        or app.store.has_action("plugin", plugin_name, "install", "allow", connector)
        or app.store.has_action("plugin", plugin_name, "file", "quarantine", connector)
        or app.store.has_action("plugin", plugin_name, "runtime", "disable", connector)
        or app.store.has_action("plugin", plugin_name, "runtime", "enable", connector)
    )


@plugin.command()
@click.argument("name")
@click.option("--reason", default="", help="Reason for blocking")
@click.option("--connector", "connector_flag", default="", help=_CONNECTOR_SCOPE_HELP)
@pass_ctx
def block(app: AppContext, name: str, reason: str, connector_flag: str) -> None:
    """Add a plugin to the install block list.

    Blocked plugins are rejected by the admission gate before any scan.
    Does not affect already-installed plugins — use 'plugin disable' or
    'plugin quarantine' for that.

    Bare ``plugin block <name>`` creates an unscoped block entry;
    ``--connector <name>`` narrows the block to one peer.
    """
    from defenseclaw.enforce import PolicyEngine

    plugin_name = os.path.basename(name)
    pe = PolicyEngine(app.store)

    if not reason:
        reason = "manual block via CLI"

    connector = _resolve_connector_scope(app, connector_flag)
    if connector:
        if pe.is_blocked_for_connector("plugin", plugin_name, connector):
            if app.store and app.store.has_action(
                "plugin", plugin_name, "install", "block", connector,
            ):
                click.echo(f"Already blocked for {connector}: {plugin_name}")
            else:
                click.echo(
                    f"Already blocked by unscoped policy (covers {connector}): {plugin_name}"
                )
            return
        pe.block_for_connector("plugin", plugin_name, connector, reason)
        plugin_path = _resolve_plugin_path(app, plugin_name, connector)
        if plugin_path:
            pe.set_source_path("plugin", plugin_name, plugin_path, connector)
        click.secho(
            f"[plugin] {plugin_name!r} added to block list (connector={connector})",
            fg="red",
        )
    else:
        pe.block("plugin", plugin_name, reason)
        plugin_path = _resolve_plugin_path(app, plugin_name)
        if plugin_path:
            pe.set_source_path("plugin", plugin_name, plugin_path)
        click.secho(f"[plugin] {plugin_name!r} added to block list", fg="red")

    if app.logger:
        app.logger.log_action(
            "plugin-block", plugin_name, f"reason={reason} connector={connector}",
        )


# ---------------------------------------------------------------------------
# plugin unblock
# ---------------------------------------------------------------------------

@plugin.command()
@click.argument("name")
@click.option(
    "--connector", "connector_flag", default="",
    help=(
        "Scope to one connector. Default: clear matching connector copies and unscoped state. "
        "Pass --connector <name> to clear only that peer's per-connector state; "
        "an unscoped block stays in force."
    ),
)
@pass_ctx
def unblock(app: AppContext, name: str, connector_flag: str) -> None:
    """Remove plugin enforcement state without adding an allow entry."""
    from defenseclaw.enforce import PolicyEngine

    plugin_name = os.path.basename(name)
    pe = PolicyEngine(app.store)
    connector = _resolve_connector_scope(app, connector_flag)
    if connector:
        has_state = bool(app.store) and (
            app.store.has_action("plugin", plugin_name, "install", "block", connector)
            or app.store.has_action("plugin", plugin_name, "install", "allow", connector)
            or app.store.has_action("plugin", plugin_name, "file", "quarantine", connector)
            or app.store.has_action("plugin", plugin_name, "runtime", "disable", connector)
        )
        if not has_state:
            click.echo(
                f"[plugin] {plugin_name!r} has no enforcement state to clear for {connector}"
            )
            return
        pe.remove_action_for_connector("plugin", plugin_name, connector)
        click.secho(
            f"[plugin] {plugin_name!r} all enforcement state cleared "
            f"(connector={connector}) (allow/block/quarantine/disable)",
            fg="green",
        )
        if app.logger:
            app.logger.log_action(
                "plugin-unblock", plugin_name, f"manual unblock via CLI connector={connector}",
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
        _plugin_has_connector_enforcement(app, plugin_name, target_connector)
        for target_connector in targets
    )
    if targets and (has_unscoped_state or has_scoped_state):
        for target_connector in targets:
            pe.remove_action_for_connector("plugin", plugin_name, target_connector)
            click.secho(
                f"[plugin] {plugin_name!r} all enforcement state cleared "
                f"(connector={target_connector}) (allow/block/quarantine/disable)",
                fg="green",
            )
        if has_unscoped_state:
            pe.remove_action("plugin", plugin_name)
        if app.logger:
            app.logger.log_action(
                "plugin-unblock", plugin_name, "manual unblock via CLI connector=all",
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

    pe.remove_action("plugin", plugin_name)
    click.secho(
        f"[plugin] {plugin_name!r} all enforcement state cleared "
        "(allow/block/quarantine/disable)",
        fg="green",
    )
    if app.logger:
        app.logger.log_action("plugin-unblock", plugin_name, "manual unblock via CLI")


# ---------------------------------------------------------------------------
# plugin allow
# ---------------------------------------------------------------------------

@plugin.command()
@click.argument("name")
@click.option("--reason", default="", help="Reason for allowing")
@click.option("--connector", "connector_flag", default="", help=_CONNECTOR_SCOPE_HELP)
@pass_ctx
def allow(app: AppContext, name: str, reason: str, connector_flag: str) -> None:
    """Add a plugin to the install allow list.

    Allow-listed plugins skip the scan gate during install.
    Adding a plugin also removes it from the block list.

    Bare ``plugin allow <name>`` allows matching configured connector copies;
    ``--connector <name>`` narrows the allow to one peer.
    """
    from defenseclaw.enforce import PolicyEngine

    plugin_name = os.path.basename(name)
    runtime_name = plugin_name
    pe = PolicyEngine(app.store)

    if not reason:
        reason = "manual allow via CLI"

    # P-A connector-scoped allow: write the narrowed entry and clear residual
    # file/runtime state for that peer. The gateway runtime-enable dance below
    # is for the unscoped/OpenClaw runtime lane and stays on the bare path.
    connector_scope = _resolve_connector_scope(app, connector_flag)
    if connector_scope:
        if pe.is_allowed_for_connector("plugin", plugin_name, connector_scope):
            if app.store and app.store.has_action(
                "plugin", plugin_name, "install", "allow", connector_scope,
            ):
                click.echo(f"Already allowed for {connector_scope}: {plugin_name}")
            else:
                click.echo(
                    f"Already allowed by unscoped policy (covers {connector_scope}): {plugin_name}"
                )
            return
        pe.allow_for_connector("plugin", plugin_name, connector_scope, reason)
        plugin_path = _resolve_plugin_path(app, plugin_name, connector_scope)
        if plugin_path:
            pe.set_source_path("plugin", plugin_name, plugin_path, connector_scope)
        click.secho(
            f"[plugin] {plugin_name!r} added to allow list (connector={connector_scope})",
            fg="green",
        )
        if app.logger:
            app.logger.log_action(
                "plugin-allow", plugin_name,
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
            pe.allow_for_connector("plugin", plugin_name, target_connector, reason)
            plugin_path = _resolve_plugin_path(app, plugin_name, target_connector)
            if plugin_path:
                pe.set_source_path("plugin", plugin_name, plugin_path, target_connector)
            click.secho(
                f"[plugin] {plugin_name!r} added to allow list "
                f"(connector={target_connector})",
                fg="green",
            )
        if app.store and pe.get_action("plugin", plugin_name) is not None:
            pe.remove_action("plugin", plugin_name)
        if app.logger:
            app.logger.log_action(
                "plugin-allow", plugin_name, f"reason={reason} connector=all",
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
    plugin_name = (
        _resolve_openclaw_plugin_id(name, connector)
        if connector == "openclaw"
        else os.path.basename(name)
    )

    if not reason:
        reason = "manual disable via CLI"

    pe = PolicyEngine(app.store)
    if not connector_flag and (
        len(_active_plugin_connectors(app)) > 1 or connector != "openclaw"
    ):
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
            click.echo(
                f"[plugin] {plugin_name!r} runtime disable recorded "
                f"(connector={target_connector})"
            )
            if _plugin_runtime_probe_enforced(target_connector):
                click.echo(
                    f"  Enforced by hook runtime gate for connector={target_connector}."
                )
            else:
                _warn_plugin_runtime_disable_advisory(plugin_name, target_connector, True)
        if app.logger:
            app.logger.log_action(
                "plugin-disable", plugin_name, f"reason={reason} connector=all",
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
        click.echo(
            f"[plugin] {plugin_name!r} runtime disable recorded "
            f"(connector={connector})"
        )
        if _plugin_runtime_probe_enforced(connector):
            click.echo(
                f"  Enforced by hook runtime gate for connector={connector}."
            )
        else:
            _warn_plugin_runtime_disable_advisory(plugin_name, connector, True)
    else:
        click.echo(f"[plugin] {plugin_name!r} runtime disable recorded as unscoped policy")
        if _plugin_runtime_probe_enforced(connector):
            click.echo(
                "  Enforced by hook runtime gates for connectors that emit plugin events."
            )
        else:
            _warn_plugin_runtime_disable_advisory(plugin_name, connector, False)

    if connector_flag:
        pe.disable_for_connector("plugin", plugin_name, connector, reason)
    else:
        pe.disable("plugin", plugin_name, reason)

    if app.logger:
        app.logger.log_action(
            "plugin-disable", plugin_name, f"reason={reason} connector={connector_flag}",
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
        _resolve_openclaw_plugin_id(name, connector)
        if connector == "openclaw"
        else os.path.basename(name)
    )

    pe = PolicyEngine(app.store)
    if not connector_flag and (
        len(_active_plugin_connectors(app)) > 1 or connector != "openclaw"
    ):
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
            click.echo(
                f"[plugin] {plugin_name!r} runtime disable cleared "
                f"(connector={target_connector})"
            )
        pe.enable("plugin", plugin_name)
        if app.logger:
            app.logger.log_action(
                "plugin-enable", plugin_name, "re-enabled via CLI connector=all",
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
        click.echo(
            f"[plugin] {plugin_name!r} runtime disable cleared "
            f"(connector={connector})"
        )
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
        app.logger.log_action(
            "plugin-enable", plugin_name, f"re-enabled via CLI connector={connector_flag}",
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

    plugin_name = os.path.basename(name)
    if not plugin_name or ".." in name:
        click.echo(f"error: invalid plugin name {name!r}", err=True)
        raise SystemExit(1)

    pe_enforcer = PluginEnforcer(app.cfg.quarantine_dir)
    resolved_connector = _resolve_connector_scope(app, connector_flag)
    scope_roots = (
        _plugin_roots_for_connector(app, resolved_connector)
        if resolved_connector
        else _all_active_plugin_dirs(app)
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
        targets = [(
            resolved_connector or _connector_for_plugin_path(app, real_path),
            real_path,
        )]
    else:
        targets = _plugin_match_dir_scopes(app, plugin_name, connector_flag)

    if not targets:
        if not reason:
            reason = "manual quarantine via CLI"
        pe = PolicyEngine(app.store)
        quarantined_connectors = (
            [resolved_connector]
            if resolved_connector and pe_enforcer.is_quarantined(plugin_name, resolved_connector)
            else [
                c
                for c in _active_plugin_connectors(app)
                if pe_enforcer.is_quarantined(plugin_name, c)
            ]
        )
        if quarantined_connectors:
            for target_connector in quarantined_connectors:
                pe.quarantine_for_connector("plugin", plugin_name, target_connector, reason)
                click.echo(
                    f"[plugin] {plugin_name!r} is already quarantined "
                    f"(connector={target_connector})"
                )
            return
        click.echo(f"error: could not locate plugin {plugin_name!r}", err=True)
        raise SystemExit(1)

    if not reason:
        reason = "manual quarantine via CLI"
    pe = PolicyEngine(app.store)

    for target_connector, plugin_path in targets:
        dest = pe_enforcer.quarantine(
            plugin_name, plugin_path, connector=target_connector,
        )
        if dest is None:
            click.echo(f"error: plugin path does not exist: {plugin_path}", err=True)
            raise SystemExit(1)

        suffix = f" (connector={target_connector})" if target_connector else ""
        click.echo(f"[plugin] {plugin_name!r} quarantined to {dest}{suffix}")

        if target_connector:
            pe.quarantine_for_connector("plugin", plugin_name, target_connector, reason)
            pe.set_source_path("plugin", plugin_name, plugin_path, target_connector)
        else:
            pe.quarantine("plugin", plugin_name, reason)
            pe.set_source_path("plugin", plugin_name, plugin_path)

        if app.logger:
            app.logger.log_action(
                "plugin-quarantine", plugin_name,
                f"reason={reason}, dest={dest} connector={target_connector}",
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

    plugin_name = os.path.basename(name)

    pe = PolicyEngine(app.store)
    targets = _resolve_plugin_quarantine_restore_scopes(
        app, pe, plugin_name, connector_flag,
    )
    if restore_path and len(targets) > 1:
        click.echo(
            "error: --path with multiple quarantined connector copies is ambiguous; "
            "pass --connector <name> to restore one copy to an explicit path",
            err=True,
        )
        raise SystemExit(1)

    pe_enforcer = PluginEnforcer(app.cfg.quarantine_dir)
    existing_targets = [
        (target_connector, entry)
        for target_connector, entry in targets
        if pe_enforcer.is_quarantined(plugin_name, target_connector)
    ]
    if not existing_targets:
        click.echo(f"error: {plugin_name!r} is not quarantined", err=True)
        raise SystemExit(1)

    for resolved_connector, entry in existing_targets:
        target_restore_path = restore_path
        if not target_restore_path:
            if entry is None or not entry.source_path:
                click.echo(
                    f"error: no stored path for {plugin_name!r}"
                    + (
                        f" on connector={resolved_connector}"
                        if resolved_connector else ""
                    )
                    + " — use --path to specify restore destination",
                    err=True,
                )
                raise SystemExit(1)
            target_restore_path = entry.source_path

        allowed_roots = (
            _plugin_roots_for_connector(app, resolved_connector)
            if resolved_connector
            else _all_active_plugin_dirs(app)
        )
        real_restore = os.path.realpath(target_restore_path)
        if allowed_roots:
            if not any(
                real_restore == os.path.realpath(root)
                or real_restore.startswith(os.path.realpath(root) + os.sep)
                for root in allowed_roots
            ):
                click.echo(
                    "error: restore path must be within configured plugin directories",
                    err=True,
                )
                raise SystemExit(1)

        if not pe_enforcer.restore(
            plugin_name,
            target_restore_path,
            allowed_roots=allowed_roots,
            connector=resolved_connector,
        ):
            click.echo(
                f"error: restore failed for {plugin_name!r}"
                + (f" on connector={resolved_connector}" if resolved_connector else ""),
                err=True,
            )
            raise SystemExit(1)

        suffix = f" (connector={resolved_connector})" if resolved_connector else ""
        click.echo(f"[plugin] {plugin_name!r} restored to {target_restore_path}{suffix}")

        if resolved_connector:
            pe.clear_quarantine_for_connector("plugin", plugin_name, resolved_connector)
            pe.set_source_path("plugin", plugin_name, target_restore_path, resolved_connector)
        else:
            pe.clear_quarantine("plugin", plugin_name)
            pe.set_source_path("plugin", plugin_name, target_restore_path)

        if app.logger:
            app.logger.log_action(
                "plugin-restore", plugin_name,
                f"restored to {target_restore_path} connector={resolved_connector}",
            )


# ---------------------------------------------------------------------------
# plugin info
# ---------------------------------------------------------------------------

@plugin.command()
@click.argument("name")
@click.option("--json", "as_json", is_flag=True, help="Output plugin info as JSON")
@click.option(
    "--connector", "connector_flag", default="",
    help="Inspect a specific connector's plugin (multi-connector installs)",
)
@pass_ctx
def info(app: AppContext, name: str, as_json: bool, connector_flag: str) -> None:
    """Show detailed information about a plugin.

    Displays plugin metadata, latest scan results from the DefenseClaw
    audit database, and enforcement actions.
    """
    plugin_name = os.path.basename(name)

    if connector_flag:
        connector = _resolve_connector_scope(app, connector_flag)
        card = _plugin_info_card(app, plugin_name, connector=connector)
        cards = [card] if card is not None else []
    else:
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
            if (
                fallback is not None
                and (
                    fallback.get("installed")
                    or fallback.get("scan")
                    or fallback.get("quarantined")
                )
            ):
                cards.append(fallback)

    if not cards:
        click.echo(f"error: plugin {plugin_name!r} not found", err=True)
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
            with open(pkg_json) as f:
                pkg = json.load(f)
            info_map["version"] = pkg.get("version", "")
            info_map["description"] = pkg.get("description", "")
        except (OSError, json.JSONDecodeError):
            pass
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
        candidate = next(
            (
                os.path.join(root, plugin_name)
                for root in _plugin_roots_for_connector(app, connector)
                if os.path.isdir(os.path.join(root, plugin_name))
            ),
            "",
        )
        if candidate:
            info_map = _plugin_metadata_from_path(plugin_name, candidate)
        else:
            oc_info = _get_openclaw_plugin_info(plugin_name, connector)
            oc_path = str(oc_info.get("rootDir") or oc_info.get("source") or "") if oc_info else ""
            if oc_path and os.path.isdir(oc_path):
                info_map = _plugin_metadata_from_path(plugin_name, oc_path)
                info_map.update({
                    "description": oc_info.get("description", info_map.get("description", "")),
                    "version": oc_info.get("version", info_map.get("version", "")),
                })
    else:
        candidate = _resolve_plugin_path(app, plugin_name)
        if candidate:
            info_map = _plugin_metadata_from_path(plugin_name, candidate)

    scan_entry = (
        _latest_plugin_scan_for_connector(app, plugin_name, connector)
        if connector
        else _build_plugin_scan_map(app.store).get(plugin_name)
    )
    actions_map = _build_plugin_actions_map(app.store, connector)
    scoped_action = None
    if suppress_global_action_only and connector and app.store is not None:
        try:
            scoped_action = app.store.get_action("plugin", plugin_name, connector)
        except Exception:
            scoped_action = None

    from defenseclaw.enforce.plugin_enforcer import PluginEnforcer
    pe_enforcer = PluginEnforcer(app.cfg.quarantine_dir)
    quarantined = pe_enforcer.is_quarantined(plugin_name, connector)

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
        info_map = {"name": plugin_name, "installed": False}
    else:
        info_map = dict(info_map)

    if connector:
        info_map["connector"] = connector
    if scan_entry is not None:
        info_map["scan"] = scan_entry
    if plugin_name in actions_map:
        ae = actions_map[plugin_name]
        if not ae.actions.is_empty():
            info_map["actions"] = ae.actions.to_dict()
    info_map["quarantined"] = quarantined
    info_map.setdefault("installed", False)
    return info_map


def _print_plugin_info_card(
    info_map: dict[str, Any], plugin_name: str, *, show_connector: bool = False,
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
    click.echo(f"Installed:   {info_map.get('installed', False)}")
    click.echo(f"Quarantined: {info_map.get('quarantined', False)}")

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
    if actions_data or info_map.get("connector"):
        from defenseclaw.models import ActionState
        state = ActionState.from_dict(actions_data)
        click.echo()
        click.echo(f"Actions:     {state.summary()}")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _resolve_plugin_path(
    app: AppContext, plugin_name: str, connector: str = "",
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
    plugin_dir = app.cfg.plugin_dir
    candidate = os.path.join(plugin_dir, plugin_name)
    if os.path.isdir(candidate):
        return candidate
    return None


def _plugin_scan_payload_from_latest(ls: dict[str, Any]) -> dict[str, Any]:
    finding_count = ls["finding_count"]
    return {
        "target": ls["target"],
        "clean": finding_count == 0,
        "max_severity": ls["max_severity"] if finding_count > 0 else "CLEAN",
        "total_findings": finding_count,
    }


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
    for ls in latest:
        name = os.path.basename(ls["target"])
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


def _scan_entry_matches_plugin_connector(
    app: AppContext, scan_data: dict[str, Any] | None, connector: str,
) -> bool:
    if not connector or not scan_data:
        return True
    target = str(scan_data.get("target") or "")
    if not target:
        return False
    real_target = os.path.realpath(target)
    roots = _plugin_roots_for_connector(app, connector)
    return any(
        real_target == os.path.realpath(root)
        or real_target.startswith(os.path.realpath(root) + os.sep)
        for root in roots
    )


def _latest_plugin_scan_for_connector(
    app: AppContext, plugin_name: str, connector: str,
) -> dict[str, Any] | None:
    if app.store is None:
        return None
    try:
        latest = app.store.latest_scans_by_scanner("plugin-scanner")
    except Exception:
        return None
    matches: list[tuple[Any, dict[str, Any]]] = []
    for ls in latest:
        if os.path.basename(ls["target"]) != plugin_name:
            continue
        payload = _plugin_scan_payload_from_latest(ls)
        if connector and not _scan_entry_matches_plugin_connector(app, payload, connector):
            continue
        matches.append((ls.get("timestamp"), payload))
    if not matches:
        return None
    matches.sort(key=lambda item: item[0], reverse=True)
    return matches[0][1]


def _build_plugin_actions_map(store, connector: str = "") -> dict:
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
        entries = store.list_actions_by_type("plugin")
    except Exception as exc:
        click.echo(f"warning: failed to load plugin actions data: {exc}", err=True)
        return actions_map
    # Global first, then overlay the connector-scoped rows so the override wins.
    # list_actions_by_type returns newest first, so keep the first row per
    # connector/name.
    for e in entries:
        if e.connector == "" and e.target_name not in actions_map:
            actions_map[e.target_name] = e
    if connector:
        seen_scoped: set[str] = set()
        for e in entries:
            if e.connector == connector and e.target_name not in seen_scoped:
                actions_map[e.target_name] = e
                seen_scoped.add(e.target_name)
    return actions_map
