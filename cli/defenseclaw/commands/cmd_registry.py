# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""``defenseclaw registry`` — manage external skill / MCP catalog sources.

The group has two layers:

* **Non-interactive primitives** (the bulk of this file): every
  subcommand accepts the full operator-facing flag surface, validates
  inputs strictly when ``--non-interactive`` is set, and emits
  stable JSON with ``--json``. These are what the TUI and CI/CD
  pipelines call.
* **Interactive prompts** layered on top of the same callbacks via
  :func:`click.prompt` / :func:`click.confirm` (mirrors
  ``cmd_setup_webhook.py``). When stdin is a TTY and the operator
  hasn't passed ``--non-interactive``, missing required inputs are
  filled in via prompt; otherwise the command fails with exit code
  2 and ``error: --foo is required``.

The :command:`wizard` shortcut at the bottom of this module bundles the
add+sync flow with prompts so first-run discoverability is a single
command.
"""

from __future__ import annotations

import json as _json
import os
import re
import sys
from dataclasses import asdict
from typing import Any

import click

from defenseclaw import ux
from defenseclaw.config import (
    REGISTRY_CONTENT_TYPES,
    REGISTRY_KINDS,
    Config,
    RegistrySource,
)
from defenseclaw.context import AppContext, pass_ctx
from defenseclaw.registries import (
    EntryVerdict,
    SourceIndex,
    SyncReport,
    load_index,
    sync_all,
    sync_source,
)
from defenseclaw.registries import (
    remove_source as remove_source_cache,
)
from defenseclaw.registries.manifest import ManifestEntry
from defenseclaw.registries.sync import (
    ScanCallback,
    manual_set_verdict,
    promote_from_cache,
)

# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

# Conservative kebab-case identifier — keeps source ids safe to use as
# a directory name under ~/.defenseclaw/registries/<id> and as part of
# the AssetPolicyRule.Reason field "registry:<id>".
_SOURCE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,63}$")
_ENV_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")


def _require(value: Any, flag: str, *, non_interactive: bool) -> Any:
    """Either return *value* unchanged or raise SystemExit(2).

    When ``non_interactive`` is True we treat a missing value as a
    hard error (matches the rule "exits non-zero on missing required
    input when --non-interactive is set"). Interactive callers fill
    the value with :func:`click.prompt` *before* calling this.
    """
    if value is None or value == "":
        if non_interactive:
            click.echo(f"error: {flag} is required", err=True)
            raise SystemExit(2)
        click.echo(f"error: {flag} is required", err=True)
        raise SystemExit(2)
    return value


def _validate_source_id(sid: str) -> str:
    sid = sid.strip().lower()
    if not _SOURCE_ID_RE.match(sid):
        raise click.BadParameter(
            f"id {sid!r} must match {_SOURCE_ID_RE.pattern!r} "
            "(lowercase letters, digits, dot, dash, underscore; 2-64 chars)"
        )
    return sid


def _validate_kind(kind: str) -> str:
    kind = kind.strip().lower()
    if kind not in REGISTRY_KINDS:
        raise click.BadParameter(
            f"kind must be one of {', '.join(REGISTRY_KINDS)} (got {kind!r})"
        )
    return kind


def _validate_content(content: str) -> str:
    c = content.strip().lower()
    if c not in REGISTRY_CONTENT_TYPES:
        raise click.BadParameter(
            f"content must be one of {', '.join(REGISTRY_CONTENT_TYPES)} (got {content!r})"
        )
    return c


def _validate_auth_env(env: str) -> str:
    env = env.strip()
    if not env:
        return ""
    if not _ENV_NAME_RE.match(env):
        raise click.BadParameter(
            f"auth-env must be an env var NAME, not a value (got {env!r}). "
            "Set the actual token via: export DEFENSECLAW_REGISTRY_TOKEN=...",
        )
    return env


def _find_source(cfg: Config, sid: str) -> RegistrySource:
    sid = sid.strip().lower()
    for s in cfg.registries.sources:
        if s.id == sid:
            return s
    click.echo(f"error: no registry source named {sid!r}", err=True)
    raise SystemExit(2)


def _require_cfg(app: AppContext) -> Config:
    """Return ``app.cfg`` after asserting it is loaded.

    AppContext.cfg is typed as ``Optional[Config]`` because the
    bootstrapper instantiates the context before parsing config. By the
    time any registry subcommand runs, ``main.py`` has already filled
    ``cfg`` in (or aborted with an error), so the None case here is
    impossible in practice. We still guard explicitly so that:

      * mypy can narrow the type for every downstream attribute access
        without a per-callsite ``assert``;
      * if a future refactor accidentally invokes a registry command on
        an unbootstrapped context, the failure is loud rather than a
        confusing AttributeError on ``.registries`` half a stack down.
    """
    cfg = _require_cfg(app)
    if cfg is None:
        # Should not happen in normal CLI flow — main() always loads cfg
        # before dispatching. Keep the message terse and operator-facing.
        raise click.ClickException(
            "internal: configuration is not loaded; run `defenseclaw setup` first"
        )
    return cfg


def _emit_json(payload: Any) -> None:
    click.echo(_json.dumps(payload, indent=2, sort_keys=True))


def _source_to_dict(source: RegistrySource) -> dict[str, Any]:
    return {
        "id": source.id,
        "kind": source.kind,
        "url": source.url,
        "content": source.content,
        "auth_env": source.auth_env,
        "enabled": source.enabled,
        "auto_sync": source.auto_sync,
        "sync_interval_hours": source.sync_interval_hours,
        "last_sync": source.last_sync,
        "last_status": source.last_status,
    }


# ---------------------------------------------------------------------------
# Group + add / edit
# ---------------------------------------------------------------------------

@click.group("registry")
def registry() -> None:
    """Manage external skill / MCP catalog sources.

    A "registry source" is a fetchable manifest (corporate HTTPS YAML,
    smithery.ai, a git repo containing ``defenseclaw-registry.yaml``,
    etc.) that DefenseClaw ingests on demand. Synced entries are
    scanned with the existing skill / MCP scanners and clean ones are
    auto-promoted into ``asset_policy.{skill,mcp}.registry`` so
    admission decisions can attribute the rule back to its source.

    \b
    Subcommands:
      add       Register a new source (interactive or flag-only).
      edit      Update an existing source.
      list      Show every configured source.
      show      Pretty-print a single source.
      remove    Delete a source and its cache.
      sync      Fetch + scan + promote one or all sources.
      entries   Show cached entries (after sync).
      approve   Mark an entry approved (forces promotion next sync).
      reject    Mark an entry rejected (always blocked).
      require   Toggle ``asset_policy.{type}.registry_required``.
      wizard    First-run interactive add+sync convenience flow.
    """


@registry.command("add")
@click.argument("source_id", required=False)
@click.option("--kind", type=click.Choice(REGISTRY_KINDS, case_sensitive=False),
              default=None, help="Source kind (clawhub / smithery / http_yaml / ...)")
@click.option("--url", default=None, help="Manifest URL or git repo URL")
@click.option("--content", type=click.Choice(REGISTRY_CONTENT_TYPES, case_sensitive=False),
              default=None, help="Declared content type (skill / mcp / both)")
@click.option("--auth-env", default=None,
              help="ENV VAR NAME holding a bearer token (never the literal token)")
@click.option("--enabled/--disabled", default=True, help="Mark source enabled or disabled")
@click.option("--auto-sync/--no-auto-sync", default=False,
              help="RESERVED: scheduled sync is not implemented yet. "
                   "The flag is persisted so a future release can pick it "
                   "up without a config rewrite. Run `defenseclaw registry "
                   "sync --all` (or schedule it via cron) for now.")
@click.option("--sync-interval-hours", type=int, default=24,
              help="RESERVED: paired with --auto-sync above; ignored at "
                   "runtime today.")
@click.option("--non-interactive", is_flag=True,
              help="Skip prompts; required flags must be present")
@click.option("--json", "emit_json", is_flag=True, help="Emit JSON")
@pass_ctx
def add_cmd(  # noqa: PLR0913 - mirrors the prompt surface
    app: AppContext,
    source_id: str | None,
    kind: str | None,
    url: str | None,
    content: str | None,
    auth_env: str | None,
    enabled: bool,
    auto_sync: bool,
    sync_interval_hours: int,
    non_interactive: bool,
    emit_json: bool,
) -> None:
    """Register a new registry source.

    Interactive (default): prompts for any missing required field.

    Non-interactive: ``--non-interactive`` plus all required flags.

    Examples:

    \b
      defenseclaw registry add corp-skills \\
          --kind http_yaml \\
          --url https://catalog.example.com/skills.yaml \\
          --content skill \\
          --non-interactive

    \b
      defenseclaw registry add smithery-public \\
          --kind smithery --content mcp --non-interactive

    \b
      defenseclaw registry add clawhub --kind clawhub --content skill --non-interactive
    """
    cfg = _require_cfg(app)

    if not non_interactive:
        if not source_id:
            source_id = click.prompt("Source id (kebab-case)", default="corp-skills")
        if not kind:
            kind = click.prompt(
                f"Kind ({'/'.join(REGISTRY_KINDS)})",
                default="http_yaml",
            )
        if not content:
            content = click.prompt(
                f"Content ({'/'.join(REGISTRY_CONTENT_TYPES)})",
                default="skill",
            )
        # URL is optional for clawhub (defaults to npmjs) and for
        # skills_sh (defaults to https://skills.sh curated view). The
        # adapter parses the URL field permissively — empty string,
        # a bare view keyword (curated/all-time/trending/hot), or a
        # full https URL with query params are all accepted.
        if kind not in ("clawhub", "skills_sh") and not url:
            url = click.prompt("Manifest URL", default="")
        if not auth_env and click.confirm(
            "Use an auth token (read from an env var)?", default=False,
        ):
            auth_env = click.prompt("Env var name", default="DEFENSECLAW_REGISTRY_TOKEN")

    source_id = _require(source_id, "--id", non_interactive=non_interactive)
    kind = _require(kind, "--kind", non_interactive=non_interactive)
    content = _require(content, "--content", non_interactive=non_interactive)

    sid = _validate_source_id(source_id)
    kind = _validate_kind(kind)
    content = _validate_content(content)
    auth_env = _validate_auth_env(auth_env or "")
    url = (url or "").strip()
    if kind in ("http_yaml", "http_json", "git", "file") and not url:
        click.echo(
            f"error: --url is required for kind={kind}",
            err=True,
        )
        raise SystemExit(2)

    if any(s.id == sid for s in cfg.registries.sources):
        click.echo(f"error: source {sid!r} already exists; use 'registry edit'", err=True)
        raise SystemExit(2)

    new_source = RegistrySource(
        id=sid,
        kind=kind,
        url=url,
        content=content,
        auth_env=auth_env,
        enabled=enabled,
        auto_sync=auto_sync,
        sync_interval_hours=max(0, int(sync_interval_hours or 0)),
    )
    cfg.registries.sources.append(new_source)
    cfg.save()

    if app.logger:
        app.logger.log_action(
            "registry-add", "config",
            f"id={sid} kind={kind} content={content} url={url}",
        )

    if emit_json:
        _emit_json({"action": "add", "source": _source_to_dict(new_source)})
        return
    ux.ok(f"Registered registry source {sid!r}.")
    ux.subhead(
        f"Run `defenseclaw registry sync {sid}` to fetch + scan + promote entries."
    )


@registry.command("edit")
@click.argument("source_id")
@click.option("--kind", type=click.Choice(REGISTRY_KINDS, case_sensitive=False),
              default=None)
@click.option("--url", default=None)
@click.option("--content", type=click.Choice(REGISTRY_CONTENT_TYPES, case_sensitive=False),
              default=None)
@click.option("--auth-env", default=None,
              help="Env var NAME (use --clear-auth-env to remove)")
@click.option("--clear-auth-env", is_flag=True, help="Drop auth_env back to empty")
@click.option("--enabled/--disabled", default=None,
              help="Toggle the enabled flag")
@click.option("--auto-sync/--no-auto-sync", default=None,
              help="RESERVED: scheduled sync is not implemented yet.")
@click.option("--sync-interval-hours", type=int, default=None,
              help="RESERVED: paired with --auto-sync; ignored today.")
@click.option("--non-interactive", is_flag=True)
@click.option("--json", "emit_json", is_flag=True)
@pass_ctx
def edit_cmd(  # noqa: PLR0913
    app: AppContext,
    source_id: str,
    kind: str | None,
    url: str | None,
    content: str | None,
    auth_env: str | None,
    clear_auth_env: bool,
    enabled: bool | None,
    auto_sync: bool | None,
    sync_interval_hours: int | None,
    non_interactive: bool,
    emit_json: bool,
) -> None:
    """Update an existing source. Only the flags you pass are changed."""
    cfg = _require_cfg(app)
    source = _find_source(cfg, source_id)

    if not non_interactive:
        if kind is None:
            new = click.prompt("Kind", default=source.kind)
            kind = new if new != source.kind else None
        if content is None:
            new = click.prompt("Content", default=source.content)
            content = new if new != source.content else None
        if url is None:
            new = click.prompt("URL", default=source.url or "")
            url = new if new != source.url else None
        if auth_env is None and not clear_auth_env:
            cur = source.auth_env or "(none)"
            new = click.prompt(
                "Auth env (or 'none' to clear)", default=cur,
            )
            if new == "none" or new == "":
                clear_auth_env = True
            elif new != cur:
                auth_env = new

    if kind is not None:
        source.kind = _validate_kind(kind)
    if content is not None:
        source.content = _validate_content(content)
    if url is not None:
        source.url = (url or "").strip()
    if clear_auth_env:
        source.auth_env = ""
    elif auth_env is not None:
        source.auth_env = _validate_auth_env(auth_env)
    if enabled is not None:
        source.enabled = enabled
    if auto_sync is not None:
        source.auto_sync = auto_sync
    if sync_interval_hours is not None:
        source.sync_interval_hours = max(0, int(sync_interval_hours))

    cfg.save()
    if app.logger:
        app.logger.log_action(
            "registry-edit", "config", f"id={source.id}",
        )

    if emit_json:
        _emit_json({"action": "edit", "source": _source_to_dict(source)})
        return
    ux.ok(f"Updated registry source {source.id!r}.")


# ---------------------------------------------------------------------------
# list / show / remove
# ---------------------------------------------------------------------------

@registry.command("list")
@click.option("--json", "emit_json", is_flag=True)
@pass_ctx
def list_cmd(app: AppContext, emit_json: bool) -> None:
    """List configured registry sources."""
    cfg = _require_cfg(app)
    sources = list(cfg.registries.sources)
    if emit_json:
        _emit_json([_source_to_dict(s) for s in sources])
        return
    if not sources:
        ux.subhead("No registry sources configured.")
        ux.subhead("Add one with: defenseclaw registry add <id> ...")
        return
    click.echo()
    ux.section("Registry sources")
    click.echo(
        f"  {'ID':<24} {'KIND':<12} {'CONTENT':<8} {'ON':<3} {'LAST SYNC':<22} URL"
    )
    click.echo(
        f"  {'-' * 24} {'-' * 12} {'-' * 8} {'-' * 3} {'-' * 22} {'-' * 32}"
    )
    for s in sources:
        on = "yes" if s.enabled else "no"
        last = s.last_sync or "-"
        url = s.url or ""
        if len(url) > 36:
            url = url[:33] + "..."
        click.echo(
            f"  {s.id:<24} {s.kind:<12} {s.content:<8} {on:<3} {last:<22} {url}"
        )
    click.echo()


@registry.command("show")
@click.argument("source_id")
@click.option("--json", "emit_json", is_flag=True)
@pass_ctx
def show_cmd(app: AppContext, source_id: str, emit_json: bool) -> None:
    """Pretty-print a single source plus a quick verdict summary."""
    cfg = _require_cfg(app)
    source = _find_source(cfg, source_id)
    idx = load_index(cfg.data_dir, source.id)
    if emit_json:
        _emit_json({
            "source": _source_to_dict(source),
            "index": idx.to_dict(),
        })
        return
    click.echo()
    state = ux._style("enabled", fg="green") if source.enabled else ux.dim("disabled")
    click.echo(f"  {ux.bold(source.id)} [{source.kind}/{source.content}] {state}")
    click.echo(f"    {ux.dim('URL:')}            {source.url or '(none)'}")
    if source.auth_env:
        click.echo(f"    {ux.dim('Auth env:')}       {source.auth_env} (value not shown)")
    click.echo(f"    {ux.dim('Last sync:')}      {source.last_sync or '(never)'}")
    click.echo(f"    {ux.dim('Last status:')}    {source.last_status or '-'}")
    click.echo(f"    {ux.dim('Entries:')}        {idx.entry_count}")
    click.echo(
        f"    {ux.dim('Verdicts:')}       "
        f"{idx.clean_count} clean, {idx.warning_count} warning, "
        f"{idx.blocked_count} blocked, {idx.error_count} error",
    )
    click.echo()


@registry.command("remove")
@click.argument("source_id")
@click.option("--keep-cache", is_flag=True,
              help="Keep ~/.defenseclaw/registries/<id> on disk")
@click.option("--non-interactive", is_flag=True)
@click.option("--json", "emit_json", is_flag=True)
@pass_ctx
def remove_cmd(
    app: AppContext,
    source_id: str,
    keep_cache: bool,
    non_interactive: bool,
    emit_json: bool,
) -> None:
    """Delete a source and (by default) drop its on-disk cache.

    Promoted ``asset_policy`` rules whose ``Reason="registry:<id>"``
    are removed from config too — the registry source is the source
    of truth for those entries.
    """
    cfg = _require_cfg(app)
    source = _find_source(cfg, source_id)
    sid = source.id

    if not non_interactive and not click.confirm(
        f"Remove registry source {sid!r}?", default=False,
    ):
        ux.subhead("Aborted.")
        return

    cfg.registries.sources = [s for s in cfg.registries.sources if s.id != sid]
    reason = f"registry:{sid}"
    cfg.asset_policy.skill.registry = [
        r for r in cfg.asset_policy.skill.registry if r.reason != reason
    ]
    cfg.asset_policy.mcp.registry = [
        r for r in cfg.asset_policy.mcp.registry if r.reason != reason
    ]
    cfg.save()

    if not keep_cache:
        remove_source_cache(cfg.data_dir, sid)

    if app.logger:
        app.logger.log_action("registry-remove", "config", f"id={sid}")

    if emit_json:
        _emit_json({"action": "remove", "source_id": sid})
        return
    ux.ok(f"Removed registry source {sid!r}.")


# ---------------------------------------------------------------------------
# sync
# ---------------------------------------------------------------------------

@registry.command("sync")
@click.argument("source_ids", nargs=-1)
@click.option("--all", "sync_all_flag", is_flag=True, help="Sync every enabled source")
@click.option("--include-disabled", is_flag=True,
              help="With --all, also sync disabled sources")
@click.option("--scan/--no-scan", default=True,
              help="Run skill/MCP scanners on each entry (default: yes)")
@click.option("--allow-private", is_flag=True,
              help="Permit RFC1918 / ULA destinations (off by default)")
@click.option("--no-promote", is_flag=True,
              help="Don't append promoted rules to asset_policy")
@click.option("--json", "emit_json", is_flag=True)
@pass_ctx
def sync_cmd(  # noqa: PLR0913
    app: AppContext,
    source_ids: tuple[str, ...],
    sync_all_flag: bool,
    include_disabled: bool,
    scan: bool,
    allow_private: bool,
    no_promote: bool,
    emit_json: bool,
) -> None:
    """Fetch, scan, and promote entries from one or more sources.

    Examples:

    \b
      defenseclaw registry sync corp-skills
      defenseclaw registry sync --all
      defenseclaw registry sync --all --no-scan       # metadata-only refresh
      defenseclaw registry sync corp-skills --no-promote   # preview
    """
    cfg = _require_cfg(app)

    callback: ScanCallback | None = (
        _make_scan_callback(app) if scan else None
    )

    if sync_all_flag:
        if source_ids:
            click.echo(
                "error: pass either --all or explicit source ids, not both",
                err=True,
            )
            raise SystemExit(2)
        reports = sync_all(
            cfg,
            cfg.data_dir,
            scan_callback=callback,
            allow_private=allow_private,
            auto_promote=not no_promote,
            include_disabled=include_disabled,
        )
    else:
        if not source_ids:
            click.echo(
                "error: pass at least one source id, or --all",
                err=True,
            )
            raise SystemExit(2)
        reports = []
        for sid in source_ids:
            source = _find_source(cfg, sid)
            reports.append(sync_source(
                cfg,
                cfg.data_dir,
                source,
                scan_callback=callback,
                allow_private=allow_private,
                auto_promote=not no_promote,
                save=False,
            ))
        cfg.save()

    if emit_json:
        _emit_json([r.to_dict() for r in reports])
        return
    _print_sync_reports(reports)


def _print_sync_reports(reports: list[SyncReport]) -> None:
    if not reports:
        ux.subhead("Nothing to sync.")
        return
    click.echo()
    ux.section("Sync results")
    click.echo(
        f"  {'SOURCE':<24} {'FETCHED':<8} {'SCANNED':<8} {'PROMOTED':<10} {'STATUS'}"
    )
    click.echo(
        f"  {'-' * 24} {'-' * 8} {'-' * 8} {'-' * 10} {'-' * 32}"
    )
    for r in reports:
        promoted = f"{r.promoted_skills}/{r.promoted_mcps}"
        status = "ok" if r.ok() else "error"
        click.echo(
            f"  {r.source_id:<24} {r.fetched:<8} {r.scanned:<8} {promoted:<10} {status}"
        )
    for r in reports:
        for err in r.errors:
            click.echo(f"  {ux.dim('!')} {r.source_id}: {err}")
    click.echo()


# Lazy scanner factory — keeps the heavy SDK import off the hot path
# of `registry list` / `registry show`. Returns None when scanner SDKs
# aren't installed so the operator still gets a metadata-only sync.
def _make_scan_callback(app: AppContext) -> ScanCallback:
    cfg = _require_cfg(app)

    def _scan(source: RegistrySource, entry: ManifestEntry):  # type: ignore[no-untyped-def]
        if entry.is_skill():
            return _run_skill_scan(app, cfg, source, entry)
        if entry.is_mcp():
            return _run_mcp_scan(app, cfg, source, entry)
        return None

    return _scan


def _run_skill_scan(app: AppContext, cfg: Config, source: RegistrySource, entry: ManifestEntry):  # type: ignore[no-untyped-def]
    """Best-effort skill scan via the SDK wrapper.

    The full clawhub:// / https:// download flow is delegated to the
    existing helpers in :mod:`cmd_skill` so we don't duplicate the
    archive-extraction logic. Failures fall through to a None return,
    which leaves the entry at status="pending" — operators can then
    use ``registry approve`` to promote it manually.
    """
    # Optional dep: the skill scanner SDK ships separately from the
    # CLI so on a stripped install (operator without the scanner
    # extras) we degrade to "leave the entry pending" instead of
    # crashing the whole sync. The import is purely a presence
    # check; the actual scan goes through cmd_skill below.
    try:
        from defenseclaw.scanner.skill import SkillScannerWrapper  # noqa: F401
    except ImportError:
        return None
    if not entry.source_url:
        return None
    try:
        from defenseclaw.commands import cmd_skill  # local import to avoid cycle
    except ImportError:
        return None

    target = entry.source_url
    if target.startswith("clawhub://"):
        return _scan_skill_via_clawhub(cmd_skill, app, target)
    if target.startswith(("http://", "https://")):
        return _scan_skill_via_http(cmd_skill, app, target)
    return None


def _scan_skill_via_clawhub(cmd_skill_module, app: AppContext, uri: str):  # type: ignore[no-untyped-def]
    # Reuse the existing helper so policy/option behaviour stays in
    # lockstep. The helper exits the process on hard errors; we wrap
    # that in a try so a single failure doesn't kill `registry sync`.
    try:
        cmd_skill_module._scan_from_clawhub(app, uri, as_json=True)  # type: ignore[attr-defined]
    except SystemExit:
        return None
    except Exception:  # noqa: BLE001 - keep the loop alive
        return None
    return None


def _scan_skill_via_http(cmd_skill_module, app: AppContext, url: str):  # type: ignore[no-untyped-def]
    try:
        cmd_skill_module._scan_from_http(app, url, as_json=True)  # type: ignore[attr-defined]
    except SystemExit:
        return None
    except Exception:  # noqa: BLE001
        return None
    return None


def _run_mcp_scan(app: AppContext, cfg: Config, source: RegistrySource, entry: ManifestEntry):  # type: ignore[no-untyped-def]
    """Best-effort MCP scan via the SDK wrapper."""
    try:
        from defenseclaw.config import MCPServerEntry
        from defenseclaw.scanner.mcp import MCPScannerWrapper
    except ImportError:
        return None
    try:
        scanner = MCPScannerWrapper(
            cfg.scanners.mcp_scanner,
            cfg.effective_inspect_llm(),
            cfg.cisco_ai_defense,
            llm=cfg.resolve_llm("scanners.mcp"),
        )
    except Exception:  # noqa: BLE001
        return None

    transport = entry.transport or "stdio"
    if transport == "stdio":
        if not entry.command:
            return None
        server = MCPServerEntry(
            name=entry.name,
            command=entry.command,
            args=list(entry.args),
            env={k: os.environ.get(k, "") for k in entry.env_required},
        )
        try:
            return scanner.scan(entry.name, server_entry=server)
        except SystemExit:
            return None
        except Exception:  # noqa: BLE001
            return None
    if not entry.url:
        return None
    try:
        return scanner.scan(entry.url)
    except SystemExit:
        return None
    except Exception:  # noqa: BLE001
        return None


# ---------------------------------------------------------------------------
# entries / approve / reject
# ---------------------------------------------------------------------------

@registry.command("entries")
@click.argument("source_id")
@click.option("--type", "entry_type",
              type=click.Choice(["skill", "mcp", "all"], case_sensitive=False),
              default="all")
@click.option("--status",
              type=click.Choice(["pending", "clean", "warning", "blocked", "error", "all"],
                                case_sensitive=False),
              default="all")
@click.option("--json", "emit_json", is_flag=True)
@pass_ctx
def entries_cmd(
    app: AppContext,
    source_id: str,
    entry_type: str,
    status: str,
    emit_json: bool,
) -> None:
    """Show cached entries for a source. Run after ``registry sync``."""
    cfg = _require_cfg(app)
    source = _find_source(cfg, source_id)
    idx = load_index(cfg.data_dir, source.id)
    rows = _filter_verdicts(idx, entry_type, status)
    if emit_json:
        _emit_json([v.to_dict() for v in rows])
        return
    if not rows:
        ux.subhead(f"No matching entries (type={entry_type}, status={status}).")
        return
    click.echo()
    ux.section(f"Entries for {source.id}")
    click.echo(
        f"  {'NAME':<32} {'TYPE':<6} {'STATUS':<10} {'SEV':<8} {'A/R'}"
    )
    click.echo(f"  {'-' * 32} {'-' * 6} {'-' * 10} {'-' * 8} {'-' * 3}")
    for v in rows:
        a = "A" if v.approved else "-"
        r = "R" if v.rejected else "-"
        click.echo(
            f"  {v.name:<32} {v.type:<6} {v.status:<10} {(v.severity or '-'):<8} {a}{r}",
        )
    click.echo()


def _filter_verdicts(idx: SourceIndex, type_: str, status: str) -> list[EntryVerdict]:
    out: list[EntryVerdict] = []
    type_ = type_.lower()
    status = status.lower()
    for v in idx.verdicts:
        if type_ != "all" and v.type != type_:
            continue
        if status != "all" and v.status != status:
            continue
        out.append(v)
    return out


@registry.command("approve")
@click.argument("source_id")
@click.argument("entry_name")
@click.option("--type", "entry_type",
              type=click.Choice(["skill", "mcp"], case_sensitive=False),
              required=True)
@click.option("--repromote/--no-repromote", default=True,
              help="Re-run asset_policy promotion against the cached "
                   "manifest immediately (no network call).")
@click.option("--json", "emit_json", is_flag=True)
@pass_ctx
def approve_cmd(
    app: AppContext,
    source_id: str,
    entry_name: str,
    entry_type: str,
    repromote: bool,
    emit_json: bool,
) -> None:
    """Mark an entry approved. Approved entries promote even if the
    scanner hasn't run, and are preserved across syncs.

    By default the asset_policy promotion is re-run immediately
    against the cached manifest so the new rule lands without a
    network round-trip. Use ``--no-repromote`` if you want to defer
    the update to the next ``registry sync``.
    """
    _do_manual_verdict(
        app, source_id, entry_name, entry_type,
        approved=True, rejected=False,
        action_label="approve", repromote=repromote, emit_json=emit_json,
    )


@registry.command("reject")
@click.argument("source_id")
@click.argument("entry_name")
@click.option("--type", "entry_type",
              type=click.Choice(["skill", "mcp"], case_sensitive=False),
              required=True)
@click.option("--repromote/--no-repromote", default=True,
              help="Re-run asset_policy promotion against the cached "
                   "manifest immediately (no network call).")
@click.option("--json", "emit_json", is_flag=True)
@pass_ctx
def reject_cmd(
    app: AppContext,
    source_id: str,
    entry_name: str,
    entry_type: str,
    repromote: bool,
    emit_json: bool,
) -> None:
    """Mark an entry rejected. Rejected entries are NEVER promoted.

    By default the asset_policy promotion is re-run immediately
    against the cached manifest so any prior rule for this entry is
    cleared. Use ``--no-repromote`` to defer to the next sync.
    """
    _do_manual_verdict(
        app, source_id, entry_name, entry_type,
        approved=False, rejected=True,
        action_label="reject", repromote=repromote, emit_json=emit_json,
    )


def _do_manual_verdict(
    app: AppContext,
    source_id: str,
    entry_name: str,
    entry_type: str,
    *,
    approved: bool,
    rejected: bool,
    action_label: str,
    repromote: bool,
    emit_json: bool,
) -> None:
    """Shared implementation for approve_cmd / reject_cmd.

    Toggles the cached verdict bit, then re-runs promotion against
    the cached manifest (no network). Falls back to surfacing a
    clear error when there's no cached manifest yet — the previous
    implementation would silently swallow a fetch failure here and
    leave the operator believing the rule had landed.
    """
    cfg = _require_cfg(app)
    source = _find_source(cfg, source_id)
    verdict = manual_set_verdict(
        cfg.data_dir, source.id, entry_type.lower(), entry_name,
        approved=approved, rejected=rejected,
    )
    if verdict is None:
        click.echo(
            f"error: no cached entry {entry_type}:{entry_name} in {source.id} "
            "(run `registry sync` first)",
            err=True,
        )
        raise SystemExit(2)

    promoted: tuple[int, int] | None = None
    if repromote:
        promoted = promote_from_cache(
            cfg, cfg.data_dir, source, save=True,
        )

    if app.logger:
        app.logger.log_action(
            f"registry-{action_label}", "config",
            f"id={source.id} {entry_type}:{entry_name}",
        )

    if emit_json:
        out: dict[str, Any] = {
            "action": action_label,
            "verdict": verdict.to_dict(),
        }
        if promoted is not None:
            out["promoted_skills"] = promoted[0]
            out["promoted_mcps"] = promoted[1]
        elif repromote:
            out["warning"] = (
                "no cached manifest; rule will land on next "
                "`registry sync`"
            )
        _emit_json(out)
        return

    label = "Approved" if approved else "Rejected"
    ux.ok(f"{label} {entry_type}:{entry_name} from {source.id}.")
    if repromote and promoted is None:
        ux.subhead(
            "No cached manifest yet — run `defenseclaw registry sync "
            f"{source.id}` to fetch and promote.",
        )


# ---------------------------------------------------------------------------
# require — toggle asset_policy.{type}.registry_required
# ---------------------------------------------------------------------------

@registry.command("require")
@click.option("--type", "asset_type",
              type=click.Choice(["skill", "mcp", "plugin"], case_sensitive=False),
              required=True)
@click.option("--enabled/--disabled", required=True,
              help="Flip asset_policy.<type>.registry_required")
@click.option("--json", "emit_json", is_flag=True)
@pass_ctx
def require_cmd(
    app: AppContext,
    asset_type: str,
    enabled: bool,
    emit_json: bool,
) -> None:
    """Toggle ``asset_policy.<type>.registry_required``.

    When enabled, an asset must match a rule in the (type) registry
    list to bypass the default deny — otherwise the configured
    ``default`` action applies. The flag is fail-closed by default at
    the gateway: an empty registry list with require=on means "no
    asset is approved".
    """
    cfg = _require_cfg(app)
    target = getattr(cfg.asset_policy, asset_type.lower())
    target.registry_required = bool(enabled)
    cfg.save()
    asset = asset_type.lower()
    empty_registry = len(target.registry) == 0
    empty_action = getattr(target, "registry_empty_action", "deny")

    if emit_json:
        _emit_json({
            "asset_type": asset,
            "registry_required": target.registry_required,
            "registry_size": len(target.registry),
            "registry_empty_action": empty_action,
        })
        return

    state = "required" if enabled else "optional"
    ux.ok(f"asset_policy.{asset}.registry is now {state}.")
    if not enabled:
        return

    # Operators routinely flip require=on without realising the
    # downstream gateway will deny every asset whose name isn't on
    # the (often-empty) registry list. Spell that out, in colour, so
    # the next `claw run` doesn't surprise them. The empty-action is
    # configurable (deny / warn / allow) but defaults to "deny" — we
    # surface whichever value is live.
    if empty_registry:
        if empty_action == "deny":
            ux.warn(
                f"registries.{asset}.registry is EMPTY and "
                f"registry_empty_action='deny' — every {asset} will be "
                "blocked at admission until you `registry sync` (or add "
                "manual rules).",
            )
        elif empty_action == "warn":
            ux.warn(
                f"registries.{asset}.registry is empty and "
                "registry_empty_action='warn' — assets will be allowed "
                "but flagged in the audit log. Run `registry sync` to "
                "populate the list.",
            )
        else:
            ux.subhead(
                f"registries.{asset}.registry is empty and "
                f"registry_empty_action={empty_action!r} — admission "
                "will fall back to the configured default action.",
            )
    else:
        ux.subhead(
            f"registry has {len(target.registry)} entries; "
            f"registry_empty_action={empty_action!r} (only matters when "
            "the list is empty).",
        )


# ---------------------------------------------------------------------------
# wizard — convenience flow that bundles add + immediate sync
# ---------------------------------------------------------------------------

@registry.command("wizard")
@pass_ctx
@click.pass_context
def wizard_cmd(ctx: click.Context, app: AppContext) -> None:
    """Interactive add+sync flow for first-run discoverability."""
    if not sys.stdin.isatty():
        click.echo("error: wizard requires an interactive terminal", err=True)
        raise SystemExit(2)

    click.echo()
    ux.section("Register a new registry source")
    sid = click.prompt("Source id (kebab-case)", default="corp-skills")
    kind = click.prompt(
        f"Kind ({'/'.join(REGISTRY_KINDS)})", default="http_yaml",
    )
    content = click.prompt(
        f"Content ({'/'.join(REGISTRY_CONTENT_TYPES)})", default="skill",
    )
    url = ""
    if kind == "skills_sh":
        url = click.prompt(
            "Manifest URL or view (curated/all-time/trending/hot)",
            default="curated",
        )
    elif kind != "clawhub":
        url = click.prompt("Manifest URL")
    auth_env = ""
    if click.confirm("Use an auth token (read from an env var)?", default=False):
        auth_env = click.prompt("Env var name", default="DEFENSECLAW_REGISTRY_TOKEN")

    ctx.invoke(
        add_cmd,
        source_id=sid,
        kind=kind,
        url=url,
        content=content,
        auth_env=auth_env or None,
        enabled=True,
        auto_sync=False,
        sync_interval_hours=24,
        non_interactive=True,
        emit_json=False,
    )

    if click.confirm("Sync now?", default=True):
        scan = click.confirm("Run scanners during sync?", default=True)
        ctx.invoke(
            sync_cmd,
            source_ids=(sid,),
            sync_all_flag=False,
            include_disabled=False,
            scan=scan,
            allow_private=False,
            no_promote=False,
            emit_json=False,
        )


# ---------------------------------------------------------------------------
# Helpers exposed for tests
# ---------------------------------------------------------------------------

def _config_dump_for_test(cfg: Config) -> dict[str, Any]:
    """Test helper — return the config slice the registry CLI mutates."""
    return {
        "registries": [_source_to_dict(s) for s in cfg.registries.sources],
        "asset_policy.skill.registry": [
            asdict(r) for r in cfg.asset_policy.skill.registry
        ],
        "asset_policy.mcp.registry": [
            asdict(r) for r in cfg.asset_policy.mcp.registry
        ],
    }
