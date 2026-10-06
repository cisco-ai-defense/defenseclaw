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

"""defenseclaw config — inspect and validate configuration.

Subcommands:

* ``config validate`` — parse ``~/.defenseclaw/config.yaml`` and
  return a non-zero exit code on any error. Used both by the operator
  and by the auto-validate hook in ``main.py``.
* ``config show`` — render the config as JSON or YAML with secrets
  masked (observability resolved; every other section as written, with
  defaults for the keys config.yaml leaves out).
* ``config get`` — print one dotted key of that view.
* ``config set`` / ``config unset`` — change one key through the single
  config writer (validated first; refused with exit 3 on a managed device).
* ``config migrate`` — move config.yaml to config_version 9.
* ``config reference`` — render schema-generated v8 reference material.
* ``config path`` — print the filesystem layout DefenseClaw uses.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import fields, is_dataclass
from pathlib import Path

import click
import yaml

from defenseclaw import config as config_module
from defenseclaw import ux
from defenseclaw.config_inspect import (
    ConfigInspectError,
    ConfigInspectTimeoutError,
    config_v8_reference,
    config_v8_schema,
    inspect_v8_config,
)
from defenseclaw.context import AppContext, pass_ctx
from defenseclaw.observability.v8_config import MAX_SOURCE_BYTES, V8ConfigError, load_validate_v8
from defenseclaw.webhooks.writer import redact_webhook_url

# Field names here catch both the bare form (``api_key``) and the
# suffixed form (``virustotal_api_key``). We deliberately exclude any
# field ending in ``_env`` because those hold env-var *names* (e.g.
# ``JUDGE_API_KEY``), not the secret values themselves.
_SECRET_FIELDS = (
    "api_key",
    "token",
    "secret",
    "password",
    "hec_token",
    "private_key",
    "pepper",
)

_V8_VERSION_LINE = re.compile(
    rb"(?m)^config_version\s*:\s*"
    rb"(?:(?:!!int|tag:yaml\.org,2002:int)\s+)?"
    rb"(?:[89]|['\"][89]['\"])\s*(?:#.*)?$"
)
_MAX_VERSION_PROBE_BYTES = 4 * 1024 * 1024 + 1


@click.group("config")
@click.pass_context
def config_cmd(ctx: click.Context) -> None:
    """Inspect and validate DefenseClaw configuration."""

    # The root command lets this group run while a pre-v8 source still exists,
    # so ``validate`` can explain a file the root preflight would only refuse,
    # and ``reference`` reads no file. Every other subcommand needs a
    # current-schema source and stops with the one instruction.
    subcommand = ctx.invoked_subcommand
    path = config_module.config_path()
    if (
        subcommand
        and subcommand not in {"validate", "reference"}
        and path.exists()
        and not _looks_like_v8_config(str(path))
    ):
        raise click.ClickException("Configuration schema v8 is required — run 'defenseclaw migrate' first.")


# ---------------------------------------------------------------------------
# validate
# ---------------------------------------------------------------------------


@config_cmd.command("validate")
@click.option("--quiet", is_flag=True, help="Exit 0/1 with no stdout output.")
def config_validate(quiet: bool) -> None:
    """Verify the config file parses and references valid enums."""
    result = validate_config()
    if quiet:
        raise SystemExit(0 if result.ok else 1)

    click.echo()
    click.echo(f"  {ux.bold('Config:')} {result.path}")
    if result.exists:
        ux.ok("file exists", indent="  ")
    else:
        ux.warn("file does not exist yet — run 'defenseclaw init' or 'defenseclaw quickstart'")

    if result.parse_error:
        ux.err(f"parse error: {result.parse_error}", indent="  ")
    elif result.ok:
        ux.ok("syntax OK", indent="  ")

    for issue in result.errors:
        ux.err(issue, indent="  ")
    for warning in result.warnings:
        ux.warn(warning, indent="  ")

    click.echo()
    if not result.ok:
        raise SystemExit(1)
    ux.ok("config is valid", indent="  ")


# ---------------------------------------------------------------------------
# show
# ---------------------------------------------------------------------------


@config_cmd.command("show")
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["yaml", "json"], case_sensitive=False),
    default="yaml",
    show_default=True,
    help="Output format.",
)
@click.option("--source", is_flag=True, help="Show config.yaml as written (secrets masked), unresolved.")
@click.option(
    "--effective",
    is_flag=True,
    help="Show only the observability section, resolved with its defaults and expansions.",
)
@click.option(
    "--provenance",
    is_flag=True,
    help="With --effective, also show where each observability setting comes from.",
)
@click.option(
    "--section",
    metavar="NAME",
    default=None,
    help="Show one top-level section, for example asset_policy, guardrail or observability.",
)
@pass_ctx
def config_show(
    app: AppContext,
    fmt: str,
    source: bool,
    effective: bool,
    provenance: bool,
    section: str | None,
) -> None:
    """Show the configuration with secrets masked.

    Every section is shown: the values config.yaml sets plus the defaults
    that apply to the keys it leaves out, with the observability section
    resolved the way the gateway runs it. --source shows only what
    config.yaml sets. Read one value with 'defenseclaw config get KEY', for
    example asset_policy.enabled.
    """
    data = _show_data(app, source=source, effective=effective, provenance=provenance)
    if section:
        view = "effective" if (effective or provenance) else ("source" if source else "full")
        data = _select_section(data, section, view=view)
    if provenance:
        effective_observability = data.get("observability")
        if isinstance(effective_observability, dict):
            effective_observability = dict(effective_observability)
            annotations = effective_observability.pop("provenance", [])
            data["observability"] = effective_observability
        else:
            annotations = []
        data["_provenance"] = {
            "basis": "canonical_go_effective_plan",
            "annotations": annotations,
        }
    _emit(data, fmt)


@config_cmd.command("get")
@click.argument("key")
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["yaml", "json"], case_sensitive=False),
    default="yaml",
    show_default=True,
    help="Format of a section or list value.",
)
@click.option(
    "--effective",
    is_flag=True,
    help="Print the value the gateway enforces and where it comes from "
    "(config.yaml, the rule pack's default, the derived scanner gate).",
)
@pass_ctx
def config_get(app: AppContext, key: str, fmt: str, effective: bool) -> None:
    """Print one configuration value (secrets masked).

    KEY is a dotted path with [i] list indexes, such as asset_policy.enabled or
    asset_policy.skill.denied[0].name. A key config.yaml leaves out prints
    its default, with a note on stderr. With --effective, guardrail levels
    (guardrail.block_at, guardrail.connectors.<c>.alert_at) and admission[.<type>]
    print what the gateway resolves them to; admission keys config.yaml leaves
    out always print that resolved value. Exits 1 when the key has no value
    and no default, and 2 for an unknown section.
    """
    from defenseclaw.config_writer import parse_path

    if not key.strip():
        raise click.UsageError("KEY must be a dotted path such as asset_policy.enabled")
    try:
        parts = list(parse_path(key.strip()))
    except ValueError as exc:
        raise click.UsageError(str(exc)) from exc
    if effective or (parts[0] == "admission" and not _written_in_source(app, parts)):
        resolved = _effective_value(app, parts)
        if resolved is not None:
            value, source = resolved
            click.echo(f"(source: {source})", err=True)
            _echo_value(value, fmt)
            return
    view = _show_data(app, source=False, effective=False, provenance=False)
    if parts[:2] == ["observability", "destinations"]:
        # config set indexes the destinations as written in config.yaml; the
        # resolved plan also lists the generated ones, such as local-sqlite
        # at index 0 (GAP-0008).
        written = _show_data(app, source=True, effective=False, provenance=False)
        if _lookup(written, parts)[0]:
            view = written
    found, value = _lookup(view, parts)
    if not found:
        sections = _v8_sections() or set(view)
        if parts[0] not in view and parts[0] not in sections:
            available = ", ".join(sorted(sections)) or "none"
            raise click.UsageError(f"no configuration section '{parts[0]}'. Sections: {available}")
        if parts[0] not in view:
            raise click.ClickException(
                f"{key} is not set: config.yaml has no '{parts[0]}' section and it has no defaults."
            )
        raise click.ClickException(
            f"{key} is not set and has no default. "
            f"Run 'defenseclaw config show --section {parts[0]}' to see the keys it has."
        )
    if parts[0] != "observability":
        written = _show_data(app, source=True, effective=False, provenance=False)
        if not _lookup(written, parts)[0]:
            click.echo(f"(default: config.yaml does not set {key})", err=True)
        elif effective:
            click.echo(f"(source: {config_module.config_path()})", err=True)
    _echo_value(value, fmt)


def _written_in_source(app: AppContext, parts: list) -> bool:
    """Whether config.yaml itself sets the key (a v8 or later source only)."""
    if not _looks_like_v8_config(str(config_module.config_path())):
        return True
    return _lookup(_show_data(app, source=True, effective=False, provenance=False), parts)[0]


def _echo_value(value: object, fmt: str) -> None:
    if isinstance(value, (dict, list)) or fmt.lower() == "json":
        _emit(value, fmt)
    elif isinstance(value, bool):
        click.echo("true" if value else "false")
    elif value is None:
        click.echo("null")
    else:
        click.echo(str(value))


_LEVEL_KEYS = ("block_at", "alert_at")
_ADMISSION_TYPES = ("skill", "mcp", "plugin")


def _effective_value(app: AppContext, parts: list[str]) -> tuple[object, str] | None:
    """The resolved value of a guardrail level or admission.<type> key and its
    source, as the gateway resolves them; None for any other key."""
    cfg = app.cfg if app.cfg is not None else config_module.load()
    if parts[0] == "guardrail" and parts[-1] in _LEVEL_KEYS:
        if len(parts) == 2:
            connector = ""
        elif len(parts) == 4 and parts[1] == "connectors":
            connector = parts[2]
        else:
            return None
        from defenseclaw.policy_catalog import level_name, pack_profile, scope_levels, scope_pack_path

        levels = scope_levels(cfg, connector)
        which = parts[-1]
        source = levels.block_source if which == "block_at" else levels.alert_source
        value = level_name(levels.block_rank if which == "block_at" else levels.alert_rank)
        if source == "pack":
            label = f"pack-default:{pack_profile(scope_pack_path(cfg, connector))}"
        elif source == "global":
            label = f"config:guardrail.{which}"
        else:
            label = f"config:guardrail.connectors.{connector}.{which}"
        if which == "alert_at" and levels.alert_clamped:
            label += " (clamped to block_at)"
        return value, label
    if parts[0] == "admission" and (len(parts) == 1 or parts[1] in _ADMISSION_TYPES):
        if len(parts) == 1:
            views = {name: _admission_view(cfg, name) for name in _ADMISSION_TYPES}
            return (
                {name: data for name, (data, _) in views.items()},
                ", ".join(f"{name}={source}" for name, (_, source) in views.items()),
            )
        data, source = _admission_view(cfg, parts[1])
        found, value = _lookup(data, parts[2:]) if len(parts) > 2 else (True, data)
        if not found:
            return None
        return value, source
    return None


def _admission_view(cfg: object, target_type: str) -> tuple[dict, str]:
    """The admission policy of one asset type as the gateway enforces it, and its source."""
    from defenseclaw.enforce.admission import ADMISSION_SEVERITY_ORDER, action_label, compile_admission

    compiled = compile_admission(cfg, target_type)
    data = {
        "scan_on_install": compiled.scan_on_install,
        "allow_list_bypass_scan": compiled.allow_list_bypass_scan,
        "actions": {
            sev.lower(): action_label(compiled.actions[sev])
            for sev in ADMISSION_SEVERITY_ORDER
            if sev in compiled.actions
        },
        "scanner_overrides": {
            scanner: {sev.lower(): action_label(action) for sev, action in actions.items()}
            for scanner, actions in compiled.scanner_overrides.items()
        },
        "first_party_allow_list": [
            {"name": name, "source_path_contains": list(paths)}
            for name, paths in compiled.first_party_allow.items()
        ],
    }
    return data, compiled.source


# ---------------------------------------------------------------------------
# set / unset / migrate (the single config writer)
# ---------------------------------------------------------------------------

#: Exit code for a change refused on a managed device.
MANAGED_EXIT_CODE = 3


def _write_config_change(app: AppContext, changes: list, expect_sha256: str | None, verb: str) -> bool:
    """Apply the changes in one write through the writer; False when they changed nothing."""
    from defenseclaw import config_writer

    path = str(config_module.config_path())
    key = ", ".join(getattr(change, "path", "") for change in changes)
    try:
        result = config_writer.apply(
            changes,
            config_writer.current_actor(config_writer.ACTOR_PREFIX_CLI),
            f"defenseclaw config {verb}",
            expect_sha256,
            path=path,
        )
    except config_writer.ManagedConfigWriteError as exc:
        from defenseclaw.enforce.asset_lists import audit_managed_refusal

        audit_managed_refusal("config-update", key or "config", f"verb={verb}")
        click.echo(f"error: {exc}", err=True)
        raise SystemExit(MANAGED_EXIT_CODE) from exc
    except config_writer.ConfigConflictError as exc:
        raise click.ClickException("config.yaml changed since --expect-sha256 was read; read it again") from exc
    except (config_writer.ConfigWriteError, V8ConfigError, ValueError) as exc:
        raise click.ClickException(f"config.yaml was not changed: {config_writer.plain_error(exc)}") from exc
    if not result.changed:
        if verb != "unset":
            click.echo(f"{key} already has that value (generation {result.generation}).")
        return False
    click.echo(f"{verb.capitalize()} {key} (config generation {result.generation}, sha256 {result.sha256[:12]}).")
    from defenseclaw.gateway import local_policy_digest

    digest = local_policy_digest(app.cfg if app.cfg is not None else config_module.load(), timeout=20)
    if digest:
        click.echo(f"Effective policy digest: {digest['effective_digest']}")
    if result.restart_required:
        click.echo(
            f"Restart the gateway to apply {', '.join(result.restart_required)}: defenseclaw-gateway restart"
        )
    logger = getattr(app, "logger", None)
    if logger is not None:
        try:
            logger.log_config_change(
                f"config-{verb}", f"{key}=" + ("(unset)" if verb == "unset" else "(set)")
            )
        except Exception:  # noqa: BLE001 - the change is committed; audit is best effort
            pass
    return True


@config_cmd.command("set")
@click.argument("key")
@click.argument("value")
@click.option("--json", "as_json", is_flag=True, help="Parse VALUE as JSON instead of a YAML scalar.")
@click.option("--expect-sha256", default=None, help="Refuse the change unless config.yaml still has this sha256.")
@pass_ctx
def config_set(app: AppContext, key: str, value: str, as_json: bool, expect_sha256: str | None) -> None:
    """Set one configuration value through the config writer.

    KEY is a dotted path with [i] list indexes, for example
    guardrail.block_at or asset_policy.skill.denied[0].name. VALUE is a YAML
    scalar (true, 3, HIGH) or, with --json, any JSON value. The change is
    validated before it is written; on a managed device it is refused (exit 3).
    """
    from defenseclaw.config_writer import Change, parse_path

    try:
        parse_path(key)
        parsed = json.loads(value) if as_json else yaml.safe_load(value)
    except (ValueError, yaml.YAMLError) as exc:
        raise click.UsageError(str(exc)) from exc
    _write_config_change(app, [Change(key, parsed)], expect_sha256, "set")


@config_cmd.command("unset")
@click.argument("keys", nargs=-1, required=True)
@click.option("--expect-sha256", default=None, help="Refuse the change unless config.yaml still has this sha256.")
@pass_ctx
def config_unset(app: AppContext, keys: tuple[str, ...], expect_sha256: str | None) -> None:
    """Remove configuration keys (their defaults apply again).

    Several KEYs are removed in one validated write, so a pair that depends on
    each other, such as openshell.admin.required_pack and
    openshell.admin.required_pack_digest, can go together.
    """
    from defenseclaw.config_writer import Change, parse_path

    try:
        parsed = [(key, list(parse_path(key))) for key in keys]
    except ValueError as exc:
        raise click.UsageError(str(exc)) from exc
    if _write_config_change(app, [Change(key, unset=True) for key in keys], expect_sha256, "unset"):
        return
    # Nothing was removed: a key with a default is already unset, anything
    # else is not a configuration key (a typo must not look like success).
    view = _show_data(app, source=False, effective=False, provenance=False)
    for key, parts in parsed:
        if not _lookup(view, parts)[0]:
            raise click.ClickException(f"{key} is not a configuration key; config.yaml was not changed.")
    if len(keys) == 1:
        click.echo(f"{keys[0]} is not set in config.yaml; its default already applies.")
    else:
        click.echo(f"{', '.join(keys)} are not set in config.yaml; their defaults already apply.")


@config_cmd.command("migrate")
@click.option("--dry-run", is_flag=True, help="Show what would move; write nothing.")
@click.option("--ack", is_flag=True, help="Mark migration-v9.json as read so doctor stops reporting it.")
@click.option("--json", "as_json", is_flag=True, help="Print the migration result as JSON.")
def config_migrate(dry_run: bool, ack: bool, as_json: bool) -> None:
    """Migrate config.yaml to config_version 9 (or acknowledge the migration).

    Moves the admission policy in policies/rego/data.json, the *_actions
    keys, rule_pack_dir, the v8 scanner keys, update_check and the operator
    block/allow entries of audit.db into config.yaml. Keeps
    config.yaml.v8.bak and writes migration-v9.json.
    """
    from defenseclaw.config_inspect import migrate_config_v9

    path = str(config_module.config_path())
    try:
        result = migrate_config_v9(config_path=path, dry_run=dry_run, ack=ack)
    except ConfigInspectError as exc:
        raise click.ClickException(str(exc)) from exc
    if ack:
        click.echo("Marked the config_version 9 migration record as read.")
        return
    if as_json:
        click.echo(json.dumps(result, indent=2))
        return
    record = result.get("record") or {}
    if record.get("from_version") == 9:
        click.echo("config.yaml is already config_version 9; nothing to migrate.")
        return
    verb = "Would move" if dry_run else "Moved"
    click.echo(
        f"{verb} {len(record.get('moved') or [])} values into config.yaml; "
        f"{len(record.get('conflicts') or [])} conflicts."
    )
    for move in record.get("moved") or []:
        click.echo(f"  {move.get('from')} -> {move.get('to')}")
    for conflict in record.get("conflicts") or []:
        click.echo(f"  conflict {conflict.get('to')}: kept {conflict.get('kept')}, dropped {conflict.get('lost')}")
    for note in record.get("notes") or []:
        click.echo(f"  note: {note}")


def _lookup(data: object, parts: list[str]) -> tuple[bool, object]:
    """Follow a dotted path through dicts and list indexes."""
    value = data
    for part in parts:
        if isinstance(value, dict) and part in value:
            value = value[part]
        elif isinstance(value, list) and isinstance(part, int) and 0 <= part < len(value):
            value = value[part]
        elif isinstance(value, list) and isinstance(part, str) and part.isdigit() and int(part) < len(value):
            value = value[int(part)]
        else:
            return False, None
    return True, value


def _v8_schema() -> dict:
    try:
        from defenseclaw.observability.v8_config import _schema_validator

        return _schema_validator().schema
    except Exception:  # noqa: BLE001 - without the schema, show only what is written.
        return {}


def _v8_sections() -> set[str]:
    return set((_v8_schema().get("properties") or {}).keys())


def _v8_defaults(app: AppContext) -> dict:
    """The masked values the CLI runs with, pruned to v8 schema keys.

    They fill the keys config.yaml leaves out, so a fresh install shows
    asset_policy.enabled and the rest (GAP-2171).
    """
    schema = _v8_schema()
    if not schema:
        return {}
    try:
        cfg = app.cfg if app.cfg is not None else config_module.load()
    except Exception:  # noqa: BLE001 - fall back to the built-in defaults.
        cfg = config_module.default_config()
    defs = schema.get("$defs") or {}

    def _resolve(node: object) -> object:
        while isinstance(node, dict) and "$ref" in node:
            node = defs.get(str(node["$ref"]).rsplit("/", 1)[-1])
        return node

    def _prune(value: object, node: object) -> object:
        node = _resolve(node)
        if not isinstance(value, dict) or not isinstance(node, dict) or "properties" not in node:
            return value
        props = node["properties"]
        return {k: _prune(v, props[k]) for k, v in value.items() if k in props}

    return _prune(_config_to_masked_dict(cfg), schema)  # type: ignore[return-value]


def _merge_defaults(written: dict, defaults: dict) -> dict:
    merged = dict(defaults)
    for key, value in written.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _merge_defaults(value, merged[key])
        else:
            merged[key] = value
    return merged


def _show_data(app: AppContext, *, source: bool, effective: bool, provenance: bool) -> dict:
    """Return the masked view 'config show' and 'config get' print."""
    if source and effective:
        raise click.UsageError("--source and --effective are mutually exclusive")
    if source and provenance:
        raise click.UsageError("--provenance annotates the effective view and cannot be combined with --source")

    cfg_path = str(config_module.config_path())
    if not os.path.isfile(cfg_path):
        # No config.yaml yet: show the defaults the CLI would run with.
        if source or effective or provenance:
            raise click.ClickException(
                "config.yaml does not exist yet; run 'defenseclaw init' or 'defenseclaw quickstart'"
            )
        return _v8_defaults(app)
    resolved_only = effective or provenance
    masked: dict = {}
    if not resolved_only:
        try:
            raw = Path(cfg_path).read_bytes()
            masked = dict(load_validate_v8(raw, source_name=cfg_path).masked)
        except OSError as exc:
            raise click.ClickException(f"cannot read configuration source: {exc}") from exc
        except (V8ConfigError, RuntimeError) as exc:
            raise click.ClickException(str(exc)) from exc
        if source:
            return masked
        masked = _merge_defaults(masked, _v8_defaults(app))
    try:
        result = inspect_v8_config("effective", config_path=cfg_path)
    except ConfigInspectError as exc:
        raise click.ClickException(str(exc)) from exc
    # Only observability has a canonical resolved plan; every other section is
    # shown as written plus its defaults (GAP-2171).
    masked["observability"] = result.effective or {}
    return masked


def _select_section(data: dict, section: str, *, view: str = "full") -> dict:
    name = section.strip().lower()
    if name in data:
        return {name: data[name]}
    if view == "effective":
        raise click.UsageError("--effective shows only the observability section; drop --effective for other sections")
    if name in _v8_sections():
        if view == "source":
            raise click.ClickException(
                f"config.yaml does not set '{name}'. Drop --source to see the defaults that apply"
            )
        raise click.ClickException(f"section '{name}' is not set in config.yaml and has no defaults")
    available = ", ".join(sorted(key for key in data if not key.startswith("_"))) or "none"
    raise click.UsageError(f"no section '{name}' in this view. Sections: {available}")


def _emit(data: object, fmt: str) -> None:
    if fmt.lower() == "json":
        click.echo(json.dumps(data, indent=2, sort_keys=True))
    else:
        click.echo(yaml.safe_dump(data, sort_keys=True, default_flow_style=False).rstrip())


# ---------------------------------------------------------------------------
# reference
# ---------------------------------------------------------------------------


_ALL_FIELDS_COMMAND = "defenseclaw config reference --format json-schema"

# Build provenance lines of the generated YAML reference; they name repository
# files a user does not have and tell them not to edit what they may copy.
_GENERATOR_HEADER_LINES = ("# GENERATED FILE. DO NOT EDIT.", "# Canonical schema:", "# Generator:")


def _strip_generator_header(rendered: str) -> str:
    lines = rendered.splitlines(keepends=True)
    kept: list[str] = []
    for line in lines[:12]:
        if line.startswith(_GENERATOR_HEADER_LINES):
            continue
        if line.strip() == "#" and kept and kept[-1].strip() == "#":
            continue
        kept.append(line)
    return "".join(kept + lines[12:])


@config_cmd.command("reference")
@click.argument(
    "section",
    type=click.Choice(["observability"], case_sensitive=False),
    required=False,
    default="observability",
)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["yaml", "json-schema", "markdown"], case_sensitive=False),
    default="yaml",
    show_default=True,
    help="Output format.",
)
@click.option(
    "--output",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Write the reference to this file instead of stdout.",
)
def config_reference(section: str, fmt: str, output: Path | None) -> None:
    """Print the configuration reference for this version.

    The yaml and markdown formats cover SECTION, and observability is the
    only section they have. --format json-schema prints the schema of every
    section (guardrail, gateway, scanners and the rest) with each field's
    allowed values.
    """

    try:
        rendered = (
            config_v8_schema() if fmt.lower() == "json-schema" else config_v8_reference(fmt, section=section.lower())
        )
    except ConfigInspectError as exc:
        raise click.ClickException(str(exc)) from exc
    if fmt.lower() == "yaml":
        rendered = _strip_generator_header(rendered)

    if output is None:
        click.echo(rendered, nl=not rendered.endswith("\n"))
        return
    try:
        with click.open_file(str(output), mode="w", encoding="utf-8", atomic=True) as stream:
            stream.write(rendered)
    except OSError as exc:
        raise click.ClickException(f"cannot write reference output: {exc}") from exc


# ---------------------------------------------------------------------------
# path
# ---------------------------------------------------------------------------


@config_cmd.command("path")
@pass_ctx
def config_path(app: AppContext) -> None:
    """Print the filesystem locations DefenseClaw uses."""
    cfg_path = str(config_module.config_path())
    if app.cfg is not None:
        cfg = app.cfg
    elif os.path.isfile(cfg_path):
        cfg = _v8_config_path_view(cfg_path)
    else:
        cfg = config_module.load()
    click.echo()
    rows = [
        ("config file", config_module.config_path()),
        ("data dir", cfg.data_dir),
        ("audit DB", cfg.audit_db),
        ("policy dir", cfg.policy_dir),
        ("plugin dir", cfg.plugin_dir),
        ("quarantine dir", cfg.quarantine_dir),
        ("dotenv", os.path.join(cfg.data_dir, ".env")),
        ("device key", cfg.gateway.device_key_file),
    ]
    # OpenClaw paths matter only when OpenClaw is set up on this host.
    claw_rows = [
        ("OpenClaw config", cfg.claw.config_file),
        ("OpenClaw home", cfg.claw.home_dir),
    ]
    if any(value and os.path.exists(os.path.expanduser(str(value))) for _, value in claw_rows):
        rows.extend(claw_rows)
    label_width = max(len(lbl) for lbl, _ in rows) + 2  # colon plus one space
    for label, value in rows:
        exists = value and os.path.exists(os.path.expanduser(str(value)))
        marker = ux._style("✓", fg="green", bold=True) if exists else ux.dim("·")
        padded = (label + ":").ljust(label_width)
        click.echo(f"  {marker}  {ux._style(padded, fg='bright_black', bold=True)}{value}")
    click.echo()


# ---------------------------------------------------------------------------
# Public helpers (shared with main.py auto-validate)
# ---------------------------------------------------------------------------


class ValidationResult:
    """Plain container so this module has zero Click dependencies at import."""

    def __init__(self) -> None:
        self.path: str = ""
        self.exists: bool = False
        self.parse_error: str = ""
        self.errors: list[str] = []
        self.warnings: list[str] = []
        # The canonical validator did not finish (a busy host); the file was
        # not judged invalid (GAP-1621).
        self.timed_out: bool = False

    @property
    def ok(self) -> bool:
        return not self.parse_error and not self.errors


def validate_config() -> ValidationResult:
    """Parse config, return structured diagnostics (no I/O on success)."""
    res = ValidationResult()
    cfg_path = str(config_module.config_path())
    res.path = cfg_path
    res.exists = os.path.isfile(cfg_path)

    if not res.exists:
        # Missing config is a soft-fail: `init`/`quickstart` will create
        # it. We return ok=True here so the auto-validate hook doesn't
        # block `init` before the file even exists.
        return res

    if _looks_like_v8_config(cfg_path):
        try:
            inspected = inspect_v8_config("validate", config_path=cfg_path)
        except ConfigInspectError as exc:
            res.timed_out = isinstance(exc, ConfigInspectTimeoutError)
            res.errors.append(_v8_failure_detail(cfg_path, exc))
            return res
        if inspected.valid is not True:
            res.errors.append("canonical v8 validator returned no validity decision")
        return res

    if config_module.config_is_empty(cfg_path):
        res.errors.append(config_module.empty_config_message(cfg_path))
        return res
    res.errors.append("Configuration schema v8 is required — run 'defenseclaw migrate' first.")
    return res


def _v8_failure_detail(cfg_path: str, exc: ConfigInspectError) -> str:
    """The canonical validator's refusal in plain words, with its line.

    The Go decision stands; this only says it plainly (GAP-1430, GAP-1499):
    the line, the field, the bad enum value and the allowed values, and the
    command to run next, instead of the "candidate field=...; reason=[code]"
    wire record.

    The Go helper reports a failure outside its schema pass (the runtime
    loader's checks, such as openshell.binary or an openshell.egress
    pattern) only as "configuration could not be compiled safely" at "$".
    For those, the Python mirror (``load_validate_v8``, value-free) says
    which field it is and what it takes.
    """

    raw = _bounded_source(cfg_path)
    if exc.field_path == "$":
        if raw is None:
            return str(exc)
        syntax = _yaml_syntax_detail(raw)
        if syntax:
            return syntax
        try:
            load_validate_v8(raw, source_name=cfg_path)
        except V8ConfigError as mirror:
            return _plain_v8_issue(raw, mirror.path, f"[{mirror.keyword}] {mirror.corrective_action}")
        except (OSError, RuntimeError, ValueError):
            pass
        return str(exc)
    if exc.field_path and exc.reason:
        return _plain_v8_issue(raw, exc.field_path, exc.reason)
    return str(exc)


def _bounded_source(cfg_path: str) -> bytes | None:
    # Read no more than the canonical validator does: an over-limit source
    # keeps its refusal, and is never read whole.
    try:
        with open(cfg_path, "rb") as stream:
            raw = stream.read(MAX_SOURCE_BYTES + 1)
    except OSError:
        return None
    return None if len(raw) > MAX_SOURCE_BYTES else raw


def _yaml_syntax_detail(raw: bytes) -> str | None:
    """Name the line and the parser's reason for a YAML syntax error."""

    from defenseclaw.observability.v8_config import yaml_error_mark

    try:
        yaml.compose(raw)
    except yaml.YAMLError as exc:
        mark = yaml_error_mark(exc)
        where = f"line {mark.line + 1}, column {mark.column + 1}: " if mark is not None else ""
        problem = str(getattr(exc, "problem", "") or "") or "malformed YAML"
        return (
            f"{where}invalid YAML ({problem}). "
            "Fix that line in config.yaml, then run 'defenseclaw config validate' again"
        )
    except Exception:  # noqa: BLE001 - anything else is the mirror's to explain.
        return None
    return None


_V8_PATH_TOKEN = re.compile(r'\.([^.\[\s]+)|\[(\d+)\]|\["((?:[^"\\]|\\.)*)"\]')
_UNDECLARED_KEY_SUMMARY = "configuration violates the additionalProperties constraint"
_V8_REASON = re.compile(r"^\[(?P<code>[A-Za-z0-9_-]+)\]\s*(?P<text>.*)$", re.S)
_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_ENV_REFERENCE = re.compile(r"\$\{(?:env:)?([A-Za-z_][A-Za-z0-9_]*)\}")


def _yaml_node_at(raw: bytes | None, field_path: str):
    """The composed YAML node at a ``$.a.b[0]["k"]`` path, or None."""

    if raw is None or not field_path.startswith("$"):
        return None
    try:
        node = yaml.compose(raw)
    except Exception:  # noqa: BLE001 - no position is better than a crash.
        return None
    rest = field_path[1:]
    while rest and node is not None:
        match = _V8_PATH_TOKEN.match(rest)
        if match is None:
            return None
        rest = rest[match.end() :]
        key, index, quoted = match.groups()
        if index is not None:
            if not isinstance(node, yaml.SequenceNode) or int(index) >= len(node.value):
                return None
            node = node.value[int(index)]
            continue
        name = key if key is not None else quoted.replace('\\"', '"')
        if not isinstance(node, yaml.MappingNode):
            return None
        node = next(
            (value for k, value in node.value if isinstance(k, yaml.ScalarNode) and k.value == name),
            None,
        )
    return None if rest else node


def _key_lines(raw: bytes | None, field_path: str) -> list[int]:
    """The 1-based lines of every definition of the last key in ``field_path``."""

    tokens = list(_V8_PATH_TOKEN.finditer(field_path, 1))
    if not field_path.startswith("$") or not tokens or tokens[-1].end() != len(field_path):
        return []
    key, _index, quoted = tokens[-1].groups()
    if key is None and quoted is None:
        return []
    name = key if key is not None else quoted.replace('\\"', '"')
    parent = _yaml_node_at(raw, field_path[: tokens[-1].start()])
    if not isinstance(parent, yaml.MappingNode):
        return []
    return [k.start_mark.line + 1 for k, _ in parent.value if isinstance(k, yaml.ScalarNode) and k.value == name]


def _duplicate_key_line(raw: bytes | None, field_path: str) -> int:
    """The 1-based line of the second definition of the key at ``field_path``, or 0."""

    lines = _key_lines(raw, field_path)
    return lines[1] if len(lines) > 1 else 0


def _key_line(raw: bytes | None, field_path: str) -> int:
    """The 1-based line of the key at ``field_path``, or 0.

    An unknown section's value starts on its first child's line; the key is
    the line to fix (GAP-2235).
    """

    lines = _key_lines(raw, field_path)
    return lines[0] if lines else 0


def _plain_v8_issue(raw: bytes | None, field_path: str, reason: str) -> str:
    path = field_path.split(" (line", 1)[0].strip()
    field = path[2:] if path.startswith("$.") else ("config.yaml" if path == "$" else path)
    node = _yaml_node_at(raw, path)
    line = _key_line(raw, path) or (node.start_mark.line + 1 if node is not None else 0)
    where = f"line {line}: " if line else ""
    match = _V8_REASON.match(reason.strip())
    code, text = (match.group("code"), match.group("text")) if match else ("", reason.strip())

    if code == "secret_reference_unresolved" and "protected credential" not in text:
        env = ""
        if isinstance(node, yaml.MappingNode):
            # setup writes the reference as a mapping, {env: NAME} (GAP-1442).
            node = next(
                (
                    value
                    for key, value in node.value
                    if isinstance(key, yaml.ScalarNode) and key.value == "env" and isinstance(value, yaml.ScalarNode)
                ),
                None,
            )
        if isinstance(node, yaml.ScalarNode):
            value = node.value.strip()
            reference = _ENV_REFERENCE.fullmatch(value)
            env = reference.group(1) if reference else (value if _ENV_NAME.fullmatch(value) else "")
        needs = env or "an environment variable"
        save = env or "<NAME>"
        return (
            f"{where}{field} needs {needs}, which has no value in the environment or the DefenseClaw "
            f".env file. Save it with: defenseclaw keys set {save}. Until it is set, setup commands "
            "refuse to run, including the one that removes this destination"
        )

    if code == "yaml_duplicate_key":
        # Name the second definition's line, not the first one's value
        # (GAP-2188).
        first = re.search(r"first definition is at line (\d+)", text)
        line = _duplicate_key_line(raw, path)
        if first and line:
            return (
                f"line {line}: {field} appears twice; the first one is at line {first.group(1)}. Merge them into one."
            )

    if code == "config_schema_invalid" and text.startswith(_UNDECLARED_KEY_SUMMARY):
        # The gateway's words for an undeclared key, not the schema keyword
        # (GAP-2235): 'guardrail.mdoe: unknown field (did you mean "mode"?).'
        suggestion = re.search(r"suggested field ([^;]+)", text)
        hint = f' (did you mean "{suggestion.group(1).strip()}"?)' if suggestion else ""
        return f"{where}{field}: unknown field{hint}. All fields: {_ALL_FIELDS_COMMAND}"

    parts = [
        part.strip()
        for part in text.split("; ")
        if part.strip() and not part.strip().startswith("inspect the canonical v8 schema")
    ]
    allowed = re.search(r"expected one of (\[.*?\])(?:;|$)", text)
    if allowed and isinstance(node, yaml.ScalarNode):
        try:
            choices = ", ".join(str(choice) for choice in json.loads(allowed.group(1)))
        except (TypeError, ValueError):
            choices = allowed.group(1)
        value = node.value if len(node.value) <= 60 else node.value[:57] + "..."
        return f'{where}{field} is "{value}"; allowed values: {choices}.'
    detail = "; ".join(parts).rstrip(".") or "is not valid"
    # ``config reference`` (YAML) covers only observability; the JSON schema
    # lists every section and field (GAP-1661).
    suffix = f" All fields: {_ALL_FIELDS_COMMAND}" if code == "config_schema_invalid" else ""
    return f"{where}{field}: {detail}.{suffix}"


def _looks_like_v8_config(path: str) -> bool:
    """Detect a root v8 declaration without constructing source values.

    ``yaml.compose`` understands valid YAML presentation variants (including
    explicit standard tags) while leaving scalar values unconstructed.  The
    narrow line probe is intentionally retained as a fallback so malformed v8
    input still reaches the canonical Go validator and its actionable errors.
    """

    try:
        with open(path, "rb") as stream:
            raw = stream.read(_MAX_VERSION_PROBE_BYTES)
    except OSError:
        return False
    try:
        root = yaml.compose(raw)
    except (yaml.YAMLError, RecursionError, OverflowError):
        root = None
    if isinstance(root, yaml.MappingNode):
        for key_node, value_node in root.value:
            if not isinstance(key_node, yaml.ScalarNode) or key_node.value != "config_version":
                continue
            if isinstance(value_node, yaml.ScalarNode):
                if value_node.value.strip() in ("8", "9"):
                    return True
                if value_node.tag == "tag:yaml.org,2002:int":
                    try:
                        if yaml.safe_load(value_node.value) in (8, 9):
                            return True
                    except yaml.YAMLError:
                        pass
    return _V8_VERSION_LINE.search(raw) is not None


def _v8_config_path_view(path: str):
    """Build the path-display shape from a masked v8 source.

    ``config path`` is a recovery command and must work while the source does
    not fully load. Only non-secret filesystem fields used by the view are
    projected; observability policy remains owned by the Go compiler.
    """

    try:
        source = load_validate_v8(Path(path).read_bytes(), source_name=path).masked
    except OSError as exc:
        raise click.ClickException(f"cannot read configuration source: {exc}") from exc
    except (V8ConfigError, RuntimeError) as exc:
        raise click.ClickException(str(exc)) from exc

    cfg = config_module.default_config()
    data_dir = str(source.get("data_dir") or cfg.data_dir)
    cfg.data_dir = data_dir
    cfg.audit_db = str(
        ((source.get("observability") or {}).get("local") or {}).get("path") or os.path.join(data_dir, "audit.db")
    )
    cfg.policy_dir = str(source.get("policy_dir") or os.path.join(data_dir, "policies"))
    cfg.plugin_dir = str(source.get("plugin_dir") or os.path.join(data_dir, "plugins"))
    cfg.quarantine_dir = str(source.get("quarantine_dir") or os.path.join(data_dir, "quarantine"))

    gateway = source.get("gateway") or {}
    cfg.gateway.device_key_file = str(gateway.get("device_key_file") or os.path.join(data_dir, "device.key"))
    claw = source.get("claw") or {}
    if claw.get("config_file"):
        cfg.claw.config_file = str(claw["config_file"])
    if claw.get("home_dir"):
        cfg.claw.home_dir = str(claw["home_dir"])
    return cfg


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _config_to_masked_dict(cfg) -> dict:
    """Convert a Config dataclass tree into a dict with secrets masked."""
    def _convert(value):
        if is_dataclass(value):
            return {f.name: _convert(getattr(value, f.name)) for f in fields(value) if not f.name.startswith("_")}
        if isinstance(value, dict):
            return {k: _convert(v) for k, v in value.items()}
        if isinstance(value, list):
            return [_convert(v) for v in value]
        return value

    raw = _convert(cfg)

    def _walk(node, key_hint: str = "") -> None:
        if isinstance(node, dict):
            # Header maps (canonical OTLP/HTTP destination headers, …)
            # carry bearer/API tokens under non-secret-looking keys such
            # as ``Authorization`` and ``x-honeycomb-team``; redact every
            # header value so none slips through (F-0221).
            in_headers = key_hint.lower() == "headers"
            # Webhook entries store the bearer secret inside ``url``.
            in_webhook = key_hint.lower() == "webhooks"
            for k, v in list(node.items()):
                if _is_secret_field(k) and isinstance(v, str) and v:
                    node[k] = "***"
                elif in_headers and isinstance(v, str) and v:
                    node[k] = "***"
                elif in_webhook and k.lower() == "url" and isinstance(v, str) and v:
                    node[k] = redact_webhook_url(v)
                else:
                    _walk(v, k)
        elif isinstance(node, list):
            for item in node:
                _walk(item, key_hint)

    _walk(raw)
    return raw


def _is_secret_field(key: str) -> bool:
    lowered = key.lower()
    # Env-var *name* fields (e.g. ``api_key_env``, ``hec_token_env``)
    # are not secrets — they're identifiers pointing to a secret stored
    # elsewhere. Never redact them.
    if lowered.endswith("_env"):
        return False
    for name in _SECRET_FIELDS:
        if lowered == name or lowered.endswith("_" + name):
            return True
    return False
