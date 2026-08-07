# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Interactive and scripted configuration-v8 redaction policy editor."""

from __future__ import annotations

import json
import subprocess
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

import click

from defenseclaw.audit_actions import ACTION_SETUP_REDACTION_POLICY
from defenseclaw.config import config_path_for_data_dir
from defenseclaw.config_inspect import ConfigInspectError, inspect_v8_config
from defenseclaw.context import AppContext, mark_setup_restart_handled, pass_ctx
from defenseclaw.gateway import resolve_gateway_binary
from defenseclaw.logger import CanonicalObservabilityUnavailableError
from defenseclaw.observability.v8_config import (
    BUCKETS,
    DESTINATION_CAPABILITIES,
    DETECTOR_GROUPS,
    FIELD_CLASSES,
    FIELD_MODES,
    SEVERITIES,
    SIGNALS,
)
from defenseclaw.observability.v8_redaction_policy import (
    ASSIGNABLE_BUILT_IN_PROFILES,
    CUSTOM_PROFILE_BASES,
    apply_mutations_to_source,
    apply_profile_everywhere_mutations,
    bucket_mutations,
    defaults_mutations,
    destination_inherit_mutations,
    destination_send_mutations,
    load_redaction_source,
    preview_redaction_mutations,
    profile_reference_paths,
    profile_remove_mutations,
    profile_set_mutations,
    redaction_profile_names,
    route_move_mutations,
    route_remove_mutations,
    route_upsert_mutations,
    source_destination,
)
from defenseclaw.observability.v8_status import inspect_v8_operator_status
from defenseclaw.observability.v8_writer import mutate_v8_config
from defenseclaw.observability.v8_yaml import V8YAMLMutation

PolicyMutationBuilder = Callable[..., tuple[V8YAMLMutation, ...]]


def _policy_mutations(
    builder: PolicyMutationBuilder,
    /,
    *args: Any,
    **kwargs: Any,
) -> tuple[V8YAMLMutation, ...]:
    """Translate policy validation failures into Click usage errors."""

    try:
        return builder(*args, **kwargs)
    except ValueError as exc:
        raise click.UsageError(str(exc)) from exc


@click.group("redaction", invoke_without_command=True)
@pass_ctx
def redaction(app: AppContext) -> None:
    """Configure centralized v8 redaction, collection, and routing policy."""

    if click.get_current_context().invoked_subcommand is None:
        _interactive_wizard(app)


@redaction.command("status")
@click.option("--json", "emit_json", is_flag=True, help="Emit machine-readable JSON.")
@pass_ctx
def status_cmd(app: AppContext, emit_json: bool) -> None:
    """Show effective bucket and destination redaction policy."""

    status = _operator_status(app)
    if emit_json:
        click.echo(
            json.dumps(
                {
                    "config": status.source,
                    "plan_digest": status.plan_digest,
                    "bucket_catalog_version": status.bucket_catalog_version,
                    "destinations": [
                        {
                            "name": item.name,
                            "kind": item.kind,
                            "enabled": item.enabled,
                            "generated": item.generated,
                            "signals": list(item.selected_signals),
                            "policy_form": item.policy_form,
                            "redaction_profiles": list(item.redaction_profiles),
                            "redaction": item.redaction_label,
                        }
                        for item in status.destinations
                    ],
                    "buckets": [
                        {
                            "name": item.name,
                            "signals": list(item.collected_signals),
                            "redaction_profile": item.redaction_profile,
                        }
                        for item in status.buckets
                    ],
                    "warnings": [
                        {"code": code, "path": path, "summary": summary} for code, path, summary in status.warnings
                    ],
                },
                indent=2,
                sort_keys=True,
            )
        )
        return
    _render_status(status)


@redaction.command("remove-all")
@click.option("--yes", is_flag=True, help="Confirm unredacted output without prompting.")
@click.option("--dry-run", is_flag=True, help="Preview without writing config.yaml.")
@click.option("--json", "emit_json", is_flag=True, help="Emit machine-readable output.")
@click.option("--restart/--no-restart", default=False, show_default=True)
@pass_ctx
def remove_all_cmd(
    app: AppContext,
    yes: bool,
    dry_run: bool,
    emit_json: bool,
    restart: bool,
) -> None:
    """Remove redaction from every configurable log and trace projection."""

    _, source = _load_source(app)
    mutations = _policy_mutations(apply_profile_everywhere_mutations, source, "none")
    _execute_mutations(
        app,
        mutations,
        action="remove-all",
        yes=yes,
        dry_run=dry_run,
        emit_json=emit_json,
        restart=restart,
    )


@redaction.command("apply")
@click.option(
    "--scope",
    type=click.Choice(["all-configurable", "defaults"]),
    required=True,
)
@click.option("--profile", required=True, help="Built-in or custom profile name.")
@click.option("--yes", is_flag=True)
@click.option("--dry-run", is_flag=True)
@click.option("--json", "emit_json", is_flag=True)
@click.option("--restart/--no-restart", default=False, show_default=True)
@pass_ctx
def apply_cmd(
    app: AppContext,
    scope: str,
    profile: str,
    yes: bool,
    dry_run: bool,
    emit_json: bool,
    restart: bool,
) -> None:
    """Apply one profile to a broad v8 policy scope."""

    _, source = _load_source(app)
    mutations = (
        _policy_mutations(apply_profile_everywhere_mutations, source, profile)
        if scope == "all-configurable"
        else _policy_mutations(defaults_mutations, source, profile=profile)
    )
    _execute_mutations(
        app,
        mutations,
        action=f"apply scope={scope} profile={profile}",
        yes=yes,
        dry_run=dry_run,
        emit_json=emit_json,
        restart=restart,
    )


@redaction.group("defaults")
def defaults_group() -> None:
    """Manage the global bucket baseline."""


@defaults_group.command("set")
@click.option("--profile", default=None)
@click.option("--logs/--no-logs", default=None)
@click.option("--traces/--no-traces", default=None)
@click.option("--metrics/--no-metrics", default=None)
@click.option("--yes", is_flag=True)
@click.option("--dry-run", is_flag=True)
@click.option("--json", "emit_json", is_flag=True)
@click.option("--restart/--no-restart", default=False, show_default=True)
@pass_ctx
def defaults_set_cmd(
    app: AppContext,
    profile: str | None,
    logs: bool | None,
    traces: bool | None,
    metrics: bool | None,
    yes: bool,
    dry_run: bool,
    emit_json: bool,
    restart: bool,
) -> None:
    """Set selected global profile or collection defaults."""

    _, source = _load_source(app)
    _require_any_change(profile, logs, traces, metrics)
    mutations = _policy_mutations(
        defaults_mutations,
        source,
        profile=profile,
        collect=_specified_collection(logs=logs, traces=traces, metrics=metrics),
    )
    _execute_mutations(
        app,
        mutations,
        action="defaults-set",
        yes=yes,
        dry_run=dry_run,
        emit_json=emit_json,
        restart=restart,
    )


@defaults_group.command("reset")
@click.option("--yes", is_flag=True)
@click.option("--dry-run", is_flag=True)
@click.option("--json", "emit_json", is_flag=True)
@click.option("--restart/--no-restart", default=False, show_default=True)
@pass_ctx
def defaults_reset_cmd(
    app: AppContext,
    yes: bool,
    dry_run: bool,
    emit_json: bool,
    restart: bool,
) -> None:
    """Reset global collection and profile values to catalog defaults."""

    _, source = _load_source(app)
    mutations = _policy_mutations(
        defaults_mutations,
        source,
        reset_profile=True,
        collect={signal: None for signal in SIGNALS},
    )
    _execute_mutations(
        app,
        mutations,
        action="defaults-reset",
        yes=yes,
        dry_run=dry_run,
        emit_json=emit_json,
        restart=restart,
    )


@redaction.group("bucket")
def bucket_group() -> None:
    """Manage per-bucket collection and redaction overrides."""


@bucket_group.command("list")
@pass_ctx
def bucket_list_cmd(app: AppContext) -> None:
    """List effective catalog-v1 bucket policies."""

    status = _operator_status(app)
    _render_buckets(status.buckets)


@bucket_group.command("set")
@click.argument("bucket", type=click.Choice(BUCKETS))
@click.option("--profile", default=None)
@click.option("--inherit-profile", is_flag=True)
@click.option("--logs/--no-logs", default=None)
@click.option("--traces/--no-traces", default=None)
@click.option("--metrics/--no-metrics", default=None)
@click.option("--yes", is_flag=True)
@click.option("--dry-run", is_flag=True)
@click.option("--json", "emit_json", is_flag=True)
@click.option("--restart/--no-restart", default=False, show_default=True)
@pass_ctx
def bucket_set_cmd(
    app: AppContext,
    bucket: str,
    profile: str | None,
    inherit_profile: bool,
    logs: bool | None,
    traces: bool | None,
    metrics: bool | None,
    yes: bool,
    dry_run: bool,
    emit_json: bool,
    restart: bool,
) -> None:
    """Set selected fields on one catalog bucket."""

    if profile is not None and inherit_profile:
        raise click.UsageError("--profile and --inherit-profile are mutually exclusive")
    if profile is None and not inherit_profile and all(value is None for value in (logs, traces, metrics)):
        raise click.UsageError("select at least one setting to change")
    _, source = _load_source(app)
    mutations = _policy_mutations(
        bucket_mutations,
        source,
        bucket,
        profile=profile,
        inherit_profile=inherit_profile,
        collect=_specified_collection(logs=logs, traces=traces, metrics=metrics),
    )
    _execute_mutations(
        app,
        mutations,
        action=f"bucket-set bucket={bucket}",
        yes=yes,
        dry_run=dry_run,
        emit_json=emit_json,
        restart=restart,
    )


@bucket_group.command("reset")
@click.argument("bucket", type=click.Choice(BUCKETS))
@click.option("--yes", is_flag=True)
@click.option("--dry-run", is_flag=True)
@click.option("--json", "emit_json", is_flag=True)
@click.option("--restart/--no-restart", default=False, show_default=True)
@pass_ctx
def bucket_reset_cmd(
    app: AppContext,
    bucket: str,
    yes: bool,
    dry_run: bool,
    emit_json: bool,
    restart: bool,
) -> None:
    """Reset one bucket to the global/catalog baseline."""

    _, source = _load_source(app)
    mutations = _policy_mutations(
        bucket_mutations,
        source,
        bucket,
        inherit_profile=True,
        collect={signal: None for signal in SIGNALS},
    )
    _execute_mutations(
        app,
        mutations,
        action=f"bucket-reset bucket={bucket}",
        yes=yes,
        dry_run=dry_run,
        emit_json=emit_json,
        restart=restart,
    )


@redaction.group("profile")
def profile_group() -> None:
    """Inspect and manage custom redaction profiles."""


@profile_group.command("list")
@click.option("--json", "emit_json", is_flag=True)
@pass_ctx
def profile_list_cmd(app: AppContext, emit_json: bool) -> None:
    """List built-in and custom profile names."""

    _, source = _load_source(app)
    profiles = redaction_profile_names(source)
    if emit_json:
        click.echo(json.dumps({"profiles": list(profiles)}, indent=2))
    else:
        for value in profiles:
            click.echo(value)
        click.echo("legacy-v7 (migration-only, read-only)")


@profile_group.command("show")
@click.argument("name")
@click.option("--json", "emit_json", is_flag=True)
@pass_ctx
def profile_show_cmd(app: AppContext, name: str, emit_json: bool) -> None:
    """Show a compiled profile's detectors and field-class modes."""

    effective = _effective(app)
    profiles = effective.get("redaction_profiles")
    found = next(
        (item for item in profiles or [] if isinstance(item, Mapping) and item.get("name") == name),
        None,
    )
    if found is None:
        raise click.ClickException(f"no compiled profile named {name!r}")
    if emit_json:
        click.echo(json.dumps(found, indent=2, sort_keys=True))
        return
    click.echo(f"Profile: {name}")
    click.echo(f"  Kind: {'built-in' if found.get('built_in') else 'custom'}")
    if found.get("extends"):
        click.echo(f"  Extends: {found['extends']}")
    click.echo(f"  Detectors: {', '.join(found.get('detectors') or ()) or '(none)'}")
    for field_class in FIELD_CLASSES:
        mode = (found.get("field_classes") or {}).get(field_class, "-")
        click.echo(f"  {field_class}: {mode}")


@profile_group.command("set")
@click.argument("name")
@click.option("--extends", type=click.Choice(CUSTOM_PROFILE_BASES), default=None)
@click.option("--detector", "detectors", multiple=True, type=click.Choice(DETECTOR_GROUPS))
@click.option("--field", "fields", multiple=True, metavar="CLASS=MODE")
@click.option("--yes", is_flag=True)
@click.option("--dry-run", is_flag=True)
@click.option("--json", "emit_json", is_flag=True)
@click.option("--restart/--no-restart", default=False, show_default=True)
@pass_ctx
def profile_set_cmd(
    app: AppContext,
    name: str,
    extends: str | None,
    detectors: tuple[str, ...],
    fields: tuple[str, ...],
    yes: bool,
    dry_run: bool,
    emit_json: bool,
    restart: bool,
) -> None:
    """Create or update one custom redaction profile."""

    _, source = _load_source(app)
    parsed_fields = _parse_fields(fields)
    mutations = _policy_mutations(
        profile_set_mutations,
        source,
        name,
        extends=extends,
        detectors=detectors or None,
        field_classes=parsed_fields,
    )
    _execute_mutations(
        app,
        mutations,
        action=f"profile-set profile={name}",
        yes=yes,
        dry_run=dry_run,
        emit_json=emit_json,
        restart=restart,
    )


@profile_group.command("remove")
@click.argument("name")
@click.option("--replace-with", default=None)
@click.option("--yes", is_flag=True)
@click.option("--dry-run", is_flag=True)
@click.option("--json", "emit_json", is_flag=True)
@click.option("--restart/--no-restart", default=False, show_default=True)
@pass_ctx
def profile_remove_cmd(
    app: AppContext,
    name: str,
    replace_with: str | None,
    yes: bool,
    dry_run: bool,
    emit_json: bool,
    restart: bool,
) -> None:
    """Remove an unreferenced custom profile or replace references atomically."""

    _, source = _load_source(app)
    mutations = _policy_mutations(profile_remove_mutations, source, name, replace_with=replace_with)
    _execute_mutations(
        app,
        mutations,
        action=f"profile-remove profile={name}",
        yes=yes,
        dry_run=dry_run,
        emit_json=emit_json,
        restart=restart,
    )


@redaction.group("destination")
def destination_group() -> None:
    """Manage destination-level concise policy."""


@destination_group.command("show")
@click.argument("name")
@pass_ctx
def destination_show_cmd(app: AppContext, name: str) -> None:
    """Show one destination's effective redaction policy."""

    status = _operator_status(app)
    found = next((item for item in status.destinations if item.name == name), None)
    if found is None:
        raise click.ClickException(f"no effective destination named {name!r}")
    click.echo(f"Destination: {found.name}")
    click.echo(f"  Kind: {found.kind}")
    click.echo(f"  Generated: {'yes' if found.generated else 'no'}")
    click.echo(f"  Policy: {found.policy_form}")
    click.echo(f"  Signals: {', '.join(found.selected_signals) or '(none)'}")
    click.echo(f"  Redaction: {found.redaction_label}")
    click.echo(f"  Buckets: {', '.join(found.buckets) or '(none)'}")


@destination_group.command("send")
@click.argument("name")
@click.option("--signal", "signals", multiple=True, type=click.Choice(SIGNALS), required=True)
@click.option("--bucket", "buckets", multiple=True, required=True)
@click.option("--profile", default=None)
@click.option("--yes", is_flag=True)
@click.option("--dry-run", is_flag=True)
@click.option("--json", "emit_json", is_flag=True)
@click.option("--restart/--no-restart", default=False, show_default=True)
@pass_ctx
def destination_send_cmd(
    app: AppContext,
    name: str,
    signals: tuple[str, ...],
    buckets: tuple[str, ...],
    profile: str | None,
    yes: bool,
    dry_run: bool,
    emit_json: bool,
    restart: bool,
) -> None:
    """Replace destination routing with one concise send policy."""

    _, source = _load_source(app)
    mutations = _policy_mutations(
        destination_send_mutations,
        source,
        name,
        signals=signals,
        buckets=buckets,
        profile=profile,
    )
    _execute_mutations(
        app,
        mutations,
        action=f"destination-send destination={name}",
        yes=yes,
        dry_run=dry_run,
        emit_json=emit_json,
        restart=restart,
    )


@destination_group.command("inherit")
@click.argument("name")
@click.option("--yes", is_flag=True)
@click.option("--dry-run", is_flag=True)
@click.option("--json", "emit_json", is_flag=True)
@click.option("--restart/--no-restart", default=False, show_default=True)
@pass_ctx
def destination_inherit_cmd(
    app: AppContext,
    name: str,
    yes: bool,
    dry_run: bool,
    emit_json: bool,
    restart: bool,
) -> None:
    """Remove explicit send/routes and restore capability-default policy."""

    _, source = _load_source(app)
    mutations = _policy_mutations(destination_inherit_mutations, source, name)
    _execute_mutations(
        app,
        mutations,
        action=f"destination-inherit destination={name}",
        yes=yes,
        dry_run=dry_run,
        emit_json=emit_json,
        restart=restart,
    )


@redaction.group("route")
def route_group() -> None:
    """Manage first-match destination routes."""


@route_group.command("list")
@click.argument("destination")
@click.option("--json", "emit_json", is_flag=True)
@pass_ctx
def route_list_cmd(app: AppContext, destination: str, emit_json: bool) -> None:
    """List source-authored routes in evaluation order."""

    _, source = _load_source(app)
    _, item = _source_destination_or_click(source, destination)
    routes = item.get("routes") or []
    if emit_json:
        click.echo(json.dumps({"destination": destination, "routes": routes}, indent=2, sort_keys=True))
        return
    if not routes:
        click.echo(f"{destination}: no explicit routes (capability-default or concise send)")
        return
    for index, route in enumerate(routes, start=1):
        click.echo(
            f"{index}. {route.get('name')} action={route.get('action', 'send')} "
            f"signals={','.join(route.get('signals') or ())} "
            f"profile={route.get('redaction_profile', 'inherit')}"
        )


def _route_options(command):
    options = (
        click.option("--signal", "signals", multiple=True, type=click.Choice(SIGNALS), required=True),
        click.option("--bucket", "buckets", multiple=True),
        click.option("--source", "sources", multiple=True),
        click.option("--connector", "connectors", multiple=True),
        click.option("--producer-action", "producer_actions", multiple=True),
        click.option("--event-name", "event_names", multiple=True),
        click.option("--min-severity", type=click.Choice(SEVERITIES), default=None),
        click.option("--route-action", type=click.Choice(["send", "drop"]), default="send", show_default=True),
        click.option("--profile", default=None),
        click.option("--yes", is_flag=True),
        click.option("--dry-run", is_flag=True),
        click.option("--json", "emit_json", is_flag=True),
        click.option("--restart/--no-restart", default=False, show_default=True),
    )
    for option in reversed(options):
        command = option(command)
    return command


@route_group.command("add")
@click.argument("destination")
@click.argument("name")
@click.option("--position", type=click.IntRange(min=1), default=None)
@_route_options
@pass_ctx
def route_add_cmd(
    app: AppContext,
    destination: str,
    name: str,
    position: int | None,
    **options,
) -> None:
    """Add one advanced route at a one-based position or at the end."""

    _, source = _load_source(app)
    route = _route_from_options(name, options)
    mutations = _policy_mutations(
        route_upsert_mutations,
        source,
        destination,
        route,
        position=None if position is None else position - 1,
        must_exist=False,
    )
    _execute_route_mutations(app, mutations, destination, name, "add", options)


@route_group.command("set")
@click.argument("destination")
@click.argument("name")
@_route_options
@pass_ctx
def route_set_cmd(app: AppContext, destination: str, name: str, **options) -> None:
    """Replace one named route while preserving its current position."""

    _, source = _load_source(app)
    route = _route_from_options(name, options)
    mutations = _policy_mutations(route_upsert_mutations, source, destination, route, must_exist=True)
    _execute_route_mutations(app, mutations, destination, name, "set", options)


@route_group.command("move")
@click.argument("destination")
@click.argument("name")
@click.option("--position", type=click.IntRange(min=1), required=True)
@click.option("--yes", is_flag=True)
@click.option("--dry-run", is_flag=True)
@click.option("--json", "emit_json", is_flag=True)
@click.option("--restart/--no-restart", default=False, show_default=True)
@pass_ctx
def route_move_cmd(
    app: AppContext,
    destination: str,
    name: str,
    position: int,
    yes: bool,
    dry_run: bool,
    emit_json: bool,
    restart: bool,
) -> None:
    """Move a route to a one-based first-match position."""

    _, source = _load_source(app)
    mutations = _policy_mutations(route_move_mutations, source, destination, name, position=position - 1)
    _execute_mutations(
        app,
        mutations,
        action=f"route-move destination={destination} route={name}",
        yes=yes,
        dry_run=dry_run,
        emit_json=emit_json,
        restart=restart,
    )


@route_group.command("remove")
@click.argument("destination")
@click.argument("name")
@click.option("--yes", is_flag=True)
@click.option("--dry-run", is_flag=True)
@click.option("--json", "emit_json", is_flag=True)
@click.option("--restart/--no-restart", default=False, show_default=True)
@pass_ctx
def route_remove_cmd(
    app: AppContext,
    destination: str,
    name: str,
    yes: bool,
    dry_run: bool,
    emit_json: bool,
    restart: bool,
) -> None:
    """Remove one source-authored route."""

    _, source = _load_source(app)
    mutations = _policy_mutations(route_remove_mutations, source, destination, name)
    _execute_mutations(
        app,
        mutations,
        action=f"route-remove destination={destination} route={name}",
        yes=yes,
        dry_run=dry_run,
        emit_json=emit_json,
        restart=restart,
    )


class _WizardDraft:
    def __init__(self, source_bytes: bytes, source: dict[str, Any], source_name: str) -> None:
        self.original = source_bytes
        self.source = source
        self.source_name = source_name
        self.mutations: list[V8YAMLMutation] = []

    def add(self, mutations: Iterable[V8YAMLMutation]) -> None:
        additions = tuple(mutations)
        candidate, source = apply_mutations_to_source(
            self.original,
            (*self.mutations, *additions),
            source_name=self.source_name,
        )
        del candidate
        self.mutations.extend(additions)
        self.source = source

    def reset(self) -> None:
        self.mutations.clear()
        _, self.source = apply_mutations_to_source(self.original, (), source_name=self.source_name)


def _interactive_wizard(app: AppContext) -> None:
    path = _config_path(app)
    raw, source = _load_source(app)
    click.echo("\nDefenseClaw redaction policy")
    click.echo(f"Config: {path}")
    click.echo("Schema: v8")
    _render_status(_operator_status(app), compact=True)
    draft = _WizardDraft(raw, source, str(path))

    click.echo("\nWhat would you like to do?")
    click.echo("  1. Keep the current policy")
    click.echo("  2. Remove all redaction from configurable projections")
    click.echo("  3. Apply one profile to all configurable projections")
    click.echo("  4. Change the global/bucket baseline")
    choice = click.prompt("\nSelect", type=click.Choice(["1", "2", "3", "4"]), default="1")
    try:
        if choice == "2":
            draft.add(_policy_mutations(apply_profile_everywhere_mutations, draft.source, "none"))
        elif choice == "3":
            profile = _prompt_profile(draft.source)
            draft.add(_policy_mutations(apply_profile_everywhere_mutations, draft.source, profile))
        elif choice == "4":
            current_defaults = _effective_source_defaults(draft.source)
            profile = _prompt_profile(
                draft.source,
                allow_inherit=True,
                default=str(current_defaults.get("redaction_profile") or "inherit"),
            )
            draft.add(
                _policy_mutations(
                    defaults_mutations,
                    draft.source,
                    profile=None if profile == "inherit" else profile,
                    reset_profile=profile == "inherit",
                )
            )
    except (ValueError, OSError, RuntimeError) as exc:
        raise click.ClickException(str(exc)) from exc

    if click.confirm("\nShow advanced settings?", default=False):
        _interactive_advanced(app, draft)

    if not draft.mutations:
        click.echo("\nNo changes selected.")
        return
    restart = click.confirm("Restart the gateway after applying?", default=False)
    _execute_mutations(
        app,
        draft.mutations,
        action="interactive-policy",
        yes=False,
        dry_run=False,
        emit_json=False,
        restart=restart,
    )


def _interactive_advanced(app: AppContext, draft: _WizardDraft) -> None:
    while True:
        click.echo("\nAdvanced redaction settings")
        click.echo("  1. Global defaults")
        click.echo("  2. Bucket policies")
        click.echo("  3. Redaction profiles")
        click.echo("  4. Destinations and routing")
        click.echo("  5. Related raw-data controls")
        click.echo("  6. Review staged changes")
        click.echo("  7. Reset staged changes")
        click.echo("  8. Done")
        choice = click.prompt("Select", type=click.Choice([str(i) for i in range(1, 9)]))
        try:
            if choice == "1":
                _interactive_defaults(draft)
            elif choice == "2":
                _interactive_buckets(draft)
            elif choice == "3":
                _interactive_profiles(draft)
            elif choice == "4":
                _interactive_destinations(draft)
            elif choice == "5":
                _render_related_controls(draft.source)
            elif choice == "6":
                _render_preview(
                    preview_redaction_mutations(_config_path(app), draft.mutations, data_dir=app.cfg.data_dir)
                )
            elif choice == "7":
                if click.confirm("Discard every staged change?", default=False):
                    draft.reset()
                    click.echo("Staged changes reset.")
            else:
                return
        except (click.ClickException, ValueError, OSError, RuntimeError, ConfigInspectError) as exc:
            click.echo(f"  error: {exc}", err=True)


def _interactive_defaults(draft: _WizardDraft) -> None:
    effective = _effective_source_defaults(draft.source)
    profile = _prompt_profile(
        draft.source,
        allow_inherit=True,
        default=str(effective.get("redaction_profile") or "inherit"),
    )
    collect = {
        signal: click.confirm(f"Collect {signal}?", default=bool(effective["collect"].get(signal, True)))
        for signal in SIGNALS
    }
    draft.add(
        _policy_mutations(
            defaults_mutations,
            draft.source,
            profile=None if profile == "inherit" else profile,
            reset_profile=profile == "inherit",
            collect=collect,
        )
    )


def _interactive_buckets(draft: _WizardDraft) -> None:
    for index, bucket in enumerate(BUCKETS, start=1):
        click.echo(f"  {index:>2}. {bucket}")
    raw = click.prompt("Buckets (number, comma list, or all)").strip().lower()
    selected = list(BUCKETS) if raw == "all" else []
    if not selected:
        for token in raw.split(","):
            normalized = token.strip()
            if normalized in BUCKETS:
                selected.append(normalized)
                continue
            try:
                position = int(normalized)
            except ValueError:
                raise click.ClickException(f"invalid bucket selection {token!r}") from None
            if not 1 <= position <= len(BUCKETS):
                raise click.ClickException(f"invalid bucket selection {token!r}")
            selected.append(BUCKETS[position - 1])
    selected = list(dict.fromkeys(selected))
    effective = [_effective_source_bucket(draft.source, bucket) for bucket in selected]
    current_profiles = {str(item["redaction_profile"]) for item in effective}
    profile: str | None = None
    inherit_profile = False
    if click.confirm("Change the selected buckets' redaction profile?", default=True):
        profile_choice = _prompt_profile(
            draft.source,
            allow_inherit=True,
            default=(next(iter(current_profiles)) if len(current_profiles) == 1 else "inherit"),
        )
        profile = None if profile_choice == "inherit" else profile_choice
        inherit_profile = profile_choice == "inherit"
    collect: dict[str, bool] = {}
    if click.confirm("Change collection for the selected buckets?", default=False):
        for signal in SIGNALS:
            current_values = {bool(item["collect"][signal]) for item in effective}
            collect[signal] = click.confirm(
                f"Collect {signal} for selected buckets?",
                default=(next(iter(current_values)) if len(current_values) == 1 else True),
            )
    if profile is None and not inherit_profile and not collect:
        click.echo("No bucket changes selected.")
        return
    for bucket in selected:
        draft.add(
            _policy_mutations(
                bucket_mutations,
                draft.source,
                bucket,
                profile=profile,
                inherit_profile=inherit_profile,
                collect=collect,
            )
        )


def _interactive_profiles(draft: _WizardDraft) -> None:
    built_in = frozenset(ASSIGNABLE_BUILT_IN_PROFILES)
    custom = [name for name in redaction_profile_names(draft.source) if name not in built_in]
    click.echo("  1. View a profile")
    click.echo("  2. Create or edit a custom profile")
    click.echo("  3. Remove a custom profile")
    action = click.prompt("Select", type=click.Choice(["1", "2", "3"]))
    if action == "1":
        click.echo("Profiles: " + ", ".join(redaction_profile_names(draft.source)))
        return
    if action == "3":
        if not custom:
            click.echo("No custom profiles are configured.")
            return
        name = click.prompt("Custom profile", type=click.Choice(custom))
        references = profile_reference_paths(draft.source, name)
        replacement = None
        if references:
            click.echo(f"Profile is referenced at {len(references)} policy path(s).")
            replacement = _prompt_profile(draft.source, excluded={name})
        draft.add(_policy_mutations(profile_remove_mutations, draft.source, name, replace_with=replacement))
        return

    name = click.prompt("Custom profile name").strip()
    current = _custom_profile(draft.source, name)
    extends = click.prompt(
        "Extends",
        type=click.Choice(CUSTOM_PROFILE_BASES),
        default=str(current.get("extends") or "sensitive"),
    )
    detectors_default = ",".join(current.get("detectors") or DETECTOR_GROUPS)
    detectors = _split_values(
        click.prompt("Detector groups", default=detectors_default),
        allowed=set(DETECTOR_GROUPS),
    )
    fields: dict[str, str | None] = {}
    current_fields = current.get("field_classes") or {}
    if click.confirm("Customize field-class modes?", default=bool(current_fields)):
        choices = ["inherit", *FIELD_MODES]
        for field_class in FIELD_CLASSES:
            default = str(current_fields.get(field_class) or "inherit")
            value = click.prompt(f"  {field_class}", type=click.Choice(choices), default=default)
            fields[field_class] = None if value == "inherit" else value
    draft.add(
        _policy_mutations(
            profile_set_mutations,
            draft.source,
            name,
            extends=extends,
            detectors=detectors,
            field_classes=fields,
        )
    )


def _interactive_destinations(draft: _WizardDraft) -> None:
    destinations = _source_destinations(draft.source)
    if not destinations:
        click.echo("No configurable destinations are present.")
        return
    names = [str(item.get("name")) for item in destinations]
    name = click.prompt("Destination", type=click.Choice(names))
    _, destination = source_destination(draft.source, name)
    click.echo("  1. Restore capability-default policy")
    click.echo("  2. Configure concise send policy")
    click.echo("  3. Edit ordered routes")
    action = click.prompt("Select", type=click.Choice(["1", "2", "3"]))
    if action == "1":
        draft.add(_policy_mutations(destination_inherit_mutations, draft.source, name))
        return
    if action == "2":
        capabilities = _destination_capabilities(destination)
        signals = _split_values(
            click.prompt("Signals", default=",".join(capabilities)),
            allowed=set(capabilities),
        )
        buckets = _split_values(click.prompt("Buckets", default="*"), allowed={"*", *BUCKETS})
        profile = _prompt_profile(draft.source, allow_inherit=True)
        draft.add(
            _policy_mutations(
                destination_send_mutations,
                draft.source,
                name,
                signals=signals,
                buckets=buckets,
                profile=None if profile == "inherit" else profile,
            )
        )
        return
    _interactive_routes(draft, name)


def _interactive_routes(draft: _WizardDraft, destination_name: str) -> None:
    while True:
        _, destination = source_destination(draft.source, destination_name)
        routes = list(destination.get("routes") or [])
        click.echo(f"\nRoutes for {destination_name} (first match wins)")
        for index, route in enumerate(routes, start=1):
            click.echo(f"  {index}. {route.get('name')} [{route.get('action', 'send')}]")
        click.echo("  a. Add route")
        click.echo("  e. Edit route")
        click.echo("  m. Move route")
        click.echo("  r. Remove route")
        click.echo("  b. Back")
        action = click.prompt("Select", type=click.Choice(["a", "e", "m", "r", "b"]))
        if action == "b":
            return
        if action == "a":
            name = click.prompt("Route name").strip()
            route = _prompt_route(draft.source, destination, name, None)
            position = click.prompt(
                "One-based position", type=click.IntRange(1, len(routes) + 1), default=len(routes) + 1
            )
            draft.add(
                _policy_mutations(
                    route_upsert_mutations,
                    draft.source,
                    destination_name,
                    route,
                    position=position - 1,
                    must_exist=False,
                )
            )
            continue
        if not routes:
            click.echo("No explicit routes are configured.")
            continue
        names = [str(route.get("name")) for route in routes]
        route_name = click.prompt("Route", type=click.Choice(names))
        if action == "e":
            current = next(route for route in routes if route.get("name") == route_name)
            draft.add(
                _policy_mutations(
                    route_upsert_mutations,
                    draft.source,
                    destination_name,
                    _prompt_route(draft.source, destination, route_name, current),
                    must_exist=True,
                )
            )
        elif action == "m":
            position = click.prompt("One-based position", type=click.IntRange(1, len(routes)), default=1)
            draft.add(
                _policy_mutations(
                    route_move_mutations,
                    draft.source,
                    destination_name,
                    route_name,
                    position=position - 1,
                )
            )
        elif click.confirm(f"Remove route {route_name!r}?", default=False):
            draft.add(_policy_mutations(route_remove_mutations, draft.source, destination_name, route_name))


def _prompt_route(
    source: Mapping[str, Any],
    destination: Mapping[str, Any],
    name: str,
    current: Mapping[str, Any] | None,
) -> dict[str, Any]:
    current = current or {}
    capabilities = _destination_capabilities(destination)
    signals = _split_values(
        click.prompt("Signals", default=",".join(current.get("signals") or capabilities)),
        allowed=set(capabilities),
    )
    route_action = click.prompt(
        "Route action",
        type=click.Choice(["send", "drop"]),
        default=str(current.get("action") or "send"),
    )
    selector_current = current.get("selector") or {}
    selector: dict[str, Any] = {}
    for key, allowed in (
        ("buckets", {"*", *BUCKETS}),
        ("sources", None),
        ("connectors", None),
        ("actions", None),
        ("event_names", None),
    ):
        default = ",".join(selector_current.get(key) or ())
        value = click.prompt(f"Selector {key} (blank means any)", default=default, show_default=bool(default))
        if value.strip():
            selector[key] = _split_values(value, allowed=allowed)
    severity_default = str(selector_current.get("min_severity") or "none")
    severity = click.prompt("Minimum severity", type=click.Choice(["none", *SEVERITIES]), default=severity_default)
    if severity != "none":
        selector["min_severity"] = severity
    route: dict[str, Any] = {
        "name": name,
        "signals": list(signals),
        "selector": selector,
        "action": route_action,
    }
    if route_action == "send" and any(signal in {"logs", "traces"} for signal in signals):
        profile = _prompt_profile(
            source,
            allow_inherit=True,
            default=str(current.get("redaction_profile") or "inherit"),
        )
        if profile != "inherit":
            route["redaction_profile"] = profile
    return route


def _execute_route_mutations(
    app: AppContext,
    mutations: Sequence[V8YAMLMutation],
    destination: str,
    name: str,
    verb: str,
    options: Mapping[str, Any],
) -> None:
    _execute_mutations(
        app,
        mutations,
        action=f"route-{verb} destination={destination} route={name}",
        yes=bool(options["yes"]),
        dry_run=bool(options["dry_run"]),
        emit_json=bool(options["emit_json"]),
        restart=bool(options["restart"]),
    )


def _execute_mutations(
    app: AppContext,
    mutations: Iterable[V8YAMLMutation],
    *,
    action: str,
    yes: bool,
    dry_run: bool,
    emit_json: bool,
    restart: bool,
) -> None:
    mutation_tuple = tuple(mutations)
    if not mutation_tuple:
        raise click.UsageError("no redaction policy changes were selected")
    if emit_json and not (yes or dry_run):
        raise click.UsageError("--json mutations require --yes or --dry-run")
    path = _config_path(app)
    try:
        preview = preview_redaction_mutations(path, mutation_tuple, data_dir=app.cfg.data_dir)
    except (ValueError, OSError, RuntimeError, ConfigInspectError) as exc:
        raise click.ClickException(str(exc)) from exc
    if not emit_json:
        _render_preview(preview)
    if not preview.changed:
        if emit_json:
            click.echo(json.dumps(_preview_json(preview, dry_run=dry_run), indent=2, sort_keys=True))
        else:
            click.echo("No configuration change is required.")
        return
    if dry_run:
        if emit_json:
            click.echo(json.dumps(_preview_json(preview, dry_run=True), indent=2, sort_keys=True))
        return
    if not yes:
        prompt = (
            "Apply this policy and allow newly unredacted output?"
            if preview.newly_unredacted
            else "Apply this redaction policy?"
        )
        if not click.confirm(prompt, default=False):
            click.echo("Aborted.")
            return
    backup = Path(app.cfg.data_dir) / "backups" / f"config.yaml.before-redaction-{time.time_ns()}"
    try:
        result = mutate_v8_config(
            path,
            mutation_tuple,
            data_dir=app.cfg.data_dir,
            expected_before_sha256=preview.before_sha256,
            backup_path=backup,
        )
    except (ValueError, OSError, RuntimeError, ConfigInspectError) as exc:
        raise click.ClickException(str(exc)) from exc
    # This command owns its explicit --restart/--no-restart contract. Claim the
    # lifecycle before any post-write operation can fail so the setup group's
    # generic result hook never restarts an unverified policy or appends text to
    # machine-readable JSON output.
    mark_setup_restart_handled()
    audit_details = (
        f"action={action} changed_legs={len(preview.changes)} "
        f"newly_unredacted={preview.newly_unredacted}"
    )
    audit_after_restart = False
    if app.logger:
        try:
            app.logger.log_action(
                ACTION_SETUP_REDACTION_POLICY,
                "redaction-policy",
                audit_details,
            )
        except CanonicalObservabilityUnavailableError:
            audit_after_restart = restart
            if not restart:
                click.echo(
                    "  ⚠ Change saved, but the gateway runtime is unavailable; the canonical setup audit "
                    "event was not recorded. Start defenseclaw-gateway before the next change.",
                    err=True,
                )
    try:
        verified = inspect_v8_config("effective", config_path=str(path), data_dir=app.cfg.data_dir)
    except (ValueError, OSError, RuntimeError, ConfigInspectError) as exc:
        rollback_path = result.backup_path or str(backup)
        message = f"configuration was written but effective plan verification failed: {exc}"
        message += f"; restore {rollback_path} to roll back"
        raise click.ClickException(message) from exc
    if verified.plan_digest != preview.after_plan_digest:
        message = "configuration was written but the verified effective plan differs from the preview"
        rollback_path = result.backup_path or str(backup)
        message += f"; restore {rollback_path} to roll back"
        raise click.ClickException(message)
    if restart:
        try:
            _restart_gateway(quiet=emit_json)
        except click.ClickException:
            if audit_after_restart:
                click.echo(
                    "  ⚠ Change saved, but the canonical setup audit event was not recorded because the "
                    "gateway restart failed. Start defenseclaw-gateway before the next change.",
                    err=True,
                )
            raise
        if audit_after_restart and app.logger:
            try:
                app.logger.log_action(
                    ACTION_SETUP_REDACTION_POLICY,
                    "redaction-policy",
                    audit_details,
                )
            except CanonicalObservabilityUnavailableError as exc:
                rollback_path = result.backup_path or str(backup)
                raise click.ClickException(
                    "configuration was written and verified, but the canonical setup audit event "
                    f"could not be recorded after restart: {exc}; restore {rollback_path} to roll back"
                ) from exc
    if emit_json:
        click.echo(
            json.dumps(
                _preview_json(
                    preview,
                    dry_run=False,
                    applied=result.changed,
                    backup_path=result.backup_path,
                    verified_plan_digest=verified.plan_digest,
                    restarted=restart,
                ),
                indent=2,
                sort_keys=True,
            )
        )
    else:
        click.echo("Configuration updated and verified.")
        if result.backup_path:
            click.echo(f"Backup: {result.backup_path}")
        if not restart:
            click.echo("The gateway will hot-reload supported policy changes; restart if required by the plan.")


def _render_status(status, *, compact: bool = False) -> None:
    click.echo(f"Plan digest: {status.plan_digest}")
    click.echo("\nDestinations")
    for destination in status.destinations:
        marker = (
            " (generated, locked)"
            if destination.generated and destination.name == "managed-enterprise-ai-defense"
            else ""
        )
        click.echo(
            f"  {destination.name}: signals={','.join(destination.selected_signals) or '-'} "
            f"redaction={destination.redaction_label}{marker}"
        )
    if compact:
        return
    click.echo("\nBuckets")
    _render_buckets(status.buckets)
    for code, path, summary in status.warnings:
        click.echo(f"warning: {code}: {path}: {summary}", err=True)


def _render_buckets(buckets) -> None:
    click.echo(f"  {'BUCKET':<24} {'SIGNALS':<22} PROFILE")
    for bucket in buckets:
        click.echo(f"  {bucket.name:<24} {','.join(bucket.collected_signals) or '-':<22} {bucket.redaction_profile}")


def _render_preview(preview) -> None:
    click.echo("\nRedaction policy preview")
    click.echo(f"  Effective legs changed: {len(preview.changes)}")
    click.echo(f"  Newly unredacted: {preview.newly_unredacted}")
    click.echo(f"  No longer unredacted: {preview.no_longer_unredacted}")
    for change in preview.changes[:40]:
        click.echo(
            f"  {change.destination}/{change.route} {change.bucket} {change.signal}: {change.before} -> {change.after}"
        )
    if len(preview.changes) > 40:
        click.echo(f"  ... {len(preview.changes) - 40} additional effective changes")
    for destination, profiles in preview.locked_profiles:
        click.echo(f"  Managed policy remains locked: {destination} ({', '.join(profiles)})")
    for code, path, summary in preview.warnings:
        click.echo(f"  warning: {code}: {path}: {summary}", err=True)


def _preview_json(
    preview,
    *,
    dry_run: bool,
    applied: bool = False,
    backup_path: str | None = None,
    verified_plan_digest: str | None = None,
    restarted: bool = False,
) -> dict[str, Any]:
    return {
        "dry_run": dry_run,
        "applied": applied,
        "backup_path": backup_path,
        "verified_plan_digest": verified_plan_digest,
        "restarted": restarted,
        "changed": preview.changed,
        "before_plan_digest": preview.before_plan_digest,
        "after_plan_digest": preview.after_plan_digest,
        "changed_legs": len(preview.changes),
        "newly_unredacted": preview.newly_unredacted,
        "no_longer_unredacted": preview.no_longer_unredacted,
        "changes": [
            {
                "destination": change.destination,
                "route": change.route,
                "bucket": change.bucket,
                "signal": change.signal,
                "before": change.before,
                "after": change.after,
            }
            for change in preview.changes
        ],
        "locked_profiles": [
            {"destination": destination, "profiles": list(profiles)}
            for destination, profiles in preview.locked_profiles
        ],
        "warnings": [{"code": code, "path": path, "summary": summary} for code, path, summary in preview.warnings],
    }


def _route_from_options(name: str, options: Mapping[str, Any]) -> dict[str, Any]:
    selector: dict[str, Any] = {}
    for option, key in (
        ("buckets", "buckets"),
        ("sources", "sources"),
        ("connectors", "connectors"),
        ("producer_actions", "actions"),
        ("event_names", "event_names"),
    ):
        values = options.get(option) or ()
        if values:
            selector[key] = list(values)
    if options.get("min_severity"):
        selector["min_severity"] = options["min_severity"]
    route: dict[str, Any] = {
        "name": name,
        "signals": list(options["signals"]),
        "selector": selector,
        "action": options["route_action"],
    }
    profile = options.get("profile")
    if profile is not None:
        route["redaction_profile"] = profile
    return route


def _parse_fields(values: Sequence[str]) -> dict[str, str | None]:
    result: dict[str, str | None] = {}
    for value in values:
        if "=" not in value:
            raise click.BadParameter("field assignments must use CLASS=MODE", param_hint="--field")
        field_class, mode = (part.strip() for part in value.split("=", 1))
        if field_class not in FIELD_CLASSES:
            raise click.BadParameter(f"unknown field class {field_class!r}", param_hint="--field")
        if mode == "inherit":
            result[field_class] = None
        elif mode in FIELD_MODES:
            result[field_class] = mode
        else:
            raise click.BadParameter(f"unknown field mode {mode!r}", param_hint="--field")
    return result


def _split_values(raw: str, *, allowed: set[str] | None) -> tuple[str, ...]:
    values = tuple(dict.fromkeys(part.strip() for part in raw.split(",") if part.strip()))
    if not values:
        raise ValueError("select at least one value")
    if allowed is not None:
        invalid = [value for value in values if value not in allowed]
        if invalid:
            raise ValueError(f"unsupported value(s): {', '.join(invalid)}")
    if "*" in values and len(values) != 1:
        raise ValueError("wildcard must be the only selected value")
    return values


def _prompt_profile(
    source: Mapping[str, Any],
    *,
    allow_inherit: bool = False,
    excluded: set[str] | None = None,
    default: str | None = None,
) -> str:
    choices = [profile for profile in redaction_profile_names(source) if profile not in (excluded or set())]
    if allow_inherit:
        choices.insert(0, "inherit")
    for index, profile in enumerate(choices, start=1):
        click.echo(f"  {index}. {profile}")
    default_index = choices.index(default) + 1 if default in choices else 1
    selected = click.prompt("Profile", type=click.IntRange(1, len(choices)), default=default_index)
    return choices[selected - 1]


def _custom_profile(source: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    observability = source.get("observability")
    profiles = observability.get("redaction_profiles") if isinstance(observability, Mapping) else None
    value = profiles.get(name) if isinstance(profiles, Mapping) else None
    return value if isinstance(value, Mapping) else {}


def _effective_source_defaults(source: Mapping[str, Any]) -> dict[str, Any]:
    observability = source.get("observability")
    defaults = observability.get("defaults") if isinstance(observability, Mapping) else None
    result = dict(defaults) if isinstance(defaults, Mapping) else {}
    result["collect"] = dict(result.get("collect") or {})
    return result


def _effective_source_bucket(source: Mapping[str, Any], bucket: str) -> dict[str, Any]:
    defaults = _effective_source_defaults(source)
    default_collect = {signal: bool(defaults["collect"].get(signal, True)) for signal in SIGNALS}
    profile = str(defaults.get("redaction_profile") or "none")
    observability = source.get("observability")
    buckets = observability.get("buckets") if isinstance(observability, Mapping) else None
    policy = buckets.get(bucket) if isinstance(buckets, Mapping) else None
    if isinstance(policy, Mapping):
        authored_collect = policy.get("collect")
        if isinstance(authored_collect, Mapping):
            for signal in SIGNALS:
                if signal in authored_collect:
                    default_collect[signal] = authored_collect[signal] is True
        if policy.get("redaction_profile"):
            profile = str(policy["redaction_profile"])
    return {"collect": default_collect, "redaction_profile": profile}


def _render_related_controls(source: Mapping[str, Any]) -> None:
    guardrail = source.get("guardrail")
    retain = True
    if isinstance(guardrail, Mapping) and "retain_judge_bodies" in guardrail:
        retain = guardrail.get("retain_judge_bodies") is True
    discovery = source.get("ai_discovery")
    raw_paths = isinstance(discovery, Mapping) and discovery.get("store_raw_local_paths") is True
    click.echo("\nRelated raw-data controls (read-only here)")
    click.echo(f"  guardrail.retain_judge_bodies: {str(retain).lower()}")
    click.echo(f"  ai_discovery.store_raw_local_paths: {str(raw_paths).lower()}")
    click.echo("  DEFENSECLAW_REVEAL_PII: display-only environment control")
    click.echo("  Mandatory local compliance-floor records remain enabled.")
    click.echo("  Managed enterprise redaction policy is release-owned and immutable.")


def _operator_status(app: AppContext):
    try:
        return inspect_v8_operator_status(_config_path(app))
    except (ValueError, OSError, RuntimeError, ConfigInspectError) as exc:
        raise click.ClickException(str(exc)) from exc


def _effective(app: AppContext) -> dict[str, Any]:
    try:
        result = inspect_v8_config("effective", config_path=str(_config_path(app)), data_dir=app.cfg.data_dir)
    except ConfigInspectError as exc:
        raise click.ClickException(str(exc)) from exc
    return result.effective or {}


def _load_source(app: AppContext) -> tuple[bytes, dict[str, Any]]:
    try:
        return load_redaction_source(_config_path(app))
    except (ValueError, OSError, RuntimeError) as exc:
        raise click.ClickException(str(exc)) from exc


def _config_path(app: AppContext) -> Path:
    if app.cfg is None:
        raise click.ClickException("DefenseClaw configuration is not loaded")
    return config_path_for_data_dir(app.cfg.data_dir)


def _source_destinations(source: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    observability = source.get("observability")
    destinations = observability.get("destinations") if isinstance(observability, Mapping) else None
    if not isinstance(destinations, Sequence) or isinstance(destinations, (str, bytes, bytearray)):
        return []
    return [item for item in destinations if isinstance(item, Mapping)]


def _source_destination_or_click(source: Mapping[str, Any], name: str) -> tuple[int, Mapping[str, Any]]:
    try:
        return source_destination(source, name)
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc


def _destination_capabilities(destination: Mapping[str, Any]) -> tuple[str, ...]:
    """Resolve one configurable destination's supported signal set."""

    if destination.get("preset") == "galileo":
        return ("traces",)
    kind = str(destination.get("kind") or "")
    capabilities = DESTINATION_CAPABILITIES.get(kind)
    if capabilities is None:
        label = kind or "<missing>"
        raise click.ClickException(f"destination kind {label!r} has no supported capability definition")
    return capabilities


def _require_any_change(*values: object) -> None:
    if not any(value is not None for value in values):
        raise click.UsageError("select at least one setting to change")


def _specified_collection(*, logs: bool | None, traces: bool | None, metrics: bool | None) -> dict[str, bool]:
    """Return only collection flags the operator explicitly supplied."""

    return {
        signal: enabled
        for signal, enabled in (("logs", logs), ("traces", traces), ("metrics", metrics))
        if enabled is not None
    }


def _restart_gateway(*, quiet: bool = False) -> None:
    binary = resolve_gateway_binary()
    if not binary:
        raise click.ClickException("configuration was written, but defenseclaw-gateway was not found for restart")
    try:
        completed = subprocess.run(
            [binary, "restart"],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise click.ClickException("configuration was written, but the gateway restart could not complete") from exc
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip()
        message = "configuration was written, but the gateway restart failed; run defenseclaw-gateway restart"
        if detail:
            message += f"\n{detail}"
        raise click.ClickException(message)
    if not quiet:
        click.echo("Gateway restarted.")


__all__ = ["redaction"]
