# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""defenseclaw setup tokenomics: turn per-call model usage and cost on or off."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import click
import yaml

from defenseclaw import config_writer
from defenseclaw.config import config_path_for_data_dir
from defenseclaw.context import AppContext, pass_ctx
from defenseclaw.tokenomics_seed import pricing_changes

MANAGED_EXIT_CODE = 3


def _read(path: Path) -> dict[str, Any]:
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise click.ClickException(f"cannot read {path}: {exc}") from exc
    return doc if isinstance(doc, dict) else {}


def _section(parent: Any, key: str) -> dict[str, Any]:
    value = parent.get(key) if isinstance(parent, dict) else None
    return value if isinstance(value, dict) else {}


def status_of(doc: dict[str, Any]) -> dict[str, Any]:
    """The tokenomics state a config file describes. Pure; used by tests and --json."""
    obs = _section(doc, "observability")
    tok = _section(obs, "tokenomics")
    price = _section(obs, "pricing")
    store = _section(tok, "local_store")
    return {
        "enabled": bool(tok.get("enabled", False)),
        "local_store": bool(store.get("enabled", False)),
        "retention_days": int(store.get("retention_days", 30) or 30),
        "pricing_version": str(price.get("version", "") or ""),
        "priced_models": len(price.get("models") or []),
    }


@click.command("tokenomics")
@click.option("--enable", is_flag=True, help="Record per-call model usage, cost and the local usage aggregate.")
@click.option("--disable", is_flag=True, help="Stop recording model usage. The price table stays in config.yaml.")
@click.option("--status", "show_status", is_flag=True, help="Show whether tokenomics is on.")
@click.option("--seed-pricing", is_flag=True, help="Write the reviewed default price table if config.yaml has none.")
@click.option("--json", "as_json", is_flag=True, help="Print JSON.")
@pass_ctx
def tokenomics(
    app: AppContext, enable: bool, disable: bool, show_status: bool, seed_pricing: bool, as_json: bool
) -> None:
    """Per-call model usage and cost (observability.tokenomics, observability.pricing).

    Off by default. Prices come only from the table in config.yaml; a model
    with no price entry has no cost, never a zero.

    \b
    Examples:
      defenseclaw setup tokenomics --enable
      defenseclaw setup tokenomics --status --json
      defenseclaw setup tokenomics --disable
    """
    if enable and disable:
        raise click.UsageError("Cannot use --enable and --disable together.")
    path = config_path_for_data_dir(getattr(app.cfg, "data_dir", None))
    if not (enable or disable or seed_pricing):
        show_status = True
    if show_status:
        _print(status_of(_read(path)), as_json)
        return
    doc = _read(path)
    changes: list[config_writer.Change] = []
    if enable:
        changes += [
            config_writer.Change("observability.tokenomics.enabled", True),
            config_writer.Change("observability.tokenomics.local_store.enabled", True),
        ]
    if disable:
        changes.append(config_writer.Change("observability.tokenomics.enabled", False))
    if enable or seed_pricing:
        changes += pricing_changes(doc)
    try:
        config_writer.apply(
            changes,
            config_writer.current_actor(config_writer.ACTOR_PREFIX_CLI),
            "defenseclaw setup tokenomics",
            path=path,
        )
    except config_writer.ManagedConfigWriteError as exc:
        click.echo(f"error: {exc}", err=True)
        raise SystemExit(MANAGED_EXIT_CODE) from exc
    except config_writer.ConfigWriteError as exc:
        raise click.ClickException(str(exc)) from exc
    _print(status_of(_read(path)), as_json)


def _onoff(flag: Any) -> str:
    return "on" if flag else "off"


def _print(state: dict[str, Any], as_json: bool) -> None:
    if as_json:
        click.echo(json.dumps(state, sort_keys=True))
        return
    enabled = _onoff(state["enabled"])
    store = _onoff(state["local_store"])
    days = state["retention_days"]
    models = state["priced_models"]
    click.echo(f"  Tokenomics:     {enabled}")
    click.echo(f"  Local store:    {store} (keeps {days} days)")
    if models:
        version = state["pricing_version"] or "(none)"
        click.echo(f"  Price table:    version {version}, {models} models")
    else:
        click.echo("  Price table:    none (cost stays absent; run: defenseclaw setup tokenomics --seed-pricing)")
