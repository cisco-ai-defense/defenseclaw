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

"""defenseclaw aibom — AI Bill of Materials commands.

``scan``      — query the active connector(s) to index skills, plugins, MCP,
                agents, tools, models, memory
"""

from __future__ import annotations

import json

import click

from defenseclaw import ux
from defenseclaw.context import AppContext, pass_ctx
from defenseclaw.provenance import stamp_aibom_inventory


@click.group()
def aibom() -> None:
    """AI Bill of Materials — scan the active connector(s)' live inventory.

    A bare ``aibom scan`` inventories every active connector (a complete
    bill of materials); pass ``--connector X`` to narrow to one. Inventory
    is read from each connector's own source (openclaw.json,
    .codex/config.toml, .claude/settings.json, …).
    """


# ── scan (live connector inventory) ───────────────────────────────────────


@aibom.command()
@click.option("--json", "as_json", is_flag=True, help="Output full inventory as JSON")
@click.option("--summary", "summary_only", is_flag=True, help="Show summary table only")
@click.option(
    "--only",
    "categories",
    default=None,
    help="Comma-separated categories to scan: skills,plugins,mcp,agents,tools,models,memory",
)
@click.option(
    "--connector", "connector_flag", default="",
    help=(
        "Inventory only a specific connector. Default: every active "
        "connector (a complete bill of materials across all of them)."
    ),
)
@pass_ctx
def scan(
    app: AppContext,
    as_json: bool,
    summary_only: bool,
    categories: str | None,
    connector_flag: str,
) -> None:
    """Index a live install (skills, plugins, MCP, agents, tools, models, memory).

    Builds a unified inventory from the active connector(s)' own
    configuration sources. Results are stored in the audit DB.

    Use --only to restrict which categories are collected (faster).
    Use --summary to show only the summary table.

    An AIBOM (AI Bill of Materials) is meant to be complete, so a bare
    ``aibom scan`` inventories EVERY active connector. On a single-connector
    install that is just the one connector (unchanged behaviour); on a
    multi-connector install it produces a full BOM across all of them. Pass
    ``--connector X`` to narrow the report to a single connector.
    """
    from defenseclaw.commands import resolve_list_connector

    cats: set[str] | None = None
    if categories:
        cats = {c.strip().lower() for c in categories.split(",") if c.strip()}

    # Resolve which connector(s) to inventory.
    #   --connector X  → just X
    #   (no flag)      → every active connector. active_connectors() returns
    #                    [active] on a single-connector install, so a bare
    #                    scan is byte-for-byte unchanged there; on multi it
    #                    fans out to a complete bill of materials.
    if connector_flag:
        connectors: list[str | None] = [resolve_list_connector(app, connector_flag)]
    elif hasattr(app.cfg, "active_connectors"):
        connectors = list(app.cfg.active_connectors())
    else:
        connectors = [None]

    invs: list[dict] = []
    for c in connectors:
        if len(connectors) > 1 and not as_json:
            click.echo(ux._style(f"\n── connector: {c} ──", fg="cyan"))
        invs.append(_scan_one_connector(app, c, cats, as_json, summary_only))

    if as_json:
        # Emit a bare object when exactly one connector resolved (unchanged
        # single-connector contract); a list when several so automation can
        # attribute each blob to its connector.
        if len(invs) == 1:
            click.echo(json.dumps(invs[0], indent=2))
        else:
            click.echo(json.dumps(invs, indent=2))
        return

    if not as_json:
        from defenseclaw.commands import hint
        hint(
            "View alerts:  defenseclaw alerts",
            "Scan skills:  defenseclaw skill scan all",
        )


def _scan_one_connector(
    app: AppContext,
    connector: str | None,
    cats: set[str] | None,
    as_json: bool,
    summary_only: bool,
) -> dict:
    """Build, enrich, log and render the inventory for a single connector.

    Returns the inventory dict so the caller can aggregate every active
    connector into a single JSON payload (the default multi-connector BOM).
    """
    from defenseclaw.inventory.claw_inventory import (
        build_claw_aibom,
        claw_aibom_to_scan_result,
        enrich_with_policy,
        format_claw_aibom_human,
    )

    label = connector or (
        app.cfg.active_connector() if hasattr(app.cfg, "active_connector") else "openclaw"
    )
    if not as_json:
        click.echo(ux.dim(f"Scanning live {label} environment …"), err=True)
    inv = build_claw_aibom(app.cfg, live=True, categories=cats, connector=connector)

    enrich_with_policy(
        inv, app.store, app.cfg.skill_actions,
        policy_dir=app.cfg.policy_dir, cfg=app.cfg,
    )
    result = claw_aibom_to_scan_result(inv, app.cfg)

    if app.logger:
        app.logger.log_scan(result)

    errors = inv.get("errors", [])
    if errors:
        msg = f"Warning: {len(errors)} openclaw command(s) failed"
        if as_json:
            click.echo(ux._style(msg, fg="yellow", bold=True), err=True)
        else:
            ux.warn(f"{len(errors)} openclaw command(s) failed")

    stamp_aibom_inventory(inv, app.cfg)
    if as_json:
        # The caller aggregates every connector's inventory and prints once
        # (a bare object for one connector, a list for several), so just
        # hand the dict back here.
        return inv

    format_claw_aibom_human(inv, summary_only=summary_only)
    return inv
