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

``scan``      — query live OpenClaw to index skills, plugins, MCP, agents, tools, models, memory
"""

from __future__ import annotations

import json

import click

from defenseclaw import ux
from defenseclaw.context import AppContext, pass_ctx
from defenseclaw.provenance import stamp_aibom_inventory


@click.group()
def aibom() -> None:
    """AI Bill of Materials — scan live OpenClaw inventory."""


# ── scan (live OpenClaw inventory) ────────────────────────────────────────


@aibom.command()
@click.option("--json", "as_json", is_flag=True, help="Output full inventory as JSON")
@click.option("--summary", "summary_only", is_flag=True, help="Show summary table only")
@click.option(
    "--only",
    "categories",
    default=None,
    help="Comma-separated categories to scan: skills,plugins,mcp,agents,tools,models,memory",
)
@pass_ctx
def scan(app: AppContext, as_json: bool, summary_only: bool, categories: str | None) -> None:
    """Index a live OpenClaw install (skills, plugins, MCP, agents, tools, models, memory).

    Calls ``openclaw`` CLI commands in parallel and builds a unified inventory.
    Results are stored in the audit DB.

    Use --only to restrict which categories are collected (faster).
    Use --summary to show only the summary table.
    """
    from defenseclaw.inventory.claw_inventory import (
        build_claw_aibom,
        claw_aibom_to_scan_result,
        enrich_with_policy,
        format_claw_aibom_human,
    )

    cats: set[str] | None = None
    if categories:
        cats = {c.strip().lower() for c in categories.split(",") if c.strip()}

    if not as_json:
        click.echo(ux.dim("Scanning live OpenClaw environment …"), err=True)
    inv = build_claw_aibom(app.cfg, live=True, categories=cats)

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

    if as_json:
        stamp_aibom_inventory(inv, app.cfg)
        click.echo(json.dumps(inv, indent=2))
        return

    format_claw_aibom_human(inv, summary_only=summary_only)

    from defenseclaw.commands import hint
    hint(
        "View alerts:  defenseclaw alerts",
        "Scan skills:  defenseclaw skill scan all",
    )
