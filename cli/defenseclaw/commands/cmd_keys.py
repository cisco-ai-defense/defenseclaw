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

"""defenseclaw keys — API-key registry UX.

Single pane of glass for the operator to see what keys DefenseClaw
knows about, which ones the current config actually needs, and where
each value came from (env vs. ``~/.defenseclaw/.env`` vs. unset).

Everything here is driven by ``defenseclaw.credentials.CREDENTIALS``
so the command never drifts from reality when a new credential is
added.
"""

from __future__ import annotations

import json

import click

from defenseclaw.context import AppContext, pass_ctx
from defenseclaw.credentials import (
    CredentialStatus,
    Requirement,
    classify,
    lookup,
    mask,
)


@click.group("keys")
def keys_cmd() -> None:
    """Inspect and manage DefenseClaw API keys."""


@keys_cmd.command("list")
@click.option("--json", "as_json", is_flag=True, help="Emit machine-readable JSON instead of a table.")
@click.option("--show-values", is_flag=True, help="Show masked value previews (still truncated).")
@click.option(
    "--missing-only",
    is_flag=True,
    help="Only show credentials that are required by the current config but unset.",
)
@pass_ctx
def keys_list(app: AppContext, as_json: bool, show_values: bool, missing_only: bool) -> None:
    """List every credential DefenseClaw knows about."""
    statuses = classify(app.cfg)
    if missing_only:
        statuses = [s for s in statuses if s.missing]

    if as_json:
        click.echo(json.dumps([_status_to_dict(s, show_values) for s in statuses], indent=2))
        return

    if not statuses:
        click.echo("  No credentials to report.")
        return

    _render_table(statuses, show_values=show_values)


@keys_cmd.command("set")
@click.argument("env_name")
@click.option("--value", "value", default=None, help="Value to store; prompts if omitted.")
@pass_ctx
def keys_set(app: AppContext, env_name: str, value: str | None) -> None:
    """Set a credential and persist it to ``~/.defenseclaw/.env``."""
    from defenseclaw.commands.cmd_setup import _save_secret_to_dotenv

    env_name = env_name.strip()
    if not env_name:
        raise click.UsageError("env_name must be non-empty")

    spec = lookup(env_name)
    if spec is None:
        click.echo(f"  ⚠ {env_name} is not in the DefenseClaw registry.")
        click.echo("    Saving anyway — it will be available via os.environ for custom setups.")
    else:
        click.echo(f"  {spec.feature}: {spec.description}")

    if value is None:
        value = click.prompt(
            f"  {env_name}",
            hide_input=True,
            confirmation_prompt=False,
            default="",
            show_default=False,
        )

    if not value:
        click.echo("  ✗ No value provided — nothing saved.")
        raise click.Abort()

    _save_secret_to_dotenv(env_name, value, app.cfg.data_dir)
    click.echo(f"  ✓ Saved {env_name} = {mask(value)} to {app.cfg.data_dir}/.env")


@keys_cmd.command("fill-missing")
@click.option("--yes", is_flag=True, help="Skip the confirmation prompt.")
@pass_ctx
def keys_fill_missing(app: AppContext, yes: bool) -> None:
    """Interactively prompt for every REQUIRED-but-unset credential."""
    from defenseclaw.commands.cmd_setup import _save_secret_to_dotenv

    statuses = [s for s in classify(app.cfg) if s.missing]
    if not statuses:
        click.echo("  ✓ No missing required credentials — you're all set.")
        return

    click.echo(f"  {len(statuses)} required credential(s) are unset:")
    for s in statuses:
        click.echo(f"    • {s.resolution.env_name}  —  {s.spec.description}")

    if not yes and not click.confirm("  Enter values now?", default=True):
        click.echo("  Skipped. Run 'defenseclaw keys set <ENV>' when you're ready.")
        return

    saved = 0
    skipped = 0
    for s in statuses:
        value = click.prompt(
            f"    {s.resolution.env_name}",
            hide_input=True,
            confirmation_prompt=False,
            default="",
            show_default=False,
        )
        if not value:
            click.echo("      ✗ skipped")
            skipped += 1
            continue
        _save_secret_to_dotenv(s.resolution.env_name, value, app.cfg.data_dir)
        click.echo(f"      ✓ saved ({mask(value)})")
        saved += 1

    click.echo()
    click.echo(f"  Result: {saved} saved, {skipped} skipped.")


@keys_cmd.command("check")
@pass_ctx
def keys_check(app: AppContext) -> None:
    """Exit 0 when all REQUIRED keys are set, non-zero otherwise.

    Intended for CI/preflight hooks. Produces a terse summary on
    stdout and nothing else.
    """
    statuses = classify(app.cfg)
    missing = [s for s in statuses if s.missing]
    total_required = sum(1 for s in statuses if s.requirement is Requirement.REQUIRED)

    click.echo(f"  {total_required - len(missing)}/{total_required} required credentials set.")
    if missing:
        for s in missing:
            click.echo(f"  ✗ {s.resolution.env_name}  —  {s.spec.description}")
        # click.get_current_context().exit(1) — plays nicely with
        # CliRunner (gives us a non-zero exit_code) while remaining
        # consistent with other Click commands in this CLI.
        click.get_current_context().exit(1)
    click.echo("  ✓ all required credentials present")


# ---------------------------------------------------------------------------
# Rendering helpers
# ---------------------------------------------------------------------------

_STATUS_GLYPH = {
    Requirement.REQUIRED: "●",
    Requirement.OPTIONAL: "○",
    Requirement.NOT_USED: "·",
}


def _render_table(statuses: list[CredentialStatus], show_values: bool) -> None:
    rows = [_format_row(s, show_values=show_values) for s in statuses]
    headers = ["", "ENV NAME", "FEATURE", "REQUIREMENT", "SOURCE", "VALUE" if show_values else "STATUS"]
    widths = [max(len(headers[i]), *(len(r[i]) for r in rows)) for i in range(len(headers))]

    # Header
    click.echo()
    click.echo("  " + "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers)))
    click.echo("  " + "  ".join("─" * widths[i] for i in range(len(headers))))
    for r in rows:
        click.echo("  " + "  ".join(r[i].ljust(widths[i]) for i in range(len(headers))))
    click.echo()
    _render_legend()


def _format_row(s: CredentialStatus, show_values: bool) -> list[str]:
    glyph = _STATUS_GLYPH[s.requirement]
    env_name = s.resolution.env_name
    feature = s.spec.feature
    requirement = s.requirement.value
    source = s.resolution.source if s.resolution.is_set else "unset"

    if show_values:
        last_col = mask(s.resolution.value) if s.resolution.is_set else "—"
    else:
        if s.resolution.is_set:
            last_col = "✓ set"
        elif s.requirement is Requirement.REQUIRED:
            last_col = "MISSING"
        elif s.requirement is Requirement.OPTIONAL:
            last_col = "unset"
        else:
            last_col = "n/a"

    return [glyph, env_name, feature, requirement, source, last_col]


def _render_legend() -> None:
    click.echo("  Legend:  ● required   ○ optional   · not used by current config")
    click.echo("           Source: 'env' = process environment, 'dotenv' = ~/.defenseclaw/.env, 'unset' = missing")


def _status_to_dict(s: CredentialStatus, include_value: bool) -> dict:
    data = {
        "env_name": s.resolution.env_name,
        "canonical_env_name": s.spec.env_name,
        "feature": s.spec.feature,
        "description": s.spec.description,
        "requirement": s.requirement.value,
        "source": s.resolution.source,
        "auto_detected": s.spec.auto_detected,
        "set": s.resolution.is_set,
    }
    if include_value and s.resolution.is_set:
        data["value_masked"] = mask(s.resolution.value)
    return data
