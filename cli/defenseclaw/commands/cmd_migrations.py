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

"""defenseclaw migrations — Inspect and recover the migration cursor.

The cursor at ``<data_dir>/.migration_state.json`` is the source of
truth for "which migrations have run on this host" (see
``defenseclaw.migration_state`` for the schema and rationale). This
command surfaces it for operators in three flavours:

* ``defenseclaw migrations status``     — show cursor + registry diff
* ``defenseclaw migrations reset``      — nuke the cursor (force re-bootstrap)
* ``defenseclaw migrations unmark VER`` — re-run a single migration next upgrade

We deliberately keep this OUT of ``defenseclaw doctor`` so the doctor
command stays a single ``--fix`` codepath. Operators who need
fine-grained recovery reach for ``migrations``; everyone else only
ever sees ``upgrade`` and ``doctor --fix``.
"""

from __future__ import annotations

import os
from typing import Any

import click

from defenseclaw import migration_state, ux
from defenseclaw.context import AppContext, pass_ctx


def _resolve_data_dir(app: AppContext) -> str:
    """Return the operator's data dir using the same precedence as
    ``run_migrations``.

    Order: explicit ``Config.data_dir`` -> ``$DEFENSECLAW_HOME``
    -> ``~/.defenseclaw``. Centralised so doctor, upgrade, and these
    subcommands all agree on which directory to inspect; an
    operator's bug report won't differ from "what defenseclaw thinks"
    based on which command they ran.
    """
    if app.cfg and app.cfg.data_dir:
        return app.cfg.data_dir
    return os.environ.get("DEFENSECLAW_HOME") or os.path.expanduser("~/.defenseclaw")


@click.group("migrations")
def migrations_cmd() -> None:
    """Inspect and recover the migration cursor.

    The cursor records every migration that has run on this host. It
    survives package re-installs, version drift, and operator
    restores from backup. If something goes wrong (a migration
    didn't take, a backup restore put you on a stale state, etc.)
    the subcommands here let you reset or partially-reset the cursor
    without clobbering the rest of ``~/.defenseclaw/``.
    """


@migrations_cmd.command("status")
@click.option(
    "--json-output", "json_out", is_flag=True,
    help="Emit machine-readable JSON instead of human-readable text.",
)
@pass_ctx
def status_cmd(app: AppContext, json_out: bool) -> None:
    """Show the cursor and any drift versus the registry.

    Output sections:
    * Cursor metadata (path, schema, package version it was last
      written by).
    * Applied entries with timestamps. ``bootstrap`` means we
      inferred this entry on first upgrade rather than observing
      it run.
    * Registry diff: any entries the operator hasn't seen yet
      (would run on next upgrade) and any orphaned cursor entries
      that no longer have a registry callable (would warn at
      next upgrade but not break anything).

    The ``--json-output`` mode is stable for tooling: doctor's
    ``--json-output`` mode and any external monitor that scrapes
    install state should consume this rather than the prose form.
    """
    from defenseclaw.migrations import MIGRATIONS, _ver_tuple

    data_dir = _resolve_data_dir(app)
    state = migration_state.load(data_dir)
    cursor_path = migration_state.state_path(data_dir)

    registry_versions = [v for v, _, _ in MIGRATIONS]
    applied_set = set(state.applied) if state else set()
    pending = [v for v in registry_versions if v not in applied_set]
    orphan = sorted(applied_set - set(registry_versions), key=_ver_tuple)

    if json_out:
        import json

        payload: dict[str, Any] = {
            "cursor_path": cursor_path,
            "cursor_present": state is not None,
            "schema": state.schema if state else None,
            "package_version": state.package_version if state else None,
            "applied": [
                {"version": v, "applied_at": (state.applied_at.get(v) if state else None)}
                for v in (state.applied if state else [])
            ],
            "pending": pending,
            "orphan": orphan,
            "registry_versions": registry_versions,
        }
        click.echo(json.dumps(payload, indent=2, sort_keys=True))
        return

    ux.banner("Migration Cursor")
    ux.kv("Path", cursor_path, indent="  ", key_width=18)
    if state is None:
        ux.kv("Status", "absent (first upgrade will bootstrap)", indent="  ", key_width=18)
        return
    ux.kv("Schema", str(state.schema), indent="  ", key_width=18)
    ux.kv("Package version", state.package_version or "(unset)", indent="  ", key_width=18)

    if state.applied:
        click.echo()
        click.echo(f"  {ux.bold('Applied:')}")
        for ver in state.applied:
            ts = state.applied_at.get(ver, "?")
            tag = "bootstrap" if ts == migration_state.BOOTSTRAP_SENTINEL else ts
            click.echo(f"    {ux.dim('•')} {ver:<8} {ux.dim(tag)}")
    else:
        click.echo()
        click.echo(f"  {ux.bold('Applied:')} (none)")

    if pending:
        click.echo()
        click.echo(f"  {ux.bold('Pending (will run on next upgrade):')}")
        for ver in pending:
            click.echo(f"    {ux.dim('•')} {ver}")

    if orphan:
        click.echo()
        ux.warn(
            "Orphan cursor entries (recorded as applied but no registry callable):",
        )
        for ver in orphan:
            click.echo(f"    {ux.dim('•')} {ver}")
        click.echo(
            f"    {ux.dim('Use')} 'defenseclaw migrations unmark <VERSION>' "
            f"{ux.dim('to clear them.')}",
        )


@migrations_cmd.command("reset")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation prompt.")
@pass_ctx
def reset_cmd(app: AppContext, yes: bool) -> None:
    """Delete the cursor entirely.

    Use this when the cursor and reality have diverged so far that
    selectively unmarking versions isn't worth it. The next
    ``defenseclaw upgrade`` will bootstrap a fresh cursor based on
    the operator's reported ``__version__`` — meaning it WILL
    re-run any migration that's strictly newer than that version.

    Migrations are required to be idempotent, so a reset followed
    by an upgrade is safe; it's just noisier than not resetting.
    """
    data_dir = _resolve_data_dir(app)
    cursor_path = migration_state.state_path(data_dir)

    if not os.path.exists(cursor_path):
        ux.subhead(f"No cursor at {cursor_path} — nothing to reset.")
        return

    if not yes:
        click.echo()
        click.echo(
            f"  {ux.bold('This will delete')} {cursor_path}.",
        )
        click.echo(
            f"  {ux.dim('The next upgrade will bootstrap from your installed __version__.')}",
        )
        if not click.confirm("  Proceed?", default=False):
            ux.subhead("Aborted.")
            return

    try:
        removed = migration_state.reset(data_dir)
    except OSError as exc:
        ux.err(f"Could not remove cursor file: {exc}", indent="  ")
        raise SystemExit(1) from exc

    if removed:
        ux.ok(f"Removed {cursor_path}")
    else:
        ux.subhead("Cursor was already absent.")


@migrations_cmd.command("unmark")
@click.argument("version")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation prompt.")
@pass_ctx
def unmark_cmd(app: AppContext, version: str, yes: bool) -> None:
    """Remove a single version from the applied set.

    The next ``defenseclaw upgrade`` will re-run that migration's
    callable. Useful when a specific migration is suspected of
    not having taken (e.g. partial filesystem failure during a
    previous upgrade) and you want a targeted re-run instead of a
    full ``reset``.

    The migration callable is required to be idempotent, so
    re-running against already-correct state is a no-op.
    """
    data_dir = _resolve_data_dir(app)
    state = migration_state.load(data_dir)
    if state is None:
        ux.subhead(
            "No cursor present — nothing to unmark. The next upgrade "
            "will bootstrap.",
        )
        return

    if not migration_state.is_applied(state, version):
        ux.subhead(
            f"Version {version} is not in the applied set; nothing to do.",
        )
        return

    if not yes:
        click.echo()
        click.echo(
            f"  {ux.bold('This will mark migration ')}{version}"
            f"{ux.bold(' as unapplied.')}",
        )
        click.echo(
            f"  {ux.dim('The next upgrade will re-run its callable.')}",
        )
        if not click.confirm("  Proceed?", default=False):
            ux.subhead("Aborted.")
            return

    if migration_state.unmark(state, version):
        try:
            migration_state.save(data_dir, state)
        except OSError as exc:
            ux.err(f"Could not persist updated cursor: {exc}", indent="  ")
            raise SystemExit(1) from exc
        ux.ok(f"Migration {version} marked unapplied")
    else:
        ux.subhead(f"Version {version} was not in the applied set.")
