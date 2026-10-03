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

from defenseclaw import ux
from defenseclaw.audit_actions import ACTION_CONFIG_UPDATE
from defenseclaw.context import AppContext, pass_ctx
from defenseclaw.credentials import (
    CredentialSpec,
    CredentialStatus,
    Requirement,
    classify,
    lookup,
    mask,
)


def _emit_bound_endpoint_hint(spec: CredentialSpec | None, cfg, *, indent: str) -> None:
    """Print a "↪ bound to <url>" hint after a credential is saved.

    Surfaces the operator's *current* paired endpoint so a key that
    was issued for a different region/host is caught at save time
    rather than at the next failed probe. No-op when the spec has no
    bound endpoint (most credentials), so this is safe to call
    unconditionally on every save.
    """
    if spec is None:
        return
    endpoint = spec.resolve_bound_endpoint(cfg)
    if not endpoint:
        return
    click.echo(f"{indent}{ux.dim('↪ bound to ' + endpoint)}")
    click.echo(f"{indent}{ux.dim('  change region/host: defenseclaw setup')}")


@click.group("keys")
def keys_cmd() -> None:
    """Inspect and manage DefenseClaw API keys (list, set, remove, check)."""


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
        click.echo(f"  {ux.dim('No credentials to report.')}")
        return

    _render_table(statuses, show_values=show_values)
    if not missing_only:
        _render_unregistered(app, statuses)


def _gateway_token_names(cfg) -> set[str]:
    """Env names that hold DefenseClaw's own gateway auth token."""
    names = {"DEFENSECLAW_GATEWAY_TOKEN", "OPENCLAW_GATEWAY_TOKEN"}
    token_env = str(getattr(getattr(cfg, "gateway", None), "token_env", "") or "").strip()
    if token_env:
        names.add(token_env)
    return names


def required_removal_warning(cfg, env_name: str) -> str:
    """The line that says removing ``env_name`` breaks a feature in use (GAP-2254).

    Empty when the current config does not REQUIRE the key. ``keys list``
    marks such a key "● REQUIRED <feature>"; ``keys remove`` and the TUI
    confirm repeat that before the key is deleted.
    """
    try:
        statuses = classify(cfg)
    except Exception:  # noqa: BLE001 - a partial config must not block a remove.
        return ""
    for status in statuses:
        if status.resolution.env_name == env_name and status.requirement is Requirement.REQUIRED:
            return (
                f"{env_name} is REQUIRED by {status.spec.feature} in the current config; "
                f"{status.spec.feature} stops working until the key is set again."
            )
    return ""


def _render_unregistered(app: AppContext, statuses: list[CredentialStatus]) -> None:
    """Name .env entries that are not in the registry so they can be removed."""
    import os

    known = {s.resolution.env_name for s in statuses} | {s.spec.env_name for s in statuses}
    dotenv_path = os.path.join(app.cfg.data_dir, ".env")
    stored = [name for name in _dotenv_names(dotenv_path) if name not in known]
    gateway_tokens = _gateway_token_names(app.cfg)
    managed = sorted(name for name in stored if name in gateway_tokens)
    extra = sorted(name for name in stored if name not in gateway_tokens)
    if managed:
        click.echo(
            f"  {ux.bold('Managed by DefenseClaw')} {ux.dim('(gateway auth token, do not remove):')} "
            f"{', '.join(managed)}"
        )
    if not extra:
        return
    click.echo(f"  {ux.bold('Other entries in .env')} {ux.dim('(not in the registry):')} {', '.join(extra)}")
    click.echo(f"  {ux.dim('Remove one with: defenseclaw keys remove <ENV_NAME>')}")


@keys_cmd.command("set")
@click.argument("env_name")
@click.option("--value", "value", default=None, help="Value to store; prompts if omitted.")
@click.option(
    "--value-stdin",
    "value_stdin",
    is_flag=True,
    help="Read the value from the first line of stdin (not echoed); for scripts and the TUI.",
)
@pass_ctx
def keys_set(app: AppContext, env_name: str, value: str | None, value_stdin: bool) -> None:
    """Set a credential and persist it to ``~/.defenseclaw/.env``.

    The value comes from ``--value``, ``--value-stdin`` (first line of
    standard input, trailing newline removed), or a hidden prompt.
    """
    import os

    if value_stdin and value is not None:
        raise click.UsageError("--value and --value-stdin are mutually exclusive")
    if value_stdin:
        line = click.get_text_stream("stdin").readline()
        value = line.rstrip("\r\n")
        if not value:
            ux.err("No value on stdin — nothing saved.")
            raise SystemExit(1)

    from defenseclaw.commands.cmd_setup import _save_secret_to_dotenv

    env_name = env_name.strip()
    if not env_name:
        raise click.UsageError("env_name must be non-empty")

    spec = lookup(env_name, app.cfg)
    if spec is None:
        ux.warn(f"{env_name} is not in the DefenseClaw registry.")
        ux.subhead(
            "Saving anyway — it will be available via os.environ for custom setups.",
            indent="    ",
        )
    else:
        click.echo(f"  {ux.bold(spec.feature + ':')} {spec.description}")

    if value is None:
        value = click.prompt(
            f"  {env_name}",
            hide_input=True,
            confirmation_prompt=False,
            default="",
            show_default=False,
        )

    if not value:
        ux.err("No value provided — nothing saved.")
        ux.subhead(f"To clear a stored key, run: defenseclaw keys remove {env_name}", indent="  ")
        raise click.Abort()

    dotenv_path = os.path.join(app.cfg.data_dir, ".env")
    had = False
    if os.path.isfile(dotenv_path):
        try:
            with open(dotenv_path, encoding="utf-8") as ef:
                had = any(
                    line.strip().startswith(f"{env_name}=")
                    for line in ef.read().splitlines()
                )
        except OSError:
            had = False

    _save_secret_to_dotenv(env_name, value, app.cfg.data_dir)
    if app.logger:
        from defenseclaw.logger import CanonicalObservabilityUnavailableError

        try:
            app.logger.log_activity(
                actor="cli:operator",
                action=ACTION_CONFIG_UPDATE,
                target_type="config",
                target_id=f"dotenv:{env_name}",
                before={"env": env_name, "had_value": had},
                after={"env": env_name, "had_value": True},
                diff=[
                    {
                        "path": f"/.env/{env_name}",
                        "op": "replace",
                        "before": "set" if had else "unset",
                        "after": "set",
                    },
                ],
            )
        except CanonicalObservabilityUnavailableError:
            # Same offline rule as policy activate: the key is saved, only the
            # audit event can't be admitted while the gateway is down.
            click.echo(
                "  ⚠ Key saved, but the gateway runtime is unavailable; the audit event was not recorded.",
                err=True,
            )
    # One path style: keys remove prints os.path.join too (GAP-1297).
    ux.ok(f"Saved {env_name} = {mask(value)} to {dotenv_path}", indent="  ")
    _emit_bound_endpoint_hint(spec, app.cfg, indent="    ")


@keys_cmd.command("remove")
@click.argument("env_name")
@click.option("--yes", "-y", is_flag=True, help="Skip the confirmation prompt.")
@pass_ctx
def keys_remove(app: AppContext, env_name: str, yes: bool) -> None:
    """Remove a credential from ``~/.defenseclaw/.env``.

    Works for any name stored there, including keys that are not in the
    DefenseClaw registry. A value exported in your shell is not touched.
    """
    import os

    env_name = env_name.strip()
    if not env_name:
        raise click.UsageError("env_name must be non-empty")

    dotenv_path = os.path.join(app.cfg.data_dir, ".env")
    if env_name not in _dotenv_names(dotenv_path):
        ux.warn(f"{env_name} is not stored in {dotenv_path} — nothing removed.")
        return
    if env_name in _gateway_token_names(app.cfg):
        raise click.ClickException(
            f"{env_name} is DefenseClaw's own gateway auth token; removing it would cut the hooks, "
            "the CLI and the TUI off from the gateway. It is not removed. "
            "To reset it, run 'defenseclaw setup' or 'defenseclaw init'."
        )
    if warning := required_removal_warning(app.cfg, env_name):
        ux.warn(warning)
    if not yes and not click.confirm(f"  Remove {env_name} from {dotenv_path}?", default=False):
        raise click.Abort()

    from defenseclaw import credential_provenance

    # Decide where the process value came from before the file changes: the
    # provenance marker is tied to the .env digest, so asking afterwards
    # always answered "the shell exported it".
    shell_value = os.environ.get(env_name, "")
    from_dotenv = bool(shell_value) and credential_provenance.was_injected_from_dotenv(
        app.cfg.data_dir, env_name, shell_value
    )
    if not _remove_dotenv_key(dotenv_path, env_name):
        ux.warn(f"{env_name} is not stored in {dotenv_path} — nothing removed.")
        return
    if from_dotenv:
        os.environ.pop(env_name, None)
    if app.logger:
        from defenseclaw.logger import CanonicalObservabilityUnavailableError

        try:
            app.logger.log_activity(
                actor="cli:operator",
                action=ACTION_CONFIG_UPDATE,
                target_type="config",
                target_id=f"dotenv:{env_name}",
                before={"env": env_name, "had_value": True},
                after={"env": env_name, "had_value": False},
                diff=[{"path": f"/.env/{env_name}", "op": "remove", "before": "set", "after": "unset"}],
            )
        except CanonicalObservabilityUnavailableError:
            click.echo(
                "  ⚠ Key removed, but the gateway runtime is unavailable; the audit event was not recorded.",
                err=True,
            )
    ux.ok(f"Removed {env_name} from {dotenv_path}", indent="  ")
    if shell_value and not from_dotenv:
        ux.subhead(f"{env_name} is still exported in this shell; unset it there too.", indent="    ")


def _dotenv_names(dotenv_path: str) -> list[str]:
    """Return the key names stored in a dotenv file (never the values)."""
    from defenseclaw.commands.cmd_setup import _load_dotenv

    try:
        return list(_load_dotenv(dotenv_path))
    except OSError:
        return []


def _remove_dotenv_key(dotenv_path: str, env_name: str) -> bool:
    """Drop every ``env_name=`` line from the dotenv file; keep all other bytes."""
    import os

    from defenseclaw.commands.cmd_setup import _rotate_token_snapshot_locked
    from defenseclaw.config import locked_file_update
    from defenseclaw.file_permissions import atomic_write_private_bytes

    wanted = env_name.encode("utf-8")
    if os.name == "nt":
        wanted = wanted.upper()
    with locked_file_update(dotenv_path):
        snapshot = _rotate_token_snapshot_locked(dotenv_path)
        if not snapshot.existed:
            return False
        kept: list[bytes] = []
        removed = False
        for line in snapshot.body.splitlines(keepends=True):
            key, sep, _value = line.strip().partition(b"=")
            key = key.strip()
            if os.name == "nt":
                key = key.upper()
            if sep and key == wanted:
                removed = True
                continue
            kept.append(line)
        if removed:
            atomic_write_private_bytes(dotenv_path, b"".join(kept))
        return removed


@keys_cmd.command("fill-missing")
@click.option("--yes", is_flag=True, help="Skip the confirmation prompt.")
@pass_ctx
def keys_fill_missing(app: AppContext, yes: bool) -> None:
    """Interactively prompt for every REQUIRED-but-unset credential."""
    from defenseclaw.commands.cmd_setup import _save_secret_to_dotenv

    statuses = [s for s in classify(app.cfg) if s.missing]
    if not statuses:
        ux.ok("No missing required credentials — you're all set.")
        return

    ux.warn(f"{len(statuses)} required credential(s) are unset:")
    for s in statuses:
        click.echo(
            f"    {ux.dim('•')} {ux.bold(s.resolution.env_name)}  "
            f"{ux.dim('—')}  {s.spec.description}"
        )

    if not yes and not click.confirm("  Enter values now?", default=True):
        ux.subhead("Skipped. Run 'defenseclaw keys set <ENV>' when you're ready.")
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
            ux.err("skipped", indent="      ")
            skipped += 1
            continue
        _save_secret_to_dotenv(s.resolution.env_name, value, app.cfg.data_dir)
        ux.ok(f"saved ({mask(value)})", indent="      ")
        _emit_bound_endpoint_hint(s.spec, app.cfg, indent="        ")
        saved += 1

    click.echo()
    click.echo(
        f"  {ux.bold('Result:')} {saved} saved, {skipped} skipped."
    )


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

    click.echo(
        f"  {total_required - len(missing)}/{total_required} "
        f"{ux.bold('required credentials')} set."
    )
    if missing:
        for s in missing:
            ux.err(f"{s.resolution.env_name}  —  {s.spec.description}", indent="  ")
        # click.get_current_context().exit(1) — plays nicely with
        # CliRunner (gives us a non-zero exit_code) while remaining
        # consistent with other Click commands in this CLI.
        click.get_current_context().exit(1)
    ux.ok("all required credentials present", indent="  ")


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
    # Pad before styling: ANSI codes count toward str.ljust widths.
    hdr = "  " + "  ".join(ux.bold(h.ljust(widths[i])) for i, h in enumerate(headers))
    click.echo(hdr)
    click.echo("  " + "  ".join(ux.dim("─" * widths[i]) for i in range(len(headers))))
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
    click.echo(
        f"  {ux.bold('Legend:')}  ● required   ○ optional   · not used by current config"
    )
    click.echo(
        "           "
        + ux.dim(
            "Source: 'env' = process environment, 'dotenv' = ~/.defenseclaw/.env, "
            "'unset' = missing"
        )
    )


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
