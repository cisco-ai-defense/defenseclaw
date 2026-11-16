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

"""``defenseclaw setup cowork``: the per-user Claude Cowork route."""

from __future__ import annotations

import json
import os
import subprocess
import time
from datetime import datetime, timezone

import click

from defenseclaw import cowork, platform_support, ux
from defenseclaw.context import AppContext, pass_ctx

_POLL_SECONDS = 3.0

# The gateway's answer when the Claude Code connector has not installed its
# hooks yet (connector cowork-plugin --json).
_NOT_SET_UP = "claudecode_not_set_up"


def _refuse_on_managed_host(cfg) -> None:
    """Exit 3, audited, beside a managed install (M-DEP-4)."""
    deployment = cowork.managed_host(cfg)
    if not deployment:
        return
    from defenseclaw.enforce.asset_lists import audit_managed_config_refusal

    audit_managed_config_refusal("cowork-plugin", "setup cowork")
    ux.echo(
        f"This computer's DefenseClaw is managed by your organization ({deployment}), so per-user Cowork setup "
        "is disabled: Cowork is covered by the Claude Code machine policy your administrator deploys. "
        "Nothing was changed.",
        err=True,
    )
    raise SystemExit(3)


def _ensure_claude_code_connector(ctx: click.Context, app: AppContext, yes: bool) -> None:
    """Cowork runs the Claude Code connector's hook: set that up first."""
    if cowork._claudecode_enabled(app.cfg):
        return
    ux.subhead(
        "Cowork runs DefenseClaw through the Claude Code connector's hooks, and that connector is not set up "
        "on this account."
    )
    if not yes and not click.confirm("  Set up the Claude Code connector now?", default=True):
        raise click.ClickException(
            "Cowork needs the Claude Code connector. Set it up with: defenseclaw setup claude-code, "
            "then run defenseclaw setup cowork again. Nothing was changed."
        )
    from defenseclaw import config as cfg_mod
    from defenseclaw.commands.cmd_setup import setup_claude_code

    ctx.invoke(setup_claude_code, yes=yes)
    app.cfg = cfg_mod.load()
    if not cowork._claudecode_enabled(app.cfg):
        raise click.ClickException(
            "The Claude Code connector is still not active, so the Cowork plugin was not built. "
            "Check it with: defenseclaw doctor"
        )


def _render_hooks(cfg, *, allow_not_set_up: bool = False) -> dict | None:
    """The gateway's hooks.json for the plugin (connector cowork-plugin).

    With *allow_not_set_up* a gateway that answers "the Claude Code connector
    is not set up" returns None: it can build the plugin once that connector
    runs. Every other refusal stops setup before anything is written.
    """
    from defenseclaw.commands.cmd_setup import _gateway_lifecycle_resolution
    from defenseclaw.config import gateway_home_for_data_dir
    from defenseclaw.pinned_exec import UnsafePathError, run_pinned_executable

    executable, refused = _gateway_lifecycle_resolution()
    if not executable:
        if refused:
            raise click.ClickException(f"The Cowork plugin was not built: {refused}. Nothing was changed.")
        raise click.ClickException(
            "defenseclaw-gateway was not found, so the Cowork plugin cannot be built. "
            "Run the DefenseClaw installer, then defenseclaw setup cowork again."
        )
    data_dir = str(cfg.data_dir)
    # The gateway reads the install-home config.yaml, which names a moved data_dir (GAP-0844).
    try:
        result = run_pinned_executable(
            [executable, "connector", "cowork-plugin", "--data-dir", data_dir, "--json"],
            capture_output=True,
            text=True,
            shell=False,
            stdin=subprocess.DEVNULL,
            timeout=60,
            env={**os.environ, "DEFENSECLAW_HOME": gateway_home_for_data_dir(data_dir)},
        )
    except (UnsafePathError, subprocess.TimeoutExpired, OSError) as exc:
        raise click.ClickException(f"defenseclaw-gateway could not render the Cowork hooks ({exc}).") from exc
    try:
        doc = json.loads(result.stdout or "")
    except ValueError:
        doc = None
    if result.returncode != 0 or not isinstance(doc, dict) or "error" in doc:
        reason = doc.get("reason") if isinstance(doc, dict) else ""
        message = str((doc.get("error") if isinstance(doc, dict) else "") or (result.stderr or "").strip())
        if reason == _NOT_SET_UP:
            if allow_not_set_up:
                return None
            raise click.ClickException(
                f"{message}. Run defenseclaw setup claude-code (the gateway installs its hooks when it starts), "
                "then defenseclaw setup cowork again. Nothing was changed."
            )
        if "unknown command" in (result.stderr or ""):
            raise click.ClickException(
                "This defenseclaw-gateway cannot build the Cowork plugin; update DefenseClaw and try again. "
                "Nothing was changed."
            )
        raise click.ClickException(
            f"The Cowork plugin was not built: {message or f'defenseclaw-gateway exited {result.returncode}'}. "
            "Nothing was changed."
        )
    try:
        return cowork.validate_hooks_document(doc)
    except ValueError as exc:
        raise click.ClickException(f"The Cowork plugin was not built: {exc}. Nothing was changed.") from exc


def _gateway_health(cfg) -> tuple[dict | None, str]:
    from defenseclaw.commands.cmd_doctor import _authenticated_gateway_health

    try:
        health, reason, _checked = _authenticated_gateway_health(cfg)
    except Exception as exc:  # noqa: BLE001 - the wait reports it and keeps polling
        return None, type(exc).__name__
    return health, reason


def _wait_for_cowork(cfg, started: datetime, timeout: int) -> datetime | None:
    """Poll the gateway's authenticated status until a Cowork hook call
    (any event; the first one is SessionStart) newer than *started* arrives."""
    deadline = time.monotonic() + timeout
    last_reason = ""
    while time.monotonic() < deadline:
        health, reason = _gateway_health(cfg)
        if health is None:
            if reason and reason != last_reason:
                ux.warn(f"Gateway: {reason}; still waiting.")
                last_reason = reason
        else:
            last_reason = ""
            activity = cowork.cowork_activity_from_health(health)
            seen = max(activity.values(), default=None)
            if seen is not None and seen >= started:
                return seen
        time.sleep(_POLL_SECONDS)
    return None


@click.command(
    "cowork",
    epilog=(
        "Cowork does not read ~/.claude/settings.json; it loads plugins from your Claude account. "
        "DefenseClaw cannot add or remove an account plugin: you upload the zip once, and remove it in "
        f"Claude ({cowork.REMOVE_PATH_TEXT}). Managed computers are covered by machine policy instead."
    ),
)
@click.option(
    "--yes",
    "-y",
    "--non-interactive",
    "yes",
    is_flag=True,
    help="Answer yes to setting up the Claude Code connector; do not open Claude or wait unless asked.",
)
@click.option(
    "--open-claude/--no-open-claude",
    default=None,
    help="Open Claude Desktop after building the plugin (default: ask; with --yes: no).",
)
@click.option(
    "--wait/--no-wait",
    default=None,
    help="Wait until a Cowork session reaches DefenseClaw (default: wait; with --yes: no).",
)
@click.option(
    "--timeout",
    type=click.IntRange(10, 3600),
    default=900,
    show_default=True,
    help="Seconds to wait for the first Cowork session.",
)
@click.pass_context
@pass_ctx
def setup_cowork(
    app: AppContext,
    ctx: click.Context,
    yes: bool,
    open_claude: bool | None,
    wait: bool | None,
    timeout: int,
) -> None:
    """Protect Claude Cowork with DefenseClaw on this account.

    Builds the DefenseClaw plugin for Claude Cowork: its hooks run the Claude
    Code connector's DefenseClaw hook on this device, so every Cowork prompt
    and tool call is inspected before it runs and audited; in the Claude Code
    connector's action mode a policy hit is blocked. Upload the zip in Claude
    Desktop (Customize > Plugins > Add > Upload plugin). Setup then waits
    until a Cowork session reaches the gateway and reports Cowork as
    protected.

    Sets up the Claude Code connector first when it is off (asks; --yes
    answers yes). Running it again rebuilds the zip with a newer plugin
    version.
    """
    from defenseclaw import __version__

    _refuse_on_managed_host(app.cfg)
    if platform_support.host_os() == "linux":
        # The support matrix lists Cowork on Linux as Preview (cowork audit P4-3).
        ux.warn(
            "Cowork on Linux is a preview: Claude Desktop for Linux is a beta, and Cowork on Linux is not certified."
        )
    if not cowork._claudecode_enabled(app.cfg):
        # Ask the gateway first: one that cannot build the plugin must not
        # leave the Claude Code connector switched on for nothing.
        _render_hooks(app.cfg, allow_not_set_up=True)
        _ensure_claude_code_connector(ctx, app, yes)
    cfg = app.cfg
    data_dir = str(cfg.data_dir)
    hooks_doc = _render_hooks(cfg)

    state = cowork.load_state(data_dir)
    rebuilt = bool(state.get("version"))
    started = datetime.now(timezone.utc)
    build, version = cowork.next_version(state, started, data_dir)
    try:
        archive = cowork.plugin_zip_bytes(hooks_doc, version, __version__)
    except (OSError, ValueError) as exc:
        raise click.ClickException(
            f"The Cowork plugin could not copy its installed Windows guard ({exc}). "
            "Run the DefenseClaw installer, then defenseclaw setup cowork again."
        ) from exc
    try:
        path, digest = cowork.write_plugin_zip(data_dir, archive)
    except OSError as exc:
        # No traceback: name the folder, the cause and the fix (GAP-0054).
        raise click.ClickException(cowork.plugin_write_refusal(data_dir, exc)) from exc
    # A new build is confirmed only by a Cowork event after it: the plugin
    # the account holds may still be the earlier one, or none.
    if previous := state.pop("last_event_at", None):
        state["previous_event_at"] = previous
    state.pop("confirmed_at", None)
    state.update(
        {
            "build": build,
            "version": version,
            "zip": path,
            "zip_sha256": digest,
            "built_at": started.isoformat(),
            "defenseclaw_version": __version__,
        }
    )
    cowork.save_state(data_dir, state)
    cowork.clear_uninstalled_marker(data_dir)

    ux.ok(f"Built the DefenseClaw Cowork plugin {version}: {path}")
    ux.echo(f"    Cowork calls will run in the Claude Code connector's {cowork.mode_text(cfg)}.")
    ux.subhead("Add it to your Claude account:")
    for number, step in enumerate(cowork.upload_steps(path), start=1):
        ux.echo(f"    {number}. {step}")
    if rebuilt:
        ux.echo(
            ux.dim(
                "    An earlier DefenseClaw plugin keeps working until this one is live; "
                "if Claude then lists two, uninstall the older version."
            )
        )
    if not cowork.claude_desktop_installed():
        ux.warn("Claude Desktop was not found for this account; install it, then follow the steps above.")

    if open_claude is None:
        open_claude = (not yes) and click.confirm("  Open Claude now?", default=True)
    if open_claude:
        if cowork.open_claude():
            ux.ok("Opened Claude. Go to Customize > Plugins.")
        else:
            ux.warn("Could not open Claude; open it yourself.")

    if wait is None:
        wait = not yes
    if not wait:
        ux.echo(ux.dim("  Check it later with: defenseclaw status"))
        return
    ux.echo(
        f"  Waiting up to {timeout // 60 or 1} min for a Cowork session to reach DefenseClaw "
        "(Ctrl+C stops waiting; the plugin stays built)..."
    )
    try:
        seen = _wait_for_cowork(cfg, started, timeout)
    except KeyboardInterrupt:
        ux.echo()
        ux.warn("Stopped waiting. Cowork is not confirmed yet; check it with: defenseclaw status")
        return
    if seen is None:
        ux.warn(
            "No Cowork session reached DefenseClaw yet, so Cowork is not protected yet. Finish the steps above, "
            "start a Cowork task, then check: defenseclaw status"
        )
        return
    state["last_event_at"] = seen.isoformat()
    state["confirmed_at"] = datetime.now(timezone.utc).isoformat()
    cowork.save_state(data_dir, state)
    ux.ok(
        "Cowork is protected: a Cowork session reached DefenseClaw at "
        f"{seen.astimezone(timezone.utc).strftime('%Y-%m-%d %H:%M:%SZ')}."
    )
    ux.echo(f"    Cowork calls run in the Claude Code connector's {cowork.mode_text(cfg)}.")
