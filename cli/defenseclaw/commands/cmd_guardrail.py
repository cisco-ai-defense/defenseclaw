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

"""``defenseclaw guardrail {enable,disable}`` — connector-agnostic toggle.

Today operators have to use ``defenseclaw setup guardrail [--disable]``,
which interleaves "I want to flip the enabled bit" with "I want to
re-prompt for model / scanner-mode / Cisco endpoint / judge config".
That works for first-time setup but feels heavy for the very common
case of "the guardrail is acting up, give me a quick off switch".

This command surfaces the toggle directly:

  defenseclaw guardrail disable    # turn off + connector teardown
  defenseclaw guardrail enable     # turn on + connector setup
  defenseclaw guardrail status     # is it on, which connector, which mode

Both ``enable`` and ``disable`` are connector-agnostic. They resolve
the active connector from ``Config.active_connector()`` and delegate
the actual config-patch work to the Go sidecar's ``Connector.Setup``
/ ``Connector.Teardown`` (running at sidecar boot when the
``guardrail.enabled`` flag flips). The Python side never has to know
how Codex / Claude Code / ZeptoClaw configure themselves.
"""

from __future__ import annotations

import click

from defenseclaw import ux
from defenseclaw.context import AppContext, pass_ctx

# Note: ``defenseclaw.commands.cmd_setup._restart_services`` is
# intentionally NOT imported at module load. Importing cmd_setup
# pulls in the heavy ``click`` command tree (every setup subcommand,
# every connector wizard) which we don't need when the operator runs
# ``defenseclaw guardrail status`` or any of the no-restart paths
# below. Each subcommand imports ``_restart_services`` lazily inside
# its ``if restart`` branch — keeps cmd_guardrail importable in
# trimmed-down environments and lets tests patch
# ``cmd_setup._restart_services`` (the canonical lookup target) once
# rather than per-subcommand.

_CONNECTOR_LABELS = {
    "openclaw": "OpenClaw",
    "claudecode": "Claude Code",
    "codex": "Codex",
    "zeptoclaw": "ZeptoClaw",
    "hermes": "Hermes",
    "cursor": "Cursor",
    "windsurf": "Windsurf",
    "geminicli": "Gemini CLI",
    "copilot": "GitHub Copilot CLI",
    "openhands": "OpenHands",
    "antigravity": "Antigravity",
}


def _resolve_active_connector(cfg) -> str:
    """Return the active connector for ``cfg``, lowercased.

    Mirrors :meth:`Config.active_connector` but tolerates older
    in-process configs that haven't been migrated yet.
    """
    if cfg is None:
        return "openclaw"
    if hasattr(cfg, "active_connector") and callable(cfg.active_connector):
        try:
            name = (cfg.active_connector() or "").strip().lower()
            if name:
                return name
        except Exception:
            pass
    if hasattr(cfg, "guardrail") and hasattr(cfg.guardrail, "connector"):
        name = (cfg.guardrail.connector or "").strip().lower()
        if name:
            return name
    return "openclaw"


def _connector_label(name: str) -> str:
    return _CONNECTOR_LABELS.get(name, name)


def _active_connector_set(cfg, fallback: str) -> list[str]:
    """Return the full active-connector set (multi-connector aware).

    Falls back to ``[fallback]`` for older configs or single-connector
    installs so enable/disable messaging stays accurate either way.
    """
    if cfg is not None and hasattr(cfg, "active_connectors"):
        try:
            names = list(cfg.active_connectors())
            if names:
                return names
        except Exception:  # noqa: BLE001 — fall back to the primary connector.
            pass
    return [fallback]


def _resolve_member_connector(app, requested: str) -> str | None:
    """Return the canonical ``guardrail.connectors`` key matching
    ``requested`` (case-insensitive), or ``None`` if it is not a member."""
    conns = getattr(app.cfg.guardrail, "connectors", {}) or {}
    req = requested.strip().lower()
    for key in conns:
        if key.strip().lower() == req:
            return key
    return None


def _toggle_connector_guardrail(
    app: AppContext, requested: str, *, enable: bool, restart: bool, yes: bool
) -> None:
    """Enable/disable the guardrail for a SINGLE connector.

    Per-connector analog of the global enable/disable: it flips
    ``guardrail.connectors[X].enabled`` and (on restart) lets the Go boot
    loop run that one connector's ``Setup``/``Teardown`` via the existing
    set-difference path — the others are untouched. The connector's other
    policy fields (mode/hilt/rule_pack_dir) are retained so re-enable
    restores it with no re-prompt.

    ``--connector`` is a multi-connector feature: on a single-connector
    install (no ``guardrail.connectors`` map) it points the operator at the
    global switch rather than silently creating a one-entry map.
    """
    conns = getattr(app.cfg.guardrail, "connectors", {}) or {}
    verb = "enable" if enable else "disable"

    if not conns:
        ux.err("--connector is only valid on multi-connector installs.", indent="  ")
        ux.subhead(
            f"This is a single-connector install; use 'defenseclaw guardrail {verb}' "
            "(no --connector).",
            indent="    ",
        )
        raise SystemExit(1)

    key = _resolve_member_connector(app, requested)
    if key is None:
        ux.err(f"Connector {requested!r} is not configured.", indent="  ")
        ux.subhead("Configured connectors: " + ", ".join(sorted(conns)), indent="    ")
        raise SystemExit(1)

    label = _connector_label(key.strip().lower())

    # No-op if already in the requested state.
    if app.cfg.guardrail.effective_enabled(key) == enable:
        state = "enabled" if enable else "disabled"
        click.echo(f"  {ux.dim(f'Connector {label} is already {state}.')}")
        return

    # Disabling the last remaining enabled connector is effectively a global
    # disable — warn so the operator can use the clearer command.
    if not enable:
        still_enabled = [
            k
            for k in conns
            if k != key and app.cfg.guardrail.effective_enabled(k)
        ]
        if not still_enabled:
            ux.subhead(
                f"{label} is the only enabled connector; disabling it leaves the "
                "gateway with nothing to enforce (equivalent to 'guardrail disable').",
                indent="  ",
            )

    click.echo()
    word = "Enabling" if enable else "Disabling"
    click.echo(f"  {ux.bold(f'{word} guardrail')} for {label} ({key}) only")
    action = "setup" if enable else "teardown"
    if restart:
        ux.subhead(
            f"Will restart the gateway so the {label} connector {action} runs immediately.",
            indent="  ",
        )
    else:
        ux.subhead(
            f"--no-restart specified: flag persisted but the connector {action} won't "
            "run until you restart the gateway manually.",
            indent="  ",
        )
    click.echo()

    if not yes and not click.confirm("  Proceed?", default=True):
        click.echo(f"  {ux.dim('Cancelled.')}")
        raise SystemExit(1)

    # Mutate the per-connector entry, preserving its other policy fields.
    from defenseclaw.config import PerConnectorGuardrailConfig

    entry = conns.get(key)
    if entry is None:
        entry = PerConnectorGuardrailConfig()
        conns[key] = entry
    entry.enabled = bool(enable)
    try:
        app.cfg.save()
        ux.ok(
            f"Config saved (guardrail.connectors.{key}.enabled = {str(enable).lower()})",
            indent="  ",
        )
    except OSError as exc:
        ux.err(f"Failed to save config: {exc}", indent="  ")
        raise SystemExit(1)

    if restart:
        from defenseclaw.commands import cmd_setup

        cmd_setup._restart_services(
            app.cfg.data_dir,
            app.cfg.gateway.host,
            app.cfg.gateway.port,
            connector=key,
        )
        ux.ok(f"{label} connector {action} complete", indent="  ")
        click.echo()

    if app.logger:
        app.logger.log_action(
            f"guardrail-{verb}",
            "config",
            f"connector={key} scope=per-connector "
            f"enabled={str(enable).lower()} restart={restart}",
        )


@click.group("guardrail")
def guardrail() -> None:
    """Toggle the LLM guardrail on or off.

    Wraps ``defenseclaw setup guardrail`` with quick on/off subcommands
    so day-to-day operators don't have to navigate the full setup flow
    just to flip the ``guardrail.enabled`` switch.
    """


@guardrail.command("status")
@pass_ctx
def status_cmd(app: AppContext) -> None:
    """Show whether the guardrail is enabled and which connector is active."""
    gc = app.cfg.guardrail
    connector = _resolve_active_connector(app.cfg)
    fail_mode = (getattr(gc, "hook_fail_mode", "") or "open").lower()
    ux.section("Guardrail status", indent="  ")
    enabled_txt = "yes" if gc.enabled else "no"
    enabled_val = ux._style(enabled_txt, fg="green") if gc.enabled else ux._style(enabled_txt, fg="yellow")
    click.echo(f"  • {ux._style('enabled:', fg='bright_black', bold=True)}    {enabled_val}")
    click.echo(
        f"  • {ux._style('connector:', fg='bright_black', bold=True)}  {_connector_label(connector)} ({connector})"
    )
    click.echo(f"  • {ux._style('mode:', fg='bright_black', bold=True)}       {gc.mode or 'observe'}")

    # D7: in a multi-connector install, status MUST reflect EVERY active
    # connector, not just the primary — each can carry its own effective
    # mode / fail mode via guardrail.connectors. Single-connector installs
    # skip this block, so their output is unchanged.
    try:
        actives = app.cfg.active_connectors() if hasattr(app.cfg, "active_connectors") else [connector]
    except Exception:  # noqa: BLE001 — fall back to the primary connector.
        actives = [connector]
    if len(actives) > 1:
        click.echo(
            f"  • {ux._style('connectors:', fg='bright_black', bold=True)} {len(actives)} active"
        )
        for name in actives:
            cmode = gc.effective_mode(name) if hasattr(gc, "effective_mode") else (gc.mode or "observe")
            cfm = (
                gc.effective_hook_fail_mode(name)
                if hasattr(gc, "effective_hook_fail_mode")
                else fail_mode
            )
            # Per-connector on/off (D-parity with the global enabled bit):
            # a connector turned off via `guardrail disable --connector X`
            # is reported as disabled so the roster never implies it is
            # enforcing when its hooks have been torn down.
            c_enabled = (
                gc.effective_enabled(name)
                if hasattr(gc, "effective_enabled")
                else True
            )
            state = (
                ux._style("enabled", fg="green")
                if c_enabled
                else ux._style("disabled", fg="yellow")
            )
            click.echo(
                f"      - {_connector_label(name)} ({name}): "
                f"{state} mode={cmode or 'observe'} fail={cfm}"
            )
    fm_display = ux._style(fail_mode, fg="yellow") if fail_mode == "closed" else fail_mode
    click.echo(
        f"  • {ux._style('fail mode:', fg='bright_black', bold=True)}  {fm_display}  "
        f"{ux.dim('(hook response-layer failures)')}"
    )
    click.echo(f"  • {ux._style('port:', fg='bright_black', bold=True)}       {gc.port}")
    click.echo()
    if gc.enabled:
        click.echo(f"  {ux.dim('Disable with:')}  defenseclaw guardrail disable")
    else:
        click.echo(f"  {ux.dim('Enable with:')}   defenseclaw guardrail enable")
    click.echo()


@guardrail.command("disable")
@click.option(
    "--restart/--no-restart",
    default=True,
    help="Restart the gateway after disabling (default: on; needed to run connector teardown).",
)
@click.option("--yes", is_flag=True, help="Skip the confirmation prompt.")
@click.option(
    "--connector",
    "connector_flag",
    default=None,
    help="Scope the disable to a single connector (multi-connector installs only). "
    "Omit to disable the whole guardrail.",
)
@pass_ctx
def disable_cmd(
    app: AppContext, restart: bool, yes: bool, connector_flag: str | None
) -> None:
    """Disable the LLM guardrail and run connector teardown.

    Without ``--connector`` this is the global kill switch: it sets
    ``guardrail.enabled = false`` in ~/.defenseclaw/config.yaml and (when
    --restart is on, the default) restarts the gateway so the sidecar boot
    path runs ``Connector.Teardown`` for EVERY active connector.

    With ``--connector X`` it scopes the disable to one connector: the boot
    loop drops X from the active set so only X's hooks/config are torn down
    (the others keep running). X's policy is retained so a later
    ``guardrail enable --connector X`` restores it with no re-prompt.
    """
    if connector_flag:
        _toggle_connector_guardrail(
            app, connector_flag, enable=False, restart=restart, yes=yes
        )
        return

    gc = app.cfg.guardrail
    connector = _resolve_active_connector(app.cfg)

    if not gc.enabled:
        click.echo(f"  {ux.dim('Guardrail is already disabled')} ({_connector_label(connector)} connector).")
        return

    click.echo()
    click.echo(f"  {ux.bold('Disabling guardrail')} for {_connector_label(connector)} ({connector})")
    if restart:
        ux.subhead(
            "Will restart the gateway so the connector teardown runs immediately.",
            indent="  ",
        )
    else:
        ux.subhead(
            "--no-restart specified: gateway will continue running with the old policy "
            "until you restart it manually ('defenseclaw-gateway restart').",
            indent="  ",
        )
    click.echo()

    if not yes and not click.confirm("  Proceed?", default=True):
        click.echo(f"  {ux.dim('Cancelled.')}")
        raise SystemExit(1)

    gc.enabled = False
    try:
        app.cfg.save()
        ux.ok("Config saved (guardrail.enabled = false)", indent="  ")
    except OSError as exc:
        ux.err(f"Failed to save config: {exc}", indent="  ")
        ux.subhead("Re-run after fixing the underlying I/O error.", indent="    ")
        raise SystemExit(1)

    if restart:
        # Lazy import: see module-level note. We import the cmd_setup
        # MODULE rather than the function so test patches that target
        # ``defenseclaw.commands.cmd_setup._restart_services`` (the
        # canonical lookup target) intercept the call. ``from
        # cmd_setup import _restart_services`` would bind a local
        # name at lazy-import time which still picks up an active
        # patch, but going through ``cmd_setup._restart_services()``
        # is the more obviously-correct form for readers.
        from defenseclaw.commands import cmd_setup

        cmd_setup._restart_services(
            app.cfg.data_dir,
            app.cfg.gateway.host,
            app.cfg.gateway.port,
            connector=connector,
        )
        # In a multi-connector install the gateway boot loop tears down
        # EVERY active connector on restart, so report them all rather
        # than implying only the primary was affected.
        _actives = _active_connector_set(app.cfg, connector)
        if len(_actives) > 1:
            ux.ok(
                f"connector teardown complete for {len(_actives)} connectors: "
                + ", ".join(_actives),
                indent="  ",
            )
        else:
            ux.ok(f"{_connector_label(connector)} connector teardown complete", indent="  ")
        click.echo()

    if app.logger:
        app.logger.log_action(
            "guardrail-disable",
            "config",
            f"connector={connector} restart={restart}",
        )


@guardrail.command("enable")
@click.option(
    "--restart/--no-restart",
    default=True,
    help="Restart the gateway after enabling (default: on; needed to run connector setup).",
)
@click.option("--yes", is_flag=True, help="Skip the confirmation prompt.")
@click.option(
    "--connector",
    "connector_flag",
    default=None,
    help="Scope the enable to a single connector (multi-connector installs only). "
    "Omit to enable the whole guardrail.",
)
@pass_ctx
def enable_cmd(
    app: AppContext, restart: bool, yes: bool, connector_flag: str | None
) -> None:
    """Re-enable the LLM guardrail using the existing config.

    Without ``--connector`` this is the inverse of the global disable: it
    sets ``guardrail.enabled = true`` and (when --restart is on) restarts
    the gateway so the sidecar runs ``Connector.Setup`` for the active
    connector. Use ``defenseclaw setup guardrail`` instead when you actually
    want to re-configure the model / scanner-mode / connector.

    With ``--connector X`` it re-enables a single previously-disabled
    connector: the boot loop runs X's ``Setup`` again while the others are
    untouched.
    """
    if connector_flag:
        _toggle_connector_guardrail(
            app, connector_flag, enable=True, restart=restart, yes=yes
        )
        return

    gc = app.cfg.guardrail
    connector = _resolve_active_connector(app.cfg)

    if gc.enabled:
        click.echo(f"  {ux.dim('Guardrail is already enabled')} ({_connector_label(connector)} connector).")
        return

    # Sanity-check that there's enough config for re-enable to actually
    # work. If model / api_key_env are empty the connector would
    # silently route real traffic through an unconfigured upstream, so
    # we fail fast with a remediation pointer to the full setup flow.
    if not (gc.model or app.cfg.llm.model):
        ux.err("Cannot enable: guardrail.model is not set.", indent="  ")
        ux.subhead("Run 'defenseclaw setup guardrail' to configure first.", indent="    ")
        raise SystemExit(1)

    click.echo()
    click.echo(f"  {ux.bold('Enabling guardrail')} for {_connector_label(connector)} ({connector})")
    if restart:
        ux.subhead(
            "Will restart the gateway so the connector setup runs immediately.",
            indent="  ",
        )
    else:
        ux.subhead(
            "--no-restart specified: enabled flag is persisted but the connector "
            "setup won't run until you restart the gateway manually.",
            indent="  ",
        )
    click.echo()

    if not yes and not click.confirm("  Proceed?", default=True):
        click.echo(f"  {ux.dim('Cancelled.')}")
        raise SystemExit(1)

    gc.enabled = True
    try:
        app.cfg.save()
        ux.ok("Config saved (guardrail.enabled = true)", indent="  ")
    except OSError as exc:
        ux.err(f"Failed to save config: {exc}", indent="  ")
        raise SystemExit(1)

    if restart:
        # Lazy import via module: see disable_cmd above for rationale.
        from defenseclaw.commands import cmd_setup

        cmd_setup._restart_services(
            app.cfg.data_dir,
            app.cfg.gateway.host,
            app.cfg.gateway.port,
            connector=connector,
        )
        # The boot loop runs Connector.Setup for EVERY active connector;
        # report them all in a multi-connector install.
        _actives = _active_connector_set(app.cfg, connector)
        if len(_actives) > 1:
            ux.ok(
                f"connector setup complete for {len(_actives)} connectors: "
                + ", ".join(_actives),
                indent="  ",
            )
        else:
            ux.ok(f"{_connector_label(connector)} connector setup complete", indent="  ")
        click.echo()

    if app.logger:
        app.logger.log_action(
            "guardrail-enable",
            "config",
            f"connector={connector} restart={restart}",
        )


@guardrail.command("fail-mode")
@click.argument("mode", required=False, type=click.Choice(["open", "closed"]))
@click.option(
    "--restart/--no-restart",
    default=True,
    help="Restart the gateway so hooks are regenerated with the new fail mode (default: on).",
)
@click.option("--yes", is_flag=True, help="Skip the confirmation prompt.")
@pass_ctx
def fail_mode_cmd(app: AppContext, mode: str | None, restart: bool, yes: bool) -> None:
    """Show or change the hook fail mode (response-layer behavior).

    The hook fail mode controls what generated hooks do when the
    DefenseClaw gateway answers but the answer is bad — a 4xx, an
    unparseable JSON body, or a missing ``action`` field. Two values
    are supported:

      \b
      open   — allow the tool/prompt and log the failure.
               A misbehaving gateway never bricks your agent.
               Recommended for almost all installs.
      closed — block the tool/prompt on any gateway error.
               Choose for regulated workflows where every prompt
               MUST be inspected.

    Transport-layer failures (gateway unreachable / 5xx) are NOT
    governed by this setting — they always allow unless the agent's
    environment has ``DEFENSECLAW_STRICT_AVAILABILITY=1``. That is
    the dedicated escape hatch for sites that prefer agent downtime
    to a missed inspection during a real outage.

    Without an argument this prints the current value. With
    ``open`` or ``closed`` it persists the choice to ~/.defenseclaw/
    config.yaml and (when --restart is on) restarts the gateway so
    the regenerated hooks pick up the new value immediately.
    """
    gc = app.cfg.guardrail
    current = (gc.hook_fail_mode or "open").lower()
    if current not in ("open", "closed"):
        current = "open"

    if mode is None:
        click.echo()
        click.echo(f"  {ux.bold('guardrail.hook_fail_mode:')} {ux.accent(current)}")
        click.echo()
        if current == "open":
            ux.subhead(
                "Response-layer failures (4xx, malformed JSON) ALLOW the tool/prompt.",
                indent="  ",
            )
            click.echo(f"  {ux.dim('Switch to closed:')} defenseclaw guardrail fail-mode closed")
        else:
            ux.subhead(
                "Response-layer failures (4xx, malformed JSON) BLOCK the tool/prompt.",
                indent="  ",
            )
            click.echo(f"  {ux.dim('Switch to open:')}   defenseclaw guardrail fail-mode open")
        click.echo()
        ux.subhead(
            "Transport-layer failures (gateway unreachable) always allow unless "
            "DEFENSECLAW_STRICT_AVAILABILITY=1 is set in the agent env.",
            indent="  ",
        )
        click.echo()
        return

    if mode == current:
        click.echo(f"  {ux.dim('Hook fail mode is already')} {mode!r} {ux.dim('— nothing to do.')}")
        return

    click.echo()
    click.echo(f"  {ux.bold('Changing hook fail mode:')} {current} {ux.dim('→')} {ux.accent(mode)}")
    if mode == "closed":
        ux.warn(
            "Response-layer failures will now BLOCK the agent.",
            indent="  ",
        )
        ux.subhead(
            "A misconfigured gateway response (4xx, bad JSON) will exit 2 from "
            "every hook. Make sure your gateway is healthy before flipping this.",
            indent="    ",
        )
    else:
        ux.subhead(
            "Response-layer failures will now ALLOW the agent and log the failure to "
            "~/.defenseclaw/logs/hook-failures.jsonl.",
            indent="  ",
        )
    click.echo()

    if not yes and not click.confirm("  Proceed?", default=True):
        click.echo(f"  {ux.dim('Cancelled.')}")
        # click.Abort routes through Click's exception handler and
        # cooperates with the result callbacks the setup group
        # registers (e.g., the auto-restart suppression keyed on
        # _SETUP_RESTART_HANDLED_KEY in cmd_setup.py); a bare
        # SystemExit bypasses that machinery.
        raise click.Abort()

    gc.hook_fail_mode = mode
    try:
        app.cfg.save()
        ux.ok(f"Config saved (guardrail.hook_fail_mode = {mode})", indent="  ")
    except OSError as exc:
        ux.err(f"Failed to save config: {exc}", indent="  ")
        raise click.Abort()

    if restart and gc.enabled:
        connector = _resolve_active_connector(app.cfg)
        # Lazy import via module: see disable_cmd above for rationale.
        from defenseclaw.commands import cmd_setup

        cmd_setup._restart_services(
            app.cfg.data_dir,
            app.cfg.gateway.host,
            app.cfg.gateway.port,
            connector=connector,
        )
        ux.ok("Gateway restarted, hooks regenerated with the new fail mode.", indent="  ")
        click.echo()
    elif not gc.enabled:
        ux.warn(
            "guardrail is currently disabled — value will take effect "
            "the next time you run 'defenseclaw guardrail enable'.",
            indent="  ",
        )

    if app.logger:
        app.logger.log_action(
            "guardrail-fail-mode",
            "config",
            f"old={current} new={mode} restart={restart}",
        )
