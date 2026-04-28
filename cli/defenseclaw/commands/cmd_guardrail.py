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

from defenseclaw.context import AppContext, pass_ctx


_CONNECTOR_LABELS = {
    "openclaw": "OpenClaw",
    "claudecode": "Claude Code",
    "codex": "Codex",
    "zeptoclaw": "ZeptoClaw",
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
    click.echo()
    click.echo("  Guardrail status")
    click.echo("  ─────────────────")
    click.echo(f"  • enabled:    {'yes' if gc.enabled else 'no'}")
    click.echo(f"  • connector:  {_connector_label(connector)} ({connector})")
    click.echo(f"  • mode:       {gc.mode or 'observe'}")
    click.echo(f"  • port:       {gc.port}")
    click.echo()
    if gc.enabled:
        click.echo("  Disable with:  defenseclaw guardrail disable")
    else:
        click.echo("  Enable with:   defenseclaw guardrail enable")
    click.echo()


@guardrail.command("disable")
@click.option("--restart/--no-restart", default=True,
              help="Restart the gateway after disabling (default: on; needed to run connector teardown).")
@click.option("--yes", is_flag=True, help="Skip the confirmation prompt.")
@pass_ctx
def disable_cmd(app: AppContext, restart: bool, yes: bool) -> None:
    """Disable the LLM guardrail and run connector teardown.

    Sets ``guardrail.enabled = false`` in ~/.defenseclaw/config.yaml
    and (when --restart is on, the default) restarts the gateway so the
    sidecar boot path runs ``Connector.Teardown`` for the active
    connector. The teardown removes hook scripts, env shims, and
    config patches that ``Connector.Setup`` originally installed.
    """
    gc = app.cfg.guardrail
    connector = _resolve_active_connector(app.cfg)

    if not gc.enabled:
        click.echo(f"  Guardrail is already disabled ({_connector_label(connector)} connector).")
        return

    click.echo()
    click.echo(f"  Disabling guardrail for {_connector_label(connector)} ({connector})")
    if restart:
        click.echo("  Will restart the gateway so the connector teardown runs immediately.")
    else:
        click.echo("  --no-restart specified: gateway will continue running with the old policy")
        click.echo("  until you restart it manually ('defenseclaw-gateway restart').")
    click.echo()

    if not yes and not click.confirm("  Proceed?", default=True):
        click.echo("  Cancelled.")
        raise SystemExit(1)

    gc.enabled = False
    try:
        app.cfg.save()
        click.echo("  ✓ Config saved (guardrail.enabled = false)")
    except OSError as exc:
        click.echo(f"  ✗ Failed to save config: {exc}", err=True)
        click.echo("    Re-run after fixing the underlying I/O error.", err=True)
        raise SystemExit(1)

    if restart:
        # Lazy import: cmd_setup pulls in heavy click trees we don't
        # need when --no-restart is set, and we want this command to
        # stay importable in environments where the operator has
        # disabled some optional providers.
        from defenseclaw.commands.cmd_setup import _restart_services

        _restart_services(
            app.cfg.data_dir,
            app.cfg.gateway.host,
            app.cfg.gateway.port,
            connector=connector,
        )
        click.echo(f"  ✓ {_connector_label(connector)} connector teardown complete")
        click.echo()

    if app.logger:
        app.logger.log_action(
            "guardrail-disable", "config",
            f"connector={connector} restart={restart}",
        )


@guardrail.command("enable")
@click.option("--restart/--no-restart", default=True,
              help="Restart the gateway after enabling (default: on; needed to run connector setup).")
@click.option("--yes", is_flag=True, help="Skip the confirmation prompt.")
@pass_ctx
def enable_cmd(app: AppContext, restart: bool, yes: bool) -> None:
    """Re-enable the LLM guardrail using the existing config.

    This is the inverse of ``defenseclaw guardrail disable``: it sets
    ``guardrail.enabled = true`` and (when --restart is on) restarts
    the gateway so the sidecar runs ``Connector.Setup`` for the active
    connector. Use ``defenseclaw setup guardrail`` instead when you
    actually want to re-configure the model / scanner-mode / connector.
    """
    gc = app.cfg.guardrail
    connector = _resolve_active_connector(app.cfg)

    if gc.enabled:
        click.echo(f"  Guardrail is already enabled ({_connector_label(connector)} connector).")
        return

    # Sanity-check that there's enough config for re-enable to actually
    # work. If model / api_key_env are empty the connector would
    # silently route real traffic through an unconfigured upstream, so
    # we fail fast with a remediation pointer to the full setup flow.
    if not (gc.model or app.cfg.llm.model):
        click.echo(
            "  ✗ Cannot enable: guardrail.model is not set.\n"
            "    Run 'defenseclaw setup guardrail' to configure first.",
            err=True,
        )
        raise SystemExit(1)

    click.echo()
    click.echo(f"  Enabling guardrail for {_connector_label(connector)} ({connector})")
    if restart:
        click.echo("  Will restart the gateway so the connector setup runs immediately.")
    else:
        click.echo("  --no-restart specified: enabled flag is persisted but the connector")
        click.echo("  setup won't run until you restart the gateway manually.")
    click.echo()

    if not yes and not click.confirm("  Proceed?", default=True):
        click.echo("  Cancelled.")
        raise SystemExit(1)

    gc.enabled = True
    try:
        app.cfg.save()
        click.echo("  ✓ Config saved (guardrail.enabled = true)")
    except OSError as exc:
        click.echo(f"  ✗ Failed to save config: {exc}", err=True)
        raise SystemExit(1)

    if restart:
        from defenseclaw.commands.cmd_setup import _restart_services

        _restart_services(
            app.cfg.data_dir,
            app.cfg.gateway.host,
            app.cfg.gateway.port,
            connector=connector,
        )
        click.echo(f"  ✓ {_connector_label(connector)} connector setup complete")
        click.echo()

    if app.logger:
        app.logger.log_action(
            "guardrail-enable", "config",
            f"connector={connector} restart={restart}",
        )
