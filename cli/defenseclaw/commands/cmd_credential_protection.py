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

"""DefenseClaw commands for the bundled s-gw credential broker."""

from __future__ import annotations

import json

import click

from defenseclaw import ux
from defenseclaw.context import AppContext, pass_ctx
from defenseclaw.credential_protection import (
    CredentialProtectionError,
    has_sgw_mcp_registrations,
    launch_agent,
    mcp_connector_status,
    mcp_reconciliation_failed,
    mcp_removal_failed,
    open_broker,
    reconcile_mcp_connectors,
    remediation,
    remove_managed_mcp_connectors,
    rollback_mcp_reconciliation,
    rollback_mcp_removal,
    safe_status,
    setup_broker_for_runtime,
)

_CONNECTORS = [
    "openclaw",
    "zeptoclaw",
    "claudecode",
    "codex",
    "hermes",
    "cursor",
    "windsurf",
    "geminicli",
    "copilot",
    "openhands",
    "antigravity",
    "opencode",
    "omnigent",
]

_RESTART_TRANSACTION_KEY = "defenseclaw._credential_protection_restart_transaction"


def _enabled(cfg) -> bool:
    return bool(getattr(getattr(cfg, "credential_protection", None), "enabled", False))


def _remember_restart_transaction(
    *,
    action: str,
    was_enabled: bool,
    mcp_results: list[dict],
) -> None:
    ctx = click.get_current_context(silent=True)
    if ctx is None:
        return
    ctx.meta[_RESTART_TRANSACTION_KEY] = {
        "action": action,
        "was_enabled": was_enabled,
        "mcp_results": list(mcp_results),
    }


def rollback_after_gateway_restart_failure(cfg, transaction: object) -> tuple[bool, str]:
    if not isinstance(transaction, dict):
        return False, "No credential-protection rollback record was available."

    action = transaction.get("action")
    was_enabled = transaction.get("was_enabled")
    results = transaction.get("mcp_results")
    if action not in {"enable", "disable"} or not isinstance(was_enabled, bool) or not isinstance(results, list):
        return False, "The credential-protection rollback record was invalid."

    current = bool(cfg.credential_protection.enabled)
    if current == was_enabled:
        state = "enabled" if current else "disabled"
        return True, f"Credential protection remains {state}; broker changes were preserved."

    cfg.credential_protection.enabled = was_enabled
    try:
        cfg.save()
    except OSError as exc:
        cfg.credential_protection.enabled = current
        return False, f"Could not restore the prior credential-protection setting: {exc}."

    try:
        if action == "enable":
            mcp_restored = rollback_mcp_reconciliation(cfg, results)
        else:
            mcp_restored = rollback_mcp_removal(cfg, results)
    except CredentialProtectionError as exc:
        mcp_restored = False
        rollback_error = str(exc)
    else:
        rollback_error = ""

    state = "enabled" if was_enabled else "disabled"
    if mcp_restored:
        return True, f"Credential protection was rolled back to {state}."
    detail = f": {rollback_error}" if rollback_error else ""
    return False, f"The setting was restored to {state}, but MCP rollback was incomplete{detail}."


def _status_line(status: dict) -> str:
    if not status["enabled"]:
        return "disabled"
    if status["ready"]:
        version = f" s-gw {status['version']}" if status.get("version") else ""
        return f"ready{version}"
    code = status.get("error_code") or status.get("state") or "unavailable"
    return str(code).replace("_", " ")


def _credential_status(cfg) -> dict:
    enabled = _enabled(cfg)
    status = safe_status(cfg.data_dir, enabled=enabled)
    status["scope"] = "credential_broker"
    status["mcp_connectors"] = mcp_connector_status(cfg) if enabled else []
    return status


def _render_mcp_results(results: list[dict]) -> None:
    if not results:
        ux.echo("  MCP registration: no active connectors configured")
        return
    for item in results:
        connector = item["connector"]
        registration = str(item["mcp_registration"]).replace("_", " ")
        proxy_coverage = str(item["proxy_prompt_tokenization"]).replace("_", " ")
        ux.echo(f"  MCP [{connector}]: {registration}; proxy prompt tokenization: {proxy_coverage}")


@click.group("credential-protection")
def credential_protection() -> None:
    """Inspect and use the local s-gw credential broker."""


@credential_protection.command("status")
@click.option("--json", "as_json", is_flag=True, help="Emit allowlisted status metadata as JSON.")
@pass_ctx
def credential_protection_status(app: AppContext, as_json: bool) -> None:
    """Show credential protection readiness without exposing secrets or handles."""
    status = _credential_status(app.cfg)
    if as_json:
        click.echo(json.dumps(status, indent=2, sort_keys=True))
        return

    ux.echo(f"Credential broker: {_status_line(status)}")
    if status["enabled"]:
        _render_mcp_results(status["mcp_connectors"])
    else:
        ux.echo("  MCP registration: not inspected while the broker is disabled")
        ux.echo("  Enable with: defenseclaw setup credential-protection --yes")
    if status["enabled"] and not status["ready"]:
        ux.echo(f"  {remediation(status)}")


def _require_enabled(app: AppContext) -> None:
    if _enabled(app.cfg):
        return
    raise click.ClickException("Credential broker is disabled. Run 'defenseclaw setup credential-protection --yes'.")


@credential_protection.command("open")
@pass_ctx
def credential_protection_open(app: AppContext) -> None:
    """Request the authenticated local s-gw approval console."""
    _require_enabled(app)
    try:
        open_broker(app.cfg.data_dir)
    except CredentialProtectionError as exc:
        raise click.ClickException(str(exc)) from exc
    ux.echo("Requested the authenticated s-gw approval console.")


@credential_protection.command(
    "launch",
    context_settings={"ignore_unknown_options": True},
)
@click.argument("connector", type=click.Choice(_CONNECTORS, case_sensitive=False))
@click.option(
    "--command",
    "agent_command",
    default="",
    help="Absolute path to an agent executable for connectors without a safe s-gw default.",
)
@click.option(
    "--inherit-environment",
    is_flag=True,
    help=(
        "Pass the current environment to the local s-gw guard for credential "
        "tokenization. Interpreter-injection variables are always removed."
    ),
)
@click.argument("agent_args", nargs=-1, type=click.UNPROCESSED)
@pass_ctx
def credential_protection_launch(
    app: AppContext,
    connector: str,
    agent_command: str,
    inherit_environment: bool,
    agent_args: tuple[str, ...],
) -> None:
    """Launch an agent through s-gw guard mode.

    Put agent-specific options after ``--`` so DefenseClaw forwards them as
    arguments instead of interpreting them.
    """
    _require_enabled(app)
    try:
        exit_code = launch_agent(
            app.cfg.data_dir,
            connector.lower(),
            list(agent_args),
            command=agent_command,
            inherit_environment=inherit_environment,
        )
    except CredentialProtectionError as exc:
        raise click.ClickException(str(exc)) from exc
    if exit_code:
        raise SystemExit(exit_code)


@click.command("credential-protection")
@click.option("--disable", is_flag=True, help="Disable the integration without deleting the shared s-gw store.")
@click.option("--dry-run", is_flag=True, help="Check readiness without changing files or starting s-gw.")
@click.option("--yes", is_flag=True, help="Confirm the non-interactive setup operation.")
@pass_ctx
def setup_credential_protection(
    app: AppContext,
    disable: bool,
    dry_run: bool,
    yes: bool,
) -> None:
    """Install and enable the bundled s-gw credential broker."""
    cfg = app.cfg

    if disable and not _enabled(cfg):
        try:
            has_sgw_entries = has_sgw_mcp_registrations(cfg, include_inactive=True)
        except CredentialProtectionError as exc:
            raise click.ClickException(
                f"Credential protection is disabled, but active connector MCP registrations "
                f"could not be inspected: {exc}"
            ) from exc
        if not has_sgw_entries:
            ux.echo("Credential broker is already disabled. The shared s-gw store was preserved.")
            return

    if not dry_run and not yes:
        if not click.get_text_stream("stdin").isatty():
            raise click.ClickException("Pass --yes to confirm credential-protection setup non-interactively.")
        action = "Disable" if disable else "Install and enable"
        click.confirm(f"{action} the local credential broker?", abort=True)

    if disable:
        if dry_run:
            try:
                results = mcp_connector_status(cfg, include_inactive=True)
            except CredentialProtectionError as exc:
                raise click.ClickException(str(exc)) from exc
            ux.echo("Would disable credential protection and preserve the shared s-gw store.")
            _render_mcp_results(results)
            return
        try:
            mcp_results = remove_managed_mcp_connectors(cfg, include_inactive=True)
        except CredentialProtectionError as exc:
            raise click.ClickException(f"Could not safely identify managed MCP registrations: {exc}") from exc
        _render_mcp_results(mcp_results)
        if mcp_removal_failed(mcp_results):
            raise click.ClickException(
                "Credential protection remains enabled because its managed MCP registrations "
                "could not be removed transactionally."
            )
        was_enabled = bool(cfg.credential_protection.enabled)
        cfg.credential_protection.enabled = False
        try:
            cfg.save()
        except OSError as exc:
            cfg.credential_protection.enabled = was_enabled
            try:
                rolled_back = rollback_mcp_removal(cfg, mcp_results)
            except CredentialProtectionError:
                rolled_back = False
            suffix = "" if rolled_back else " One or more MCP registrations could not be restored safely."
            raise click.ClickException(
                f"Could not save the disabled credential-protection setting: {exc}.{suffix}"
            ) from exc
        _remember_restart_transaction(
            action="disable",
            was_enabled=was_enabled,
            mcp_results=mcp_results,
        )
        ux.echo("Credential broker disabled. The shared s-gw store was preserved.")
        return

    if dry_run:
        status = safe_status(cfg.data_dir, enabled=True)
        if status["ready"]:
            results = mcp_connector_status(cfg)
            ux.echo("Credential broker is ready; setup would enable it in DefenseClaw.")
            _render_mcp_results(results)
            return
        raise click.ClickException(f"{_status_line({**status, 'enabled': True})}. {remediation(status)}")

    try:
        status = setup_broker_for_runtime(
            cfg.data_dir,
            already_enabled=_enabled(cfg),
        )
        mcp_results = reconcile_mcp_connectors(cfg)
    except CredentialProtectionError as exc:
        failed = safe_status(cfg.data_dir, enabled=True)
        raise click.ClickException(f"{exc} {remediation(failed)}") from exc

    _render_mcp_results(mcp_results)
    if mcp_reconciliation_failed(mcp_results):
        raise click.ClickException(
            "The credential broker is ready, but one or more active connector MCP registrations require attention."
        )

    was_enabled = bool(cfg.credential_protection.enabled)
    cfg.credential_protection.enabled = True
    try:
        cfg.save()
    except OSError as exc:
        cfg.credential_protection.enabled = was_enabled
        try:
            rolled_back = rollback_mcp_reconciliation(cfg, mcp_results)
        except CredentialProtectionError:
            rolled_back = False
        suffix = "" if rolled_back else " One or more new MCP registrations could not be rolled back safely."
        raise click.ClickException(
            f"s-gw is ready, but DefenseClaw could not save its configuration: {exc}.{suffix}"
        ) from exc
    _remember_restart_transaction(
        action="enable",
        was_enabled=was_enabled,
        mcp_results=mcp_results,
    )
    version = f" {status['version']}" if status.get("version") else ""
    ux.echo(f"Credential broker enabled with s-gw{version}.")
