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

"""defenseclaw codeguard — opt-in Project CodeGuard asset management."""

from __future__ import annotations

import os
import shlex

import click

from defenseclaw.context import AppContext, pass_ctx


@click.group()
def codeguard() -> None:
    """CodeGuard native skill/rule asset management.

    ``codeguard status`` reports every active connector by default; the
    install subcommands take ``--connector X`` to target one configured peer.
    """


@codeguard.command("status")
@click.option(
    "--connector",
    "connector_flag",
    default="",
    help="Inspect a single configured connector (default: every active connector).",
)
@click.option("--target", type=click.Choice(["skill", "rule"]), default="skill", show_default=True)
@pass_ctx
def status_cmd(app: AppContext, connector_flag: str, target: str) -> None:
    """Show whether a native CodeGuard asset is installed.

    Lists every active connector by default — one line each, tagged with the
    connector name — so the output reads the same whether one or many
    connectors are active. ``--connector <name>`` narrows to a single peer.
    """
    from defenseclaw.codeguard_skill import codeguard_status
    from defenseclaw.commands import resolve_list_connectors

    for connector in resolve_list_connectors(app, connector_flag):
        status = codeguard_status(app.cfg, connector=connector, target=target)
        click.echo(f"CodeGuard {target} [{status.connector}]: {status.format()}")


@codeguard.command("install")
@click.option(
    "--connector",
    "connector_flag",
    default="",
    help="Connector to install into (default: every active connector).",
)
@click.option("--target", type=click.Choice(["skill", "rule"]), default="skill", show_default=True)
@click.option("--replace", is_flag=True, help="Replace an existing non-CodeGuard asset at the target path.")
@pass_ctx
def install_cmd(app: AppContext, connector_flag: str, target: str, replace: bool) -> None:
    """Install a native CodeGuard skill or rule asset.

    Without ``--connector`` the asset is installed into EVERY active connector
    (mirroring ``codeguard status``); ``--connector <name>`` scopes the install
    to one configured peer. Per-connector failures are isolated and reported
    together so one connector's conflict never silently skips the rest.
    """
    from defenseclaw.codeguard_skill import install_codeguard_asset
    from defenseclaw.commands import resolve_list_connectors

    failures: list[str] = []
    for connector in resolve_list_connectors(app, connector_flag):
        status = install_codeguard_asset(app.cfg, connector=connector, target=target, replace=replace)
        click.echo(f"CodeGuard {target} [{connector}]: {status}")
        if _is_codeguard_install_error(status):
            failures.append(connector)

    if failures:
        raise click.ClickException(
            f"CodeGuard {target} install failed for: {', '.join(failures)} "
            "(see per-connector status above)"
        )

    _emit_code_scan_hint()


@codeguard.command("install-skill")
@click.option(
    "--connector",
    "connector_flag",
    default="",
    help="Connector to install into (default: every active connector).",
)
@pass_ctx
def install_skill_cmd(app: AppContext, connector_flag: str) -> None:
    """Backward-compatible alias for ``codeguard install --target skill``.

    Like ``codeguard install --target skill``, installs into every active
    connector by default; ``--connector <name>`` scopes to one peer.
    """
    from defenseclaw.codeguard_skill import install_codeguard_skill
    from defenseclaw.commands import resolve_list_connectors

    failures: list[str] = []
    for connector in resolve_list_connectors(app, connector_flag):
        status = install_codeguard_skill(app.cfg, connector=connector)
        click.echo(f"CodeGuard skill [{connector}]: {status}")
        if _is_codeguard_install_error(status):
            failures.append(connector)

    if failures:
        raise click.ClickException(
            f"CodeGuard skill install failed for: {', '.join(failures)} "
            "(see per-connector status above)"
        )

    _emit_code_scan_hint()


def _emit_code_scan_hint() -> None:
    """Print a copy-safe command for the real CodeGuard scanner surface."""
    from defenseclaw.commands import hint

    executable = _resolved_gateway_executable()
    if executable is None:
        hint(
            "Code scan unavailable: no runnable defenseclaw-gateway executable was resolved. "
            "Install or repair the gateway, or set DEFENSECLAW_GATEWAY_BIN to its absolute path."
        )
        return

    command = _format_code_scan_command(executable)
    label = "Scan code now (PowerShell)" if os.name == "nt" else "Scan code now"
    hint(f"{label}:  {command}")


def _resolved_gateway_executable() -> str | None:
    """Resolve a trusted runnable gateway path without consulting PATH."""
    from defenseclaw import gateway

    try:
        if gateway.packaged_windows_install_root() is not None:
            packaged = _runnable_absolute_path(gateway.packaged_windows_gateway_path())
            if packaged is not None:
                return packaged

        if "DEFENSECLAW_GATEWAY_BIN" in os.environ:
            return _runnable_absolute_path(os.environ["DEFENSECLAW_GATEWAY_BIN"])

        canonical = gateway.canonical_install_path()
        if os.name == "nt" and not canonical.lower().endswith(".exe"):
            canonical += ".exe"
        return _runnable_absolute_path(canonical)
    except (OSError, ValueError):
        return None


def _runnable_absolute_path(candidate: object) -> str | None:
    """Admit one explicit, control-free, absolute executable path."""
    if not isinstance(candidate, str) or not candidate:
        return None
    if candidate != candidate.strip():
        return None
    if any(ord(char) < 32 or ord(char) == 127 for char in candidate):
        return None

    try:
        if not os.path.isabs(candidate):
            return None
        candidate = os.path.abspath(candidate)
        if not os.path.isfile(candidate) or not os.access(candidate, os.X_OK):
            return None
    except (OSError, ValueError):
        return None
    return candidate


def _format_code_scan_command(executable: str) -> str:
    """Render the absolute executable for the operator's current shell."""
    argv = (executable, "scan", "code", "<path to scan>")
    if os.name != "nt":
        return shlex.join(argv)
    return "& " + " ".join(_powershell_quote(arg) for arg in argv)


def _powershell_quote(value: str) -> str:
    """Single-quote a fixed PowerShell argument without interpolation."""
    return "'" + value.replace("'", "''") + "'"


def _is_codeguard_install_error(status: str) -> bool:
    # ``unsupported`` means the connector has no skill/rule install target by
    # design (e.g. antigravity) — that is a SKIP, not a failure, so it must not
    # fail an otherwise-successful multi-connector install. Only a genuine
    # conflict (an existing non-DefenseClaw asset in the way) is an error.
    return status.startswith("conflict at ")
