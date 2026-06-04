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

    from defenseclaw.commands import hint
    hint("Scan code now:  defenseclaw scan code <path>")


@codeguard.command("install-skill")
@pass_ctx
def install_skill_cmd(app: AppContext) -> None:
    """Backward-compatible alias for ``codeguard install --target skill``.

    Like ``codeguard install``, installs into every active connector.
    """
    from defenseclaw.codeguard_skill import install_codeguard_skill
    from defenseclaw.commands import resolve_list_connectors

    failures: list[str] = []
    for connector in resolve_list_connectors(app, ""):
        status = install_codeguard_skill(app.cfg, connector=connector)
        click.echo(f"CodeGuard skill [{connector}]: {status}")
        if _is_codeguard_install_error(status):
            failures.append(connector)

    if failures:
        raise click.ClickException(
            f"CodeGuard skill install failed for: {', '.join(failures)} "
            "(see per-connector status above)"
        )

    from defenseclaw.commands import hint
    hint("Scan code now:  defenseclaw scan code <path>")


def _is_codeguard_install_error(status: str) -> bool:
    return status.startswith("conflict at ") or status.startswith("unsupported")
