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

from defenseclaw import ux
from defenseclaw.context import AppContext, pass_ctx


@click.group()
def codeguard() -> None:
    """CodeGuard native skill/rule asset management."""


@codeguard.command("status")
@click.option("--connector", default="", help="Connector to inspect (default: active connector).")
@click.option("--target", type=click.Choice(["skill", "rule"]), default="skill", show_default=True)
@pass_ctx
def status_cmd(app: AppContext, connector: str, target: str) -> None:
    """Show whether a native CodeGuard asset is installed."""
    from defenseclaw.codeguard_skill import codeguard_status

    status = codeguard_status(app.cfg, connector=connector or None, target=target)
    click.echo(f"CodeGuard {target} [{status.connector}]: {status.format()}")


@codeguard.command("install")
@click.option("--connector", default="", help="Connector to install into (default: active connector).")
@click.option("--target", type=click.Choice(["skill", "rule"]), default="skill", show_default=True)
@click.option("--replace", is_flag=True, help="Replace an existing non-CodeGuard asset at the target path.")
@pass_ctx
def install_cmd(app: AppContext, connector: str, target: str, replace: bool) -> None:
    """Install a native CodeGuard skill or rule asset explicitly."""
    from defenseclaw.codeguard_skill import install_codeguard_asset

    status = install_codeguard_asset(app.cfg, connector=connector or None, target=target, replace=replace)
    _raise_install_error_if_needed(target, status)
    click.echo(f"CodeGuard {target}: {status}")

    from defenseclaw.commands import hint
    hint("Scan code now:  defenseclaw scan code <path>")


@codeguard.command("install-skill")
@pass_ctx
def install_skill_cmd(app: AppContext) -> None:
    """Backward-compatible alias for ``codeguard install --target skill``."""
    from defenseclaw.codeguard_skill import install_codeguard_skill

    click.echo(f"{ux.bold('CodeGuard skill:')} installing...", nl=False)
    status = install_codeguard_skill(app.cfg)
    _raise_install_error_if_needed("skill", status)
    click.echo(f" {status}")

    from defenseclaw.commands import hint
    hint("Scan code now:  defenseclaw scan code <path>")


def _raise_install_error_if_needed(target: str, status: str) -> None:
    if status.startswith("conflict at ") or status.startswith("unsupported"):
        raise click.ClickException(f"CodeGuard {target}: {status}")
