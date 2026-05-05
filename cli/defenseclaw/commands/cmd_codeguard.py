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

"""defenseclaw codeguard — CodeGuard skill management."""

from __future__ import annotations

import click

from defenseclaw import ux
from defenseclaw.context import AppContext, pass_ctx


@click.group()
def codeguard() -> None:
    """CodeGuard static-analysis skill management."""


@codeguard.command("install-skill")
@pass_ctx
def install_skill_cmd(app: AppContext) -> None:
    """Install the CodeGuard skill into the OpenClaw workspace skills directory.

    Copies the bundled CodeGuard skill into the highest-priority OpenClaw
    skills directory (workspace skills dir when configured, otherwise the
    global skills dir) and enables it in openclaw.json.

    Equivalent to the auto-install that runs during ``defenseclaw init``.
    """
    from defenseclaw.codeguard_skill import install_codeguard_skill

    click.echo(f"{ux.bold('CodeGuard skill:')} installing...", nl=False)
    status = install_codeguard_skill(app.cfg)
    click.echo(f" {status}")

    from defenseclaw.commands import hint
    hint("Scan code now:  defenseclaw scan code <path>")
