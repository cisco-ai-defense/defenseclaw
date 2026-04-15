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

"""Launch the DefenseClaw TUI (Go gateway)."""

from __future__ import annotations

import os
import shutil
import sys

import click


@click.command("tui")
def tui() -> None:
    """Launch the DefenseClaw interactive dashboard (TUI).

    Hands off to the defenseclaw-gateway binary which provides the
    full Bubbletea-based terminal UI with alerts, skills, MCPs,
    inventory, logs, and audit panels.
    """
    gateway = shutil.which("defenseclaw-gateway")
    if gateway is None:
        click.echo(
            "Error: defenseclaw-gateway not found on PATH.\n"
            "Install it with: make gateway-install",
            err=True,
        )
        raise SystemExit(1)

    os.execvp(gateway, [gateway, "tui"])
