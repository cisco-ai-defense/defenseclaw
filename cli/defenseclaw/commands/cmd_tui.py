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

import click

from defenseclaw.gateway import canonical_install_path, resolve_gateway_binary


@click.command("tui")
def tui() -> None:
    """Launch the DefenseClaw interactive dashboard (TUI).

    Hands off to the defenseclaw-gateway binary which provides the
    full Bubbletea-based terminal UI with alerts, skills, MCPs,
    inventory, logs, and audit panels.

    Binary resolution goes through :func:`defenseclaw.gateway.resolve_gateway_binary`
    which also falls back to the canonical install path so we keep
    working in the very shell that just ran ``make all`` (where
    ``~/.local/bin`` is not yet on ``PATH``).
    """
    gateway = resolve_gateway_binary()
    if gateway is None:
        canonical = canonical_install_path()
        click.echo(
            "Error: defenseclaw-gateway not found.\n"
            f"  Looked on PATH and at {canonical}.\n"
            "  Install it with: make gateway-install\n"
            "  If you just ran 'make all', open a new shell or run:\n"
            "    source ~/.zshrc   # or ~/.bashrc / ~/.profile",
            err=True,
        )
        raise SystemExit(1)

    os.execvp(gateway, [gateway, "tui"])
