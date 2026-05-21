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

"""Launch the DefenseClaw TUI."""

from __future__ import annotations

import os

import click

from defenseclaw.gateway import canonical_install_path, resolve_gateway_binary


@click.command("tui")
@click.option(
    "--backend",
    type=click.Choice(["go", "textual"], case_sensitive=False),
    default=None,
    help="TUI backend to launch. Defaults to DEFENSECLAW_TUI_BACKEND or textual.",
)
def tui(backend: str | None = None) -> None:
    """Launch the DefenseClaw interactive dashboard (TUI).

    The Textual Python backend is the default dashboard. Use
    ``--backend go`` or ``DEFENSECLAW_TUI_BACKEND=go`` to launch the
    legacy Go backend while it remains in-tree for parity comparison.

    Binary resolution goes through :func:`defenseclaw.gateway.resolve_gateway_binary`
    which also falls back to the canonical install path so we keep
    working in the very shell that just ran ``make all`` (where
    ``~/.local/bin`` is not yet on ``PATH``).
    """
    selected = (backend or os.environ.get("DEFENSECLAW_TUI_BACKEND") or "textual").strip().lower()
    if selected == "textual":
        from defenseclaw.tui import run_textual_tui

        run_textual_tui()
        return

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
