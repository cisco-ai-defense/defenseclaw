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

"""Small terminal renderer shared by first-run commands.

The renderer intentionally keeps presentation out of the bootstrap
backend. It honors non-TTY/NO_COLOR output, gives operators concise step
lines, and still produces plain text that is friendly to CI logs.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass

import click


@dataclass
class CLIRenderer:
    """Minimal status renderer for CLI setup flows."""

    color: bool | None = None
    quiet: bool = False

    def __post_init__(self) -> None:
        if self.color is None:
            self.color = sys.stdout.isatty() and "NO_COLOR" not in os.environ

    def echo(self, text: str = "", *, err: bool = False) -> None:
        if self.quiet:
            return
        click.echo(text, err=err)

    def title(self, text: str, subtitle: str = "") -> None:
        if self.quiet:
            return
        self.echo()
        self.echo(self._style(f"  {text}", fg="cyan", bold=True))
        if subtitle:
            self.echo(self._style(f"  {subtitle}", fg="bright_black"))
        self.echo("  " + self._style("─" * 56, fg="bright_black"))

    def section(self, text: str) -> None:
        if self.quiet:
            return
        self.echo()
        self.echo(self._style(f"  {text}", fg="bright_black", bold=True))

    def step(self, status: str, label: str, detail: str = "") -> None:
        if self.quiet:
            return
        icon = {
            "pass": "✓",
            "warn": "!",
            "fail": "x",
            "skip": "-",
        }.get(status, "-")
        fg = {
            "pass": "green",
            "warn": "yellow",
            "fail": "red",
            "skip": "bright_black",
        }.get(status, "white")
        line = f"  {self._style(icon, fg=fg, bold=True)} {label}"
        if detail:
            line += self._style(f"  {detail}", fg="bright_black")
        self.echo(line)

    def _style(self, text: str, **kwargs) -> str:
        if not self.color:
            return text
        return click.style(text, **kwargs)
