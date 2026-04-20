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

"""CLI command modules."""

from __future__ import annotations

import sys
from typing import Any

import click


def hint(*lines: str) -> None:
    """Print dim post-command hints, only when stdout is a terminal."""
    if not sys.stdout.isatty():
        return
    click.echo()
    for line in lines:
        click.echo(click.style(line, dim=True))


def compute_verdict(
    action_entry: Any | None = None,
    scan_entry: dict[str, Any] | None = None,
) -> tuple[str, str]:
    """Derive a (label, rich_style) verdict from action + scan state.

    Priority: explicit enforcement actions > scan severity > no data.
    """
    if action_entry and not action_entry.actions.is_empty():
        a = action_entry.actions
        if a.file == "quarantine":
            return "quarantined", "red"
        if a.install == "block":
            return "blocked", "red"
        if a.runtime == "disable":
            return "disabled", "red"
        if a.install == "allow":
            return "allowed", "green"
    if scan_entry:
        sev = scan_entry.get("max_severity", "CLEAN")
        if sev in ("CRITICAL", "HIGH"):
            return "rejected", "red"
        if sev in ("MEDIUM", "LOW"):
            return "warning", "yellow"
        if sev == "CLEAN":
            return "clean", "green"
    return "-", ""
