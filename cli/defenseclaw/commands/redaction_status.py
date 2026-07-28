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

"""Shared canonical-v8 redaction-policy guidance for setup commands."""

from __future__ import annotations

from typing import Any

import click


def print_redaction_status_hint(cfg: Any, *, indent: str = "  ") -> None:
    """Point operators at the effective per-destination policy."""
    status, command_label, command = redaction_status_hint(cfg)
    click.echo(f"{indent}Redaction: {status}")
    click.echo(f"{indent}{command_label}: {command}")


def redaction_status_hint(cfg: Any) -> tuple[str, str, str]:
    """Return ``(status, command_label, command)`` for setup summaries."""
    del cfg
    return (
        "PER DESTINATION (defaults are unredacted)",
        "Inspect collection and route redaction",
        "defenseclaw config show --effective --section observability",
    )
