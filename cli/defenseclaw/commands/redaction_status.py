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

"""Shared redaction-status copy for setup commands.

Observability setup should not prompt for privacy policy. It should
state the current effective state and point at the audited toggle
command so operators can make that choice deliberately.
"""

from __future__ import annotations

import os
from typing import Any

import click


def print_redaction_status_hint(cfg: Any, *, indent: str = "  ") -> None:
    """Print the effective redaction state and the command to flip it."""
    status, command_label, command = redaction_status_hint(cfg)
    click.echo(f"{indent}Redaction: {status}")
    click.echo(f"{indent}{command_label}: {command}")


def redaction_status_hint(cfg: Any) -> tuple[str, str, str]:
    """Return ``(status, command_label, command)`` for setup summaries."""
    config_disabled = _config_disables_redaction(cfg)
    env_value = os.environ.get("DEFENSECLAW_DISABLE_REDACTION", "").strip()
    env_disabled = env_value.lower() in {"1", "true", "yes", "on"}

    if config_disabled or env_disabled:
        source = "privacy.disable_redaction=true" if config_disabled else ""
        if env_disabled:
            env_source = f"DEFENSECLAW_DISABLE_REDACTION={env_value}"
            source = f"{source}, {env_source}" if source else env_source
        status = f"OFF (RAW telemetry; {source})"
        command = "defenseclaw setup redaction on"
        if env_disabled:
            command = f"unset DEFENSECLAW_DISABLE_REDACTION && {command}"
        return status, "To re-enable redaction", command

    return (
        "ON (redacted telemetry)",
        "To send raw prompts/tool args/tool calls",
        "defenseclaw setup redaction off --yes",
    )


def _config_disables_redaction(cfg: Any) -> bool:
    privacy = getattr(cfg, "privacy", None)
    return bool(getattr(privacy, "disable_redaction", False))
