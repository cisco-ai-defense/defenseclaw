# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Operator-facing connector config write failures from gateway startup."""

from __future__ import annotations

import ast
import os
import re

from defenseclaw.connector_paths import claude_config_dir

_TYPED_CONFIG_WRITE = re.compile(r'connector config file ("(?:\\.|[^"\\])*") cannot be written')
_RENDERED_CONFIG_WRITE = re.compile(r'(?:Claude Code settings|Connector config) file (.+?) cannot be written')
_LEGACY_CLAUDE_STEP = re.compile(r'claudecode (?:settings hooks|otel env):', re.IGNORECASE)
_LEGACY_PERMISSION = re.compile(
    r'operation not permitted|permission denied|read-only|access is denied|sharing violation',
    re.IGNORECASE,
)


def unwritable_config_remedy(message: str, *, connector: str, command: str) -> str | None:
    """Classify a path-bearing gateway error, with a 0.x Claude fallback."""
    match = _TYPED_CONFIG_WRITE.search(message)
    if match:
        try:
            path = ast.literal_eval(match.group(1))
        except (SyntaxError, ValueError):
            return None
        if not isinstance(path, str) or not path:
            return None
    else:
        rendered = _RENDERED_CONFIG_WRITE.search(message)
        if rendered:
            path = rendered.group(1)
        elif connector == "claudecode" and _LEGACY_CLAUDE_STEP.search(message) and _LEGACY_PERMISSION.search(message):
            path = os.path.join(claude_config_dir(), "settings.json")
        else:
            return None
    label = (
        "Claude Code settings file"
        if connector == "claudecode" and path.endswith("settings.json")
        else "Connector config file"
    )
    return (
        f"{label} {path} cannot be written. Make it writable or ask your administrator, "
        f"then rerun {command}."
    )
