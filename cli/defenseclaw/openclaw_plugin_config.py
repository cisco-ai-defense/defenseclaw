# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Read-only check of OpenClaw's DefenseClaw plugin config against its manifest."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

from jsonschema import Draft202012Validator, SchemaError


def _has_external_schema_reference(value: object) -> bool:
    if isinstance(value, dict):
        if "$ref" in value or "$dynamicRef" in value:
            return True
        return any(_has_external_schema_reference(child) for child in value.values())
    if isinstance(value, list):
        return any(_has_external_schema_reference(child) for child in value)
    return False


def openclaw_plugin_config_issue(config_file: str, openclaw_home: str) -> str | None:
    """Return a plain issue when OpenClaw would reject the plugin config.

    The installed plugin manifest is the schema owner. A missing manifest is
    handled by the separate plugin installation check.
    """
    config_path = Path(os.path.expanduser(config_file))
    try:
        with config_path.open(encoding="utf-8") as handle:
            document = json.load(handle)
    except FileNotFoundError:
        return None
    except (OSError, UnicodeError, json.JSONDecodeError):
        return "OpenClaw config cannot be read as JSON"

    if not isinstance(document, dict):
        return "OpenClaw config is not a JSON object"
    plugins = document.get("plugins")
    entries = plugins.get("entries") if isinstance(plugins, dict) else None
    entry = entries.get("defenseclaw") if isinstance(entries, dict) else None
    if not isinstance(entry, dict) or "config" not in entry:
        return None

    manifest_path = Path(os.path.expanduser(openclaw_home)) / "extensions" / "defenseclaw" / "openclaw.plugin.json"
    try:
        info = manifest_path.lstat()
    except FileNotFoundError:
        return None
    except OSError:
        return "OpenClaw plugin manifest cannot be read"
    if not stat.S_ISREG(info.st_mode) or info.st_size > 256 * 1024:
        return "OpenClaw plugin manifest is not a regular file within the size limit"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        schema = manifest["configSchema"] if manifest["id"] == "defenseclaw" else None
        if _has_external_schema_reference(schema):
            return "OpenClaw plugin manifest config schema has unsupported references"
        Draft202012Validator.check_schema(schema)
        if not Draft202012Validator(schema).is_valid(entry["config"]):
            return "plugins.entries.defenseclaw.config has values the installed plugin schema rejects"
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError, ValueError, SchemaError):
        return "OpenClaw plugin manifest has no usable DefenseClaw config schema"
    return None


def configured_openclaw_plugin_config_issue(cfg: object) -> str | None:
    """Check the OpenClaw paths selected by DefenseClaw's current config."""
    claw = getattr(cfg, "claw", None)
    home = str(getattr(claw, "home_dir", "") or "~/.openclaw")
    config_file = str(getattr(claw, "config_file", "") or os.path.join(home, "openclaw.json"))
    return openclaw_plugin_config_issue(config_file, home)
