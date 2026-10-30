# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""What a connector setup put back in an agent settings file that went missing.

The gateway's connector setup puts back a settings file DefenseClaw managed
(Claude Code settings.json, Codex config.toml, Hermes config.yaml, Devin
config.json) from the copy it kept, before it registers its hooks again, and
writes a notice beside the connector's backup record
(internal/gateway/connector/agent_config_restore.go). ``defenseclaw setup``
reads the notices the setup it just ran wrote and says what happened
(GAP-0581): before, the file came back with DefenseClaw's entries alone and
nothing was said.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone

#: connector -> (label, the backup record's logical file name)
_FILES = {
    "claudecode": ("Claude Code settings", "settings.json"),
    "codex": ("Codex config", "config.toml"),
    "hermes": ("Hermes config", "config.yaml"),
    "devin": ("Devin config", "config"),
}


def put_back_notes(data_dir: str, connectors, since: float) -> list[str]:
    """One line per connector whose setup since *since* (epoch seconds) put back or recreated its file."""
    notes = []
    for name in connectors or ():
        entry = _FILES.get(str(name))
        if entry is None:
            continue
        label, logical = entry
        path = os.path.join(data_dir, "connector_backups", str(name), f"{logical}.restore-notice")
        try:
            with open(path, encoding="utf-8") as stream:
                notice = json.loads(stream.read(64 << 10))
            at = datetime.strptime(str(notice.get("at")), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        except (OSError, ValueError, TypeError, AttributeError):
            continue
        if not isinstance(notice, dict) or notice.get("version") != 1 or at.timestamp() < since - 1:
            continue
        target = str(notice.get("path") or label)
        source = notice.get("source")
        if source == "last_good":
            what = (
                "DefenseClaw put back the copy it kept when it last set it up, with your settings; "
                "changes made after that are not in it"
            )
        elif source == "pristine":
            what = "DefenseClaw put back the file as its first setup found it; changes made after that are not in it"
        elif notice.get("settings_lost"):
            what = (
                "DefenseClaw had no copy of your settings in it to put back, so it now holds DefenseClaw's "
                "entries only: enter your own settings (model, permissions, MCP servers) again"
            )
        else:
            what = (
                "DefenseClaw had no copy of it and recreated it with its own entries only: "
                "if you had settings in it, enter them again"
            )
        notes.append(f"{label} {target} was missing; {what}.")
    return notes
