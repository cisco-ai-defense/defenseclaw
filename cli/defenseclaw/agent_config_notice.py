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
import time
from datetime import datetime

#: Beside a connector's restore notice: the notice timestamp a setup has shown.
_SEEN_SUFFIX = "-seen"

#: connector -> (label, the backup record's logical file name)
_FILES = {
    "claudecode": ("Claude Code settings", "settings.json"),
    "codex": ("Codex config", "config.toml"),
    "hermes": ("Hermes config", "config.yaml"),
    "devin": ("Devin config", "config"),
}


def _put_back_pending(data_dir: str, name: str) -> bool:
    """True when the copy DefenseClaw keeps of *name*'s settings file names a file that is missing now."""
    entry = _FILES.get(name)
    if entry is None:
        return False
    copy = os.path.join(data_dir, "connector_backups", name, f"{entry[1]}.last-good")
    try:
        with open(copy, encoding="utf-8") as stream:
            path = json.loads(stream.read(5 << 20)).get("path")
    except (OSError, ValueError, AttributeError):
        return False
    return isinstance(path, str) and bool(path) and not os.path.lexists(path)


def wait_for_put_back(data_dir: str, connectors, timeout: float = 15.0, interval: float = 0.25) -> None:
    """Wait, bounded, until every settings file DefenseClaw is due to put back is there again.

    The gateway puts the file back when it applies the connector's setup,
    which can finish after the restart step has read the notices (GAP-0333).
    A file with no kept copy is not waited for.
    """
    deadline = time.monotonic() + timeout
    while any(_put_back_pending(data_dir, str(name)) for name in connectors or ()):
        if time.monotonic() >= deadline:
            return
        time.sleep(interval)


def put_back_notes(data_dir: str, connectors) -> list[str]:
    """One line per put-back of a connector's file that no setup has reported yet.

    A put-back is reported once, by the next setup that looks, whoever made it:
    the setup itself, the gateway applying it, or the background watchdog that
    restores a lost file within a second or so, before the user runs setup
    again. Time cutoffs lost most of them (GAP-0333); the notice's own
    timestamp is recorded beside it when it is shown (``<notice>-seen``).
    """
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
            datetime.strptime(str(notice.get("at")), "%Y-%m-%dT%H:%M:%SZ")
        except (OSError, ValueError, TypeError, AttributeError):
            continue
        if not isinstance(notice, dict) or notice.get("version") != 1:
            continue
        seen_path = path + _SEEN_SUFFIX
        try:
            with open(seen_path, encoding="utf-8") as stream:
                if stream.read(64).strip() == str(notice.get("at")):
                    continue
        except OSError:
            pass
        target = str(notice.get("path") or label)
        source = notice.get("source")
        if source in ("last_good", "pristine") and notice.get("hooks_only"):
            # The copy held DefenseClaw's hooks only: say the hooks came back
            # and nothing about the account's settings (GAP-0333).
            what = "DefenseClaw put its hooks back (the copy it kept held DefenseClaw's hooks only)"
        elif source == "last_good":
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
        try:
            with open(seen_path, "w", encoding="utf-8") as stream:
                stream.write(str(notice.get("at")))
            os.chmod(seen_path, 0o600)
        except OSError:
            pass  # reported again next time rather than lost
    return notes
