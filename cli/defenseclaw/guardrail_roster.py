# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""The roster rule a config.yaml must meet before protection is on (GAP-0588).

One place for the admissibility rule, applied by the config writer itself to
every write that turns the guardrail on and by the commands that edit the
roster, so no command can save a file the gateway refuses to boot.
"""

from __future__ import annotations

from defenseclaw import config as config_module
from defenseclaw import config_writer
from defenseclaw.connector_contracts import normalize_connector


def _file_selected_connector(document: object) -> str:
    """The connector a config document selects, by the loader rule (no host probe).

    guardrail.connector, else claw.mode when it is on the roster (or the first
    roster entry), else claw.mode; a missing claw.mode loads as openclaw.
    """
    guardrail = document.get("guardrail") if isinstance(document, dict) else None
    guardrail = guardrail if isinstance(guardrail, dict) else {}
    claw = document.get("claw") if isinstance(document, dict) else None
    claw = claw if isinstance(claw, dict) else {}
    named = guardrail.get("connector")
    if isinstance(named, str) and named.strip():
        return normalize_connector(named)
    mode = claw.get("mode", "openclaw")
    mode = normalize_connector(mode) if isinstance(mode, str) and mode.strip() else ""
    roster = guardrail.get("connectors")
    names = (
        sorted(normalize_connector(n) for n in roster if isinstance(n, str) and n.strip())
        if isinstance(roster, dict) else []
    )
    if names:
        return mode if mode in names else names[0]
    return mode


def check_guardrail_connector_roster(path: str, candidate: bytes) -> None:
    """Refuse a final file the gateway cannot boot with its proxy connector.

    A proxy connector (openclaw, zeptoclaw) needs its own proxy binding, so it
    cannot share a gateway process with hook connectors (GAP-0588). The
    process is the enabled roster entries plus the installed connector. The
    gateway also chooses the shared (multi-connector) boot from the number of
    entries listed, enabled or not (Config.GuardrailBootSet), so a proxy in the
    process beside any second listed entry, even a disabled one, is refused:
    a successful edit never saves a file the gateway would reject. When the final file
    names no connector, the installed one is what the file selected before
    the edit, so an implicit default OpenClaw (no guardrail.connector, no
    claw.mode, no roster) counts, whether the edit adds one entry or a whole
    map. The check reads the files, so the top-level config command, which
    loads no config, is judged the same as a loaded one.
    """
    document = config_writer._parse_config_document(candidate)
    if config_writer.secure_client_document(document):
        return
    guardrail = document.get("guardrail", {}) if isinstance(document, dict) else {}
    guardrail = guardrail if isinstance(guardrail, dict) else {}
    roster = guardrail.get("connectors", {})
    roster = roster if isinstance(roster, dict) else {}
    listed = {
        normalize_connector(name)
        for name in roster
        if isinstance(name, str) and name.strip() and not config_module._is_retired_connector_name(name)
    }
    process = {
        normalize_connector(name)
        for name, entry in roster.items()
        if isinstance(name, str) and isinstance(entry, dict) and entry.get("enabled") is not False
    }
    claw = document.get("claw") if isinstance(document, dict) else None
    claw = claw if isinstance(claw, dict) else {}
    named = guardrail.get("connector")
    if not (isinstance(named, str) and named.strip()):
        named = claw.get("mode") if "mode" in claw else None
    if not (isinstance(named, str) and named.strip()):
        # A file that exists selected something before the edit (an implicit
        # OpenClaw counts); a first save has no earlier selection, and the
        # roster it writes names its own primary, as the gateway reads it.
        current, _, exists = config_writer._read_current(path)
        document_now = config_writer._parse_config_document(current if exists else candidate)
        named = _file_selected_connector(document_now)
    if isinstance(named, str) and named.strip() and not config_module._is_retired_connector_name(named):
        installed = normalize_connector(named)
        own = next(
            (e for n, e in roster.items() if isinstance(n, str) and normalize_connector(n) == installed),
            None,
        )
        if not (isinstance(own, dict) and own.get("enabled") is False):
            process.add(installed)
    proxies = sorted(process & {"openclaw", "zeptoclaw"})
    if proxies and (len(process) > 1 or len(listed) > 1):
        proxy = proxies[0]
        others = sorted((process | listed) - {proxy})
        label = "hook connectors" if not set(others) & {"openclaw", "zeptoclaw"} else "other connectors"
        raise config_writer.ConfigWriteError(
            f"{proxy} needs a proxy binding and cannot share a gateway process "
            f"with {label} ({', '.join(others)}). A disabled entry under guardrail.connectors "
            "still counts: remove the other entries first."
        )


def guardrail_enabled(raw: bytes) -> bool:
    '''Whether config bytes have guardrail.enabled switched on.'''
    document = config_writer._parse_config_document(raw)
    guardrail = document.get("guardrail") if isinstance(document, dict) else None
    return isinstance(guardrail, dict) and guardrail.get("enabled") is True


def check_guardrail_activation(path: str, candidate: bytes) -> None:
    """Refuse the write that turns protection on for a roster that cannot boot.

    The config writer runs this on every ordinary write, so a command that
    sets ``guardrail.enabled`` (setup, init, enable) needs no check of its own.
    Only the off-to-on change is judged: a file already on, and a write that
    leaves protection off, are never refused here.
    """
    if not guardrail_enabled(candidate):
        return
    current, _mode, _exists = config_writer._read_current(path)
    if not guardrail_enabled(current):
        check_guardrail_connector_roster(path, candidate)
