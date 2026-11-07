# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Links inside a plugin dependency folder that reach protected state.

The source walk skips ``node_modules``, so a link kept there (the installer
links the OpenClaw host package as a peer) is never read as a path. An
ordinary link to a host package is the agent runtime and is not a finding. A
link that names or resolves into protected state (SSH, cloud and cluster
credentials, the DefenseClaw data folder), directly or through another link,
is the same escape as a link anywhere else in the plugin and is reported HIGH
on every profile, whichever package the link claims to be.

An ordinary link to a folder is followed, because the plugin reads that folder
like any other dependency: a link inside it is judged the same way, however
many ordinary links lead there. A folder is walked once.
"""

from __future__ import annotations

import os

from defenseclaw.hermes_skills import _is_link_or_junction
from defenseclaw.scanner.plugin_scanner.helpers import make_finding
from defenseclaw.scanner.plugin_scanner.types import Finding
from defenseclaw.scanner.plugin_scanner.vendor_identity import link_reaches_private_state

_WALK_LIMIT = 300000


def audit_protected_links(target: str, *, data_dir: str = "") -> list[Finding]:
    root = os.path.join(target, "node_modules")
    findings: list[Finding] = []
    for link, reason in _flagged(root, data_dir):
        rel = os.path.relpath(link, target).replace(os.sep, "/")
        findings.append(make_finding(
            len(findings) + 1,
            rule_id="STRUCT-SYMLINK-ESCAPE",
            severity="HIGH",
            confidence=0.95,
            title="Dependency link reaches protected state",
            description=(
                f"The link at \x27{rel}\x27 {reason}. A dependency folder must not "
                "link to credentials, keys or DefenseClaw state."
            ),
            location=rel,
            remediation="Remove the link, or install the dependency as a regular folder.",
            tags=["supply-chain"],
        ))
    return findings


def _flagged(root: str, data_dir: str):
    """Yield (link, reason) for every link under ``root`` that reaches protected state.

    A link to an ordinary folder is followed: what the folder holds is judged
    the same way, because the folder is read by the plugin like any other
    dependency. A folder is walked once, whichever links lead to it.
    """

    pending = [root]
    walked: set[str] = set()
    seen = 0
    try:
        root_info = os.lstat(root)
    except OSError:
        return
    if _is_link_or_junction(root_info) and link_reaches_private_state(root, data_dir):
        yield root, "reaches protected state"
        return
    while pending:
        folder = pending.pop()
        real = os.path.realpath(folder)
        if real in walked:
            continue
        walked.add(real)
        for current, dirs, files in os.walk(folder, followlinks=False):
            for name in (*dirs, *files):
                seen += 1
                if seen > _WALK_LIMIT:
                    yield root, "could not be checked: the folders it links to have too many entries"
                    return
                path = os.path.join(current, name)
                try:
                    is_link = _is_link_or_junction(os.lstat(path))
                except OSError:
                    continue
                if not is_link:
                    continue
                if link_reaches_private_state(path, data_dir):
                    yield path, "reaches protected state"
                elif os.path.isdir(path):
                    pending.append(path)
