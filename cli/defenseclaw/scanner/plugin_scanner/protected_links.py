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
"""

from __future__ import annotations

import os

from defenseclaw.hermes_skills import _is_link_or_junction
from defenseclaw.scanner.plugin_scanner.helpers import make_finding
from defenseclaw.scanner.plugin_scanner.types import Finding
from defenseclaw.scanner.plugin_scanner.vendor_identity import link_reaches_private_state

_WALK_LIMIT = 50000


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
    try:
        info = os.lstat(root)
    except OSError:
        return
    if _is_link_or_junction(info):
        if link_reaches_private_state(root, data_dir):
            yield root, "reaches protected state"
        return
    seen = 0
    for current, dirs, files in os.walk(root, followlinks=False):
        for name in (*dirs, *files):
            seen += 1
            if seen > _WALK_LIMIT:
                yield root, "could not be checked: the folder has too many entries"
                return
            path = os.path.join(current, name)
            try:
                is_link = _is_link_or_junction(os.lstat(path))
            except OSError:
                continue
            if is_link and link_reaches_private_state(path, data_dir):
                yield path, "reaches protected state"
