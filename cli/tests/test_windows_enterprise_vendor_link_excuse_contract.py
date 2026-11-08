# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Source contract for the vendor-folder link excuse of the manifest adoption gate.

An uninstall keeps an administrator link at a machine vendor folder, so a failed
guardian row that only reports that link must not keep the adoption of a
republished manifest refused. Upgrade, Repair, Reconcile and Ensure still refuse
the link, so the flag that allows the excuse is set for a standalone Uninstall
and nowhere else. The smoke sets the flag by hand; this check pins the real
assignment, which runs on Linux CI where the module cannot be run.
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "packaging/windows/DefenseClawEnterprise.psm1"
FLAG = "$script:DefenseClawVendorLinkExcuse"


def _assignments(source: str) -> list[tuple[int, str]]:
    found = []
    for match in re.finditer(re.escape(FLAG) + r"\s*=", source):
        line = source.count("\n", 0, match.start())
        found.append((line, source[match.start() : match.start() + 160]))
    return found


def test_flag_is_false_at_load_and_set_once_for_a_standalone_uninstall() -> None:
    source = MODULE.read_text(encoding="utf-8")
    assignments = _assignments(source)
    assert len(assignments) == 2, assignments

    load, entry = assignments
    assert re.match(re.escape(FLAG) + r"\s*=\s*\$false\b", load[1]), load

    # The second assignment sits at the entry of the lifecycle function and is
    # an Uninstall-and-standalone test, with no other action in it.
    start = source.index("function Invoke-DefenseClawEnterpriseLifecycle {")
    end = source.index("\nfunction ", start + 1)
    body = source[start:end]
    assert body.count(FLAG) == 1
    expression = re.search(re.escape(FLAG) + r"\s*=\s*\((.*?)\n    \)", body, re.S)
    assert expression is not None
    normalized = " ".join(expression.group(1).split())
    assert normalized == "$Action -eq 'Uninstall' -and (Test-DefenseClawStandaloneProfile)", normalized


def test_flag_is_read_only_by_the_link_excuse() -> None:
    source = MODULE.read_text(encoding="utf-8")
    readers = [m.start() for m in re.finditer(re.escape(FLAG) + r"(?!\s*=)", source)]
    assert len(readers) == 1
    function = source.rfind("\nfunction ", 0, readers[0])
    name = re.match(r"\nfunction (\S+)", source[function:]).group(1)
    assert name == "Get-DefenseClawGuardianRowMachineFolderLink"
