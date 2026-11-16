# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""The Windows scope-exclusivity checks list services through
Get-DefenseClawServiceInventory.

Both scope checks are shared with Secure Client. An unreadable service must
not fail them: the inventory lists services with -ErrorAction SilentlyContinue
and logs each query error as a defenseclaw_accept resilience event. This also
covers GAP-0023: on Windows 11 24H2 SYSTEM cannot read IsolationSession, and
PowerShell 7.4/7.5 Get-Service reports that as a query error, which must not
fail ensure with 1603.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "packaging" / "windows" / "DefenseClawEnterprise.psm1"


def _text() -> str:
    return MODULE.read_text(encoding="utf-8")


def _function_body(text: str, name: str) -> str:
    start = text.index(f"function {name} {{\n")
    end = text.index("\n}\n", start)
    return text[start : end + 3]


def test_service_inventory_logs_query_errors_instead_of_throwing() -> None:
    module = _text()
    assert module.count("function Get-DefenseClawServiceInventory {\n") == 1
    inventory = _function_body(module, "Get-DefenseClawServiceInventory")

    query = re.search(
        r"Microsoft\.PowerShell\.Management\\Get-Service\s*`\s*"
        r"-ErrorAction SilentlyContinue\s*`\s*"
        r"-ErrorVariable queryErrors\)",
        inventory,
    )
    assert query is not None, inventory
    assert "-ErrorAction Stop" not in inventory
    assert "throw" not in inventory

    loop = inventory[inventory.index("foreach ($queryError in @($queryErrors))") :]
    assert "Write-DefenseClawResilienceEvent -Marker defenseclaw_accept" in loop
    assert 'reason  = "service could not be queried: $($queryError.Exception.Message)"' in loop
    assert inventory.rstrip().endswith("return $services\n}")

    markers = module[module.index("$script:ResilienceMarkers = @(") :]
    assert "'defenseclaw_accept'" in markers[: markers.index(")")]


def test_both_scope_exclusivity_checks_use_the_service_inventory() -> None:
    module = _text()
    for caller in (
        "Assert-DefenseClawInstallSharedHookScopeExclusive",
        "Assert-DefenseClawTargetRuntimeCleanupScopeExclusive",
    ):
        body = _function_body(module, caller)
        assert "-Services @(Get-DefenseClawServiceInventory)" in body, caller
        assert "Get-Service" not in body, caller
