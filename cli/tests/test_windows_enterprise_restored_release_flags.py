# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""The restored release never receives this module's new helper flags.

rel-1-0-6 GAP-0767 (1.0.9 replay R10-T1-09): after an upgrade was cut off
and its transaction restored the previous release, the next lifecycle run
called the restored gateway with a target-runtime planning flag that only the
new release knows, and failed. GAP-0649 stops a Repair that restored another
release before any helper runs. These checks pin the flag to the one planner
and every path into that planner behind the restored-release stop, so a new
caller or a moved stop fails here instead of on a host.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "packaging" / "windows" / "DefenseClawEnterprise.psm1"
NEW_FLAG = "--skip-account-failures"
PLANNER = "Invoke-DefenseClawTargetRuntimePreparation"
LIFECYCLE = "Invoke-DefenseClawInstallLikeLifecycle"


def _code(text: str) -> str:
    """The module without comment-based help and line comments."""
    text = re.sub(r"<#.*?#>", "", text, flags=re.DOTALL)
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


def _functions(code: str) -> dict[str, str]:
    starts = [(m.start(), m.group(1)) for m in re.finditer(r"^function ([\w-]+) \{\n", code, re.MULTILINE)]
    bodies = {}
    for index, (start, name) in enumerate(starts):
        end = starts[index + 1][0] if index + 1 < len(starts) else len(code)
        bodies[name] = code[start:end]
    return bodies


def _calls(callee: str) -> re.Pattern[str]:
    """Every mention of the callee by name, whatever follows it on the line."""
    return re.compile(r"(?<![\w-])" + re.escape(callee) + r"(?![\w-])")


def _callers(functions: dict[str, str], callee: str) -> list[str]:
    call = _calls(callee)
    return sorted(name for name, body in functions.items() if name != callee and call.search(body))


def test_the_new_plan_flag_has_one_sender() -> None:
    functions = _functions(_code(MODULE.read_text(encoding="utf-8")))
    senders = sorted(name for name, body in functions.items() if NEW_FLAG in body)
    assert senders == [PLANNER]
    assert _callers(functions, PLANNER) == [LIFECYCLE]


def _check_lifecycle_entries(text: str) -> None:
    """Fail unless every mention of the lifecycle follows the restored-release stop."""
    functions = _functions(_code(text))
    callers = _callers(functions, LIFECYCLE)
    assert callers, f"no caller of {LIFECYCLE}"
    for name in callers:
        body = functions[name]
        calls = list(_calls(LIFECYCLE).finditer(body))
        assert calls, f"{name}: no {LIFECYCLE} call found in a function that mentions it"
        for call in calls:
            before = body[: call.start()]
            recovery = before.rfind("$pendingRecovery = Recover-DefenseClawPendingTransaction `")
            assert recovery >= 0, f"{name}: {LIFECYCLE} without a pending-transaction recovery before it"
            stop = before.find("if (Test-DefenseClawRecoveryRestoredOtherRelease `", recovery)
            assert stop > recovery, f"{name}: no restored-release stop between the recovery and {LIFECYCLE}"
            # The stop ends the run with the restored deployment's status.
            stopped = before[stop : stop + 600]
            assert "return Get-DefenseClawRecoveryRestoredOtherReleaseResult `" in stopped
            # Repair is the action that runs the restored helpers when no gateway is brought.
            assert "-Action $Action" in stopped and "-Sources $sources" in stopped


def test_every_lifecycle_entry_follows_the_restored_release_stop() -> None:
    _check_lifecycle_entries(MODULE.read_text(encoding="utf-8"))


RECOVERY = "                $pendingRecovery = Recover-DefenseClawPendingTransaction `"
SINGLE_LINE_CALL = (
    "                if ($Action -eq 'Repair') {\n"
    "                    return Invoke-DefenseClawInstallLikeLifecycle -Action $Action -Layout $layout -Sources $sources"
    " -GatewayServiceName $GatewayServiceName -GuardianServiceName $GuardianServiceName\n"
    "                }\n"
)


def test_a_call_in_any_form_before_the_stop_is_rejected() -> None:
    text = MODULE.read_text(encoding="utf-8")
    index = text.rfind(RECOVERY)
    assert index >= 0
    # A valid single-line call ahead of the pending-recovery step.
    with pytest.raises(AssertionError, match="without a pending-transaction recovery"):
        _check_lifecycle_entries(text[:index] + SINGLE_LINE_CALL + text[index:])
    # The same call after the recovery step but ahead of the stop.
    after_recovery = text.index("\n", index + len(RECOVERY)) + 1
    after_continuation = text.index("\n", after_recovery) + 1
    while text[after_continuation - 3 : after_continuation - 1] == " `":
        after_continuation = text.index("\n", after_continuation) + 1
    with pytest.raises(AssertionError, match="no restored-release stop"):
        _check_lifecycle_entries(text[:after_continuation] + SINGLE_LINE_CALL + text[after_continuation:])


def test_a_module_with_no_lifecycle_caller_is_rejected() -> None:
    text = MODULE.read_text(encoding="utf-8")
    stripped = text.replace("return Invoke-DefenseClawInstallLikeLifecycle `", "return $null `")
    assert stripped != text
    with pytest.raises(AssertionError, match="no caller"):
        _check_lifecycle_entries(stripped)


def test_the_stop_covers_a_repair_without_its_own_gateway() -> None:
    functions = _functions(_code(MODULE.read_text(encoding="utf-8")))
    stop = functions["Test-DefenseClawRecoveryRestoredOtherRelease"]
    assert "$Action -notin @('Repair', 'Uninstall')" in stop
    assert "$Sources.ContainsKey('gateway')" in stop
    assert "-cne [string]$script:DefenseClawRunningModuleSHA256" in stop
