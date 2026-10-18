# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""GAP-0114: Intune Remediations on a device that takes signed policy bundles.

A config.yaml edited outside the lifecycle verified healthy with a
config_edited_outside_lifecycle warning, the remediation exited 0 without
putting the bundle config back, and post-detection reported compliant while
the gateway enforced the edit. These tests run the real Remediate-Detect.ps1
and Remediate-Fix.ps1 bodies in PowerShell 7 (Linux or Windows) against a
stand-in for the installed CLI and the enterprise marker, in the order Intune
runs them: detect, remediate, detect again.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "packaging" / "mdm" / "intune" / "windows"
SHARED_BEGIN = "# region DefenseClaw MDM shared helpers"
SHARED_END = "# endregion DefenseClaw MDM shared helpers"
BUNDLE_ID = "b-01M4XRVFSG2C3VST7D5FYX95E9"
BUNDLE_DIGEST = "sha256:bd021570b814a56644816c791ad88aa6bf163b72b1cf27af8462bbe84e799543"
EDITED_DIGEST = "sha256:f7d2f379e9819384e611f7365a22c5c3569d0159390a6c864bb4d3192b8d9765"
# Windows keeps the full exit code; a POSIX exit status keeps its low byte.
FAILED = 1603 if os.name == "nt" else 1603 & 0xFF

# Stand-ins for the shared helpers: the deployment, the 64-bit marker key
# and the installed CLI. The CLI keeps the device state in a JSON file so
# ensure can change what the next verify and bundle status report.
_STUBS = r"""
$script:DefenseClawMarkerKey = 'SOFTWARE\Cisco\DefenseClaw\Enterprise'
$script:Device = $env:DC_TEST_DEVICE
# The fast path waits for started services; the stand-in needs no wait.
function Start-Sleep { param([int]$Seconds) }
function Read-TestDevice { Get-Content -Raw -LiteralPath $script:Device | ConvertFrom-Json }
function Save-TestDevice($State) { $State | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $script:Device }
function Get-DefenseClawInstalledDeployment {
    New-Object -TypeName PSObject -Property @{ Version = '9.9.9'; Cli = 'C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw.exe' }
}
function Get-DefenseClawRegistryKey64 {
    param([string]$SubKey)
    if ($SubKey -ne $script:DefenseClawMarkerKey) { return $null }
    $key = New-Object -TypeName PSObject -Property @{ Values = (Read-TestDevice).marker }
    $key | Add-Member -MemberType ScriptMethod -Name GetValue -Value {
        param([string]$Name, $Default)
        $property = $this.Values.PSObject.Properties[$Name]
        if ($null -eq $property) { return $Default }
        return $property.Value
    }
    $key | Add-Member -MemberType ScriptMethod -Name Dispose -Value { }
    return $key
}
function Invoke-DefenseClawNative {
    param([string]$FilePath, [string[]]$ArgumentList, [int]$TimeoutSeconds)
    $state = Read-TestDevice
    $verb = ($ArgumentList | Select-Object -First 3) -join ' '
    $state.calls += @($verb)
    $applied = [bool]$state.applied
    $id = $state.marker.PSObject.Properties['BundleId']
    $label = if ($null -ne $id) { "signed policy bundle $($id.Value) version 3" } else { '' }
    $exit = 0
    switch -Wildcard ($verb) {
        'enterprise windows verify' {
            $errors = @()
            if (-not $applied -and $state.verify_checks_bundle) {
                $errors = @(@{ code = 'bundle_not_applied'; message = "config.yaml is not the config of $label" })
            }
            $guardian = 'running'
            if ($state.side_stopped) {
                $guardian = 'stopped'
                $errors += @(@{ code = 'not_ready'; message = 'DefenseClawHookGuardian is not running' })
            }
            if ($errors.Count -gt 0) { $exit = 1603 }
            $out = @{ ok = ($errors.Count -eq 0); errors = $errors; services = @(
                @{ name = 'DefenseClawGateway'; kind = 'gateway'; state = 'running'; required = $true }
                @{ name = 'DefenseClawSensorHelper'; kind = 'sensor_helper'; state = 'running'; required = $true }
                @{ name = 'DefenseClawHookGuardian'; kind = 'guardian'; state = $guardian; required = $true }) } | ConvertTo-Json -Depth 6
        }
        'config DefenseClaw* start=' { $out = '' }
        'start DefenseClaw*' {
            $state.side_stopped = $false
            $out = ''
        }
        'enterprise windows ensure' {
            switch ($state.ensure) {
                'restores' {
                    # Older results could also carry noop: the warning decides.
                    $state.applied = $true
                    $out = @{ ok = $true; noop = $true; errors = @(); warnings = @(@{ code = 'bundle_config_restored'
                        message = "config.yaml was not the config of $label; ensure re-applied the bundle from the bundle store" }) } | ConvertTo-Json -Depth 6
                }
                'noop' {
                    $out = @{ ok = $true; noop = $true; errors = @(); warnings = @() } | ConvertTo-Json -Depth 6
                }
                'cannot_restore' {
                    # What the CLI reports: the restore error, then the health
                    # check's bundle_not_applied with the same reason.
                    $exit = 1603
                    $why = "$label is confirmed, but its config cannot be read from the bundle store (file_hash_mismatch), so the device cannot prove it enforces it; deliver the bundle again or a newer one"
                    $out = @{ ok = $false; noop = $false; warnings = @(); errors = @(
                        @{ code = 'bundle_restore_failed'; message = $why }
                        @{ code = 'bundle_not_applied'; message = $why }) } | ConvertTo-Json -Depth 6
                }
                'ok_without_restore' {
                    $out = @{ ok = $true; noop = $false; errors = @(); warnings = @(@{ code = 'config_edited_outside_lifecycle'; message = 'hand edit' }) } | ConvertTo-Json -Depth 6
                }
            }
        }
        'enterprise bundle status' {
            $gateway = if ($applied) { $state.bundle_digest } else { $state.edited_digest }
            $out = @{ ok = $true; bundle_mode = $true; gateway_checked = $true; gateway_digest = $gateway; applied = $applied
                current = @{ bundle_id = $state.marker.BundleId; version = 3; effective_policy_digest = $state.bundle_digest } } | ConvertTo-Json -Depth 6
        }
        default { throw "unexpected CLI call: $verb" }
    }
    Save-TestDevice $state
    return New-Object -TypeName PSObject -Property @{ ExitCode = $exit; StdOut = $out; StdErr = '' }
}
"""


def _pwsh() -> str | None:
    for candidate in (os.environ.get("DEFENSECLAW_TEST_PWSH"), shutil.which("pwsh"), shutil.which("pwsh.exe")):
        if candidate and Path(candidate).is_file():
            return candidate
    return None


def _harness(name: str, tmp_path: Path) -> Path:
    """The script with its shared helper region replaced by the stand-ins."""
    text = (SCRIPTS / name).read_text(encoding="utf-8")
    head, rest = text.split(SHARED_BEGIN, 1)
    _, body = rest.split(SHARED_END, 1)
    path = tmp_path / name
    path.write_text(head + _STUBS + body, encoding="utf-8")
    return path


def _device(tmp_path: Path, **overrides) -> Path:
    state = {
        "marker": {
            "ProductVersion": "9.9.9",
            "Profile": "standalone",
            "BundleState": "confirmed",
            "BundleId": BUNDLE_ID,
            "BundleVersion": "3",
        },
        "applied": True,
        "verify_checks_bundle": True,
        "ensure": "noop",
        "side_stopped": False,
        "bundle_digest": BUNDLE_DIGEST,
        "edited_digest": EDITED_DIGEST,
        "calls": [],
    }
    state.update(overrides)
    path = tmp_path / "device.json"
    path.write_text(json.dumps(state), encoding="utf-8")
    return path


def _run(engine: str, script: Path, device: Path) -> tuple[int, str]:
    result = subprocess.run(
        [engine, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(script)],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
        env={**os.environ, "DC_TEST_DEVICE": str(device)},
    )
    assert not result.stderr.strip(), result.stderr
    return result.returncode, result.stdout.strip()


@pytest.fixture
def engine() -> str:
    found = _pwsh()
    if not found:
        pytest.skip("PowerShell 7 (pwsh) is not installed; set DEFENSECLAW_TEST_PWSH")
    return found


@pytest.fixture
def scripts(tmp_path: Path) -> tuple[Path, Path]:
    return _harness("Remediate-Detect.ps1", tmp_path), _harness("Remediate-Fix.ps1", tmp_path)


def _calls(device: Path) -> list[str]:
    return json.loads(device.read_text(encoding="utf-8"))["calls"]


def test_tampered_config_is_not_compliant_until_the_remediation_restores_the_bundle(engine, scripts, tmp_path):
    detect, fix = scripts
    device = _device(tmp_path, applied=False, ensure="restores")
    code, out = _run(engine, detect, device)
    assert code == 1, out
    assert "verify failed (bundle_not_applied)" in out, out
    code, out = _run(engine, fix, device)
    assert code == 0, out
    assert out == (
        f"DefenseClaw 9.9.9: repaired (bundle_config_restored): config.yaml was not the config of signed policy bundle {BUNDLE_ID} version 3; "
        f"ensure re-applied the bundle from the bundle store; signed policy bundle {BUNDLE_ID} version 3 is applied"
    ), out
    code, out = _run(engine, detect, device)
    assert code == 0, out
    assert f"healthy; signed policy bundle {BUNDLE_ID} version 3 is applied (the gateway enforces it)" in out, out


def test_detection_checks_the_bundle_even_when_verify_passes(engine, scripts, tmp_path):
    # The GAP-0114 run: verify returned ok with only a warning. Detection
    # asks bundle status and stays non-compliant.
    detect, _ = scripts
    device = _device(tmp_path, applied=False, verify_checks_bundle=False)
    code, out = _run(engine, detect, device)
    assert code == 1, out
    assert f"signed policy bundle {BUNDLE_ID} version 3 is confirmed but not applied" in out, out
    assert "the gateway enforces sha256:f7d2f379e981, not sha256:bd021570b814" in out, out


def test_remediation_that_cannot_restore_the_bundle_fails(engine, scripts, tmp_path):
    _, fix = scripts
    device = _device(tmp_path, applied=False, ensure="cannot_restore")
    code, out = _run(engine, fix, device)
    assert code == FAILED, out
    assert out.startswith(
        f"DefenseClaw 9.9.9: still failing (bundle_restore_failed): signed policy bundle {BUNDLE_ID} "
        "version 3 is confirmed, but its config cannot be read from the bundle store (file_hash_mismatch)"
    ), out


def test_remediation_whose_ensure_succeeds_without_restoring_fails(engine, scripts, tmp_path):
    # An installed CLI without the restore (or a gateway that never adopts the
    # bundle): ensure exits 0, the re-detection does not, so Intune shows a
    # failure instead of "remediated".
    _, fix = scripts
    device = _device(tmp_path, applied=False, verify_checks_bundle=False, ensure="ok_without_restore")
    code, out = _run(engine, fix, device)
    assert code == FAILED, out
    assert f"not repaired: signed policy bundle {BUNDLE_ID} version 3 is confirmed but not applied" in out, out


def test_side_service_fast_path_still_runs_ensure_while_the_bundle_is_not_applied(engine, scripts, tmp_path):
    # A stopped guardian sends Remediate-Fix down its fast path: start the
    # side service, verify again. Verify then passes (a CLI whose verify
    # does not check the bundle), but the gateway still enforces the edit, so
    # the fast path must not report success: ensure runs and restores.
    _, fix = scripts
    device = _device(tmp_path, applied=False, verify_checks_bundle=False, side_stopped=True, ensure="restores")
    code, out = _run(engine, fix, device)
    assert code == 0, out
    assert "repaired (started" not in out, out
    assert f"repaired (bundle_config_restored): config.yaml was not the config of signed policy bundle {BUNDLE_ID} version 3" in out, out
    calls = _calls(device)
    assert "start DefenseClawHookGuardian" in calls, calls
    assert "enterprise windows ensure" in calls, calls


def test_side_service_fast_path_repairs_a_device_whose_bundle_is_applied(engine, scripts, tmp_path):
    _, fix = scripts
    device = _device(tmp_path, side_stopped=True)
    code, out = _run(engine, fix, device)
    assert code == 0, out
    assert out == "DefenseClaw 9.9.9: repaired (started DefenseClawHookGuardian)", out
    assert "enterprise windows ensure" not in _calls(device)


def test_untampered_bundle_device_is_compliant_and_remediation_is_a_noop(engine, scripts, tmp_path):
    detect, fix = scripts
    device = _device(tmp_path)
    code, out = _run(engine, detect, device)
    assert code == 0, out
    assert "is applied (the gateway enforces it)" in out, out
    code, out = _run(engine, fix, device)
    assert code == 0, out
    assert "no repair needed after verify; signed policy bundle" in out, out


def test_base_only_device_is_unaffected(engine, scripts, tmp_path):
    detect, fix = scripts
    device = _device(tmp_path, marker={"ProductVersion": "9.9.9", "Profile": "standalone"})
    code, out = _run(engine, detect, device)
    assert code == 0, out
    assert "healthy; no signed policy bundle is confirmed; the installed config enforces" in out, out
    code, out = _run(engine, fix, device)
    assert code == 0, out
    assert out.endswith("no repair needed after verify"), out
    assert "enterprise bundle status" not in _calls(device)


def test_bundle_check_is_identical_in_detect_and_fix():
    def function(name: str) -> str:
        text = (SCRIPTS / name).read_text(encoding="utf-8")
        start = text.index("function Get-DefenseClawBundleEnforcement {")
        return text[start : text.index("\n}\n", start)]

    assert function("Remediate-Detect.ps1") == function("Remediate-Fix.ps1")
