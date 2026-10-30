# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""GAP-0126: an Intune uninstall that met a running installed CLI.

Setup refuses /uninstall with uninstall_in_use, before it changes anything,
while a program runs from the install folder. On the enrolled VM that
program was an Intune detection script running the installed CLI, and the
uninstall failed 1603 with no retry. The launcher now runs Setup again and
exits 1618 (Intune retries) when the refusal lasts; the kit's detection and
Remediations scripts start no installed CLI while lifecycle.lock is held.

These tests run the real scripts in PowerShell 7 (Linux or Windows). The
launcher keeps its shared helpers and pin checks; only the Setup process and
Start-Sleep are stand-ins.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MDM = ROOT / "packaging" / "mdm"
KIT = MDM / "intune" / "windows"
LAUNCHER = KIT / "Install-DefenseClawIntune.ps1"
SETUP = "DefenseClawSetup-Enterprise-Standalone-x64.exe"
SHARED_BEGIN = "# region DefenseClaw MDM shared helpers"
SHARED_END = "# endregion DefenseClaw MDM shared helpers"
PROBE_SCRIPTS = (KIT / "Remediate-Detect.ps1", KIT / "Remediate-Fix.ps1", MDM / "windows" / "detect.ps1")
# No process has this id, so the launcher does not wait for it to exit.
GONE_PID = 2147483000


def _exit(code: int) -> int:
    # Windows keeps the full exit code; a POSIX exit status keeps its low byte.
    return code if os.name == "nt" else code & 0xFF


def _pwsh() -> str:
    for candidate in (os.environ.get("DEFENSECLAW_TEST_PWSH"), shutil.which("pwsh"), shutil.which("pwsh.exe")):
        if candidate and Path(candidate).is_file():
            return candidate
    pytest.skip("PowerShell 7 (pwsh) is not installed; set DEFENSECLAW_TEST_PWSH")


# Appended after the launcher's shared helpers, so these definitions win.
# Setup answers from a queue in DC_TEST_SETUP and records each command line.
_SETUP_STUB = r"""
function Read-TestSetup { Get-Content -Raw -LiteralPath $env:DC_TEST_SETUP | ConvertFrom-Json }
function Save-TestSetup($State) { $State | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $env:DC_TEST_SETUP }
function Invoke-DefenseClawNative {
    param([string]$FilePath, [string[]]$ArgumentList = @(), [string]$StandardInputPath = '', [int]$TimeoutSeconds = 7200)
    if ([IO.Path]::GetFileName($FilePath) -ne 'DefenseClawSetup-Enterprise-Standalone-x64.exe') { throw "unexpected program $FilePath" }
    $state = Read-TestSetup
    $responses = @($state.responses)
    $response = $responses[[Math]::Min(@($state.calls).Count, $responses.Count - 1)]
    $state.calls = @(@($state.calls) + ($ArgumentList -join ' '))
    Save-TestSetup $state
    return New-Object -TypeName PSObject -Property @{ ExitCode = [int]$response.exit; StdOut = [string]$response.stdout; StdErr = '' }
}
function Start-Sleep {
    param([int]$Seconds, [int]$Milliseconds)
    $state = Read-TestSetup
    $state.sleeps = [int]$state.sleeps + 1
    Save-TestSetup $state
}
"""


def _result(code: str | None, exit_code: int, message: str = "") -> dict:
    errors = [{"code": code, "message": message}] if code else []
    return {
        "exit": exit_code,
        "stdout": json.dumps(
            {"schema_version": 2, "ok": not errors, "action": "uninstall", "errors": errors, "exit_code": exit_code}
        ),
    }


def _in_use(pid: int) -> dict:
    return _result(
        "uninstall_in_use",
        1603,
        f"uninstall_in_use: defenseclaw.exe (pid {pid}, account NT AUTHORITY\\SYSTEM, started by powershell) "
        "runs from C:\\Program Files\\Cisco\\DefenseClaw\\bin\\, so DefenseClaw cannot remove its files; "
        "nothing was changed. Close it first",
    )


SUCCESS = _result(None, 0)


def _content(tmp_path: Path, *, bundle: bool = False, single: bool = False) -> Path:
    content = tmp_path / "content"
    content.mkdir()
    text = LAUNCHER.read_text(encoding="utf-8")
    assert text.count(SHARED_END) == 1
    (content / LAUNCHER.name).write_text(text.replace(SHARED_END, SHARED_END + _SETUP_STUB), encoding="utf-8")
    setup = content / SETUP
    setup.write_bytes(b"stand-in Setup; Invoke-DefenseClawNative is stubbed")
    config = content / "config.yaml"
    config.write_text("enterprise:\n  profile: standalone\n", encoding="ascii")
    pins = {
        "schema_version": 1,
        "setup_sha256": hashlib.sha256(setup.read_bytes()).hexdigest(),
        "config_sha256": "" if bundle and not single else hashlib.sha256(config.read_bytes()).hexdigest(),
        "bundle_sha256": "",
        "trust_anchors_sha256": "",
        "trust_mode": "hash_pinned",
        "allowed_signers": [],
        "product_version": "9.9.9",
    }
    if bundle:
        (content / "policy.dcbundle").write_bytes(b"bundle")
        pins["bundle_sha256"] = hashlib.sha256(b"bundle").hexdigest()
    (content / "intune-package.json").write_text(json.dumps(pins), encoding="utf-8")
    return content


def _launch(tmp_path: Path, responses: list[dict], *args: str, bundle: bool = False, single: bool = False):
    content = _content(tmp_path, bundle=bundle or single, single=single)
    state = tmp_path / "setup.json"
    state.write_text(json.dumps({"responses": responses, "calls": [], "sleeps": 0}), encoding="utf-8")
    result = subprocess.run(
        [_pwsh(), "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(content / LAUNCHER.name), *args],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
        env={**os.environ, "DC_TEST_SETUP": str(state)},
    )
    document = json.loads(result.stdout.strip().splitlines()[-1])
    return result, document, json.loads(state.read_text(encoding="utf-8"))


def test_uninstall_retries_a_refusal_and_reports_the_success(tmp_path):
    result, document, setup = _launch(tmp_path, [_in_use(GONE_PID), SUCCESS], "-Uninstall")
    assert result.returncode == 0, result.stdout + result.stderr
    assert document["ok"] is True and document["exit_code"] == 0
    assert setup["calls"] == ["/uninstall JSON=1", "/uninstall JSON=1"]
    # The named process is gone, so the launcher does not wait.
    assert setup["sleeps"] == 0
    assert f"attempt 1 of 6 refused, retrying: uninstall_in_use: defenseclaw.exe (pid {GONE_PID}" in result.stderr


def test_lasting_refusal_exits_1618_and_names_the_program(tmp_path):
    result, document, setup = _launch(tmp_path, [_in_use(GONE_PID)], "-Uninstall", "-Purge")
    assert result.returncode == _exit(1618), result.stdout + result.stderr
    assert setup["calls"] == ["/uninstall JSON=1 PURGE=1"] * 6
    assert document["schema_version"] == 2 and document["action"] == "uninstall"
    assert document["exit_code"] == 1618 and document["ok"] is False
    [error] = document["errors"]
    assert error["code"] == "uninstall_in_use"
    assert f"defenseclaw.exe (pid {GONE_PID}, account NT AUTHORITY\\SYSTEM, started by powershell)" in error["message"]
    assert "Setup refused the uninstall 6 times; Intune retries it later" in error["message"]
    assert result.stderr.count("refused, retrying") == 5


def test_launcher_waits_while_the_named_process_runs(tmp_path):
    # This test's own process stays alive: one bounded 20 x 1 s wait.
    result, _, setup = _launch(tmp_path, [_in_use(os.getpid()), SUCCESS], "-Uninstall")
    assert result.returncode == 0, result.stdout + result.stderr
    assert len(setup["calls"]) == 2
    assert setup["sleeps"] == 20


@pytest.mark.parametrize(
    ("response", "expected"),
    [
        (_result("service_stop_failed", 1603, "DefenseClawGateway did not stop"), 1603),
        (_result("lifecycle_busy", 1618, "another run holds the protected file lock"), 1618),
        (_result("invalid_arguments", 1639, "bad"), 1639),
    ],
)
def test_other_uninstall_failures_keep_setups_code_without_retry(tmp_path, response, expected):
    result, document, setup = _launch(tmp_path, [response, SUCCESS], "-Uninstall")
    assert result.returncode == _exit(expected), result.stdout + result.stderr
    assert document["exit_code"] == expected
    assert setup["calls"] == ["/uninstall JSON=1"]


def test_install_mode_is_unaffected_by_an_in_use_result(tmp_path):
    result, document, setup = _launch(tmp_path, [_in_use(GONE_PID), SUCCESS])
    assert result.returncode == _exit(1603), result.stdout + result.stderr
    assert document["errors"][0]["code"] == "uninstall_in_use"
    [call] = setup["calls"]
    assert call.startswith("/ensure JSON=1 CONFIG=") and call.endswith("config.yaml")
    assert "refused, retrying" not in result.stderr


def test_single_app_ensures_with_both_inputs_and_uninstalls(tmp_path):
    # The single app (config.yaml and a bundle, private #2) passes both to
    # Setup /ensure and, unlike a bundle-only app, is the app that removes
    # DefenseClaw.
    ensure_dir, uninstall_dir = tmp_path / "ensure", tmp_path / "uninstall"
    ensure_dir.mkdir()
    uninstall_dir.mkdir()
    result, document, setup = _launch(ensure_dir, [SUCCESS], single=True)
    assert result.returncode == 0, result.stdout + result.stderr
    [call] = setup["calls"]
    assert call.startswith("/ensure JSON=1 CONFIG=") and "config.yaml BUNDLE=" in call and call.endswith("policy.dcbundle")
    result, document, setup = _launch(uninstall_dir, [SUCCESS], "-Uninstall", single=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert setup["calls"] == ["/uninstall JSON=1"]


@pytest.mark.parametrize(
    ("args", "bundle", "message"),
    [
        (("-Purge",), False, "-Purge is valid only with -Uninstall"),
        (("-Uninstall",), True, "a policy bundle app is not uninstalled"),
    ],
)
def test_launcher_refuses_invalid_uninstall_arguments(tmp_path, args, bundle, message):
    result, document, setup = _launch(tmp_path, [SUCCESS], *args, bundle=bundle)
    assert result.returncode == _exit(1639), result.stdout + result.stderr
    assert document["errors"][0]["code"] == "mdm_invalid_arguments"
    assert message in document["errors"][0]["message"]
    assert setup["calls"] == []


# --- the lifecycle-lock probe in the detection and Remediations scripts ---

_PROBE_STUBS = r"""
$script:DefenseClawMarkerKey = 'SOFTWARE\Cisco\DefenseClaw\Enterprise'
function Start-Sleep { param([int]$Seconds) }
function Get-DefenseClawInstalledDeployment {
    New-Object -TypeName PSObject -Property @{ Version = '9.9.9'; Cli = 'defenseclaw.exe' }
}
function Get-DefenseClawRegistryKey64 {
    param([string]$SubKey)
    if ($SubKey -ne 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders') { return $null }
    $key = New-Object -TypeName PSObject
    $key | Add-Member -MemberType ScriptMethod -Name GetValue -Value {
        param([string]$Name, $Default, $Options)
        if ($Name -eq 'Common AppData') { return 'C:\ProgramData' }
        return $Default
    }
    $key | Add-Member -MemberType ScriptMethod -Name Dispose -Value { }
    return $key
}
function Invoke-DefenseClawNative {
    param([string]$FilePath, [string[]]$ArgumentList, [int]$TimeoutSeconds)
    Add-Content -LiteralPath $env:DC_TEST_CALLS -Value (($ArgumentList | Select-Object -First 3) -join ' ')
    return New-Object -TypeName PSObject -Property @{ ExitCode = 0; StdOut = '{"ok":true,"noop":true,"errors":[],"warnings":[],"services":[]}'; StdErr = '' }
}
"""
# On Linux the Windows lock path is one relative file name in the working
# directory, so the real probe opens a file this test can lock.
LOCK_NAME = "C:\\ProgramData\\Cisco\\DefenseClaw-Lifecycle\\lifecycle.lock"


def _probe_run(tmp_path: Path, script: Path, *args: str) -> tuple[int, str, list[str]]:
    text = script.read_text(encoding="utf-8")
    head, rest = text.split(SHARED_BEGIN, 1)
    _, body = rest.split(SHARED_END, 1)
    harness = tmp_path / script.name
    harness.write_text(head + _PROBE_STUBS + body, encoding="utf-8")
    calls = tmp_path / "calls.txt"
    calls.write_text("", encoding="utf-8")
    result = subprocess.run(
        [_pwsh(), "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(harness), *args],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
        cwd=tmp_path,
        env={**os.environ, "DC_TEST_CALLS": str(calls)},
    )
    return result.returncode, result.stdout + result.stderr, calls.read_text(encoding="utf-8").splitlines()


@pytest.mark.skipif(os.name == "nt", reason="the stand-in lock path is the real ProgramData on Windows")
@pytest.mark.parametrize(
    ("script", "args", "busy_exit", "busy_text"),
    [
        (
            KIT / "Remediate-Detect.ps1",
            (),
            0,
            "another DefenseClaw lifecycle run is in progress; checked again at the next run",
        ),
        (KIT / "Remediate-Fix.ps1", (), 1618, "not started: another DefenseClaw lifecycle run is in progress"),
        (MDM / "windows" / "detect.ps1", ("-RequireHealthy",), 1, "another DefenseClaw lifecycle run is in progress"),
    ],
)
def test_kit_scripts_start_no_cli_while_lifecycle_lock_is_held(tmp_path, script, args, busy_exit, busy_text):
    import fcntl  # POSIX only: Windows CI collects this module, the test is skipped there

    lock = tmp_path / LOCK_NAME
    lock.write_bytes(b"")
    with lock.open("rb") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        code, out, calls = _probe_run(tmp_path, script, *args)
        assert code == _exit(busy_exit), out
        assert busy_text in out, out
        assert calls == []
    # Released, and then absent: the script runs the installed CLI again.
    for present in (True, False):
        if not present:
            lock.unlink()
        code, out, calls = _probe_run(tmp_path, script, *args)
        assert code == 0, out
        assert "enterprise windows verify" in calls, (present, calls)


def test_lifecycle_probe_is_identical_in_every_script():
    def function(path: Path) -> str:
        text = path.read_text(encoding="utf-8")
        start = text.index("function Test-DefenseClawLifecycleRunning {")
        return text[start : text.index("\n}\n", start)]

    first, *others = (function(path) for path in PROBE_SCRIPTS)
    assert all(other == first for other in others)
    for path in PROBE_SCRIPTS:
        text = path.read_text(encoding="utf-8")
        assert text.index("(Test-DefenseClawLifecycleRunning)") < text.index(
            "Invoke-DefenseClawNative -FilePath $deployment.Cli"
        ), path
