"""Static regression checks for the self-contained Windows MDM scripts.

The build box has no PowerShell engine; these checks cover the timeout and
recovery wiring before the scripts are exercised on an Intune device.
"""

from pathlib import Path


MDM = Path(__file__).resolve().parents[2]
SCRIPTS = sorted(
    path
    for directory in (MDM / "windows", MDM / "intune" / "windows")
    for path in directory.glob("*.ps1")
    if "# region DefenseClaw MDM shared helpers" in path.read_text()
)


def helper_block(source: str) -> str:
    return source.split("# region DefenseClaw MDM shared helpers", 1)[1].split(
        "# endregion DefenseClaw MDM shared helpers", 1
    )[0]


def test_native_helper_has_a_bounded_process_and_pipe_wait_in_every_upload():
    helpers = [helper_block(path.read_text()) for path in SCRIPTS]
    assert len(set(helpers)) == 1
    helper = helpers[0]
    assert "$process.WaitForExit($TimeoutSeconds * 1000)" in helper
    assert "taskkill.exe" in helper and "/T /F" in helper
    assert "[System.Threading.Tasks.Task]::WaitAll(" in helper
    assert "$process.WaitForExit()" not in helper


def test_remediation_bounds_ensure_and_restores_start_modes_on_failure():
    script = (MDM / "intune" / "windows" / "Remediate-Fix.ps1").read_text()
    assert "Get-DefenseClawRemediationStartModes" in script
    assert "Restore-DefenseClawRemediationStartModes -PriorModes $priorModes" in script
    assert "if ($ensureFailure -or ($null -ne $run -and $run.ExitCode -ne 0))" in script
    assert "-TimeoutSeconds 840 -ArgumentList @(" in script
    assert "startup-mode restore failed" in script


def test_standalone_installer_binds_native_output_to_the_process_deadline():
    module = (MDM.parent / "windows" / "DefenseClawEnterprise.psm1").read_text()
    native = module.split("function Invoke-DefenseClawProcess {", 1)[1].split(
        "function Invoke-DefenseClawNative {", 1
    )[0]
    assert "if (Test-DefenseClawStandaloneProfile)" in native
    assert "[Threading.Tasks.Task]::WaitAll(" in native
    assert "native process output timed out" in native
