# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Contracts of scripts/install.ps1, the Windows installer and upgrader.

The installer's behavior is tested end to end on Windows by
scripts/test-install-lifecycle.ps1. These checks pin what other code relies on.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from defenseclaw import upgrade_shim
from defenseclaw.commands import cmd_uninstall, windows_uninstall_helper
from defenseclaw.platform_support import ACP_ONLY_CONNECTORS, UNSUPPORTED, WINDOWS_CONNECTOR_SUPPORT

ROOT = Path(__file__).resolve().parents[2]
INSTALL_PS1 = ROOT / "scripts" / "install.ps1"
LIFECYCLE_PS1 = ROOT / "scripts" / "test-install-lifecycle.ps1"
TOKEN = "__DEFENSECLAW_VERSION__"
POWERSHELL = shutil.which("powershell.exe") or shutil.which("pwsh.exe") or shutil.which("pwsh")


def _text() -> str:
    return INSTALL_PS1.read_text(encoding="utf-8")


def _list(name: str) -> list[str]:
    match = re.search(rf"\${name} = @\((.*?)\)", _text(), re.S)
    assert match is not None, name
    return re.findall(r'"([^"]+)"', match.group(1))


def test_version_token_is_only_on_the_stamp_line() -> None:
    # `make dist-installers` replaces every occurrence, so a second one (say, to
    # detect an unstamped copy) would be stamped too and turn that check around.
    text = _text()
    assert text.count(TOKEN) == 1
    assert f'$DcVersion = "{TOKEN}"' in text
    assert "if (-not (Test-Version $Ver))" in text


def test_upgrade_shim_reads_the_stamped_version(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "install.ps1").write_text(_text().replace(TOKEN, "1.2.3"), encoding="utf-8")
    monkeypatch.setattr(upgrade_shim, "_installer_name", lambda: "install.ps1")
    assert upgrade_shim._local_version(str(tmp_path)) == "1.2.3"


def test_scripts_are_ascii() -> None:
    # Windows PowerShell 5.1 reads a script without a BOM, and an `irm | iex`
    # download, in the ANSI code page.
    INSTALL_PS1.read_text(encoding="utf-8").encode("ascii")
    LIFECYCLE_PS1.read_text(encoding="utf-8").encode("ascii")


def test_only_a_file_run_exits() -> None:
    # `exit` from a script block run by `irm | iex` closes the user's window.
    assert re.findall(r"(?:^|[{;]\s*)exit\b[^\n]*", _text(), re.M) == ["{ exit $code }"]
    assert "if ($RunAsFile) { exit $code }" in _text()


def test_permanent_parameters_and_unknown_arguments() -> None:
    parameters = _text().split("param(", 1)[1].split("\n)\n", 1)[0]
    for name in ("Yes", "Version", "Local", "Rollback", "Connector", "NoOpenclaw", "Quickstart",
                 "QuickstartMode", "NoPersistPath", "CosignPath", "Help"):
        assert re.search(rf"\]\${name}\b", parameters), name
    assert "[Parameter(ValueFromRemainingArguments = $true)]" in parameters
    assert "[CmdletBinding(PositionalBinding = $false)]" in _text()


def test_enterprise_policy_stops_it_before_any_change() -> None:
    # The policy 0.8.x `defenseclaw upgrade` honored; install.ps1 would otherwise
    # replace a per-user Setup an enterprise pushed through Intune or SCCM.
    text = _text()
    check = text.index('GetValue("DisableSelfUpdate")')
    assert 'OpenSubKey("SOFTWARE\\Policies\\Cisco\\DefenseClaw")' in text
    assert "[Microsoft.Win32.RegistryView]::Registry64" in text
    assert "DefenseClaw self-update is disabled by enterprise policy; use the managed deployment channel." in text
    assert "Could not read the enterprise update policy" in text
    # Before -Version and unstamped hand-offs, the lock, and -Rollback.
    assert check < text.index("return Invoke-ReleaseInstaller") < text.index("# Lock and log.")
    assert check < text.index("if ($Rollback) { return Invoke-Rollback }")


def test_connector_choices_are_the_windows_supported_connectors() -> None:
    choices = _list("ConnectorChoices")
    supported = {
        name
        for name, support in WINDOWS_CONNECTOR_SUPPORT.items()
        if support.status != UNSUPPORTED and name not in ACP_ONLY_CONNECTORS
    }
    assert choices[-1] == "none"
    assert len(choices) == len(set(choices))
    assert set(choices[:-1]) == supported


def test_uninstall_owns_every_file_the_installer_writes_to_local_bin() -> None:
    hook_state = re.search(r'\$HookState = "([^"]+)"', _text())
    posix_shim = re.search(r'\$PosixShim = "([^"]+)"', _text())
    assert hook_state is not None and posix_shim is not None
    written = (
        set(_list("ManagedBinaries"))
        | {f"{shim}.cmd" for shim in _list("ManagedShims")}
        | {hook_state.group(1), posix_shim.group(1)}
    )
    _root, targets = cmd_uninstall._owned_binary_targets("win32")
    assert written == {re.split(r"[\\/]", target)[-1] for target in targets}
    # Install-Uv adds uv and the digest record uninstall checks it against.
    uv = re.search(r"foreach \(\$name in @\(([^)]*)\)\)", _text()[_text().index("function Install-Uv") :])
    assert uv is not None
    uv_written = set(re.findall(r'"([^"]+)"', uv.group(1))) | {cmd_uninstall._UV_RECORD}
    assert uv_written == set(cmd_uninstall._UV_NAMES["win32"]) | {cmd_uninstall._UV_RECORD}
    assert written | uv_written == windows_uninstall_helper._ALLOWED_BINARIES


def test_a_release_install_removes_the_developer_install_files() -> None:
    # GAP-1493: defenseclaw.exe from `make all` shadows the release
    # defenseclaw.cmd (PATHEXT), so the release install removes what make all
    # published beyond the managed binaries, once the swap is done.
    developer = set(cmd_uninstall._WINDOWS_DEVELOPER_FILES) - set(_list("ManagedBinaries"))
    assert set(_list("DeveloperFiles")) == developer
    text = _text()
    assert '(Join-Path $BinDir ".defenseclaw-source-root") -PathType Leaf' in text
    assert "    Complete-Swap\n    Remove-DeveloperFiles\n" in text


def test_cli_shim_is_the_one_uninstall_recognizes() -> None:
    match = re.search(r'\$text = "(@echo off[^\n]*)"\n', _text())
    assert match is not None
    venv = "C:\\Users\\Zoe\\.defenseclaw\\.venv"
    target = f"{venv}\\Scripts\\defenseclaw.exe"
    shim = match.group(1).replace("`r", "\r").replace("`n", "\n").replace('`"', '"').replace("$Target", target)
    assert shim == f'@echo off\r\n"{target}" %*\r\n'
    # cmd_uninstall._validate_windows_binary_ownership and the deferred helper
    # look for exactly this command line.
    assert f'"{target}" %*'.lower() in shim.lower()


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
def test_powershell_parses_the_scripts_and_help_runs(tmp_path: Path) -> None:
    script = rf"""
foreach ($path in '{INSTALL_PS1}', '{LIFECYCLE_PS1}') {{
    $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$errors)
    if (@($errors).Count) {{ throw "${{path}}: $($errors -join '; ')" }}
}}
& '{POWERSHELL}' -NoProfile -NonInteractive -ExecutionPolicy Bypass -File '{INSTALL_PS1}' -Help
exit $LASTEXITCODE
"""
    env = {
        **os.environ,
        "USERPROFILE": str(tmp_path),
        # pwsh on Linux and macOS has no profile folders; the script computes its paths up front.
        "LOCALAPPDATA": str(tmp_path / "AppData" / "Local"),
        "APPDATA": str(tmp_path / "AppData" / "Roaming"),
        "DEFENSECLAW_HOME": str(tmp_path / "home"),
    }
    completed = subprocess.run(
        [POWERSHELL, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
        env=env,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "-Rollback" in completed.stdout
    assert not (tmp_path / "home").exists()


def test_hook_state_matches_what_the_hook_reads() -> None:
    # internal/cli/hook_trusted_state_windows.go accepts a PowerShell install's
    # state only with these values; anything else makes the hook fall back to
    # the profile's .defenseclaw and ignore a custom DEFENSECLAW_HOME.
    body = re.search(r"function Write-HookState \{(.*?)\n\}", _text(), re.S)
    assert body is not None
    for field in ('schema_version = 1', 'install_kind = "powershell-windows"', 'install_scope = "user"'):
        assert field in body.group(1)
    for field in ("install_root = $root", "command_dir = $root", "data_root = "):
        assert field in body.group(1)
    go = (ROOT / "internal" / "cli" / "hook_trusted_state_windows.go").read_text()
    assert 'powerShellHookStateName = "defenseclaw-hook-state.json"' in go
    assert re.search(r'\$HookState = "defenseclaw-hook-state.json"', _text())


def test_a_failed_first_run_quickstart_keeps_the_install_and_exits_4() -> None:
    text = _text()
    extras = text[text.index("function Invoke-FirstInstallExtras") : text.index("function Show-Usage")]
    assert "$quickstartRc = Invoke-Native" in extras
    assert '$Run.QuickstartRerun = "defenseclaw " + ($quickstartArgs -join " ")' in extras
    summary = text[text.index('Write-Host "  DefenseClaw $Ver is installed."') : text.index("$savedEnv = @{}")]
    assert summary.index("if ($Run.QuickstartRerun)") < summary.index("return 4") < summary.index("return $startRc")
    # `irm | iex` cannot exit; it reports the installed-but-not-set-up outcome instead.
    tail = text[text.index("Wait-BeforeClose $code\nif ($RunAsFile) { exit $code }") :]
    assert tail.index("if ($code -eq 4) { & ([scriptblock]::Create('throw") < tail.index(
        "if ($code -ne 0 -and $code -ne 3) { & ([scriptblock]::Create('throw"
    )


def test_the_upgrade_window_keeps_the_outcome_on_screen_with_yes() -> None:
    # `defenseclaw upgrade --yes` runs install.ps1 in its own console: -Yes must
    # not close it at once, but it must not wait forever either.
    text = _text()
    body = text[text.index("function Wait-BeforeClose") : text.index("# -- Existing install")]
    assert "if ($Yes -or" not in body
    assert "[Console]::KeyAvailable" in body and "$Run.Log" in body
    # Windows PowerShell 5.1 runs this installer and has no [uint] accelerator.
    assert '"uint[]"' not in body
    # GAP-1570: `& install.ps1` typed into the user's own shell returns at once;
    # only a console started for the script waits before closing.
    started_for_script = (
        "[Environment]::CommandLine.IndexOf($scriptName, [StringComparison]::OrdinalIgnoreCase) -lt 0) { return }"
    )
    assert body.index("$Run.Log") < body.index(started_for_script) < body.index("if (-not $Yes)")


def test_the_suggested_cleanup_removes_the_read_only_key_copy() -> None:
    # GAP-1645: Remove-Item -Force first resets each file's attributes, which the
    # read-only redaction key copy refuses; rd /s /q deletes it through the folder.
    text = _text()
    assert "Remove-Item -Recurse -Force '" not in text
    assert text.count('cmd /c rd /s /q `"') == 3
    # The installer's own cleanup deletes through .NET first, which is also much
    # faster than Remove-Item in Windows PowerShell 5.1 (GAP-1600).
    body = text[text.index("function Remove-Tree") : text.index("function New-InstallDirectory")]
    assert body.index("[IO.Directory]::Delete(") < body.index("-Recurse -Force -ErrorAction SilentlyContinue")


def test_remove_tree_retries_without_logging_a_terminating_error() -> None:
    # WIN2-U3-13 item 10: a caught Remove-Item -ErrorAction Stop still wrote
    # "TerminatingError(Remove-Item)" into the upgrade transcript.
    text = _text()
    body = text[text.index("function Remove-Tree") : text.index("function New-InstallDirectory")]
    retry = body[: body.index("if ($attempt -ge 30)")] + body[body.index("Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue") :]
    assert "-ErrorAction Stop" not in retry
    assert "if ($attempt -ge 30) { Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop; return }" in body


def test_architecture_check_avoids_the_psreadline_polyfill() -> None:
    # GAP-1054: in an interactive Windows PowerShell 5.1 console (`irm | iex`)
    # [Runtime.InteropServices.RuntimeInformation] is PSReadLine's polyfill.
    text = _text()
    assert "[Runtime.InteropServices.RuntimeInformation]::OSArchitecture" not in text
    assert "switch (Get-OSArchitectureName) {" in text
    body = text[text.index("function Get-OSArchitectureName {") :][:900]
    assert '[object].Assembly.GetType("System.Runtime.InteropServices.RuntimeInformation")' in body
    assert "$env:PROCESSOR_ARCHITEW6432" in body and "$env:PROCESSOR_ARCHITECTURE" in body


def test_a_uv_in_the_bin_folder_is_used_not_replaced() -> None:
    # GAP-1125: a uv.exe in %USERPROFILE%\\.local\\bin that is not on PATH yet is
    # the user's; the installer must not overwrite and record it.
    text = _text()
    lookup = text[text.index("$Uv = [string](Get-Command uv.exe") :][:600]
    assert '(Test-Path -LiteralPath (Join-Path $BinDir "uv.exe") -PathType Leaf)) { $Uv = Join-Path $BinDir "uv.exe" }' in lookup
    assert lookup.index("Join-Path $BinDir") < lookup.index("$Uv = Install-Uv")


def test_the_locked_package_install_is_retried_with_backoff() -> None:
    # GAP-1315: a sharing violation (os error 32) on uv's cache rename failed
    # the whole Windows install.
    # The DefenseClaw wheel install hit the same hold, so both uv pip steps
    # go through the retry helper.
    start = _text().index("function New-Venv")
    body = _text()[start : _text().index("function Invoke-UvPipInstall")]
    assert body.count("Invoke-UvPipInstall") == 2
    assert "Invoke-Native $Uv @(\"pip\"" not in body
    # GAP-1941: on a busy host one retry hit the same hold on the next
    # package, so it backs off several times, checks for a full disk before
    # each attempt, and the last failure says to run the command again.
    helper = _text()[_text().index("function Invoke-UvPipInstall(") :][:1200]
    assert "$waits = @(5, 15, 30)" in helper
    assert helper.index("Test-DiskFull") > helper.index("for ($i = 0")
    assert "Start-Sleep -Seconds $waits[$i]" in helper
    assert "run the same command again" in helper


def _ps1_function(name: str) -> str:
    text = _text()
    start = text.index(f"function {name} ")
    return text[start : text.index("\n}\n", start) + 3]


def test_a_slow_first_start_is_waited_for_before_restoring() -> None:
    # GAP-1348: a 1.x gateway over a large audit database outlasted start's
    # 60-second readiness wait, and the upgrade rolled back while it was
    # still starting.
    body = _ps1_function("Start-Gateway")
    assert "if ($rc -in @(0, 3) -or -not (Get-GatewayProcess)) { return $rc }" in body
    assert "$deadline = (Get-Date).AddMinutes(3)" in body
    assert 'Invoke-Native $gateway @("status") -Quiet' in body
    assert 'Write-Ok "The gateway finished starting"; return 0' in body


def test_a_restore_that_leaves_the_old_gateway_down_says_so() -> None:
    # GAP-1349: "Your previous install is back" while the gateway that ran
    # before stayed down and fail-closed connectors blocked every tool call.
    body = _ps1_function("Restart-Old")
    assert "$Run.OldGatewayDown = $WasRunning -and -not (Get-GatewayProcess)" in body
    assert "did not start again, so agent hooks are not guarded" in body
    assert "but its gateway is not running" in _ps1_function("Get-RestoredNote")
    text = _text()
    assert text.count("$(Get-RestoredNote) Log: $($Run.Log)") == 2
    assert "Your previous install is back. Log:" not in text


def test_a_later_upgrade_keeps_the_0_x_audit_history() -> None:
    # GAP-1360: previous\ held the only copy of the 0.x audit history, and the
    # next upgrade replaced it.
    body = _ps1_function("Save-RolledBackData")
    assert '$label = "audit-history"' in body
    assert '[version]$version -lt [version]"1.0.0"' in body
    assert "backups\\$label-$version-" in body


def test_the_rollback_copy_states_its_size_and_the_free_space() -> None:
    # GAP-1519: an upgrade with a 1.3 GB audit.db never said how much it copied.
    body = _text()[_text().index("function Save-Snapshot") :][:1400]
    assert "Saving a rollback copy of the data folder ({0:N0} MB needed{1})" in body
    assert body.index("Saving a rollback copy") < body.index("Not enough free disk space")


def test_a_pending_uninstall_cleanup_is_waited_for_before_the_data_dir_is_touched() -> None:
    # GAP-1647: an install started right after `uninstall --all` lost its
    # .staging to the deferred cleanup, which runs after the CLI exits.
    start = _text().index("function Wait-UninstallCleanup(")
    body = _text()[start : _text().index("\n}\n", start)]
    assert '-Filter "defenseclaw-uninstall-*"' in body and '"plan.json"' in body
    assert '"interpreter_dirs"' in body
    assert "AddMinutes(-10)" in body
    assert "wait a minute, then run the installer again. Nothing was changed." in body
    install = _ps1_function("Invoke-Install")
    assert install.index("Wait-UninstallCleanup") < install.index('Join-Path $DataDir "logs"')
    # The helper's folder names match what uninstall writes.
    uninstall = (ROOT / "cli" / "defenseclaw" / "commands" / "cmd_uninstall.py").read_text(encoding="utf-8")
    assert 'tempfile.mkdtemp(prefix=f"defenseclaw-uninstall-{token}-")' in uninstall
    assert 'os.path.join(helper_dir, "plan.json")' in uninstall
    assert '"interpreter_dirs"' in uninstall


def test_uv_gets_load_tolerant_timeouts_and_they_are_restored() -> None:
    # GAP-1776: uv's 60 s bytecode and 30 s HTTP limits failed installs on a
    # busy Windows host.
    install = _ps1_function("Invoke-Install")
    assert 'if (-not $env:UV_COMPILE_BYTECODE_TIMEOUT) { $env:UV_COMPILE_BYTECODE_TIMEOUT = "600" }' in install
    assert 'if (-not $env:UV_HTTP_TIMEOUT) { $env:UV_HTTP_TIMEOUT = "300" }' in install
    restore = _text()[_text().index("$savedEnv = @{}") :][:400]
    assert '"UV_COMPILE_BYTECODE_TIMEOUT", "UV_HTTP_TIMEOUT"' in restore


def test_a_first_install_does_not_mention_a_previous_install() -> None:
    # GAP-1827: a first install printed "Saving a rollback copy ... (0 MB needed)"
    # and "Cleaning up the previous install's files".
    assert "if ($PrevVersion -or $need -gt 0) {" in _ps1_function("Save-Snapshot")
    swap = _ps1_function("Complete-Swap")
    assert "if ($PrevVersion) { Write-Info \"Cleaning up the previous install's files" in swap
    assert 'else { Write-Info "Removing the staging files" }' in swap


def test_the_install_log_can_time_a_failed_gateway_start() -> None:
    # GAP-1797: no line of the install log (a transcript) had a time.
    text = _text()
    assert '"--- $Message  [$(Get-UtcClock)]"' in text
    assert 'Write-Info "Starting the gateway [$(Get-UtcClock)]"' in _ps1_function("Start-Gateway")
    assert "did not become healthy within {0:N0} s [{1}]" in text


def test_the_previous_watchdog_is_stopped_even_when_the_gateway_is_down() -> None:
    # GAP-1833: with the gateway down the old watchdog kept running from the
    # renamed binary and held its ownership lock against the new one.
    body = _ps1_function("Stop-Watchdog")
    assert '$image = Join-Path $BinDir "defenseclaw-gateway.exe"' in body
    assert "Get-ProcessesUnder @($image)" in body  # a prefix: .old-* too
    assert 'Invoke-Native $image @("watchdog", "stop") -Quiet' in body
    assert "Stop-Process -Id $_.ProcessId -Force" in body
    # Rollback and recovery stop the gateway through Stop-Gateway, running or not.
    stop_gateway = _ps1_function("Stop-Gateway")
    assert "if (-not $process) { Stop-Watchdog; return $true }" in stop_gateway
    assert stop_gateway.count("Stop-Watchdog") == 2
    install = _ps1_function("Invoke-Install")
    stop = install.index("    Stop-Watchdog\n")
    assert install.index('Write-Info "Stopping the gateway') < stop < install.index("Save-Snapshot")
    assert not install[install.index("if ($WasRunning) {") : stop].count("Stop-Watchdog")


def test_disk_room_is_checked_before_staging_and_before_the_gateway_stops() -> None:
    # GAP-1841: only the rollback copy was checked, after staging and after
    # the gateway was stopped. GAP-1839: the staging and environment sizes
    # were never counted.
    text = _text()
    room = text[text.index("function Assert-InstallRoom(") :][:1400]
    assert "$data = Get-DataSize" in room
    assert "$free -ge $data + $Extra + 100MB" in room
    assert "nothing was changed" in room
    install = _ps1_function("Invoke-Install")
    first = install.index('Assert-InstallRoom $InstallRoom "the new version"')
    assert first < install.index("New-InstallDirectory $Staging")
    second = install.index('Assert-InstallRoom $FinalEnvRoom "the final Python environment"')
    assert install.index("is staged and checked") < second < install.index('Write-Info "Stopping the gateway')


def test_a_stopped_or_undone_install_frees_the_staged_release_first() -> None:
    # GAP-1839/GAP-1841: the 873 MB .staging left no room for the restore or
    # for the old gateway's restart.
    clear = _ps1_function("Clear-StagedRelease")
    assert 'Where-Object { $_.Name -ne "hook-runtime-state.json" }' in clear
    restore = _ps1_function("Restore-Snapshot")
    assert restore.index("Clear-StagedRelease") < restore.index("Restore-Slot $Snap")
    assert "run the installer again to finish restoring it" in restore
    install = _ps1_function("Invoke-Install")
    failed = install[install.index("if (-not $saved) {") :][:500]
    assert failed.index("Clear-StagedRelease") < failed.index("Restart-Old")
    assert "it was not changed, but its gateway is not running" in failed
    final = _text()[_text().index("if ($Run.Lock) {") :][:200]
    assert "Invoke-Quietly { Clear-StagedRelease }" in final


def test_a_first_install_on_a_full_disk_says_so_and_keeps_no_failed_copy() -> None:
    # GAP-1883: the uv retry blamed a busy host, and a failed first install
    # kept about 2 GB (.failed-*, .venv) that held the disk full.
    uv = _text()[_text().index("function Invoke-UvPipInstall(") :][:1200]
    assert uv.index("if (Test-DiskFull) { return $false }") < uv.index("Retrying the Python package install")
    full = _ps1_function("Test-DiskFull")
    assert "$free -ge 300MB" in full and "then run the installer again" in full
    restore = _ps1_function("Restore-Snapshot")
    first = restore[restore.index("if (-not $PrevVersion) {") :]
    assert first.index("Remove-Tree $failed") < first.index("return") < first.index("was kept in $failed")
    assert 'if (-not $PrevVersion) { return "Nothing was left installed." }' in _ps1_function("Get-RestoredNote")


def test_an_interrupted_setup_upgrade_restarts_the_setup_gateway() -> None:
    # GAP-1839: recovery ran ~\.local\bin\defenseclaw-gateway.exe, which a
    # DefenseClaw Setup install never had ("is not recognized").
    start = _ps1_function("Start-Gateway")
    assert "if (-not (Test-Path -LiteralPath $gateway -PathType Leaf))" in start
    assert start.index("Test-Path -LiteralPath $gateway") < start.index('Invoke-Native $gateway @("start")')
    resume = _ps1_function("Resume-InterruptedRun")
    assert "Start-SetupGateway $setupInstall.Root" in resume
    assert "Start-SetupGateway $Setup.Root" in _ps1_function("Restore-SetupInstall")
