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
import sys
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
    cli_launcher = re.search(r'\$CliLauncher = "([^"]+)"', _text())
    assert hook_state is not None and posix_shim is not None and cli_launcher is not None
    written = (
        set(_list("ManagedBinaries"))
        | {f"{shim}.cmd" for shim in _list("ManagedShims")}
        | {hook_state.group(1), posix_shim.group(1), cli_launcher.group(1)}
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
    # Its defenseclaw.exe is replaced by the installer's launcher (GAP-2237).
    developer = set(cmd_uninstall._WINDOWS_DEVELOPER_FILES) - set(_list("ManagedBinaries")) - {"defenseclaw.exe"}
    assert set(_list("DeveloperFiles")) == developer
    text = _text()
    assert '(Join-Path $BinDir ".defenseclaw-source-root") -PathType Leaf' in text
    assert "    Complete-Swap\n    Remove-DeveloperFiles\n" in text


def test_powershell_runs_a_native_cli_launcher() -> None:
    # GAP-2237: through defenseclaw.cmd, cmd.exe asked "Terminate batch job
    # (Y/N)?" after Ctrl+C. PATHEXT runs .exe before .cmd, so the installer
    # puts the venv's own launcher beside the shim, and rollback keeps it.
    text = _text()
    assert '$CliLauncher = "defenseclaw.exe"' in text
    assert "@($PosixShim, $CliLauncher, $HookState)" in text
    assert "Write-PosixShim $target; Install-File $target (Join-Path $BinDir $CliLauncher)" in text
    assert "defenseclaw.exe" not in _list("DeveloperFiles")


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


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
@pytest.mark.parametrize(
    ("argument", "message"),
    [("-Frobnicate", "Unknown option: -Frobnicate"), ("-Connector=bogus", "Invalid -Connector 'bogus'")],
)
def test_an_unknown_argument_stops_with_exit_2(tmp_path: Path, argument: str, message: str) -> None:
    # GAP-0361: an unknown argument (a typo, or the -Name=value form) was
    # ignored with a warning and the install went on without it.
    env = {
        **os.environ,
        "USERPROFILE": str(tmp_path),
        "LOCALAPPDATA": str(tmp_path / "AppData" / "Local"),
        "APPDATA": str(tmp_path / "AppData" / "Roaming"),
        "DEFENSECLAW_HOME": str(tmp_path / "home"),
    }
    completed = subprocess.run(
        [POWERSHELL, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(INSTALL_PS1), argument],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
        env=env,
        check=False,
    )
    assert completed.returncode == 2, completed.stdout + completed.stderr
    assert message in completed.stdout + completed.stderr
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
    go = (ROOT / "internal" / "cli" / "hook_trusted_state_windows.go").read_text(encoding="utf-8")
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
    assert text.count('cmd /c rd /s /q `"') == 2
    # A failed install can own unresolved external connector transactions;
    # its troubleshooting copy must not be advertised as safe to delete.
    failed = _ps1_function("Restore-Snapshot")
    assert "keep this copy until any connector recovery is complete" in failed
    assert "cmd /c rd /s /q" not in failed
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
    match = re.search(rf"^function {re.escape(name)}[ (]", text, re.M)
    assert match is not None, name
    start = match.start()
    return text[start : text.index("\n}\n", start) + 3]


_GUARDRAIL_CONFIGS = {
    # What 'uninstall --binaries' and 'setup guardrail --disable' save.
    "off": ("guardrail:\n  enabled: false\n  mode: action\n  judge:\n    enabled: true\ngateway:\n  port: 18970\n", True),
    "on": ("guardrail:\n  enabled: true\n  judge:\n    enabled: false\n", False),
    "other-section": ("guardrail:\n  mode: action\nwebhook:\n  enabled: false\n", False),
    "no-guardrail": ("gateway:\n  enabled: false\n", False),
}


def test_reinstall_over_a_disabled_guardrail_names_setup_guardrail() -> None:
    # GAP-2481: after 'uninstall --binaries' (guardrail off, hooks torn down)
    # the reinstall said only "Start it with: defenseclaw-gateway start".
    install = _ps1_function("Invoke-Install")
    branch = install[install.index("if (Test-GuardrailOff) {") :]
    assert branch.index("Turn it back on with: defenseclaw setup guardrail") < branch.index(
        "Start it with: defenseclaw-gateway start"
    )


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
@pytest.mark.parametrize("name", sorted(_GUARDRAIL_CONFIGS))
def test_test_guardrail_off_reads_the_kept_config(tmp_path: Path, name: str) -> None:
    body, expected = _GUARDRAIL_CONFIGS[name]
    (tmp_path / "config.yaml").write_text(body, encoding="utf-8")
    script = f"$DataDir = '{tmp_path}'\n{_ps1_function('Test-GuardrailOff')}\nif (Test-GuardrailOff) {{ 'off' }} else {{ 'on' }}\n"
    env = {k: v for k, v in os.environ.items() if k != "DEFENSECLAW_CONFIG"}
    completed = subprocess.run(
        [POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        timeout=60,
        env=env,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert completed.stdout.strip() == ("off" if expected else "on")


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
    assert install.index("$WasRunning = Stop-GatewayForSwap $stagedGateway") < stop < install.index("Save-Snapshot")
    assert "Stop-Watchdog" not in _ps1_function("Stop-GatewayForSwap")


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
    assert install.index("is staged and checked") < second < install.index("$WasRunning = Stop-GatewayForSwap")


def test_a_room_refusal_runs_before_the_uv_folder_or_uv_is_created() -> None:
    # GAP-2614: "nothing was changed", but the refusal came after
    # Protect-UvDirectory -Create had made an empty .uv in the data folder.
    install = _ps1_function("Invoke-Install")
    room = install.index('Assert-InstallRoom $InstallRoom "the new version"')
    assert room < install.index("Protect-UvDirectory -Create") < install.index("$Uv = Install-Uv")


def _bin_dir_functions() -> str:
    text = _text()
    out = []
    for name in ("Copy-BinDir", "Restore-BinDir"):
        start = text.index(f"function {name}(")
        out.append(text[start : text.index("\n}\n", start) + 3])
    return "\n".join(out)


def test_a_restore_removes_the_bin_folder_only_when_the_run_created_it() -> None:
    # GAP-2614: "Nothing was left installed." / "Your previous install is
    # back." left an empty ~\.local\bin after a failed first install or a
    # restored DefenseClaw Setup upgrade.
    body = _bin_dir_functions()
    copy = body[: body.index("function Restore-BinDir(")]
    assert copy.index('(Join-Path $To "NO_BINDIR")') < copy.index("foreach ($name in $ManagedFiles)")
    # A first install also made ~\.local; the restore takes that out too.
    assert "$made += $parent" in copy
    restore = body[body.index("function Restore-BinDir(") :]
    marker = restore.index('$marker = Join-Path $From "NO_BINDIR"')
    # With no bin folder before, the restore never recreates it.
    assert marker < restore.index("New-Item -ItemType Directory -Path $BinDir")
    assert "Remove-Item -LiteralPath $dir -Force" in restore
    assert "-Recurse" not in restore


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
@pytest.mark.parametrize("existed", ["none", "parent", "bin"])
def test_restore_bin_dir_puts_the_bin_folder_back_as_it_was(tmp_path: Path, existed: str) -> None:
    bin_dir, slot = tmp_path / "local" / "bin", tmp_path / "slot"
    if existed != "none":
        bin_dir.parent.mkdir()
    if existed == "bin":
        bin_dir.mkdir()
    script = f"""
$ErrorActionPreference = 'Stop'
$BinDir = '{bin_dir}'
$ManagedFiles = @('defenseclaw-gateway.exe')
function Install-File([string]$From, [string]$To) {{ Copy-Item -LiteralPath $From -Destination $To -Force }}
function Remove-Aside([string]$Path) {{ Remove-Item -LiteralPath $Path -Force }}
{_bin_dir_functions()}
Copy-BinDir '{slot}'
New-Item -ItemType Directory -Path $BinDir -Force | Out-Null
Set-Content -LiteralPath (Join-Path $BinDir 'defenseclaw-gateway.exe') -Value 'new'
Restore-BinDir '{slot}'
"""
    completed = subprocess.run(
        [POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert bin_dir.parent.is_dir() is (existed != "none")
    assert bin_dir.is_dir() is (existed == "bin")
    if existed == "bin":
        assert list(bin_dir.iterdir()) == []


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
def test_a_file_robocopy_refuses_is_copied_or_named_with_a_next_step(tmp_path: Path) -> None:
    # GAP-1048: robocopy exit 8 on the audit.db a failed 0.8.10 Setup left
    # stopped the upgrade with no cause and no next step.
    source = tmp_path / "data" / "audit.db"
    source.parent.mkdir()
    source.write_text("db", encoding="utf-8")
    slot = tmp_path / "slot"
    slot.mkdir()
    script = f"""
$ErrorActionPreference = 'Stop'
function Invoke-Robocopy([string[]]$Arguments) {{
    [pscustomobject]@{{ Code = 8; Error = 'ERROR 5 (0x00000005) Copying NTFS Security to Destination File Access is denied.' }}
}}
{_ps1_function("Copy-Kept")}
Copy-Kept '{source}' '{slot}'
try {{ Copy-Kept '{source}' '{tmp_path / "missing"}' }} catch {{ Write-Output $_.Exception.Message }}
"""
    completed = subprocess.run(
        [POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert (slot / "audit.db").read_text(encoding="utf-8") == "db"
    assert "ERROR 5" in completed.stdout and "then run the installer again" in completed.stdout, completed.stdout


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
    assert first.index("Remove-FailedInstall $failed") < first.index("return") < first.index("was kept in $failed")
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


def test_a_restored_setup_install_keeps_no_failed_copy_or_uv_cache_in_its_data_dir() -> None:
    # GAP-1839: the failed 1.0 copy and the uv cache stayed in Setup's data
    # dir, and Setup's gateway, which walks it all before it starts, then
    # timed out on every start.
    clear = _ps1_function("Clear-SetupDataDir")
    assert "Remove-FailedInstall $Failed" in clear
    assert 'Remove-Tree (Join-Path $DataDir ".uv")' in clear
    restore = _ps1_function("Restore-Snapshot")
    assert restore.index("Restore-Slot $Snap") < restore.index("Clear-SetupDataDir $failed") < restore.index("Restart-Old")
    resume = _ps1_function("Resume-InterruptedRun")
    assert resume.index("Clear-SetupDataDir $failed") < resume.index("Start-SetupGateway $setupInstall.Root")
    assert '} elseif (-not $setupBack) {\n                Write-Warn "The interrupted install was kept in $failed"' in resume


def test_the_uv_folder_is_protected_before_uv_runs_and_before_a_rollback_starts_the_gateway() -> None:
    # GAP-1988: the uv cache and Python in the data dir inherited its
    # permissions, so the 1.0.0 gateway, which re-applies them on every private
    # write, missed its 5-second start window after a rollback to 1.0.0.
    protect = _ps1_function("Protect-UvDirectory")
    assert protect.index("if (-not $Create) { return }") < protect.index("New-Item -ItemType Directory")
    assert "if ($acl.AreAccessRulesProtected) { return }" in protect
    assert "$acl.SetAccessRuleProtection($true, $true)" in protect
    install = _ps1_function("Invoke-Install")
    uv_env = install.index('$env:UV_PYTHON_INSTALL_DIR = Join-Path $DataDir ".uv\\python"')
    assert uv_env < install.index("Protect-UvDirectory -Create") < install.index("$Uv = Install-Uv")
    rollback = _ps1_function("Invoke-Rollback")
    # GAP-1284: this install's gateway converts its hook entries before the older one is restored.
    assert rollback.index("if ($canConvertHooks)") < rollback.index("Convert-HooksForRollback") < rollback.index("Switch-WithPrevious")
    assert (
        rollback.index("Switch-WithPrevious")
        < rollback.index("Protect-UvDirectory")
        < rollback.index("if ($startAfter -and (Start-Gateway)")
    )


def test_a_rollback_to_1_0_0_starts_its_gateway_on_a_large_wal_audit_db(tmp_path: Path) -> None:
    # GAP-1988: the 1.0.0 gateway refuses a WAL-mode audit.db whose 5-second
    # startup check times out ("SQLite sidecar -wal changed before secure
    # open"), so the installers put the store in rollback-journal mode before
    # they start a gateway older than 1.0.1.
    import sqlite3
    import sys

    ps1 = re.search(r'^\$AuditJournalPy = "([^"]+)"$', _text(), re.M)
    sh_text = (Path(__file__).resolve().parents[2] / "scripts" / "install.sh").read_text(encoding="utf-8")
    sh = re.search(r'^AUDIT_JOURNAL_PY="([^"]+)"$', sh_text, re.M)
    assert ps1 and sh and ps1.group(1) == sh.group(1)
    db = tmp_path / "audit.db"
    with sqlite3.connect(db) as conn:
        assert conn.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal"
        conn.execute("CREATE TABLE audit_events (id TEXT)")
        conn.execute("INSERT INTO audit_events VALUES ('kept')")
    conn.close()
    for _ in range(2):  # a store already in rollback-journal mode is left as it is
        subprocess.run([sys.executable, "-c", ps1.group(1), str(db)], check=True)
        conn = sqlite3.connect(db)
        assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "delete"
        assert conn.execute("SELECT id FROM audit_events").fetchall() == [("kept",)]
        conn.close()
        assert not (tmp_path / "audit.db-wal").exists()
    start = _ps1_function("Start-Gateway")
    guard = 'if ((Test-Version $version) -and [version]$version -lt [version]"1.0.1") { Reset-AuditJournalMode }'
    assert start.index(guard) < start.index('Invoke-Native $gateway @("start")')
    sh_start = sh_text[sh_text.index("\nstart_gateway() {") :]
    assert sh_start.index('version_lt "${version}" 1.0.1; then reset_audit_journal_mode; fi') < sh_start.index(
        '"${BIN_DIR}/defenseclaw-gateway" start'
    )


def test_a_rollback_to_0_x_checks_the_saved_stores_and_undoes_itself_when_0_x_stays_down(tmp_path: Path) -> None:
    # GAP-1388: a rollback restored a damaged 0.8.10 audit.db, its gateway
    # could not start, and the agents were left unguarded. Both installers
    # check the saved stores with the same code, without writing beside them.
    import sqlite3
    import sys

    ps1 = re.search(r"^\$RollbackDbCheckPy = @'\n(.*?)'@$", _text(), re.M | re.S)
    sh_text = (ROOT / "scripts" / "install.sh").read_text(encoding="utf-8")
    sh = re.search(r"^ROLLBACK_DB_CHECK_PY='(.*?)'$", sh_text, re.M | re.S)
    assert ps1 and sh and ps1.group(1) == sh.group(1)
    good, bad = tmp_path / "good.db", tmp_path / "audit.db"
    stores = {}
    for path in (good, bad):
        stores[path] = sqlite3.connect(path)
        stores[path].execute("PRAGMA journal_mode=WAL")
        stores[path].execute("CREATE TABLE audit_events (detail TEXT)")
        stores[path].executemany("INSERT INTO audit_events VALUES (?)", [("x" * 500,)] * 2000)
        stores[path].commit()
    stores[bad].close()
    with bad.open("r+b") as handle:
        handle.seek(4096 * 2)
        handle.write(b"\xff" * 4096 * 3)
    # good.db is still open, with its -wal: the check reads a copy of it.
    before = sorted(p.name for p in tmp_path.iterdir())
    found = subprocess.run(
        [sys.executable, "-I", "-c", sh.group(1), str(good), str(bad), str(tmp_path / "missing.db")],
        capture_output=True,
        text=True,
        check=True,
    )
    after = sorted(p.name for p in tmp_path.iterdir())
    stores[good].close()
    assert found.stdout.splitlines() == [str(bad)], found.stdout + found.stderr
    assert after == before
    rollback = _ps1_function("Invoke-Rollback")
    assert (
        rollback.index("Test-RollbackData $backTo")
        < rollback.index("Stop-Gateway")
        < rollback.index("Switch-WithPrevious")
        < rollback.index("Move-DamagedAuditStore $backTo")
        < rollback.index("if ($startAfter -and (Start-Gateway)")
        < rollback.index("if ($toLegacy) { return Undo-Rollback")
    )
    undo = _ps1_function("Undo-Rollback")
    assert undo.index("Switch-WithPrevious $BackTo") < undo.index("Start-Gateway") < undo.rindex("return 1")


def test_install_folders_set_only_the_acl_part_that_changed() -> None:
    # GAP-2004: Set-Acl writes every part of the security descriptor and was
    # refused for a standard user on a second NTFS volume, so a
    # DEFENSECLAW_HOME there died with a raw PowerShell error.
    helper = _text()[_text().index("function Set-DirectoryAcl(") :][:600]
    assert "$dir.SetAccessControl($Acl)" in helper
    assert "[IO.FileSystemAclExtensions]::SetAccessControl($dir, $Acl)" in helper
    new_dir = _text()[_text().index("function New-InstallDirectory(") :][:900]
    assert "Set-Acl" not in new_dir
    assert 'catch { Die "Could not set the permissions of ${Path}:' in new_dir
    assert "Set-Acl" not in _ps1_function("Protect-UvDirectory")
    assert "Set-DirectoryAcl $DataDir $acl" in _ps1_function("Invoke-Install")


def test_the_last_uv_hint_names_both_lock_errors() -> None:
    # GAP-2025: a held uv cache file fails with os error 5 as well as 32.
    assert "file in use or access denied (os error 32 or 5)" in _text()[_text().index("function Invoke-UvPipInstall(") :][:1300]


def test_tree_sizes_do_not_read_sum_from_measure_object() -> None:
    # GAP-2616: under StrictMode, Measure-Object over no files has no .Sum, so
    # the space refusal on a fresh first install (no or an empty .uv) crashed.
    assert "Measure-Object -Property Length -Sum" not in _text()
    assert "$bytes = Get-TreeSize $uvDir" in _ps1_function("Write-KeptUvCache")


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
@pytest.mark.parametrize("cache", ["missing", "empty", "one-file"])
def test_write_kept_uv_cache_runs_under_strict_mode(tmp_path: Path, cache: str) -> None:
    if cache != "missing":
        (tmp_path / ".uv").mkdir()
    if cache == "one-file":
        (tmp_path / ".uv" / "wheel").write_bytes(b"x" * 2048)
    tree = _text()[_text().index("function Get-TreeSize(") :]
    tree = tree[: tree.index("\n}\n") + 3]
    script = (
        "Set-StrictMode -Version Latest\n$ErrorActionPreference = 'Stop'\n"
        f"$DataDir = '{tmp_path}'\nfunction Write-Info([string]$m) {{ 'info: ' + $m }}\n"
        f"{tree}\n{_ps1_function('Write-KeptUvCache')}\nWrite-KeptUvCache\n'done'\n"
    )
    completed = subprocess.run(
        [POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    lines = completed.stdout.strip().splitlines()
    assert lines[-1] == "done"
    assert any("download cache" in line for line in lines) == (cache == "one-file")


def test_a_failed_first_install_names_the_kept_uv_cache_and_a_full_disk() -> None:
    # GAP-1883: the space refusal and a staging failure kept the uv cache
    # silently, and a disk that filled at the binary copy showed only the
    # raw .NET text.
    assert "Write-KeptUvCache" in _ps1_function("Restore-Snapshot")
    room = _text()[_text().index("function Assert-InstallRoom(") :][:1400]
    assert room.index("if (-not $PrevVersion) { Write-KeptUvCache }") < room.index("Die (")
    install = _ps1_function("Invoke-Install")
    staging = install[install.index('(New-Venv (Join-Path $Staging "venv")') :][:300]
    assert staging.index("Write-KeptUvCache") < staging.index("Die ")
    assert "Write-Err $_.Exception.Message; [void](Test-DiskFull); $installed = $false" in install
    assert "Write-Err $_.Exception.Message; [void](Test-DiskFull); $saved = $false" in install


def test_an_interrupted_first_install_leaves_no_new_files_or_failed_copy() -> None:
    # GAP-2618: a first install killed mid-copy left ~\.local\bin\*.new (so
    # ~\.local\bin and ~\.local stayed), a .failed-<time> copy of a venv that
    # never was an install, and "restoring the install it replaced".
    restore = _bin_dir_functions()
    restore = restore[restore.index("function Restore-BinDir(") :]
    no_bin = restore[: restore.index("New-Item -ItemType Directory -Path $BinDir")]
    assert '(Join-Path $BinDir "$name.new")' in no_bin
    resume = _ps1_function("Resume-InterruptedRun")
    first = resume.index('$firstInstall = -not (Read-Text (Join-Path $slot "VERSION"))')
    assert first < resume.index("$failed = Restore-Slot $slot")
    assert "An earlier first install was interrupted; removing what it had copied" in resume
    assert resume.index("$failed = Restore-Slot $slot") < resume.index(
        "if ($firstInstall -and -not $setupBack) { Invoke-Quietly { Remove-FailedInstall $failed } }"
    )
    assert 'Write-Info "Nothing was left installed"' in resume


# ── 1.0.2 (FG-01) ───────────────────────────────────────────────────────────


def _run_powershell(script: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
        check=False,
    )


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
def test_rollback_and_upgrade_prune_hook_entries_of_connectors_no_longer_configured(tmp_path: Path) -> None:
    # rel-1-0-1:GAP-0009 on Windows: the newer gateway of the two removes the
    # DefenseClaw hook entries of a connector the live install does not
    # configure; an older gateway prints its connector help instead.
    calls = tmp_path / "calls.txt"
    gateways = []
    for name, usage in (("older", "defenseclaw-gateway connector [command]"), ("newer", "defenseclaw-gateway connector prune-orphans [flags]")):
        body = (
            f"param()\nAdd-Content -LiteralPath '{calls}' -Value ('{name} ' + ($args -join ' '))\n"
            f"if ($args -contains '--help') {{ Write-Output 'Usage:'; Write-Output '  {usage}' }}\nexit 0\n"
        )
        path = tmp_path / f"{name}.ps1"
        path.write_text(body, encoding="utf-8")
        gateways.append(path)
    data_dir = tmp_path / "dc"
    script = (
        "Set-StrictMode -Version Latest\n$ErrorActionPreference = 'Stop'\n"
        f"$DataDir = '{data_dir}'\nfunction Write-Warn([string]$m) {{ 'warn: ' + $m }}\n"
        f"{_ps1_function('Invoke-Native')}\n{_ps1_function('Get-NativeOutput')}\n{_ps1_function('Invoke-PruneOrphanedHooks')}\n"
        f"Invoke-PruneOrphanedHooks @('{tmp_path / 'missing.exe'}', '{gateways[0]}', '{gateways[1]}')\n"
    )
    completed = _run_powershell(script)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert calls.read_text(encoding="utf-8").splitlines() == [
        "older connector prune-orphans --help",
        "newer connector prune-orphans --help",
        f"newer connector prune-orphans --data-dir {data_dir}",
    ]


def test_windows_rollback_and_upgrade_run_the_hook_entry_prune() -> None:
    # rel-1-0-1:GAP-0009: after the swap of a 1.x rollback (live gateway, then
    # the one just left in previous\bin), and in the upgrade after the migration.
    rollback = _ps1_function("Invoke-Rollback")
    prune = (
        'Invoke-PruneOrphanedHooks @((Join-Path $BinDir "defenseclaw-gateway.exe"), '
        '(Join-Path $Previous "bin\\defenseclaw-gateway.exe"))'
    )
    assert rollback.index("Switch-WithPrevious $current") < rollback.index(prune)
    assert "if (-not $toLegacy) {\n        " + prune in rollback
    install = _ps1_function("Install-New")
    assert install.index('"migrate"') < install.index('Invoke-PruneOrphanedHooks @((Join-Path $BinDir "defenseclaw-gateway.exe"))')


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
def test_an_unreadable_file_is_named_once_without_the_raw_hash_error(tmp_path: Path) -> None:
    # rel-1-0-1:GAP-0007: a rollback over an unreadable previous gateway printed
    # PowerShell's ReadError record and "The property 'Hash' cannot be found".
    missing = tmp_path / "previous" / "bin" / "defenseclaw-gateway.exe"
    script = (
        "Set-StrictMode -Version Latest\n$ErrorActionPreference = 'Stop'\n"
        f"{_ps1_function('Get-Sha256')}\n"
        f"try {{ Get-Sha256 '{missing}' }} catch {{ 'caught: ' + $_.Exception.Message }}\n"
    )
    completed = _run_powershell(script)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    out = completed.stdout + completed.stderr
    assert f"caught: Could not read {missing}; restore read access to it, then try again" in out
    assert "Hash" not in out and "CategoryInfo" not in out


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
@pytest.mark.parametrize("arguments", [["-Local="], ["-Local", ""]])
def test_an_empty_local_stops_with_exit_2(tmp_path: Path, arguments: list[str]) -> None:
    # #1096/GAP-1336: an empty -Local was taken as no -Local, so the install
    # went online instead of using the assets folder that was meant.
    env = {
        **os.environ,
        "USERPROFILE": str(tmp_path),
        "LOCALAPPDATA": str(tmp_path / "AppData" / "Local"),
        "APPDATA": str(tmp_path / "AppData" / "Roaming"),
        "DEFENSECLAW_HOME": str(tmp_path / "home"),
    }
    completed = subprocess.run(
        [POWERSHELL, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(INSTALL_PS1), *arguments],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
        env=env,
        check=False,
    )
    assert completed.returncode == 2, completed.stdout + completed.stderr
    assert "-Local needs the folder that holds the release assets" in completed.stdout + completed.stderr
    assert not (tmp_path / "home").exists()


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
@pytest.mark.parametrize(
    ("arguments", "message"),
    [
        (["-Version="], "-Version needs a value such as 1.2.3"),
        (["-Version", ""], "-Version needs a value such as 1.2.3"),
        (["-Version", "w0-invalid-version"], "-Version must look like 1.2.3, got 'w0-invalid-version'"),
    ],
)
def test_an_empty_or_malformed_version_stops_with_exit_2(tmp_path: Path, arguments: list[str], message: str) -> None:
    # GAP-0069: a malformed -Version exited 1, and an empty one installed the
    # latest release; both are usage errors before anything changes.
    env = {
        **os.environ,
        "USERPROFILE": str(tmp_path),
        "LOCALAPPDATA": str(tmp_path / "AppData" / "Local"),
        "APPDATA": str(tmp_path / "AppData" / "Roaming"),
        "DEFENSECLAW_HOME": str(tmp_path / "home"),
    }
    completed = subprocess.run(
        [POWERSHELL, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(INSTALL_PS1), *arguments],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
        env=env,
        check=False,
    )
    out = completed.stdout + completed.stderr
    assert completed.returncode == 2, out
    assert message in out and "nothing was changed" in out
    assert not (tmp_path / "home").exists()


# ── 1.0.2 (DELTA-11): the rollback moves an audit store as one unit ─────────

_POWERSHELLS = sorted({p for p in (shutil.which("powershell.exe"), shutil.which("pwsh.exe") or shutil.which("pwsh")) if p})


def _run_audit_store_case(shell: str, tmp_path: Path, call: str, fail: str = "", fail_back: str = "") -> str:
    # The functions of the shipped installer, with Move-Path made to fail at
    # one step (the injection of the wave's windows-audit-injection.ps1).
    move_path = _ps1_function("Move-Path").replace("function Move-Path(", "function Move-PathReal(", 1)
    script = tmp_path / "case.ps1"
    script.write_text(
        "Set-StrictMode -Version Latest\n$ErrorActionPreference = 'Stop'\n"
        f"$DataDir = '{tmp_path / 'live'}'\n$Previous = '{tmp_path / 'previous'}'\n$BinDir = '{tmp_path / 'bin'}'\n"
        "$Run = [pscustomobject]@{ Log = 'install.log' }\n"
        f"$fail = '{fail}'\n$failBack = '{fail_back}'\n"
        + move_path
        + "function Move-Path([string]$From, [string]$To) {\n"
        "    if ($fail -and $From -eq $fail) { throw 'injected move failure' }\n"
        "    if ($failBack -and $To -eq $failBack) { throw 'injected move-back failure' }\n"
        "    Move-PathReal $From $To 0\n}\n"
        "function Write-Warn([string]$m) { Write-Host \"warn: $m\" }\n"
        "function Write-Info([string]$m) { Write-Host \"info: $m\" }\n"
        "function Write-Ok([string]$m) { Write-Host \"ok: $m\" }\n"
        "function Write-Err([string]$m) { Write-Host \"err: $m\" }\n"
        "function Stop-Gateway { return $true }\nfunction Switch-WithPrevious { return 0 }\nfunction Start-Gateway { return 0 }\n"
        + _ps1_function("Move-AuditStore")
        + _ps1_function("Move-DamagedAuditStore")
        + _ps1_function("Undo-Rollback")
        + f"try {{ $r = {call}; Write-Host \"result: $r\" }} catch {{ Write-Host \"thrown: $($_.Exception.Message)\" }}\n",
        encoding="utf-8",
    )
    completed = subprocess.run(
        [shell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(script)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    return completed.stdout


def _audit_store(path: Path, label: str) -> dict[str, str]:
    store = {"": f"{label} db", "-wal": f"{label} wal", "-shm": f"{label} shm"}
    for suffix, body in store.items():
        Path(f"{path}{suffix}").write_text(body, encoding="utf-8")
    return store


def _assert_store_at(path: Path, store: dict[str, str]) -> None:
    for suffix, body in store.items():
        assert Path(f"{path}{suffix}").read_text(encoding="utf-8") == body, f"{path}{suffix}"


@pytest.mark.skipif(not _POWERSHELLS, reason="PowerShell is not installed")
@pytest.mark.parametrize("shell", _POWERSHELLS)
@pytest.mark.parametrize("failing", ["", "audit.db", "audit.db-wal", "audit.db-shm"])
def test_the_damaged_audit_store_moves_aside_as_one_unit(tmp_path: Path, shell: str, failing: str) -> None:
    # rel-1-0-2:GAP-0491: Move-DamagedAuditStore moved audit.db-wal first, and
    # a database that then did not move stayed behind without its WAL.
    live = tmp_path / "live"
    live.mkdir()
    store = _audit_store(live / "audit.db", "saved")
    out = _run_audit_store_case(shell, tmp_path, "Move-DamagedAuditStore '0.8.10'", str(live / failing) if failing else "")
    aside = sorted(live.glob("audit.db.corrupt-*"))
    if not failing:
        assert "result: " + str(live / "audit.db.corrupt-") in out, out
        assert "warn: The saved 0.8.10 audit store failed SQLite's integrity check" in out
        _assert_store_at(Path(str(aside[0])), store)
        assert len(aside) == 3 and not (live / "audit.db").exists()
        return
    assert "thrown: injected move failure" in out, out
    _assert_store_at(live / "audit.db", store)
    assert aside == []


@pytest.mark.skipif(not _POWERSHELLS, reason="PowerShell is not installed")
@pytest.mark.parametrize("shell", _POWERSHELLS)
def test_a_store_that_cannot_move_back_is_named(tmp_path: Path, shell: str) -> None:
    live = tmp_path / "live"
    live.mkdir()
    _audit_store(live / "audit.db", "saved")
    out = _run_audit_store_case(
        shell, tmp_path, "Move-DamagedAuditStore '0.8.10'", str(live / "audit.db-shm"), str(live / "audit.db")
    )
    assert "thrown: injected move failure; " in out and ".corrupt-" in out and f"could not be moved back to {live / 'audit.db'}" in out, out
    # The WAL went back; only the database that refused is aside, and named.
    assert (live / "audit.db-wal").read_text(encoding="utf-8") == "saved wal"
    aside = list(live.glob("audit.db.corrupt-*"))
    assert len(aside) == 1 and aside[0].read_text(encoding="utf-8") == "saved db", aside
    assert (live / "audit.db-shm").read_text(encoding="utf-8") == "saved shm"


@pytest.mark.skipif(sys.platform != "win32" or not _POWERSHELLS, reason="Windows paths (previous\\data)")
@pytest.mark.parametrize("shell", _POWERSHELLS)
@pytest.mark.parametrize(
    "failing",
    ["", "audit.db", "audit.db-wal", "audit.db.corrupt-fixture", "audit.db.corrupt-fixture-wal", "audit.db.corrupt-fixture-shm"],
)
def test_an_undone_legacy_rollback_puts_the_saved_store_back_over_a_new_one(tmp_path: Path, shell: str, failing: str) -> None:
    # rel-1-0-2:GAP-0492: the failed start of the 0.x gateway made a new, empty
    # audit.db, and the undo left it there while the saved store and its WAL
    # stayed aside, so the next rollback used the empty one without a word.
    data = tmp_path / "previous" / "data"
    data.mkdir(parents=True)
    (tmp_path / "live").mkdir()
    kept = data / "audit.db.corrupt-fixture"
    saved = _audit_store(kept, "saved")
    Path(f"{data / 'audit.db'}").write_text("", encoding="utf-8")
    Path(f"{data / 'audit.db'}-wal").write_text("new wal", encoding="utf-8")
    new = {"": "", "-wal": "new wal"}
    out = _run_audit_store_case(
        shell,
        tmp_path,
        f"Undo-Rollback 'The gateway of DefenseClaw 0.8.10 did not start' '1.0.2' '0.8.10' 'true' '{tmp_path / 'live' / kept.name}'",
        str(data / failing) if failing else "",
    )
    assert "result: 1" in out, out
    assert "ok: DefenseClaw 1.0.2 is back" in out
    fresh = sorted(p for p in data.glob("audit.db.failed-start-*") if not p.name.endswith(("-wal", "-shm")))
    if not failing:
        _assert_store_at(data / "audit.db", saved)
        assert len(fresh) == 1
        _assert_store_at(fresh[0], new)
        assert not list(data.glob("audit.db.corrupt-*")) and "is still" not in out
        return
    # Nothing is mixed: each store is whole at one place, and the warning says
    # where the saved one is.
    _assert_store_at(kept, saved)
    assert f"warn: The saved 0.8.10 audit store is still {kept}" in out, out
    if failing.startswith("audit.db.corrupt-"):
        assert not (data / "audit.db").exists() and not Path(f"{data / 'audit.db'}-wal").exists()
        _assert_store_at(fresh[0], new)
    else:
        _assert_store_at(data / "audit.db", new)
        assert fresh == []


# ── 1.0.3 (B-01, GAP-0196): the new hook answers during the install ─────────


def test_the_new_hook_goes_in_before_the_data_copy() -> None:
    # GAP-0196: the 1.0.2 hook answered the whole data copy and environment
    # build with the operator-stop notice and cold starts. The new hook goes
    # in once the rollback copy holds the old one, before the slow copies.
    save = _ps1_function("Save-Snapshot")
    order = [
        'Copy-BinDir (Join-Path $Snap "bin")',
        "Install-HookFirst $Snap",
        "foreach ($entry in $entries) { Copy-Kept",
        'Move-Path $Venv (Join-Path $Snap "venv")',
        'Join-Path $Snap "COMPLETE"',
    ]
    positions = [save.index(step) for step in order]
    assert positions == sorted(positions), save
    first = _ps1_function("Install-HookFirst")
    assert first.index('(Join-Path $Slot "HOOK_FIRST")') < first.index("Install-File $staged $live")
    # An unfinished snapshot puts the old hook back before anything else.
    undo = _ps1_function("Undo-Snapshot")
    assert undo.index("Undo-HookFirst $Slot") < undo.index("Move-Path")
    # A finished one is restored with the rest of the bin folder.
    assert 'Restore-BinDir (Join-Path $Slot "bin")' in _ps1_function("Restore-Slot")


def test_hook_fail_modes_are_held_from_before_the_gateway_stops_until_it_exits() -> None:
    # An earlier release's sidecar can hold an open nobody chose. For a
    # running gateway the new one sets the modes from the config and holds
    # the lock every release's hook writer takes until the old gateway has
    # exited, then sets them again (r104 W3 G3-upg round 3: the old gateway
    # could render its open again between two separate refreshes). Hooks it
    # cannot make safe refuse the swap: before the stop nothing changed,
    # after it the old gateway comes back. With no gateway running, one
    # refresh.
    install = _ps1_function("Invoke-Install")
    swap = install.index("$WasRunning = Stop-GatewayForSwap $stagedGateway")
    assert install.index("$stagedGateway = Join-Path $Staging") < swap < install.index("$saved = Save-Snapshot"), install
    handoff = _ps1_function("Stop-GatewayForSwap")
    plain = handoff.index("if (-not (Update-HookFailModes $StagedGateway))")
    hold = handoff.index("if (-not (Start-HookFailModeHold $StagedGateway $gatewayProcess.Id))")
    stop = handoff.index("if (-not (Stop-Gateway))")
    finish = handoff.index("if (-not (Complete-HookFailModeHold))")
    assert plain < hold < stop < finish, handoff
    before = handoff[hold:stop]
    assert "nothing was changed (see above)" in before, before
    stopped = handoff[stop:finish]
    assert stopped.index("Stop-HookFailModeHold") < stopped.index("did not stop; nothing was changed"), stopped
    after = handoff[finish:]
    assert after.index("Clear-StagedRelease") < after.index("Restart-Old") < after.index("$(Get-RestoredNote)"), after
    start = _ps1_function("Start-HookFailModeHold")
    assert '--hold-until-exit $GatewayId' in start and 'Contains("Holding the hook fail modes")' in start, start
    assert 'Join-Path $DataDir "hooks\\.hookcfg"' in start, start
    assert "Stop-HookFailModeHold" in start and start.rstrip().endswith("return $false\n}"), start
    assert "$hold.Process.ExitCode -eq 0" in _ps1_function("Complete-HookFailModeHold")
    update = _ps1_function("Update-HookFailModes")
    assert '@("connector", "refresh-fail-modes", "--data-dir", $DataDir)) -eq 0' in update, update
    assert 'Join-Path $DataDir "hooks\\.hookcfg"' in update, update
    # A downgrade's older gateway prints the connector help instead; any other
    # probe answer refuses the swap.
    probe = _ps1_function("Test-HookFailModeRefresh")
    assert '-match "defenseclaw-gateway connector \\[command\\]") { return 1 }' in probe, probe
    assert probe.rstrip().endswith("return 2\n}"), probe


def test_setup_hooks_are_disabled_only_once_the_fail_modes_are_ready() -> None:
    # r104 Guard follow-up 4 (loop round 2): Disable-SetupHooks ran before the
    # fail-mode refresh and its hold, so DefenseClaw Setup's hook launcher,
    # which agents keep at its cached path, answered every call with exit 0
    # and no decision while the staged gateway took up to a minute to hold the
    # modes. Every refresh and the hold now run with the launcher enabled; it
    # is disabled right before the stop, or, with no gateway running, right
    # after the refresh, and put back when a gateway it started turns up.
    handoff = _ps1_function("Stop-GatewayForSwap")
    disables = [m.start() for m in re.finditer(r"^ +(?:if \(\$Setup\) \{ )?Disable-SetupHooks", handoff, re.M)]
    assert len(disables) == 2, handoff
    plain = handoff.index("if (-not (Update-HookFailModes $StagedGateway))")
    hold = handoff.index("if (-not (Start-HookFailModeHold $StagedGateway $gatewayProcess.Id))")
    stop = handoff.index("if (-not (Stop-Gateway))")
    assert plain < disables[0] < handoff.index("Enable-SetupHooks") < hold < disables[1] < stop, handoff
    install = _ps1_function("Invoke-Install")
    assert "Disable-SetupHooks" not in install and "Start-HookFailModeHold" not in install, install
    assert "Update-HookFailModes" not in install, install
    assert "Enable-SetupHooks" in _ps1_function("Restore-SetupInstall")


_HANDOFF_STUBS = """
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$Staging = '{staging}'
$SetupHookState = '{state}'
$Setup = {setup}
$events = New-Object System.Collections.Generic.List[string]
$script:looks = @({looks})
$script:look = 0
function Mark([string]$step) {{ $events.Add("$step=$(if (Test-Path -LiteralPath $SetupHookState) {{ 'enabled' }} else {{ 'disabled' }})") }}
function Get-GatewayProcess {{
    $i = [Math]::Min($script:look, $script:looks.Count - 1); $script:look++
    if ($script:looks[$i]) {{ return [pscustomobject]@{{ Id = 4242 }} }}
    return $null
}}
function Update-HookFailModes([string]$Gateway) {{ Mark 'refresh'; return {refresh} }}
function Start-HookFailModeHold([string]$Gateway, [int]$GatewayId) {{ Mark "hold:$GatewayId"; return {hold} }}
function Stop-HookFailModeHold {{ Mark 'release' }}
function Complete-HookFailModeHold {{ Mark 'complete'; return {complete} }}
function Stop-Gateway {{ Mark 'stop'; return {stop} }}
function Clear-StagedRelease {{ Mark 'clear' }}
function Restart-Old {{ if ($Setup) {{ Restore-SetupInstall }} }}
function Start-SetupGateway([string]$Root) {{ Mark 'start-setup' }}
function Get-RestoredNote {{ return 'restored' }}
function Get-UtcClock {{ return 'T' }}
function Write-Info([string]$m) {{ }}
function Die([string]$m) {{ throw $m }}
"""


@pytest.mark.skipif(not _POWERSHELLS, reason="PowerShell is not installed")
@pytest.mark.parametrize("shell", _POWERSHELLS)
@pytest.mark.parametrize(
    ("case", "setup", "looks", "results", "want_events", "want_out"),
    [
        # A running Setup gateway: the launcher answers through it while the hold is taken.
        ("running", True, ["1"], {}, ["hold:4242=enabled", "stop=disabled", "complete=disabled"], "was=True"),
        # None running: enabled through the refresh, then disabled.
        ("stopped", True, ["0", "0"], {}, ["refresh=enabled"], "was=False"),
        # The enabled launcher started Setup's gateway during the refresh: held and stopped like a running one.
        (
            "started-by-launcher",
            True,
            ["0", "1"],
            {},
            ["refresh=enabled", "hold:4242=enabled", "stop=disabled", "complete=disabled"],
            "was=True",
        ),
        # Refusals leave the launcher enabled.
        ("hold-fails", True, ["1"], {"hold": "$false"}, ["hold:4242=enabled"], "thrown=Could not set"),
        ("refresh-fails", True, ["0"], {"refresh": "$false"}, ["refresh=enabled"], "thrown=Could not set"),
        (
            "stop-fails",
            True,
            ["1"],
            {"stop": "$false"},
            ["hold:4242=enabled", "stop=disabled", "release=disabled", "start-setup=enabled"],
            "thrown=The running gateway did not stop",
        ),
        (
            "second-refresh-fails",
            True,
            ["1"],
            {"complete": "$false"},
            ["hold:4242=enabled", "stop=disabled", "complete=disabled", "clear=disabled", "start-setup=enabled"],
            "thrown=Could not set",
        ),
        # No Setup install: its state is never touched.
        ("plain-running", False, ["1"], {}, ["hold:4242=enabled", "stop=enabled", "complete=enabled"], "was=True"),
        ("plain-stopped", False, ["0"], {}, ["refresh=enabled"], "was=False"),
    ],
)
def test_setup_hook_launcher_answers_until_the_fail_mode_hold_is_ready(
    tmp_path: Path,
    shell: str,
    case: str,
    setup: bool,
    looks: list[str],
    results: dict[str, str],
    want_events: list[str],
    want_out: str,
) -> None:
    # The handoff of the shipped installer with its steps stubbed: each step
    # records whether Setup's launcher state was in place when it ran.
    staging, runtime = tmp_path / "staging", tmp_path / "HookRuntime"
    staging.mkdir()
    runtime.mkdir()
    state = runtime / "hook-runtime-state.json"
    state.write_text('{"status":"active"}', encoding="utf-8")
    values = {"refresh": "$true", "hold": "$true", "complete": "$true", "stop": "$true", **results}
    stubs = _HANDOFF_STUBS.format(
        staging=staging,
        state=state,
        setup="[pscustomobject]@{ Root = 'C:\\Setup' }" if setup else "$null",
        looks=", ".join(f"${'true' if look == '1' else 'false'}" for look in looks),
        **values,
    )
    script = tmp_path / "handoff.ps1"
    script.write_text(
        stubs
        + _ps1_function("Move-Path")
        + _ps1_function("Disable-SetupHooks")
        + _ps1_function("Enable-SetupHooks")
        + _ps1_function("Restore-SetupInstall")
        + _ps1_function("Stop-GatewayForSwap")
        + "try { $was = Stop-GatewayForSwap 'staged-gateway.exe'; Write-Host \"was=$was\" } "
        + "catch { Write-Host \"thrown=$($_.Exception.Message)\" }\n"
        + "foreach ($e in $events) { Write-Host \"event $e\" }\n"
        + "Write-Host \"end=$(if (Test-Path -LiteralPath $SetupHookState) { 'enabled' } else { 'disabled' })\"\n",
        encoding="utf-8",
    )
    completed = subprocess.run(
        [shell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(script)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    lines = completed.stdout.splitlines()
    assert [line[len("event ") :] for line in lines if line.startswith("event ")] == want_events, (case, completed.stdout)
    assert any(line.startswith(want_out) for line in lines), (case, completed.stdout)
    # The launcher stays disabled only when the swap goes on with Setup's gateway down.
    want_end = "disabled" if setup and want_out.startswith("was=") else "enabled"
    assert f"end={want_end}" in lines, (case, completed.stdout)
    assert not (staging / "hook-runtime-state.json").exists() or want_end == "disabled", (case, completed.stdout)


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
def test_hook_fail_mode_refresh_refuses_a_probe_that_fails(tmp_path: Path) -> None:
    # r104 W3 G3-upg: a staged gateway whose help probe failed or printed
    # nothing was taken for an older one and the swap went on, so the gateway
    # could stop with a stale open in hooks\.hookcfg. Only the newer
    # gateway's help runs the refresh and only an older one's connector help
    # skips it; every other answer is false.
    data_dir = tmp_path / "dc"
    (data_dir / "hooks").mkdir(parents=True)
    (data_dir / "hooks" / ".hookcfg").write_text("{}", encoding="utf-8")
    calls = tmp_path / "calls.txt"
    cases = {
        "newer": ("Write-Output '  defenseclaw-gateway connector refresh-fail-modes [flags]'; exit 0", True),
        "older": ("Write-Output '  defenseclaw-gateway connector [command]'; exit 0", True),
        "fails": ("[Console]::Error.WriteLine('cannot run'); exit 1", False),
        "silent": ("exit 0", False),
    }
    for name, (help_body, want) in cases.items():
        gateway = tmp_path / f"{name}.ps1"
        gateway.write_text(
            f"Add-Content -LiteralPath '{calls}' -Value ('{name} ' + ($args -join ' '))\n"
            f"if ($args -contains '--help') {{ {help_body} }}\nexit 0\n",
            encoding="utf-8",
        )
        script = (
            "Set-StrictMode -Version Latest\n$ErrorActionPreference = 'Stop'\n"
            f"$DataDir = '{data_dir}'\nfunction Write-Warn([string]$m) {{ [Console]::Error.WriteLine('warn: ' + $m) }}\n"
            f"{_ps1_function('Invoke-Native')}\n{_ps1_function('Get-NativeProbe')}\n"
            f"{_ps1_function('Test-HookFailModeRefresh')}\n{_ps1_function('Update-HookFailModes')}\n"
            f"if (Update-HookFailModes '{gateway}') {{ 'refresh=true' }} else {{ 'refresh=false' }}\n"
        )
        completed = _run_powershell(script)
        assert completed.returncode == 0, completed.stdout + completed.stderr
        assert f"refresh={str(want).lower()}" in completed.stdout, (name, completed.stdout, completed.stderr)
    ran = [line for line in calls.read_text(encoding="utf-8").splitlines() if "--data-dir" in line]
    assert ran == [f"newer connector refresh-fail-modes --data-dir {data_dir}"]


@pytest.mark.skipif(not _POWERSHELLS, reason="PowerShell is not installed")
@pytest.mark.parametrize("shell", _POWERSHELLS)
@pytest.mark.parametrize("case", ["upgrade", "first-install", "interrupted-before-marker"])
def test_install_hook_first_swaps_the_hook_and_undo_puts_it_back(tmp_path: Path, shell: str, case: str) -> None:
    bin_dir, staging, slot = tmp_path / "bin", tmp_path / "staging", tmp_path / "slot"
    (staging / "bin").mkdir(parents=True)
    (staging / "bin" / "defenseclaw-hook.exe").write_text("new", encoding="utf-8")
    if case != "first-install":
        bin_dir.mkdir()
        (bin_dir / "defenseclaw-hook.exe").write_text("old", encoding="utf-8")
    steps = (
        "Copy-BinDir (Join-Path $Slot bin); Undo-HookFirst $Slot"
        if case == "interrupted-before-marker"
        else "Copy-BinDir (Join-Path $Slot bin); Install-HookFirst $Slot; Write-Host \"after: $(Get-Content -Raw (Join-Path $BinDir 'defenseclaw-hook.exe') -ErrorAction SilentlyContinue)\"; Undo-HookFirst $Slot"
    )
    script = tmp_path / "case.ps1"
    script.write_text(
        "Set-StrictMode -Version Latest\n$ErrorActionPreference = 'Stop'\n"
        f"$BinDir = '{bin_dir}'\n$Staging = '{staging}'\n$Slot = '{slot}'\n"
        "$ManagedFiles = @('defenseclaw-hook.exe')\n"
        "function Install-File([string]$From, [string]$To) { Copy-Item -LiteralPath $From -Destination $To -Force }\n"
        "function Remove-Aside([string]$Path) { Remove-Item -LiteralPath $Path -Force }\n"
        + _bin_dir_functions()
        + _ps1_function("Install-HookFirst")
        + _ps1_function("Undo-HookFirst")
        + steps
        + "\n",
        encoding="utf-8",
    )
    completed = subprocess.run(
        [shell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(script)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
        check=False,
    )
    out = completed.stdout + completed.stderr
    assert completed.returncode == 0, out
    live = bin_dir / "defenseclaw-hook.exe"
    if case == "first-install":
        # Nothing ran a hook before: nothing to swap, no marker, no hook yet.
        assert not live.exists() and not (slot / "HOOK_FIRST").exists(), out
        return
    if case == "upgrade":
        assert "after: new" in out, out
        assert (slot / "HOOK_FIRST").exists()
        assert (slot / "bin" / "defenseclaw-hook.exe").read_text(encoding="utf-8") == "old"
    else:
        assert not (slot / "HOOK_FIRST").exists()
    # Undo leaves the old hook live.
    assert live.read_text(encoding="utf-8").strip() == "old", out


# ── 1.0.4 (GAP-0004) ────────────────────────────────────────────────────────


def _ps_functions(*names: str) -> str:
    text = _text()
    out = []
    for name in names:
        start = text.index(f"function {name}(")
        out.append(text[start : text.index("\n}\n", start) + 3])
    return "\n".join(out)


def test_an_upgrade_replaces_an_installed_binary_in_place() -> None:
    # rel-1-0-4 GAP-0004: renaming the old defenseclaw-hook.exe aside before
    # the new one was in place left a gap in which an agent's registered hook
    # found no launcher. Install-File swaps an existing file in with
    # File.Replace first and renames only when that fails.
    assert "Publish-File" in _ps_functions("Install-File")
    publish = _ps_functions("Publish-File")
    assert publish.index("Switch-InPlace") < publish.index("Remove-Aside")
    # The shims and the hook state the native hook reads are swapped the same
    # way (1.0.4 review): none of them goes missing during an upgrade.
    text = _text()
    hook_state = text[text.index("function Write-HookState {") :]
    hook_state = hook_state[: hook_state.index("\n}\n") + 3]
    for writer, body in (
        ("Write-PosixShim", _ps_functions("Write-PosixShim")),
        ("Write-Shim", _ps_functions("Write-Shim")),
        ("Write-HookState", hook_state),
    ):
        assert 'Publish-File "$path.new" $path' in body and "Remove-Aside" not in body, writer
    assert "[IO.File]::Replace($New, $Destination, $Backup, $true)" in _ps_functions("Invoke-FileReplace")
    # 1.0.4 review: a file ReplaceFile cannot swap is never renamed aside; the
    # install fails and the installed launcher stays where hooks find it.
    switch = _ps_functions("Switch-InPlace")
    assert "Remove-Aside" not in switch and "Move-Path" not in switch
    # 1.0.4 lead directive: the switch is one atomic rename of the new file
    # over the installed one; ReplaceFile only for a launcher that runs.
    assert switch.index("Invoke-AtomicReplace $New $Destination") < switch.index("Invoke-FileReplace $New")
    atomic = _ps_functions("Invoke-AtomicReplace")
    assert "MoveFileExW($New, $Destination, 0x9)" in atomic
    # The new copy is checked whole before anything is switched.
    install = _ps_functions("Install-File")
    assert install.index('(Get-Sha256 "$Destination.new") -ne (Get-Sha256 $Source)') < install.index("Publish-File")
    assert "it was left as it was" in switch
    # 1.0.4 review (loop round 2): an independent restore copy is made before
    # every attempt and handed to Close-SwapGap. Loop round 3: only a verified
    # whole copy, and Close-SwapGap copies only to a ready file that it then
    # renames in, never into the live path.
    assert "New-VerifiedCopy $Destination $restore" in switch
    assert "Close-SwapGap $New $aside $restoreCopy $Destination" in switch
    close = _ps_functions("Close-SwapGap")
    assert "New-VerifiedCopy $old $candidate" in close and "Invoke-FileMove $ready $Destination" in close
    assert "Invoke-FileCopy" not in close


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
def test_install_file_never_leaves_the_destination_missing(tmp_path: Path) -> None:
    source, dest = tmp_path / "staged.exe", tmp_path / "defenseclaw-hook.exe"
    source.write_text("new", encoding="ascii")
    dest.write_text("old", encoding="ascii")
    script = f"""
$ErrorActionPreference = 'Stop'
function Remove-Aside([string]$Path) {{ throw "the destination was renamed away: $Path" }}
function Move-Path([string]$From, [string]$To) {{ throw "rename used: $From" }}
{_ps_functions("Get-Sha256", "Install-File", "Publish-File", "Invoke-FileReplace", "Invoke-FileCopy", "New-VerifiedCopy", "Switch-InPlace")}
Install-File '{source}' '{dest}'
"""
    completed = _run_powershell(script)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert dest.read_text(encoding="ascii") == "new"
    assert sorted(path.name for path in tmp_path.iterdir()) == ["defenseclaw-hook.exe", "staged.exe"]


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
def test_an_idle_installed_file_switches_by_one_atomic_rename(tmp_path: Path) -> None:
    # 1.0.4 lead directive: the new launcher is written beside the old one
    # and switched with one rename over it, so the path names the old or the
    # new file at every instant. ReplaceFile, its backup rename and the
    # restore copy are not used for a file that does not run.
    source, dest = tmp_path / "staged.exe", tmp_path / "defenseclaw-hook.exe"
    source.write_text("new", encoding="ascii")
    dest.write_text("old", encoding="ascii")
    script = f"""
$ErrorActionPreference = 'Stop'
$script:atomic = 0
function Remove-Aside([string]$Path) {{ throw "the destination was renamed away: $Path" }}
function Move-Path([string]$From, [string]$To) {{ throw "rename used: $From" }}
function Invoke-FileReplace([string]$New, [string]$Destination, [string]$Backup) {{ throw "ReplaceFile used" }}
function Invoke-AtomicReplace([string]$New, [string]$Destination) {{
    $script:atomic++
    if (-not (Test-Path -LiteralPath $Destination)) {{ throw "the destination was missing" }}
    [IO.File]::Move($New, $Destination, $true)
}}
{_ps_functions("Get-Sha256", "Install-File", "Publish-File", "Invoke-FileCopy", "New-VerifiedCopy", "Switch-InPlace")}
Install-File '{source}' '{dest}'
Write-Output "ATOMIC=$script:atomic"
"""
    completed = _run_powershell(script)
    out = completed.stdout + completed.stderr
    assert completed.returncode == 0, out
    assert "ATOMIC=1" in out, out
    assert dest.read_text(encoding="ascii") == "new"
    assert sorted(path.name for path in tmp_path.iterdir()) == ["defenseclaw-hook.exe", "staged.exe"]


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
def test_a_running_launcher_that_refuses_the_rename_is_swapped_by_replacefile(tmp_path: Path) -> None:
    # A launcher a hook runs from refuses a rename over it (access denied,
    # nothing changes). The swap then takes ReplaceFile, and every attempt
    # finds the old launcher at the path.
    source, dest = tmp_path / "staged.exe", tmp_path / "defenseclaw-hook.exe"
    source.write_text("new", encoding="ascii")
    dest.write_text("old", encoding="ascii")
    script = f"""
$ErrorActionPreference = 'Stop'
$script:atomic = 0
$script:missing = 0
function Start-Sleep {{ }}
function Invoke-AtomicReplace([string]$New, [string]$Destination) {{
    $script:atomic++
    if (-not (Test-Path -LiteralPath $Destination)) {{ $script:missing++ }}
    throw "Access is denied."
}}
{_ps_functions("Get-Sha256", "Install-File", "Publish-File", "Invoke-FileReplace", "Invoke-FileCopy", "New-VerifiedCopy", "Switch-InPlace")}
Install-File '{source}' '{dest}'
Write-Output "ATOMIC=$script:atomic MISSING=$script:missing"
"""
    completed = _run_powershell(script)
    out = completed.stdout + completed.stderr
    assert completed.returncode == 0, out
    assert "ATOMIC=1 MISSING=0" in out, out
    assert dest.read_text(encoding="ascii") == "new"
    assert sorted(path.name for path in tmp_path.iterdir()) == ["defenseclaw-hook.exe", "staged.exe"]


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
def test_a_copy_that_is_not_whole_is_never_switched_in(tmp_path: Path) -> None:
    # 1.0.4 lead directive: the old launcher stays until the new one is
    # verified. A staged copy that does not match the source (cut short by a
    # full disk or a scanner) is removed and nothing is switched.
    source, dest = tmp_path / "staged.exe", tmp_path / "defenseclaw-hook.exe"
    source.write_text("new launcher", encoding="ascii")
    dest.write_text("old", encoding="ascii")
    script = f"""
$ErrorActionPreference = 'Stop'
$script:switches = 0
function Copy-Item {{ param([string]$LiteralPath, [string]$Destination, [switch]$Force) [IO.File]::WriteAllText($Destination, "new") }}
function Invoke-AtomicReplace([string]$New, [string]$Destination) {{ $script:switches++; throw "switched" }}
function Invoke-FileReplace([string]$New, [string]$Destination, [string]$Backup) {{ $script:switches++; throw "switched" }}
function Remove-Aside([string]$Path) {{ $script:switches++; throw "switched" }}
function Move-Path([string]$From, [string]$To) {{ $script:switches++; throw "switched" }}
{_ps_functions("Get-Sha256", "Install-File", "Publish-File", "Invoke-FileCopy", "New-VerifiedCopy", "Switch-InPlace")}
try {{ Install-File '{source}' '{dest}'; Write-Output 'INSTALLED' }} catch {{ Write-Output "FAILED: $($_.Exception.Message)" }}
Write-Output "SWITCHES=$script:switches"
"""
    completed = _run_powershell(script)
    out = completed.stdout + completed.stderr
    assert completed.returncode == 0, out
    assert "FAILED: The copy of" in out and "was left as it was" in out, out
    assert "SWITCHES=0" in out, out
    assert dest.read_text(encoding="ascii") == "old"
    assert sorted(path.name for path in tmp_path.iterdir()) == ["defenseclaw-hook.exe", "staged.exe"]


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
def test_a_held_file_fails_the_install_and_keeps_the_launcher(tmp_path: Path) -> None:
    # 1.0.4 review of GAP-0004: while a running hook or a scanner holds the
    # file, every hook call that arrives during the retries still finds the
    # installed launcher, and when the hold never ends the install fails
    # instead of renaming the launcher aside.
    source, dest = tmp_path / "staged.exe", tmp_path / "defenseclaw-hook.exe"
    source.write_text("new", encoding="ascii")
    dest.write_text("old", encoding="ascii")
    script = f"""
$ErrorActionPreference = 'Stop'
$script:calls = 0
$script:missing = 0
function Start-Sleep {{ }}
function Remove-Aside([string]$Path) {{ throw "the destination was renamed away: $Path" }}
function Move-Path([string]$From, [string]$To) {{ throw "rename used: $From" }}
{_ps_functions("Get-Sha256", "Install-File", "Publish-File", "Invoke-FileCopy", "New-VerifiedCopy", "Switch-InPlace")}
function Invoke-FileReplace([string]$New, [string]$Destination, [string]$Backup) {{
    $script:calls++
    if (-not (Test-Path -LiteralPath $Destination)) {{ $script:missing++ }}
    throw "The process cannot access the file because it is being used by another process."
}}
try {{ Install-File '{source}' '{dest}'; Write-Output 'INSTALLED' }} catch {{ Write-Output "FAILED: $($_.Exception.Message)" }}
Write-Output "CALLS=$script:calls MISSING=$script:missing"
"""
    completed = _run_powershell(script)
    out = completed.stdout + completed.stderr
    assert completed.returncode == 0, out
    assert "FAILED: Could not replace" in out and "it was left as it was" in out, out
    assert "MISSING=0" in out and "CALLS=21" in out, out
    assert dest.read_text(encoding="ascii") == "old"
    assert sorted(path.name for path in tmp_path.iterdir()) == ["defenseclaw-hook.exe", "staged.exe"]


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
def test_a_replace_that_stops_after_the_backup_rename_finishes_the_swap(tmp_path: Path) -> None:
    # ERROR_UNABLE_TO_MOVE_REPLACEMENT_2: ReplaceFile renamed the old file to
    # the backup and did not move the new one in. The swap is finished at once.
    source, dest = tmp_path / "staged.exe", tmp_path / "defenseclaw-hook.exe"
    source.write_text("new", encoding="ascii")
    dest.write_text("old", encoding="ascii")
    script = f"""
$ErrorActionPreference = 'Stop'
function Start-Sleep {{ }}
{_ps_functions("Get-Sha256", "Move-Path", "Install-File", "Publish-File", "Switch-InPlace", "Invoke-FileMove", "Invoke-FileCopy", "New-VerifiedCopy", "Close-SwapGap")}
function Invoke-FileReplace([string]$New, [string]$Destination, [string]$Backup) {{
    [IO.File]::Move($Destination, $Backup)
    throw "Unable to move the replacement file to the file to be replaced."
}}
Install-File '{source}' '{dest}'
"""
    completed = _run_powershell(script)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert dest.read_text(encoding="ascii") == "new"
    assert sorted(path.name for path in tmp_path.iterdir()) == ["defenseclaw-hook.exe", "staged.exe"]


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
@pytest.mark.parametrize("held_moves", [3, 1000])
def test_a_partial_replace_with_a_held_replacement_puts_the_launcher_back_at_once(tmp_path: Path, held_moves: int) -> None:
    # 1.0.4 review: ReplaceFile renamed the installed launcher to the backup
    # (error 1177) while a scanner held the new copy. The old launcher goes
    # back before any wait, so every hook call during the retries finds it;
    # the swap then finishes when the hold ends, or the install fails with the
    # old launcher in place.
    source, dest = tmp_path / "staged.exe", tmp_path / "defenseclaw-hook.exe"
    source.write_text("new", encoding="ascii")
    dest.write_text("old", encoding="ascii")
    script = f"""
$ErrorActionPreference = 'Stop'
$script:replaces = 0
$script:heldMoves = 0
$script:missingAtWait = 0
$script:waits = 0
function Start-Sleep {{ $script:waits++; if (-not (Test-Path -LiteralPath '{dest}')) {{ $script:missingAtWait++ }} }}
function Remove-Aside([string]$Path) {{ throw "the destination was renamed away: $Path" }}
function Move-Path([string]$From, [string]$To) {{ throw "a retried rename was used: $From" }}
{_ps_functions("Get-Sha256", "Install-File", "Publish-File", "Invoke-FileCopy", "New-VerifiedCopy", "Switch-InPlace", "Close-SwapGap")}
function Invoke-FileReplace([string]$New, [string]$Destination, [string]$Backup) {{
    $script:replaces++
    if ($script:heldMoves -lt {held_moves}) {{
        [IO.File]::Move($Destination, $Backup)
        throw "Unable to move the replacement file to the file to be replaced."
    }}
    [IO.File]::Replace($New, $Destination, $Backup, $true)
}}
function Invoke-FileMove([string]$From, [string]$To) {{
    if ($From.EndsWith('.new') -and $script:heldMoves -lt {held_moves}) {{
        $script:heldMoves++
        throw "The process cannot access the file because it is being used by another process."
    }}
    [IO.File]::Move($From, $To)
}}
try {{ Install-File '{source}' '{dest}'; Write-Output 'INSTALLED' }} catch {{ Write-Output "FAILED: $($_.Exception.Message)" }}
Write-Output "REPLACES=$script:replaces WAITS=$script:waits MISSING_AT_WAIT=$script:missingAtWait"
"""
    completed = _run_powershell(script)
    out = completed.stdout + completed.stderr
    assert completed.returncode == 0, out
    assert "MISSING_AT_WAIT=0" in out and "WAITS=0 " not in out, out
    if held_moves == 3:
        assert "INSTALLED" in out, out
        assert dest.read_text(encoding="ascii") == "new"
        assert sorted(path.name for path in tmp_path.iterdir()) == ["defenseclaw-hook.exe", "staged.exe"]
    else:
        assert "FAILED: Could not replace" in out and "it was left as it was" in out, out
        assert dest.read_text(encoding="ascii") == "old"
        assert sorted(path.name for path in tmp_path.iterdir()) == ["defenseclaw-hook.exe", "staged.exe"]


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
@pytest.mark.parametrize("held_replaces", [3, 1000])
@pytest.mark.parametrize("refused", ["new+backup", "new+backup+restore"])
def test_a_partial_replace_with_the_new_file_and_the_backup_held_puts_the_launcher_back_at_once(
    tmp_path: Path, held_replaces: int, refused: str
) -> None:
    # 1.0.4 review (loop round 2): ReplaceFile renamed the installed launcher
    # to the backup (error 1177) and a scanner then held both the staged new
    # file and the backup against a rename, for the whole recovery. The
    # launcher must still be back before any wait: Close-SwapGap publishes the
    # independent restore copy, or copies the old file in when the restore
    # copy is held as well. Every ReplaceFile retry then runs with the
    # launcher in place.
    source, dest = tmp_path / "staged.exe", tmp_path / "defenseclaw-hook.exe"
    source.write_text("new", encoding="ascii")
    dest.write_text("old", encoding="ascii")
    restore_clause = " -or $From.EndsWith('.restore')" if refused.endswith("+restore") else ""
    script = f"""
$ErrorActionPreference = 'Stop'
$script:replaces = 0
$script:refused = 0
$script:copiesIn = 0
$script:waits = 0
$script:missingAtWait = 0
$script:missingAtReplace = 0
function Start-Sleep {{ $script:waits++; if (-not (Test-Path -LiteralPath '{dest}')) {{ $script:missingAtWait++ }} }}
function Remove-Aside([string]$Path) {{ throw "the destination was renamed away: $Path" }}
function Move-Path([string]$From, [string]$To) {{ throw "a retried rename was used: $From" }}
{_ps_functions("Get-Sha256", "Install-File", "Publish-File", "New-VerifiedCopy", "Switch-InPlace", "Close-SwapGap")}
function Invoke-FileReplace([string]$New, [string]$Destination, [string]$Backup) {{
    $script:replaces++
    if (-not (Test-Path -LiteralPath $Destination)) {{ $script:missingAtReplace++ }}
    if ($script:replaces -le {held_replaces}) {{
        # A held backup cannot be replaced: ReplaceFile fails before it
        # touches the installed file.
        if (Test-Path -LiteralPath $Backup) {{ throw "The process cannot access the file because it is being used by another process." }}
        [IO.File]::Move($Destination, $Backup)
        throw "Unable to move the replacement file to the file to be replaced."
    }}
    # The scanner let go.
    [IO.File]::Delete($Backup)
    [IO.File]::Replace($New, $Destination, $Backup, $true)
}}
function Invoke-FileMove([string]$From, [string]$To) {{
    if ($script:replaces -le {held_replaces} -and ($From.EndsWith('.new') -or $From -match '\\.old-[0-9T]+$'{restore_clause})) {{
        $script:refused++
        throw "The process cannot access the file because it is being used by another process."
    }}
    [IO.File]::Move($From, $To)
}}
function Invoke-FileCopy([string]$From, [string]$To) {{
    if ($To -eq '{dest}') {{ $script:copiesToDest++ }}
    if ($To -match '\\.ready[0-9]+$') {{ $script:copiesReady++ }}
    [IO.File]::Copy($From, $To, $false)
}}
$script:copiesToDest = 0
$script:copiesReady = 0
try {{ Install-File '{source}' '{dest}'; Write-Output 'INSTALLED' }} catch {{ Write-Output "FAILED: $($_.Exception.Message)" }}
Write-Output "REPLACES=$script:replaces REFUSED=$script:refused COPIES_READY=$script:copiesReady COPIES_TO_DEST=$script:copiesToDest WAITS=$script:waits"
Write-Output "MISSING_AT_WAIT=$script:missingAtWait MISSING_AT_REPLACE=$script:missingAtReplace"
"""
    completed = _run_powershell(script)
    out = completed.stdout + completed.stderr
    assert completed.returncode == 0, out
    assert "MISSING_AT_WAIT=0 MISSING_AT_REPLACE=0" in out and "WAITS=0 " not in out, out
    refused_moves = 3 if refused.endswith("+restore") else 2
    assert f"REFUSED={refused_moves} " in out, out
    # The old file is copied to a ready file and renamed in, never copied
    # into the live path (loop round 3).
    assert ("COPIES_READY=1 " if refused.endswith("+restore") else "COPIES_READY=0 ") in out, out
    assert "COPIES_TO_DEST=0 " in out, out
    if held_replaces == 3:
        assert "INSTALLED" in out, out
        assert dest.read_text(encoding="ascii") == "new"
    else:
        assert "FAILED: Could not replace" in out and "it was left as it was" in out, out
        assert dest.read_text(encoding="ascii") == "old"
    assert sorted(path.name for path in tmp_path.iterdir()) == ["defenseclaw-hook.exe", "staged.exe"]


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
@pytest.mark.parametrize("failed_copies", [1, 1000])
def test_a_slow_or_failing_recovery_copy_never_exposes_a_partial_launcher(tmp_path: Path, failed_copies: int) -> None:
    # 1.0.4 review (loop round 3): with the new file, the backup and the
    # restore copy all held against a rename, Close-SwapGap copied the old
    # file straight into the live defenseclaw-hook.exe path. A hook bridge
    # call during that slow copy ran an incomplete launcher, and a copy that
    # failed halfway left a partial file there that counted as restored, so
    # the backup and the restore copy (the only whole old launcher) were
    # deleted. The copy now goes to a ready file, is checked, and is renamed
    # in; a hook bridge call between every chunk written sees the whole old
    # launcher, the whole new one or nothing, never part of one.
    source, dest = tmp_path / "staged.exe", tmp_path / "defenseclaw-hook.exe"
    old_body = "MZ-old-launcher-" * 64
    new_body = "MZ-new-launcher-" * 64
    source.write_text(new_body, encoding="ascii")
    dest.write_text(old_body, encoding="ascii")
    held_replaces = 3 if failed_copies == 1 else 1000
    script = f"""
$ErrorActionPreference = 'Stop'
$script:replaces = 0
$script:failedCopies = 0
$script:bridgeCalls = 0
$script:bridgePartial = 0
$script:waits = 0
$script:missingAtWait = 0
function Invoke-Bridge {{
    # A hook the agent starts now: it opens and reads the launcher.
    $script:bridgeCalls++
    if (-not (Test-Path -LiteralPath '{dest}')) {{ return }}
    $stream = [IO.File]::Open('{dest}', 'Open', 'Read', 'ReadWrite, Delete')
    try {{ $text = (New-Object IO.StreamReader($stream)).ReadToEnd() }} finally {{ $stream.Dispose() }}
    if ($text -cne '{old_body}' -and $text -cne '{new_body}') {{ $script:bridgePartial++ }}
}}
function Start-Sleep {{ $script:waits++; Invoke-Bridge; if (-not (Test-Path -LiteralPath '{dest}')) {{ $script:missingAtWait++ }} }}
function Remove-Aside([string]$Path) {{ throw "the destination was renamed away: $Path" }}
function Move-Path([string]$From, [string]$To) {{ throw "a retried rename was used: $From" }}
{_ps_functions("Get-Sha256", "Install-File", "Publish-File", "New-VerifiedCopy", "Switch-InPlace", "Close-SwapGap")}
function Invoke-FileReplace([string]$New, [string]$Destination, [string]$Backup) {{
    $script:replaces++
    Invoke-Bridge
    if ($script:replaces -le {held_replaces}) {{
        if (Test-Path -LiteralPath $Backup) {{ throw "The process cannot access the file because it is being used by another process." }}
        [IO.File]::Move($Destination, $Backup)
        throw "Unable to move the replacement file to the file to be replaced."
    }}
    [IO.File]::Delete($Backup)
    [IO.File]::Replace($New, $Destination, $Backup, $true)
}}
function Invoke-FileMove([string]$From, [string]$To) {{
    Invoke-Bridge
    if ($script:replaces -le {held_replaces} -and ($From.EndsWith('.new') -or $From.EndsWith('.restore') -or $From -match '\\.old-[0-9T]+$')) {{
        throw "The process cannot access the file because it is being used by another process."
    }}
    [IO.File]::Move($From, $To)
}}
function Invoke-FileCopy([string]$From, [string]$To) {{
    # A slow copy, 128 bytes at a time, with a hook bridge call after each
    # chunk; a recovery copy (not the restore copy made before the swap)
    # fails halfway the first {failed_copies} time(s).
    $bytes = [IO.File]::ReadAllBytes($From)
    $failing = -not $To.EndsWith('.restore') -and $script:failedCopies -lt {failed_copies}
    $stream = [IO.File]::Open($To, 'CreateNew', 'Write', 'ReadWrite, Delete')
    try {{
        for ($i = 0; $i -lt $bytes.Length; $i += 128) {{
            $stream.Write($bytes, $i, [Math]::Min(128, $bytes.Length - $i))
            $stream.Flush()
            $stream.Dispose(); $stream = [IO.File]::Open($To, 'Append', 'Write', 'ReadWrite, Delete')
            Invoke-Bridge
            if ($failing -and $i -ge $bytes.Length / 2) {{
                $script:failedCopies++
                throw "The specified network name is no longer available."
            }}
        }}
    }} finally {{ $stream.Dispose() }}
}}
try {{ Install-File '{source}' '{dest}'; Write-Output 'INSTALLED' }} catch {{ Write-Output "FAILED: $($_.Exception.Message)" }}
Write-Output "BRIDGE_CALLS=$script:bridgeCalls BRIDGE_PARTIAL=$script:bridgePartial FAILED_COPIES=$script:failedCopies"
Write-Output "WAITS=$script:waits MISSING_AT_WAIT=$script:missingAtWait"
"""
    completed = _run_powershell(script)
    out = completed.stdout + completed.stderr
    assert completed.returncode == 0, out
    assert "BRIDGE_PARTIAL=0 " in out and "BRIDGE_CALLS=0 " not in out, out
    leftovers = sorted(path.name for path in tmp_path.iterdir())
    if failed_copies == 1:
        # The second copy is whole: the old launcher is back before any wait,
        # and the swap finishes when the hold ends.
        assert "FAILED_COPIES=1\n" in out and "MISSING_AT_WAIT=0" in out, out
        assert "INSTALLED" in out, out
        assert dest.read_text(encoding="ascii") == new_body
        assert leftovers == ["defenseclaw-hook.exe", "staged.exe"], leftovers
    else:
        # No copy ever completes: the install fails, nothing partial is at the
        # launcher path, and the backup and the restore copy are kept whole.
        assert "FAILED: Could not put" in out, out
        assert not dest.exists()
        assert not [name for name in leftovers if ".ready" in name], leftovers
        kept = [tmp_path / name for name in leftovers if name.startswith("defenseclaw-hook.exe.old-")]
        assert len(kept) == 2 and any(path.name.endswith(".restore") for path in kept), leftovers
        assert all(path.read_text(encoding="ascii") == old_body for path in kept)
