// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookruntime

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// installerTrampolineHarness runs scripts/install.ps1's own
// Publish-SetupLauncherTrampoline, with its real file protection, against a
// stable runtime the test publishes as Setup does.
const installerTrampolineHarness = `
param([string]$Installer, [string]$Template, [string]$Hook, [string]$Gateway, [string]$State, [string]$Delegated, [string]$Bin, [string]$Data)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($Installer, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) { throw "install.ps1 parse failed: $($errors[0].Message)" }
foreach ($name in @('Get-Field', 'Read-Json', 'Protect-SetupLauncherFile', 'Publish-SetupLauncherTrampoline')) {
    $definition = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name }, $true)
    if ($null -eq $definition) { throw "install.ps1 has no $name" }
    . ([ScriptBlock]::Create($definition.Extent.Text))
}
$SetupHookState = $State
$SetupDelegatedHooks = $Delegated
$BinDir = $Bin
$DataDir = $Data
if (-not (Publish-SetupLauncherTrampoline $Template $Hook $Gateway)) { throw 'the installer did not point the launcher at its hook' }
`

// GAP-1000: install.ps1 points DefenseClaw Setup 0.8.10's stable launcher
// at a private copy of this release's hook, so an agent session that cached
// the launcher's path keeps being checked after the upgrade. The launcher
// trusts only state and a hook that pass its own checks (readTrustedAt,
// LockVerifiedHook: current-user ownership, a private DACL, the digests):
// the installer's state must pass them on Windows as written.
func TestInstallerPointsSetupsLauncherAtAPrivateCopyOfItsHook(t *testing.T) {
	shell, err := exec.LookPath("powershell.exe")
	if err != nil {
		if shell, err = exec.LookPath("pwsh.exe"); err != nil {
			t.Skip("no PowerShell")
		}
	}
	paths := testRuntimePaths(t)
	launcher := writeRuntimeSource(t, "MZ-0.8.10-trampoline-launcher")
	setupHook := filepath.Join(t.TempDir(), LauncherName)
	if err := os.WriteFile(setupHook, []byte("MZ-0.8.10-full-hook"), 0o700); err != nil {
		t.Fatal(err)
	}
	dataRoot := filepath.Join(t.TempDir(), "data")
	if err := publishAt(paths, launcher, setupHook, writeRuntimeGateway(t, "MZ-0.8.10-gateway"), dataRoot, stableRuntimeTransactionOne); err != nil {
		t.Fatalf("Setup publish: %v", err)
	}
	// The installer sets Setup's state aside (Disable-SetupHooks).
	template := filepath.Join(t.TempDir(), StateName)
	if err := os.Rename(paths.State, template); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	hook := filepath.Join(bin, LauncherName)
	if err := os.WriteFile(hook, []byte("MZ-1.0.4-hook"), 0o700); err != nil {
		t.Fatal(err)
	}
	gateway := filepath.Join(bin, GatewayName)
	if err := os.WriteFile(gateway, []byte("MZ-1.0.4-gateway"), 0o700); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(t.TempDir(), "trampoline.ps1")
	if err := os.WriteFile(script, []byte(installerTrampolineHarness), 0o600); err != nil {
		t.Fatal(err)
	}
	installer, err := filepath.Abs(filepath.Join("..", "..", "scripts", "install.ps1"))
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(shell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script,
		"-Installer", installer, "-Template", template, "-Hook", hook, "-Gateway", gateway,
		"-State", paths.State, "-Delegated", filepath.Join(paths.Root, "delegated"), "-Bin", bin, "-Data", dataRoot).CombinedOutput()
	if err != nil {
		t.Fatalf("installer publish: %v\n%s", err, out)
	}

	state, recognized, err := readTrustedAt(paths, paths.Launcher)
	if err != nil || !recognized {
		t.Fatalf("the launcher does not trust the installer's state: recognized=%v err=%v", recognized, err)
	}
	if !state.Active() || !state.DelegationCapable() || state.LauncherKind != LauncherKindTrampoline {
		t.Fatalf("state %+v is not an active trampoline", state)
	}
	locked, err := LockVerifiedHook(state)
	if err != nil {
		t.Fatalf("the launcher does not trust the installer's hook copy: %v", err)
	}
	defer locked.Close()
	body, err := io.ReadAll(locked)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, []byte("MZ-1.0.4-hook")) {
		t.Fatalf("the launcher delegates to %q, want this release's hook", body)
	}
	if filepath.Dir(filepath.Dir(state.HookPath)) != filepath.Join(paths.Root, "delegated") {
		t.Fatalf("hook copy %s is not under the runtime's delegated folder", state.HookPath)
	}
}
