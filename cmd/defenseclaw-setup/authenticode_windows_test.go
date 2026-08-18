// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

func TestStableHookVerificationHandleDeniesWriteAndReplacement(t *testing.T) {
	root := t.TempDir()
	if err := safefile.ProtectDirectory(root); err != nil {
		t.Fatal(err)
	}
	filePath := filepath.Join(root, "defenseclaw-hook.exe")
	if err := os.WriteFile(filePath, unsignedTestPE(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := safefile.ProtectFile(filePath); err != nil {
		t.Fatal(err)
	}
	locked, err := openStableHookVerificationFile(filePath)
	if err != nil {
		t.Fatalf("openStableHookVerificationFile: %v", err)
	}
	defer locked.Close()

	if writable, err := os.OpenFile(filePath, os.O_WRONLY, 0); err == nil {
		_ = writable.Close()
		t.Fatal("stable hook verification handle allowed a concurrent writer")
	}
	if err := os.Rename(filePath, filePath+".replaced"); err == nil {
		t.Fatal("stable hook verification handle allowed path replacement")
	}
}

func TestStableHookSourceVerificationHandleAllowsInstalledACLAndDeniesMutation(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "defenseclaw-hook-launcher.exe")
	if err := os.WriteFile(filePath, unsignedTestPE(), 0o700); err != nil {
		t.Fatal(err)
	}
	locked, err := openStableHookSourceVerificationFile(filePath)
	if err != nil {
		t.Fatalf("openStableHookSourceVerificationFile: %v", err)
	}
	defer locked.Close()

	if writable, err := os.OpenFile(filePath, os.O_WRONLY, 0); err == nil {
		_ = writable.Close()
		t.Fatal("installed source verification handle allowed a concurrent writer")
	}
	if err := os.Rename(filePath, filePath+".replaced"); err == nil {
		t.Fatal("installed source verification handle allowed path replacement")
	}
}

func TestWindowsAuthenticodeTrustAcceptsSignedPEAndRejectsTamper(t *testing.T) {
	output, err := exec.Command(
		"pwsh.exe", "-NoProfile", "-NonInteractive", "-Command", "(Get-Process -Id $PID).Path",
	).Output()
	if err != nil {
		t.Skip("signed PowerShell 7 executable is unavailable")
	}
	signed := strings.TrimSpace(string(output))
	metadata, err := inspectEmbeddedAuthenticode(signed)
	if err != nil {
		t.Fatalf("inspect signed PowerShell: %v", err)
	}
	if !metadata.Present || !metadata.RFC3161TimestampPresent {
		t.Skip("available PowerShell executable is not embedded/RFC3161 Authenticode-signed")
	}
	if err := verifyEmbeddedAuthenticodeTrust(signed); err != nil {
		t.Fatalf("WinVerifyTrust rejected signed PowerShell: %v", err)
	}
	if err := verifySetupExecutablePolicyAt(signed, false); err == nil {
		t.Fatal("release Setup policy accepted a trusted non-Cisco executable")
	}

	data, err := os.ReadFile(signed)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) < 512 {
		t.Fatal("signed PowerShell fixture is unexpectedly small")
	}
	data[len(data)/2] ^= 0xff
	tampered := filepath.Join(t.TempDir(), "tampered-pwsh.exe")
	if err := os.WriteFile(tampered, data, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := verifyEmbeddedAuthenticodeTrust(tampered); err == nil {
		t.Fatal("WinVerifyTrust accepted a tampered signed executable")
	}
}

func TestUnsignedGoExecutableMatchesLocalSetupPolicy(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := inspectEmbeddedAuthenticode(executable)
	if err != nil {
		t.Fatalf("inspect Go test executable: %v", err)
	}
	if metadata.Present {
		t.Skip("Go test executable was unexpectedly signed by the environment")
	}
	if err := verifySetupExecutablePolicyAt(executable, true); err != nil {
		t.Fatalf("unsigned local setup policy rejected Go executable: %v", err)
	}
}
