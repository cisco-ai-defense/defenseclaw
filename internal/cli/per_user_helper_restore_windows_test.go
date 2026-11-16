// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// newWindowsRollForwardFixture is the state a 1.0.2 or 1.0.3 install.ps1
// roll-forward leaves (GAP-2525): the 1.0.5 gateway and installer folder are
// back, defenseclaw-hook-guard.exe beside the gateway is not.
func newWindowsRollForwardFixture(t *testing.T) (dataDir, gateway, recovery, target string, guard []byte) {
	t.Helper()
	root := t.TempDir()
	dataDir = filepath.Join(root, ".defenseclaw")
	binDir := filepath.Join(root, ".local", "bin")
	gateway = filepath.Join(binDir, "defenseclaw-gateway.exe")
	recovery = filepath.Join(dataDir, "installer", "defenseclaw-hook-guard.exe")
	target = filepath.Join(binDir, "defenseclaw-hook-guard.exe")
	guard = []byte("hook-guard 1.0.5 binary")
	gatewayData := []byte("gateway 1.0.5 binary")
	for _, dir := range []string{binDir, filepath.Dir(recovery)} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(gateway, gatewayData, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(recovery, guard, 0o700); err != nil {
		t.Fatal(err)
	}
	line := func(name string, data []byte) string {
		sum := sha256.Sum256(data)
		return hex.EncodeToString(sum[:]) + "  " + name + "\n"
	}
	record := line("defenseclaw-gateway.exe", gatewayData) + line("defenseclaw-hook-guard.exe", guard)
	if err := os.WriteFile(filepath.Join(dataDir, "installer", "binaries.sha256"), []byte(record), 0o600); err != nil {
		t.Fatal(err)
	}
	return dataDir, gateway, recovery, target, guard
}

func TestARollForwardByAnOlderWindowsReleaseGetsTheHookGuardBack(t *testing.T) {
	dataDir, gateway, _, target, guard := newWindowsRollForwardFixture(t)
	restored := restorePerUserInstallerHelpersFor(dataDir, gateway)
	if len(restored) != 1 || restored[0] != "defenseclaw-hook-guard.exe" {
		t.Fatalf("restored = %v, want [defenseclaw-hook-guard.exe]", restored)
	}
	got, err := os.ReadFile(target)
	if err != nil || !bytes.Equal(got, guard) {
		t.Fatalf("guard beside the gateway = %q, %v; want the recorded copy", got, err)
	}
	leftovers, _ := filepath.Glob(filepath.Join(filepath.Dir(target), ".defenseclaw-hook-guard.exe.restore-*"))
	if len(leftovers) != 0 {
		t.Fatalf("temporary files left: %v", leftovers)
	}
	if again := restorePerUserInstallerHelpersFor(dataDir, gateway); len(again) != 0 {
		t.Fatalf("second start restored %v again", again)
	}
}

func TestWindowsGuardRestoreRefusesAnInstallerFolderOtherAccountsCanWrite(t *testing.T) {
	dataDir, gateway, recovery, target, _ := newWindowsRollForwardFixture(t)
	// Everyone (S-1-1-0) may modify the installer folder and what it holds.
	out, err := exec.Command("icacls", filepath.Dir(recovery), "/grant", "*S-1-1-0:(OI)(CI)M", "/T").CombinedOutput()
	if err != nil {
		t.Fatalf("icacls: %v: %s", err, out)
	}
	if restored := restorePerUserInstallerHelpersFor(dataDir, gateway); len(restored) != 0 {
		t.Fatalf("restored %v from a folder other accounts can write", restored)
	}
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Fatalf("guard created from an unprotected copy: %v", err)
	}
}

func TestWindowsGuardRestoreNeedsTheRecordedGatewayAndCopy(t *testing.T) {
	t.Run("another gateway", func(t *testing.T) {
		dataDir, gateway, _, target, _ := newWindowsRollForwardFixture(t)
		if err := os.WriteFile(gateway, []byte("gateway 1.0.2 binary"), 0o755); err != nil {
			t.Fatal(err)
		}
		if restored := restorePerUserInstallerHelpersFor(dataDir, gateway); len(restored) != 0 {
			t.Fatalf("restored %v for a gateway the record does not name", restored)
		}
		if _, err := os.Lstat(target); !os.IsNotExist(err) {
			t.Fatalf("guard created: %v", err)
		}
	})
	t.Run("changed copy", func(t *testing.T) {
		dataDir, gateway, recovery, target, _ := newWindowsRollForwardFixture(t)
		if err := os.WriteFile(recovery, []byte("tampered"), 0o700); err != nil {
			t.Fatal(err)
		}
		if restored := restorePerUserInstallerHelpersFor(dataDir, gateway); len(restored) != 0 {
			t.Fatalf("restored %v from a copy that is not the recorded binary", restored)
		}
		if _, err := os.Lstat(target); !os.IsNotExist(err) {
			t.Fatalf("guard created: %v", err)
		}
	})
}
