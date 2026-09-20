// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnsureCodexConfigDirWindowsCreatesTrustedMissingDirectory(t *testing.T) {
	configDir := filepath.Join(t.TempDir(), "missing", ".codex")
	if err := ensureCodexConfigDir(configDir); err != nil {
		t.Fatalf("ensureCodexConfigDir: %v", err)
	}
	if err := hookAPIValidateDirectory(configDir); err != nil {
		t.Fatalf("created Codex configuration directory is not trusted: %v", err)
	}
}

func TestEnsureCodexConfigDirWindowsRejectsReparseParent(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(root, "outside")
	if err := os.Mkdir(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	junction := filepath.Join(root, "codex-home")
	output, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", junction, outside).CombinedOutput()
	if err != nil {
		t.Skipf("junction creation unavailable: %v (%s)", err, output)
	}
	defer os.Remove(junction)

	err = ensureCodexConfigDir(filepath.Join(junction, ".codex"))
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "reparse") {
		t.Fatalf("ensureCodexConfigDir through junction error = %v, want reparse-point rejection", err)
	}
	if _, statErr := os.Stat(filepath.Join(outside, ".codex")); !os.IsNotExist(statErr) {
		t.Fatalf("Codex directory escaped through junction: %v", statErr)
	}
}
