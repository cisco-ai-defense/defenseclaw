// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"os"
	"path/filepath"
	"testing"
)

// writeShellPostRecordForTest writes the .gateway-helper record setup leaves
// beside a per-user hook, naming home's ~/.local/bin gateway, and returns the
// hook folder. The shell native post runs only the recorded gateway and the
// hook-post helper beside it (GAP-1755).
func writeShellPostRecordForTest(t *testing.T, home string) string {
	t.Helper()
	hookDir := filepath.Join(home, ".defenseclaw", "hooks")
	if err := os.MkdirAll(hookDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{home, filepath.Join(home, ".defenseclaw"), hookDir} {
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	record := filepath.Join(home, ".local", "bin", "defenseclaw-gateway") + "\n"
	if err := os.WriteFile(filepath.Join(hookDir, ".gateway-helper"), []byte(record), 0o600); err != nil {
		t.Fatal(err)
	}
	return hookDir
}
