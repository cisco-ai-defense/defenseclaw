//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package guardianstate

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func TestPathForDataDirNonWindowsPreservesFallback(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv(managed.WindowsServiceAccountEnv, `NT SERVICE\IgnoredWindowsPin`)
	t.Setenv(managed.HookGuardianAuthorizationDirEnv, filepath.Join(t.TempDir(), "hook-guardian-state"))
	stateDir := filepath.Join(dataDir, StateDirName)
	if err := os.Mkdir(stateDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := WriteState(PathForStateRoot(stateDir), StateReady); err != nil {
		t.Fatal(err)
	}
	if got := ReadState(PathForDataDir(dataDir)); got != StateReady {
		t.Fatalf("non-Windows fallback state = %q", got)
	}
}
