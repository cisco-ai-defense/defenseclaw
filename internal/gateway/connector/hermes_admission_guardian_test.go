// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hermespath"
)

// A guardian acting for a target user (WithUserHomeDir) resolves the
// updater-managed Hermes image inside that profile and never launches it.
func TestHermesGuardianResolvesTargetImageWithoutLaunching(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Hermes executable admission is Windows-only")
	}
	home := t.TempDir()
	want := hermespath.ManagedExecutablePathForUserHome(home)
	if want == "" {
		t.Fatal("no managed executable path for a profile home")
	}
	err := WithUserHomeDir(home, func() error {
		if got := hermesManagedExecutablePath(); got != want {
			t.Fatalf("guardian path = %q, want %q", got, want)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	agent := filepath.Dir(filepath.Dir(filepath.Dir(want)))
	if err := os.MkdirAll(filepath.Dir(want), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(want, []byte("image"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := hermespath.InstalledVersionForManagedExecutable(want); err == nil {
		t.Fatal("missing install stamp produced a version")
	}
	if err := os.WriteFile(filepath.Join(agent, "install-stamp.json"), []byte(`{"baseVersion":"0.21.5"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := hermespath.InstalledVersionForManagedExecutable(want)
	if err != nil || got != "0.21.5" {
		t.Fatalf("installed version = %q, %v", got, err)
	}
	if _, err := hermespath.InstalledVersionForManagedExecutable(filepath.Join(home, "elsewhere", "hermes.exe")); err == nil {
		t.Fatal("an image outside the managed virtual environment produced a version")
	}
}
