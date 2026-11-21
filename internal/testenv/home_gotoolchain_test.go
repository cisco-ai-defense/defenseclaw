// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package testenv

import (
	"os"
	"path/filepath"
	"testing"
)

// rel-1-0-10:GAP-0167: a moved home keeps the go command's caches where they
// were, so a test that builds a helper after IsolateAccount neither downloads
// every module into its temp home nor fails to remove it; a value that is
// already set stays.
func TestSetHomeKeepsTheGoToolchainCaches(t *testing.T) {
	for _, name := range []string{"GOPATH", "GOMODCACHE", "GOCACHE", "GOENV"} {
		t.Setenv(name, "")
		if err := os.Unsetenv(name); err != nil {
			t.Fatal(err)
		}
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		t.Skip("no home to keep")
	}
	cache, cacheErr := os.UserCacheDir()
	config, configErr := os.UserConfigDir()
	if cacheErr != nil || configErr != nil {
		t.Skip("no user cache or config folder")
	}
	IsolateAccount(t)
	for name, want := range map[string]string{
		"GOPATH":     filepath.Join(home, "go"),
		"GOMODCACHE": filepath.Join(home, "go", "pkg", "mod"),
		"GOCACHE":    filepath.Join(cache, "go-build"),
		"GOENV":      filepath.Join(config, "go", "env"),
	} {
		if got := os.Getenv(name); got != want {
			t.Errorf("%s = %q after the home moved, want %q", name, got, want)
		}
	}

	t.Run("set values stay", func(t *testing.T) {
		t.Setenv("GOMODCACHE", filepath.Join(t.TempDir(), "mod"))
		want := os.Getenv("GOMODCACHE")
		SetHome(t, t.TempDir())
		if got := os.Getenv("GOMODCACHE"); got != want {
			t.Errorf("GOMODCACHE = %q, want the value set before, %q", got, want)
		}
	})
}
