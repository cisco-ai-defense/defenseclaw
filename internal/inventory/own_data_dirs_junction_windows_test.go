// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package inventory

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A data folder reached through a junction is DefenseClaw's own folder where
// the junction leads, as it is through a symbolic link, so the discovery
// walks never descend into it (rel-1-0-10:GAP-2182).
func TestOwnDataDirsFollowAJunction(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real-data")
	if err := os.MkdirAll(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "data-link")
	if out, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", link, real).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v: %s", err, out)
	}
	want, err := filepath.EvalSymlinks(real)
	if err != nil {
		t.Fatal(err)
	}
	s := &ContinuousDiscoveryService{opts: AIDiscoveryOptions{DataDir: link}}
	dirs := s.ownDataDirs()
	for _, dir := range dirs {
		if strings.EqualFold(dir, want) {
			return
		}
	}
	t.Fatalf("ownDataDirs() = %q, want it to hold the junction target %q", dirs, want)
}
