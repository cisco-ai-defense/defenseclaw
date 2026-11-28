// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// A junction out of an OpenClaw root leaves the root as a symbolic link does,
// and a standard user makes one without any privilege, so the plugin
// credential may not scan through it (rel-1-0-10:GAP-2182). A junction that
// stays inside the root is still inside.
func TestOpenClawPathUnderAnyRefusesAJunctionOutOfTheRoot(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "oc-home")
	other := filepath.Join(root, "dc-data")
	for _, d := range []string{filepath.Join(home, "skills", "s1"), filepath.Join(other, "sub")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	escape := filepath.Join(home, "skills", "escape")
	twin := filepath.Join(home, "skills", "twin")
	makeGAP2182Junction(t, escape, other)
	makeGAP2182Junction(t, twin, filepath.Join(home, "skills", "s1"))
	roots := []string{home}
	for p, want := range map[string]bool{
		escape:                              false,
		filepath.Join(escape, "sub"):        false,
		twin:                                true,
		filepath.Join(home, "skills", "s1"): true,
	} {
		if got := openClawPathUnderAny(p, roots); got != want {
			t.Errorf("openClawPathUnderAny(%q) = %v, want %v", p, got, want)
		}
	}
}

func makeGAP2182Junction(t *testing.T, link, target string) {
	t.Helper()
	if out, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J %s %s: %v: %s", link, target, err, out)
	}
}
