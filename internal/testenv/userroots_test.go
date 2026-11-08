// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package testenv

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const rootProbe = "DC_TESTENV_USER_ROOT_PROBE"

func redirectProbe(runDir string) map[string]string {
	return map[string]string{rootProbe: filepath.Join(runDir, "root")}
}

func writeProbeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// A run that writes below a watched real folder is reported, naming the
// path; a run that leaves it alone is not (GAP-0887).
func TestIsolateUserRootsReportsChangesToTheWatchedRealFolder(t *testing.T) {
	watched := filepath.Join(t.TempDir(), "real", "devin")
	if err := os.MkdirAll(watched, 0o700); err != nil {
		t.Fatal(err)
	}
	existing := filepath.Join(watched, "config.json")
	extra := filepath.Join(watched, "extra.json")
	writeProbeFile(t, existing, "{}")
	t.Setenv(rootProbe, "original")

	finish, err := isolateUserRoots([]string{watched}, redirectProbe)
	if err != nil {
		t.Fatal(err)
	}
	if got := os.Getenv(rootProbe); got == "original" || !strings.Contains(got, "defenseclaw-user-roots-") {
		t.Fatalf("the root was not moved to a folder of the run: %q", got)
	}
	if err := finish(); err != nil {
		t.Fatalf("a run that left the real folder alone was reported: %v", err)
	}
	if got := os.Getenv(rootProbe); got != "original" {
		t.Fatalf("the root was not restored: %q", got)
	}

	for _, tc := range []struct {
		kind, path string
		leak       func()
	}{
		{"added", extra, func() { writeProbeFile(t, extra, "{}") }},
		{"changed", existing, func() { writeProbeFile(t, existing, `{"hooks":{"PreToolUse":[]}}`) }},
		{"removed", existing, func() {
			if err := os.Remove(existing); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		finish, err := isolateUserRoots([]string{watched}, redirectProbe)
		if err != nil {
			t.Fatal(err)
		}
		tc.leak()
		err = finish()
		if err == nil || !strings.Contains(err.Error(), tc.kind+" "+tc.path) {
			t.Fatalf("a %s file in the real folder was not reported: %v", tc.kind, err)
		}
		_ = os.Remove(extra)
		writeProbeFile(t, existing, "{}")
	}
}

// The run folder is removed with the run, so the redirected root leaves
// nothing behind.
func TestIsolateUserRootsRemovesItsRunFolder(t *testing.T) {
	finish, err := isolateUserRoots(nil, redirectProbe)
	if err != nil {
		t.Fatal(err)
	}
	moved := os.Getenv(rootProbe)
	if info, err := os.Stat(moved); err != nil || !info.IsDir() {
		t.Fatalf("the redirected root %q is not a folder: %v", moved, err)
	}
	if err := finish(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(moved); !os.IsNotExist(err) {
		t.Fatalf("the run folder %q was left behind: %v", moved, err)
	}
}
