// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookpaths

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func makeProjectSkillJunction(t *testing.T, link, target string) {
	t.Helper()
	if out, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Fatalf("create junction: %v: %s", err, out)
	}
}

// A project folder that is a junction to a folder outside the profile is a
// root the profile does not hold, as a symbolic link to it is. Go leaves a
// junction unfollowed in filepath.EvalSymlinks and reports it as an irregular
// file, so both the kind of the root and its final place are read through the
// link (rel-1-0-9:GAP-0621).
func TestProjectSkillRootJunctionIsJudgedByItsFinalFolder(t *testing.T) {
	home := t.TempDir()
	outside := t.TempDir()
	inside := filepath.Join(home, "private-skills")
	for _, dir := range []string{filepath.Join(outside, "skills"), filepath.Join(inside, "skills")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	project := filepath.Join(home, "project")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	// The twin is judged on the profile boundary only: whether another
	// account can write a test folder depends on the runner volume.
	for name, tc := range map[string]struct {
		target  string
		outside bool
	}{
		"outside the profile":       {outside, true},
		"inside the profile (twin)": {inside, false},
	} {
		t.Run(name, func(t *testing.T) {
			link := filepath.Join(project, ".claude"+filepath.Base(tc.target))
			makeProjectSkillJunction(t, link, tc.target)
			for _, root := range []string{filepath.Join(link, "skills"), link} {
				got := inspectProjectSkillRoot(home, root)
				if (got == ProjectSkillRootOutsideProfile) != tc.outside {
					t.Errorf("junction %s to %s: finding %q, outside the profile = %v", root, tc.target, got, tc.outside)
				}
			}
		})
	}
}
