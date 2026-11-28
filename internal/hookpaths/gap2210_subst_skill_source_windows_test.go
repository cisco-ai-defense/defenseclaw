// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookpaths

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
)

// rel-1-0-10:GAP-2210: an explicit Skill source that names the project skill
// root through a subst drive letter selects the root, as the root's own
// spelling does. pathEvalSymlinks keeps the drive letter, so the source is
// also compared with the root by their real final paths.
func TestGAP2210SkillSourceThroughASubstDriveSelectsTheRoot(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "project")
	root := filepath.Join(project, ".claude", "skills")
	if err := os.MkdirAll(filepath.Join(root, "sample"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "sample", "SKILL.md"), []byte("---\nname: sample\n---\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	letter := ""
	for c := 'Y'; c >= 'M' && letter == ""; c-- {
		if _, err := os.Lstat(string(c) + `:\`); err != nil {
			letter = string(c) + ":"
		}
	}
	if letter == "" {
		t.Fatal("no free drive letter between M: and Y:")
	}
	if out, err := exec.Command("subst.exe", letter, root).CombinedOutput(); err != nil {
		t.Fatalf("subst %s %s: %v: %s", letter, root, err, out)
	}
	t.Cleanup(func() { _ = exec.Command("subst.exe", letter, "/d").Run() })
	if !slices.Contains(projectSkillSourceFolders(root, "sample", root, home, project), root) {
		t.Fatal("the root's own spelling does not select the root")
	}
	if got := projectSkillSourceFolders(root, "sample", letter+`\`, home, project); !slices.Contains(got, root) {
		t.Errorf("source %s\\ (subst to the root) selects %v, want the root", letter, got)
	}
}
