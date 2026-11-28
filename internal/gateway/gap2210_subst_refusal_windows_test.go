// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// gap2210Subst maps a free drive letter to target for the test.
func gap2210Subst(t *testing.T, target string) string {
	t.Helper()
	for c := 'Y'; c >= 'M'; c-- {
		letter := string(c) + ":"
		if _, err := os.Lstat(letter + `\`); err == nil {
			continue
		}
		if out, err := exec.Command("subst.exe", letter, target).CombinedOutput(); err != nil {
			t.Fatalf("subst %s %s: %v: %s", letter, target, err, out)
		}
		t.Cleanup(func() { _ = exec.Command("subst.exe", letter, "/d").Run() })
		return letter
	}
	t.Fatal("no free drive letter between M: and Y:")
	return ""
}

// rel-1-0-10:GAP-2210: a refused project skill root is refused through a
// subst drive letter that maps into it. winpath.EvalLinks keeps the drive
// letter, which never compares under the C:-spelled refused root; the
// refusal also compares the real final path (winpath.FinalPath).
func TestGAP2210RefusedRootIsRefusedThroughASubstDrive(t *testing.T) {
	root := filepath.Join(t.TempDir(), "project", ".claude", "skills")
	if err := os.MkdirAll(filepath.Join(root, "sample"), 0o700); err != nil {
		t.Fatal(err)
	}
	var roots projectSkillRoots
	roots.refuse(root, "unverified for the test", time.Now())
	if got, _ := roots.refusalForPath(filepath.Join(root, "sample")); got == "" {
		t.Fatal("the refused root's own folder is not refused")
	}
	letter := gap2210Subst(t, root)
	for _, path := range []string{letter + `\sample`, letter + `\`} {
		if got, _ := roots.refusalForPath(path); got == "" {
			t.Errorf("%s (subst to the refused root) is not refused", path)
		}
	}
	elsewhere := t.TempDir()
	if got, _ := roots.refusalForPath(elsewhere); got != "" {
		t.Errorf("an unrelated folder is refused by %s", got)
	}
}
