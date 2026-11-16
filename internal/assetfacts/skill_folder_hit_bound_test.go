// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package assetfacts

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A call that names more paths into skill folders than maxSkillFolderHits is
// not read to its end: it is reported cut, so that the caller refuses it when
// a skill is held or denied. The reading stops at the bound, so the work does
// not grow with the call. A call below the bound is read whole and not cut.
func TestCallNamingMoreSkillFoldersThanTheBoundIsReportedCut(t *testing.T) {
	home, held, proj := operandTree(t, "lnk-held")
	root := filepath.Dir(held)
	if err := os.MkdirAll(filepath.Join(proj, "w4"), 0o755); err != nil {
		t.Fatal(err)
	}
	var slash, bare []string
	for i := 0; i < maxSkillFolderHits+50; i++ {
		dir := filepath.Join(root, fmt.Sprintf("ordinary%04d", i))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		name := fmt.Sprintf("l%04d", i)
		linkOrSkip(t, dir, filepath.Join(proj, "w4", name))
		linkOrSkip(t, dir, filepath.Join(proj, "b"+name))
		slash = append(slash, "w4/"+name)
		bare = append(bare, "b"+name)
	}
	call := func(names []string) ([]FolderRef, bool) {
		command := "ls -d " + strings.Join(names, " ") + " lnk-held"
		return SkillFolderRefsAndCut("Bash", map[string]any{"command": command}, home, proj, "", os.Geteuid(), os.Getegid(), false)
	}
	for name, names := range map[string][]string{"links by path": slash, "links by name": bare} {
		refs, cut := call(names)
		if !cut || len(refs) > maxSkillFolderHits+8 {
			t.Errorf("%s: cut = %t with %d folders, want cut and about %d", name, cut, len(refs), maxSkillFolderHits)
		}
	}
	for name, names := range map[string][]string{"links by path": slash[:12], "links by name": bare[:12]} {
		refs, cut := call(names)
		if cut || !reaches(refs, held) || len(refs) != 13 {
			t.Errorf("%s below the bound: cut = %t, %d folders, held reached = %t, want read whole", name, cut, len(refs), reaches(refs, held))
		}
	}
	// Any number of paths that lead nowhere near a skill folder is read.
	var plain []string
	for i := 0; i < 3*maxSkillFolderHits; i++ {
		plain = append(plain, fmt.Sprintf("src/file%04d.go", i))
	}
	if refs, cut := call(plain); cut || reaches(refs, held) != true {
		t.Errorf("ordinary paths: cut = %t, held reached = %t, want read whole", cut, reaches(refs, held))
	}
}
