// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestGAP1083WalkSlotSeamsAreCalledOnlyByTests is the census of the exports
// that exist only as test seams: HoldCredentialPathWalkSlotsForTest takes
// every walk slot, and CredentialWalkSlotWaitsForTest reads the count of the
// waits for one. A production caller that kept the slots would cut every walk
// to the unknown tier, so only _test.go files may call them, and they keep
// the ForTest name of the repo's other seams (RV-0674S F3, RV-0674T F1).
func TestGAP1083WalkSlotSeamsAreCalledOnlyByTests(t *testing.T) {
	for _, seam := range []string{"HoldCredentialPathWalkSlotsForTest", "CredentialWalkSlotWaitsForTest"} {
		t.Run(seam, func(t *testing.T) { walkSlotSeamIsCalledOnlyByTests(t, seam) })
	}
}

func walkSlotSeamIsCalledOnlyByTests(t *testing.T, seam string) {
	t.Helper()
	// Split, so this file does not name the old call itself.
	oldName := "HoldCredentialPathWalk" + "Slots("
	root := filepath.Join("..", "..")
	defined := false
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "vendor", "openwiki":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		text := string(body)
		if strings.Contains(text, oldName) {
			t.Errorf("%s uses HoldCredentialPathWalkSlots, which is %s now", path, seam)
		}
		if !strings.Contains(text, seam) || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		if filepath.Base(path) == "credential_path_reads.go" && filepath.Base(filepath.Dir(path)) == "actionfacts" {
			defined = strings.Contains(text, "func "+seam+"(")
			if strings.Count(text, seam+"(") > 1 {
				// The definition's own doc comment names it as "Name takes";
				// a call has the name followed by "(" outside "func ".
				for _, line := range strings.Split(text, "\n") {
					if strings.Contains(line, seam+"(") && !strings.HasPrefix(line, "func ") && !strings.HasPrefix(strings.TrimSpace(line), "//") {
						t.Errorf("%s calls %s in production code: %s", path, seam, strings.TrimSpace(line))
					}
				}
			}
			return nil
		}
		t.Errorf("%s is not a test file and names %s: only _test.go files may call it", path, seam)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !defined {
		t.Errorf("internal/actionfacts/credential_path_reads.go does not define %s", seam)
	}
}
