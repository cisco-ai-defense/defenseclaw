// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// GAP-1491: a glob operand or loop item that expanded to more than 64 matches
// was skipped before the registered-file check, with no signal, so a write
// to every file of a folder that holds a registered hook config was no
// registration write. Every match up to maxRegistrationGlobMatches is judged
// now, and past it the reading is truncated (bounded.Items).
func TestGAP1491RegistrationGlobPastSixtyFourMatches(t *testing.T) {
	home := t.TempDir()
	folder := filepath.Join(home, ".claude")
	registered := filepath.Join(folder, "settings.json")
	if err := os.MkdirAll(folder, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{registered} {
		if err := os.WriteFile(name, []byte("{}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for index := 0; index < 70; index++ {
		if err := os.WriteFile(filepath.Join(folder, fmt.Sprintf("a%02d.json", index)), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	wide := filepath.Join(home, "wide")
	if err := os.MkdirAll(wide, 0o755); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 1100; index++ {
		if err := os.WriteFile(filepath.Join(wide, fmt.Sprintf("w%04d", index)), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, row := range []struct {
		command            string
		reached, truncated bool
	}{
		{"rm -f " + folder + "/*.json", true, false},
		{"for f in " + folder + "/*.json; do rm -f \"$f\"; done", true, false},
		{"rm -f " + folder + "/a0*.json", false, false},
		{"rm -f " + wide + "/w*", false, true},
	} {
		reached, truncated := RegistrationWriteReachedBounded(row.command, home, home, []string{registered})
		if got := len(reached) != 0; got != row.reached {
			t.Errorf("%q: reached %q, want reached=%v", row.command, reached, row.reached)
		}
		if got := truncated.Any(); got != row.truncated && !row.reached {
			t.Errorf("%q: truncated %q, want truncated=%v", row.command, truncated.Reason(), row.truncated)
		}
	}
}
