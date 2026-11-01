// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"testing"
)

// GAP-1093: protectedReachFromText read a bare ~ token as home/~, so `cd ~
// && bash run.sh test` had no home reach while `cd ~/ && ...` had one.
func TestProtectedReachFromTextReadsABareTildeAsTheHome(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "proj")
	for _, command := range []string{"cd ~ && bash run.sh test", "cd ~/ && bash run.sh test", `cd "~" && x`} {
		if !protectedReachFromText(command, cwd, home) {
			t.Errorf("protectedReachFromText(%q) = false, want the home reach", command)
		}
	}
	if protectedReachFromText("cd build && bash run.sh test", cwd, home) {
		t.Error("a project directory is not a home reach")
	}
}
