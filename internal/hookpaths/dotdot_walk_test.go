// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestDotDotWalkUnresolvedReadings: a .. after a folder that does not exist
// yet keeps its lexical reading; a .. after a link loop and an operand past
// the walk bound are unknown (TRUNCATED); a walk that resolves is known
// (rel-1-0-10:GAP-1007).
func TestDotDotWalkUnresolvedReadings(t *testing.T) {
	root := t.TempDir()
	sep := string(filepath.Separator)
	if dotDotWalkUnresolved(root + sep + "missing" + sep + ".." + sep + "x") {
		t.Fatal("a missing folder before .. read as unknown")
	}
	if err := os.Mkdir(filepath.Join(root, "dir"), 0o700); err != nil {
		t.Fatal(err)
	}
	if dotDotWalkUnresolved(root + sep + "dir" + sep + ".." + sep + "x") {
		t.Fatal("a walk that resolves read as unknown")
	}
	deep := root + strings.Repeat(sep+"m", maxDotDotWalkParts+1)
	if !dotDotWalkUnresolved(deep + sep + ".." + sep + "x") {
		t.Fatal("an operand past the walk bound was not TRUNCATED")
	}
	if runtime.GOOS == "windows" {
		return // the junction loop is in the gateway test (mklink /J)
	}
	if err := os.Symlink("lp", filepath.Join(root, "lp")); err != nil {
		t.Fatal(err)
	}
	if !dotDotWalkUnresolved(root + sep + "lp" + sep + ".." + sep + "x") {
		t.Fatal("a .. after a link loop read as known")
	}
}
