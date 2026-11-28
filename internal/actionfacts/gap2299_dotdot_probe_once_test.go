// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package actionfacts

import "testing"

// A dot-dot walk reads a folder only once it climbs from one the walk has
// not already proved plain: a folder that exists with no link in its path
// proves every folder above it, so find roots of three steps each cost one
// read, not three (rel-1-0-10:GAP-2299). The answers are unchanged.
func TestGAP2299DotDotWalkReadsAFolderAboveAPlainOneOnce(t *testing.T) {
	const root = "/h/proj"
	previous := operandPlainDirProbe
	t.Cleanup(func() { operandPlainDirProbe = previous })
	for _, row := range []struct {
		name, want string
		plain      bool
		reads      int
	}{
		{root + "/d0/e/../../d0/..", root, true, 1},
		{root + "/d0/e/../../../x", "/h/x", true, 1},
		{root + "/d0/../d1/e/..", root + "/d1", true, 2},
		{root + "/d0/e/../..", root + "/d0/e/../..", false, 1},
	} {
		var asked []string
		operandPlainDirProbe = func(dir string) bool {
			asked = append(asked, dir)
			return row.plain
		}
		if got := OperandPath(row.name, root); got != row.want || len(asked) != row.reads {
			t.Errorf("OperandPath(%q) = %q after %d reads %v, want %q after %d", row.name, got, len(asked), asked, row.want, row.reads)
		}
	}
}

func TestGAP2299FolderAtOrAbove(t *testing.T) {
	const a = "/h/a"
	for _, row := range []struct {
		folder, below string
		want          bool
	}{
		{a, a, true},
		{"/h", a, true},
		{"/", a, true},
		{"/h/ab", a, false},
		{"/h/a/b", a, false},
		{"/h", "", false},
	} {
		if got := folderAtOrAbove(row.folder, row.below); got != row.want {
			t.Errorf("folderAtOrAbove(%q, %q) = %v, want %v", row.folder, row.below, got, row.want)
		}
	}
}
