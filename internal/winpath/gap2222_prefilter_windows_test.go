//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package winpath

import (
	"path/filepath"
	"testing"
)

// GAP-2222: the guardian's ownership check compares every handler command
// with the hook binary. A command that cannot be the hook binary by its
// spelling (a different folder or file name outside its ~ components) must
// not cost a long-name lookup, which can wait longNameLookupBudget on
// stalled storage.
func TestGAP2222SameNamedFileAsksNoLookupForAnotherSpelling(t *testing.T) {
	_, hook, _ := gap2175Image(t)
	oldLookups, oldLookup := longNames, getLongPathName
	longNames = newLongNameLookups()
	lookups := 0
	// Count the lookups; never ask real storage (one row is a share).
	getLongPathName = func(string) (string, bool) {
		lookups++
		return "", false
	}
	t.Cleanup(func() { longNames, getLongPathName = oldLookups, oldLookup })
	dir := filepath.Dir(hook)
	for _, command := range []string{
		`\\host\share\X~1\tools\run.exe`,
		`C:\Users\U~1\bin\defenseclaw-hook.exe`,
		filepath.Join(dir, "RUN~1.EXE", "x"),
		filepath.Join(filepath.Dir(dir), "OTHER~1", "defenseclaw-other.exe"),
	} {
		if SameNamedFile(command, hook) {
			t.Fatalf("%s was taken for the hook binary", command)
		}
	}
	if lookups != 0 {
		t.Fatalf("%d long-name lookups for commands that cannot name the hook binary, want 0", lookups)
	}
}

// The prefilter keeps every spelling that can share the key: ~ components on
// either side, the \\?\ prefix, slashes and case.
func TestGAP2222MayShareComparisonKeyKeepsAliasSpellings(t *testing.T) {
	want := `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`
	for _, path := range []string{
		want,
		`C:\PROGRA~1\Cisco\DEFENS~1\bin\DEFENS~1.EXE`,
		`\\?\C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`,
		`c:/program files/cisco/defenseclaw/bin/DEFENSECLAW-HOOK.EXE`,
		`C:\Program Files\Cisco\DefenseClaw\bin\..\bin\defenseclaw-hook.exe`,
	} {
		if !mayShareComparisonKey(path, want) {
			t.Fatalf("%s refused before the lookup", path)
		}
	}
	if !mayShareComparisonKey(want, `C:\PROGRA~1\Cisco\DEFENS~1\bin\DEFENS~1.EXE`) {
		t.Fatal("a short spelling on the want side refused")
	}
	for _, path := range []string{
		`C:\Program Files\Cisco\DefenseClaw\bin\x\defenseclaw-hook.exe`,
		`C:\PROGRA~1\Other\DEFENS~1\bin\DEFENS~1.EXE`,
		`D:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`,
	} {
		if mayShareComparisonKey(path, want) {
			t.Fatalf("%s kept", path)
		}
	}
}
