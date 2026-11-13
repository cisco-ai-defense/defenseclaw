// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package winpath

import (
	"testing"
)

func TestExpectedFinalPathBelowComparesTheOpenedFile(t *testing.T) {
	// The root's final path can differ from its spelling (a redirected
	// profile, an 8.3 name, the \\?\ prefix); the elements below it cannot.
	want, err := ExpectedFinalPathBelow(`\\?\D:\Profiles\alice`, `\\?\C:\Users\alice`, `C:\Users\alice\.claude\settings.json`)
	if err != nil {
		t.Fatal(err)
	}
	if !SameWindowsPath(want, `\\?\d:\profiles\ALICE\.claude\settings.json`) {
		t.Fatalf("plain path: %s", want)
	}
	// A junction at .claude makes the opened file's final path another one.
	if SameWindowsPath(want, `\\?\C:\Windows\System32\config\settings.json`) {
		t.Fatal("a file behind a link compares equal")
	}
	if !SameWindowsPath(`\\?\UNC\server\share\a`, `\\server\share\a\`) {
		t.Fatal("UNC prefix not normalised")
	}
	if _, err := ExpectedFinalPathBelow(`C:\x`, `C:\Users\alice`, `C:\Users\bob\a.json`); err == nil {
		t.Fatal("a path outside the root has an expected final path")
	}
}
