// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package winpath

import "testing"

// rel-1-0-10:GAP-2211: Windows names compare as NTFS compares them, through
// the uppercase table, not by Unicode case folding: the Kelvin sign (U+212A)
// is not k, so a folder spelled with it is not the k-spelled folder and no
// path below one is below the other.
func TestGAP2211WindowsNamesCompareAsNTFS(t *testing.T) {
	if !SameWindowsPath(`C:\Users\Alice\KDir`, `c:\users\alice\kdir\`) {
		t.Error("an ASCII case difference is the same NTFS name")
	}
	if SameWindowsPath("C:\\x\\\u212Adir", `C:\x\kdir`) {
		t.Error("the Kelvin sign compared equal to k")
	}
	if parts, err := windowsRelativeBelow("C:\\x\\\u212Adir", `C:\x\kdir\f`); err == nil {
		t.Errorf("C:\\x\\kdir\\f is below the Kelvin-sign folder: %v", parts)
	}
	if parts, err := windowsRelativeBelow(`C:\X\KDIR`, `c:\x\kdir\f\g`); err != nil || len(parts) != 2 || parts[0] != "f" || parts[1] != "g" {
		t.Errorf("windowsRelativeBelow case-folded = %v, %v; want [f g]", parts, err)
	}
	for _, tc := range []struct {
		root, path string
	}{{`C:\u\o`, `C:\u\out`}, {`C:\u`, `C:\u`}, {`C:\u`, `C:\u\`}, {`C:\u`, `C:\u\\x`}} {
		if parts, err := windowsRelativeBelow(tc.root, tc.path); err == nil {
			t.Errorf("windowsRelativeBelow(%q, %q) = %v, want not below", tc.root, tc.path, parts)
		}
	}
	if parts, err := windowsRelativeBelow(`C:\`, `C:\a`); err != nil || len(parts) != 1 || parts[0] != "a" {
		t.Errorf("below the drive root = %v, %v", parts, err)
	}
	if parts, err := windowsRelativeBelow(`\\server\share`, `\\SERVER\Share\a`); err != nil || len(parts) != 1 {
		t.Errorf("below a share = %v, %v", parts, err)
	}
}

// EqualNames is the name rule SameWindowsPath and windowsRelativeBelow use.
func TestEqualNamesIsNTFSNameEquality(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{"hook.exe", "HOOK.EXE", true},
		{"\u00e9t\u00e9", "\u00c9T\u00c9", true},
		{"\u212Adir", "kdir", false},
		{"\u212Adir", "Kdir", false},
		{"a", "ab", false},
		{"", "", true},
	} {
		if got := EqualNames(tc.a, tc.b); got != tc.want {
			t.Errorf("EqualNames(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}
