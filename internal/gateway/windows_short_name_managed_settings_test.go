// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"testing"
)

// rel-1-0-6:GAP-0734: the 8.3 short name of a managed agent settings file or
// folder is the same file, so a file-tool write to it is self-protection in
// every profile. The alias exists only on a volume that makes short names, so
// on Windows the names come from the file system (the test makes the files,
// reads their short names, asserts every one that exists, and skips only where the volume has none at all); elsewhere no
// volume can say and the shape of the name decides.
func TestWindowsShortNamesOfManagedAgentSettingsStayBlocked(t *testing.T) {
	const home = `C:\Users\vn`
	aliases := windowsManagedSettingsShortNames(t)
	for _, managed := range []bool{false, true} {
		for _, pack := range []string{"", "permissive", "strict"} {
			for _, file := range aliases {
				for _, input := range []map[string]any{
					{"file_path": file, "content": "x"},
					{"content": "x", "file_path": home + `\proj\a.txt`, "destination": file},
				} {
					if block, got := postFileToolCell(t, home, home+`\proj`, "Write", input, managed, pack); !block {
						t.Errorf("managed=%t pack=%s %v = %.160s, want protected block", managed, pack, input, got)
					}
				}
			}
		}
	}
}

// rel-1-0-6:GAP-0734 benign twin: the 8.3 name the volume gives to another
// file in the vendor folder of the managed settings is that file, not a
// managed settings file, and stays allowed in every profile.
func TestWindowsShortNameOfAnotherVendorFolderFileStaysAllowed(t *testing.T) {
	const home = `C:\Users\vn`
	short := windowsOrdinaryVendorFileShortName(t)
	if short == "" {
		t.Skip("the volume has no 8.3 name for an ordinary file in the vendor folder")
	}
	for _, managed := range []bool{false, true} {
		for _, pack := range []string{"", "permissive", "strict"} {
			if _, got := postFileToolCell(t, home, home+`\proj`, "Write", map[string]any{"file_path": short, "content": "x"}, managed, pack); strings.HasPrefix(got, fileToolBlockPrefix) {
				t.Errorf("managed=%t pack=%s %s = %.160s, want allow (another file)", managed, pack, short, got)
			}
		}
	}
}
