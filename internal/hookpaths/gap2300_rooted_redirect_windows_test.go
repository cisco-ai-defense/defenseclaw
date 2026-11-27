// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"runtime"
	"slices"
	"testing"
)

// A rooted Windows redirect target with no drive is on the working
// directory's volume, not below the directory (rel-1-0-10:GAP-2300). A
// relative target keeps its reading.
func TestGAP2300RootedRedirectUsesTheVolume(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows volume rules")
	}
	cwd := `C:\Users\synthetic\repo`
	for _, tc := range []struct{ command, want string }{
		{"echo x > /tmp/list.txt", `C:\tmp\list.txt`},
		{"echo x >> /tmp/list.txt", `C:\tmp\list.txt`},
		{"echo x > tmp/list.txt", `C:\Users\synthetic\repo\tmp\list.txt`},
		{"echo x > D:/x/list.txt", `D:\x\list.txt`},
	} {
		operands, ok, _ := ShellWriteOperands(tc.command, cwd, `C:\Users\synthetic`)
		got := make([]string, len(operands))
		for i, operand := range operands {
			got[i] = filepath.Clean(operand)
		}
		if !ok || !slices.Contains(got, tc.want) {
			t.Errorf("%q: operands %q, want %q", tc.command, got, tc.want)
		}
	}
	// The directory walk places the redirect after a cd on the same volume.
	work := t.TempDir()
	directory, unknown := ShellDirectoryWriteOperands("cd "+filepath.ToSlash(work)+" && echo x > /tmp/list.txt", work, `C:\Users\synthetic`, nil, false, false)
	if want := filepath.VolumeName(work) + `\tmp\list.txt`; unknown || len(directory) != 1 || filepath.Clean(directory[0].Path) != want {
		t.Errorf("after cd: directory operands %+v, unknown=%v", directory, unknown)
	}
	operands, _, _ := ShellWriteOperands("echo x > /tmp/list.txt", `\\server\share\repo`, `C:\Users\synthetic`)
	if len(operands) != 1 || filepath.Clean(operands[0]) != `\\server\share\tmp\list.txt` {
		t.Errorf("share cwd: operands %q", operands)
	}
}
