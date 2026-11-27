// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"path/filepath"
	"runtime"
	"testing"
)

// A rooted Windows name with no drive is on the working directory's volume,
// not below the directory (rel-1-0-10:GAP-2300). A drive-relative name and a
// relative name keep their reading.
func TestGAP2300OperandPathRootedWindowsNameUsesTheVolume(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows volume rules")
	}
	cwd := `C:\Users\synthetic\repo`
	for _, tc := range []struct{ name, want string }{
		{"/tmp/list.txt", `C:\tmp\list.txt`},
		{`\tmp\list.txt`, `C:\tmp\list.txt`},
		{"tmp/list.txt", `C:\Users\synthetic\repo\tmp\list.txt`},
		{"../list.txt", `C:\Users\synthetic\list.txt`},
		{`D:\x\list.txt`, `D:\x\list.txt`},
	} {
		if got := OperandPath(tc.name, cwd); filepath.Clean(got) != tc.want {
			t.Errorf("OperandPath(%q, %q) = %q, want %q", tc.name, cwd, got, tc.want)
		}
	}
	if got := OperandPath("/tmp/list.txt", `\\server\share\repo`); got != `\\server\share\tmp\list.txt` {
		t.Errorf("share cwd: got %q", got)
	}
	// With no absolute directory the name keeps its (cleaned) spelling.
	if got := OperandPath("/tmp/list.txt", "repo"); got != filepath.Clean("/tmp/list.txt") {
		t.Errorf("relative cwd: got %q", got)
	}
}
