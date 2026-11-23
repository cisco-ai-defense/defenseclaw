// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "testing"

// localhost:///C:/x is the local drive path C:/x, never a path under the
// working folder (rel-1-0-10:GAP-1671). Another scheme and a rest with no
// drive keep their reading under the working folder.
func TestGAP1671LocalhostDriveURIIsTheDrivePath(t *testing.T) {
	const cwd, home = `C:\Users\alice\project`, `C:\Users\alice`
	for _, row := range []struct{ value, want string }{
		{"localhost:///C:/Users/alice/.ssh/authorized_keys", "c:/users/alice/.ssh/authorized_keys"},
		{`LOCALHOST:///c:\Users\alice\.ssh\authorized_keys`, "c:/users/alice/.ssh/authorized_keys"},
		{"localhost:///D:/data/x", "d:/data/x"},
		{"localhost:///home/u/x", "c:/users/alice/project/localhost:/home/u/x"},
		{"other:///C:/Users/alice/x", "c:/users/alice/project/other:/c:/users/alice/x"},
	} {
		if got, ok := actionWindowsPath(row.value, cwd, home); !ok || got != row.want {
			t.Errorf("actionWindowsPath(%q) = %q, %v; want %q", row.value, got, ok, row.want)
		}
	}
}
