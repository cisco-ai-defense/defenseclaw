// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// rel-1-0-10:GAP-0945 (P2): on a Windows home a Git Bash find that starts at
// a drive folder above the home (find C:/ -type f -delete, find C:/ ...
// -exec mv) reaches the DefenseClaw state as find ~ does, and blocks as find
// / does on Linux. The drive start was cleaned to "C:" and the home kept its
// backslash spelling, so the ancestor test never matched (allow). A drive
// start with a cleanup name, a depth bound above the state, a project folder
// and a plain listing stay quiet. Root cause: the Git Bash path fact C:/
// failed the semantic projection (path.Clean spells it C:), so no semantic
// rule judged the call, and the ancestor test cleaned the start the same way.
func TestGAP0945WindowsGitBashFindFromTheDriveRoot(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("a Windows drive home is a Windows form")
	}
	home, cwd := gap1173WindowsStateHome(t)
	drive := filepath.ToSlash(filepath.VolumeName(home))
	parent := filepath.ToSlash(filepath.Dir(home))
	// A folder of the project: a find over the project itself is judged by
	// the agent hook config guard (tamper.agent_hook_config_*) on every
	// OS, which this test does not cover.
	project := filepath.ToSlash(cwd)
	rows := []r105StateRow{
		{"drive root delete", "find " + drive + "/ -type f -delete", true, ""},
		{"drive root mv", "find " + drive + "/ -type f -exec mv {} /tmp/x/ \\;", true, ""},
		{"drive root rm", "find " + drive + "/ -name '*.yaml' -exec rm {} \\;", true, ""},
		{"lower-case drive root delete", "find " + strings.ToLower(drive) + "/ -type f -delete", true, ""},
		{"home parent delete", "find " + parent + " -type f -delete", true, ""},
		// Allowed: a cleanup name, a depth bound above the state, a project
		// start and a listing.
		{"drive root cleanup name", "find " + drive + "/ -name '*.tmp' -delete", false, ""},
		{"drive root maxdepth 1", "find " + drive + "/ -maxdepth 1 -type f -delete", false, ""},
		{"project folder delete", "find " + project + "/build -type f -delete", false, ""},
		{"drive root listing", "find " + drive + "/ -name notes.txt", false, ""},
	}
	for _, mode := range []string{"observe", "action"} {
		r105RunStateRowsChecked(t, mode, cwd, rows, true)
	}
}
