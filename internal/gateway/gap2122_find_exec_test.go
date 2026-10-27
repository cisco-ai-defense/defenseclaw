// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"runtime"
	"testing"
)

// GAP-2122: find -exec/-execdir/-ok with rm, unlink, rmdir or shred given
// only the found entry removes it, like -delete, and mv {} DEST moves it
// away; the same order rule applies, so a named log cleanup and a
// read-only -exec stay allowed. Only an exact embedded command (the
// program given only options and {}) is read; any other embedded command
// keeps the find partial, as before.
func TestR105GAP2122FindExecDeleteOfActiveState(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell forms")
	}
	_, cwd := r105StateFixture(t)
	rows := []r105StateRow{
		// GAP-2122
		{"exec rm hooks plus", "find ~/.defenseclaw/hooks -exec rm -f {} +", true, ""},
		{"exec rm root before name", `find ~/.defenseclaw -exec rm -f {} \; -name '*.log'`, true, ""},
		{"exec true or delete", `find ~/.defenseclaw -name '*.log' -exec true \; -o -delete`, true, ""},
		{"execdir rm installer", "find ~/.defenseclaw/installer -type f -execdir rm {} +", true, ""},
		{"exec unlink HOME hooks", `find $HOME/.defenseclaw/hooks -exec unlink {} \;`, true, ""},
		{"exec rm name config", `find ~/.defenseclaw -name config.yaml -exec rm {} \;`, true, ""},
		{"exec bin rm policies", "find ~/.defenseclaw/policies -type f -exec /bin/rm -f {} +", true, ""},
		{"exec mv policies out", `find ~/.defenseclaw/policies -exec mv {} /tmp/ \;`, true, ""},
		{"ok rm previous", `find ~/.defenseclaw/previous -ok rm {} \;`, true, ""},
		// Benign: named cleanup through -exec, read-only -exec, other trees.
		{"exec rm log cleanup", `find ~/.defenseclaw -name '*.log' -exec rm -f {} \;`, false, ""},
		{"exec rm log cleanup plus", "find ~/.defenseclaw -name '*.log' -mtime +7 -exec rm -f {} +", false, ""},
		{"exec ls root", `find ~/.defenseclaw -type f -exec ls -l {} \;`, false, ""},
		{"exec grep root", "find ~/.defenseclaw -exec grep -l fixture {} +", false, ""},
		{"exec sha256sum hooks", "find ~/.defenseclaw/hooks -type f -exec sha256sum {} +", false, ""},
		{"exec rm logs tree", "find ~/.defenseclaw/logs -exec rm -f {} +", false, ""},
		{"exec rm project objects", "find ./build -name '*.o' -exec rm -f {} +", false, ""},
	}
	for _, mode := range []string{"observe", "action"} {
		r105RunStateRowsChecked(t, mode, cwd, rows, true)
	}
}
