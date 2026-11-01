// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"runtime"
	"testing"
)

// GAP-2498 (T9, macOS rc.9): a find whose start is the DefenseClaw state
// and whose action deletes or hands off to a writer is judged the same
// whether its -name/-iname/-path pattern is quoted or an unquoted glob
// (the shell leaves an unmatched glob literal, and a matching one names
// entries of the cwd, which the start tree does not change).
func TestR105GAP2498FindUnquotedNameGlob(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell forms")
	}
	_, cwd := r105StateFixture(t)
	rows := []r105StateRow{
		{"U0 quoted -exec rm", "find ~/.defenseclaw/hooks -name \"t9d-none*\" -exec rm -f {} +", true, ""},
		{"U5 unquoted -exec rm", "find ~/.defenseclaw/hooks -name t9d-none* -exec rm -f {} +", true, ""},
		{"U6 unquoted *.sh -exec rm", "find ~/.defenseclaw/hooks -name *.sh -exec rm -f {} +", true, ""},
		{"U7 unquoted -iname -delete", "find ~/.defenseclaw/hooks -iname t9d* -delete", true, ""},
		{"U8 unquoted -name -delete", "find ~/.defenseclaw/hooks -name t9d-none* -delete", true, ""},
		{"U9 unquoted -path -delete", "find ~/.defenseclaw -path */hooks/* -delete", true, ""},
		{"U10 unquoted root config", "find ~/.defenseclaw -maxdepth 1 -name config.y* -delete", true, ""},
		{"U11 unquoted root yaml", "find ~/.defenseclaw -name *.yaml -delete", true, ""},
		{"U12 -L unquoted -exec mv", "find -L ~/.defenseclaw/hooks -name *.sh -exec mv {} /tmp \\;", true, ""},
		// Allowed and quiet.
		{"B1 unquoted list", "find ~/.defenseclaw/hooks -name *.sh", false, ""},
		{"B2 unquoted log cleanup", "find ~/.defenseclaw/logs -name *.log -delete", false, ""},
		{"B3 project unquoted delete", "find ~/proj -name *.pyc -delete", false, ""},
		{"B4 unquoted -exec cat", "find ~/.defenseclaw/hooks -name *.sh -exec cat {} +", false, ""},
		{"B5 cwd unquoted delete", "find . -name *.pyc -delete", false, ""},
		{"B6 state root old logs", "find ~/.defenseclaw -name *.log -mtime +7 -delete", false, ""},
		{"B7 unquoted print", "find ~/.defenseclaw/hooks -name *.sh -print", false, ""},
		{"B8 project unquoted exec rm", "find ~/proj -name *.tmp -exec rm -f {} +", false, ""},
	}
	for _, mode := range []string{"observe", "action"} {
		r105RunStateRowsChecked(t, mode, cwd, rows, true)
	}
}
