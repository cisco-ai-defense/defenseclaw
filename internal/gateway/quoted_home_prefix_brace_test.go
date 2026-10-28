// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"runtime"
	"testing"
)

// GAP-2047 pod check19: a quoted $HOME prefix before a brace
// (`"$HOME/.defenseclaw/"{installer,hooks}`) names the same trees as the
// unquoted form, so the removal blocks in every mode; the same form on
// project folders stays allowed.
func TestR105GAP2047QuotedHomePrefixBeforeBrace(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell forms")
	}
	_, cwd := r105StateFixture(t)
	rows := []r105StateRow{
		{"quoted home slash brace", `rm -rf "$HOME/.defenseclaw/"{installer,hooks}`, true, ""},
		{"quoted home brace", `rm -rf "$HOME"/.defenseclaw/{installer,hooks}`, true, ""},
		{"quoted braced home brace", `rm -rf "${HOME}/.defenseclaw/"{hooks,policies}`, true, ""},
		{"single-quoted part brace", `rm -rf "$HOME"'/.defenseclaw/'{installer,hooks}`, true, ""},
		// Allowed.
		{"quoted home brace project", `rm -rf "$HOME/proj/"{build,dist}`, false, ""},
		{"quoted home brace project list", `ls "$HOME/.defenseclaw/"{installer,hooks}`, false, ""},
	}
	for _, mode := range []string{"observe", "action"} {
		r105RunStateRowsChecked(t, mode, cwd, rows, true)
	}
}
