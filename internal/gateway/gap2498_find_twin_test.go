// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// GAP-2498 pod check27: a find with an unquoted -name/-path pattern is
// judged as its quoted twin, so a writer hand-off, a pipe to xargs, a
// redirect, sudo and a $HOME start block the way the quoted spelling does.
// Project, log and read forms stay allowed and quiet.
func TestR105GAP2498FindGlobTwinHandOffs(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell forms")
	}
	home, _ := r105StateFixture(t)
	project := filepath.Join(home, "proj2")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	rows := []r105StateRow{
		{"E1 exec sed -i", "find ~/.defenseclaw/policies -name *.yaml -exec sed -i s/a/b/ {} +", true, ""},
		{"E2 exec truncate", "find ~/.defenseclaw/hooks -name *.sh -exec truncate -s0 {} +", true, ""},
		{"E3 exec sh -c rm", "find ~/.defenseclaw/hooks -name *.sh -exec sh -c 'rm \"$1\"' _ {} \\;", true, ""},
		{"E4 exec cp onto", "find ~/.defenseclaw/hooks -name *.sh -exec cp /tmp/x {} \\;", true, ""},
		{"E7 pipe xargs rm", "find ~/.defenseclaw/hooks -name *.sh | xargs rm -f", true, ""},
		{"E8 print0 xargs -0 rm", "find ~/.defenseclaw/hooks -name *.sh -print0 | xargs -0 rm -f", true, ""},
		{"E11 stderr redirect", "find ~/.defenseclaw/hooks -type f -name *.sh -exec rm -f {} + 2>/dev/null", true, ""},
		{"E12 sudo find delete", "sudo find ~/.defenseclaw/hooks -name *.sh -delete", true, ""},
		{"E14 $HOME start", "find $HOME/.defenseclaw/hooks -name *.sh -delete", true, ""},
		{"path pattern", "find ~/.defenseclaw -path *hooks* -delete", true, ""},
		// Allowed and quiet.
		{"project pyc delete", "find . -name *.pyc -delete", false, ""},
		{"project xargs rm", "find ~/proj2 -name *.o | xargs rm -f", false, ""},
		{"state log delete", "find ~/.defenseclaw/logs -name *.log -delete", false, ""},
		{"hooks listing", "find ~/.defenseclaw/hooks -name *.sh", false, ""},
		{"state read", "find ~/.defenseclaw -name *.yaml -exec cat {} +", false, ""},
		{"state grep", "find ~/.defenseclaw/policies -name *.yaml | xargs grep -l mode", false, ""},
	}
	for _, mode := range []string{"observe", "action"} {
		r105RunStateRowsChecked(t, mode, project, rows, true)
	}
}
