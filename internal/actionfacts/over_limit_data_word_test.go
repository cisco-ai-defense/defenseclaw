// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"strings"
	"testing"
)

// SplitOverLimitWords tells a word the local shell passes on (DATA) from one
// it runs (CODE) by its position in the call (rel-1-0-10:GAP-0382).
func TestSplitOverLimitWordsByPosition(t *testing.T) {
	big := strings.Repeat("a", maxScalarBytes+10)
	rows := []struct {
		id, command string
		data, code  int
	}{
		{"dcx-script", "dcx - '" + big + "'", 1, 0},
		{"ssh-after-destination", "ssh -p 22 host '" + big + "'", 1, 0},
		{"ssh-option-before-destination", "ssh -o 'ProxyCommand=" + big + "' host true", 0, 1},
		{"echo", "echo " + big, 1, 0},
		{"double-quoted", "dcx \"" + big + "\"", 1, 0},
		{"two-words", "dcx '" + big + "' '" + big + "'", 2, 0},
		{"timeout-wraps-data", "timeout 5 dcx '" + big + "'", 1, 0},
		{"timeout-wraps-shell", "timeout 5 sh -c '" + big + "'", 0, 1},
		{"sh-c", "sh -c '" + big + "'", 0, 1},
		{"eval", "eval " + big, 0, 1},
		{"source", "source " + big, 0, 1},
		{"command-name", big + " x", 0, 1},
		{"redirect-target", "echo x > " + big, 0, 1},
		{"python-c", "python3 -c '" + big + "'", 0, 1},
		{"python-script-arg", "python3 tool.py '" + big + "'", 1, 0},
		{"awk-program", "awk '" + big + "' f", 0, 1},
		{"variable-command", "D=/opt/tools/dcx; $D - '" + big + "'", 1, 0},
		{"variable-directory", "K=/opt/tools; $K/dcx - '" + big + "'", 1, 0},
		{"variable-unbound", "$CMD - '" + big + "'", 0, 1},
		{"variable-shell", "S=/bin/sh; $S -c '" + big + "'", 0, 1},
		{"variable-rebound", "D=/opt/tools/dcx; read D; $D - '" + big + "'", 0, 1},
		{"mixed", "dcx '" + big + "'; sh -c '" + big + "'", 1, 1},
		{"substitution", "echo $(dcx '" + big + "')", 1, 0},
	}
	for _, r := range rows {
		split, ok := SplitOverLimitWords(r.command)
		if r.data == 0 {
			if ok {
				t.Errorf("%s: split ok with data=%d code=%d, want unreadable", r.id, split.Data, split.Code)
			}
			continue
		}
		if !ok || split.Data != r.data || split.Code != r.code {
			t.Errorf("%s: ok=%t data=%d code=%d, want data=%d code=%d", r.id, ok, split.Data, split.Code, r.data, r.code)
			continue
		}
		if split.Code == 0 && len(split.Twin) >= len(r.command) {
			t.Errorf("%s: twin not shortened", r.id)
		}
	}
}
