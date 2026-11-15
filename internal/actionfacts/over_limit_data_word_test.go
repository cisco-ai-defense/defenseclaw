// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"strings"
	"testing"
)

// SplitOverLimitWords tells a word the local shell passes on (DATA) from one
// it runs (CODE) by its position in the call (rel-1-0-10:GAP-0382).
// TestSplitOverLimitWordsRunsOperand: an operand past the string bound that a
// program runs as code in its own grammar (sed script, make assignment, git
// -c alias, tar option, rsync remote shell) is CODE, so the call stays
// truncated; the plain operand of other programs, a git commit message
// included, stays DATA (rel-1-0-10:GAP-0761, probe ids of s7-cf2chk).
func TestSplitOverLimitWordsRunsOperand(t *testing.T) {
	big := strings.Repeat("a", maxScalarBytes+10)
	rows := []struct {
		id, command string
		data, code  int
	}{
		{"sed-e", "sed -e '" + big + "' f", 0, 1},
		{"sed-script-arg", "sed '" + big + "' f", 0, 1},
		{"gsed-e", "gsed -n -e '" + big + "' f", 0, 1},
		{"make-var", "make VAR='" + big + "' all", 0, 1},
		{"git-c-alias", "git -c alias.x='" + big + "' x", 0, 1},
		{"tar-checkpoint", "tar --checkpoint-action='" + big + "' -cf a.tar b", 0, 1},
		{"rsync-e", "rsync -e '" + big + "' a b:c", 0, 1},
		{"timeout-sed", "timeout 5 sed -e '" + big + "' f", 0, 1},
		{"git-commit-m", "git commit -m '" + big + "'", 1, 0},
		{"git-other-config", "git -C repo commit -m '" + big + "'", 1, 0},
		{"echo-data", "echo '" + big + "'", 1, 0},
		{"dcx-data", "dcx - '" + big + "'", 1, 0},
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
		}
	}
}

func TestSplitOverLimitWordsByPosition(t *testing.T) {
	big := strings.Repeat("a", maxScalarBytes+10)
	rows := []struct {
		id, command string
		data, code  int
	}{
		{"dcx-script", "dcx - '" + big + "'", 1, 0},
		{"ssh-after-destination", "ssh -p 22 host '" + big + "'", 1, 0},
		{"ssh-option-before-destination", "ssh -o 'ProxyCommand=" + big + "' host true", 0, 1},
		{"ssh-inert-option-then-data", "ssh -o BatchMode=yes host '" + big + "'", 1, 0},
		{"ssh-inert-joined-options-then-data", "ssh -oConnectTimeout=5 -o StrictHostKeyChecking=no host \"" + big + "\"", 1, 0},
		{"ssh-proxycommand-then-data", "ssh -o ProxyCommand=nc host '" + big + "'", 0, 1},
		{"ssh-localcommand-then-data", "ssh -o PermitLocalCommand=yes -o LocalCommand=id host '" + big + "'", 0, 1},
		{"ssh-option-path-then-data", "ssh -o ControlPath=/tmp/c host '" + big + "'", 0, 1},
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
