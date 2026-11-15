// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"strings"
	"testing"

	"mvdan.cc/sh/v3/syntax"
)

// A glob copy source becomes one more name only when no word of the copy may
// name a protected file by its text and, for a copy the walk did not place in
// a folder, the glob is rooted; any other copy keeps the reading of rel, in
// either slash spelling (rel-1-0-10:GAP-0018, GAP-0944, GAP-0960, GAP-0963,
// GAP-0964).
func TestCopyGlobOperandKeepsSSHFolderGlobs(t *testing.T) {
	for _, tc := range []struct {
		command string
		placed  bool
		swapped bool
	}{
		{`cp /etc/pam.d/* /backup/`, true, true},
		{`cp -r project/* backup/`, true, true},
		{`cp -r C:\Users\other\.ssh\* /tmp/b/`, true, false},
		{`cp -r C:/Users/other/.ssh/* /tmp/b/`, true, false},
		{`cp -r /home/other/.SSH/* /tmp/b/`, true, false},
		{`cp /home/other/.s?h/id_* /tmp/b/`, true, false},
		{`cp /home/*/authorized_k* /tmp/b/`, true, false},
		{`cp -r backup/* C:\Users\other\.ssh`, true, false},
		{`cp -r backup/* /home/other/.ssh/`, true, false},
		{`cp ~/.aws/* /tmp/b/`, true, false},
		{`cp ~/.net* /tmp/b/`, true, false},
		{`cp ~/.git-cred* /tmp/b/`, true, false},
		{`cp -r ~/.kube/* /tmp/b/`, true, false},
		{`cp -r ~/.defenseclaw/* /tmp/b/`, true, false},
		{`cp -r /home/other/.aws/* /tmp/b/`, true, false},
		{`cp -r ~/* /tmp/b/`, true, false},
		{`cp -r $HOME/.* /tmp/b/`, true, false},
		{`cp ~/projects/app/*.json /tmp/x`, true, true},
		{`cp .aws/* /tmp/b/`, false, false},
		{`cp *.txt /tmp/b/`, false, false},
		{`cp /etc/pam.d/* /backup/`, false, true},
	} {
		file, err := syntax.NewParser().Parse(strings.NewReader(tc.command), "")
		if err != nil {
			t.Fatal(err)
		}
		call := file.Stmts[0].Cmd.(*syntax.CallExpr)
		words := make([]string, len(call.Args))
		static := make([]bool, len(call.Args))
		for i, word := range call.Args {
			words[i], static[i] = staticShellWord(word, nil, true)
		}
		out, _ := copyGlobOperandsAsNames(call.Args, words, static, "/home/user", tc.placed)
		if got := strings.Contains(strings.Join(out, " "), copyGlobOperand); got != tc.swapped {
			t.Errorf("%s: swapped=%t, want %t", tc.command, got, tc.swapped)
		}
	}
}
