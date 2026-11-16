// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "testing"

// TestEchoSubstitutionValueRefusesBraceText is the review should-fix of
// fix/r107-bd-hookparse3: $(echo {keylink,}) is keylink in bash, so the
// echo reader must not return the unexpanded brace text as a known value.
func TestEchoSubstitutionValueRefusesBraceText(t *testing.T) {
	const home, cwd = "/home/alice", "/home/alice/project"
	for _, row := range []struct {
		word  string
		value string
		known bool
	}{
		{"$(echo keylink)", "keylink", true},
		{"$(echo -n notes.txt)", "notes.txt", true},
		{"$(echo {keylink,})", "", false},
		{"$(echo key{link,})", "", false},
		{"$(echo '{a,b}')", "{a,b}", true},
	} {
		file, ok := parseShell("echo x > " + row.word)
		if !ok {
			t.Fatalf("parse %q", row.word)
		}
		word := file.Stmts[0].Redirs[0].Word
		value, known := actionWordValue(word, actionValues{"HOME": home}, cwd, home)
		if known != row.known || known && value != row.value {
			t.Errorf("%q = %q, %v; want %q, %v", row.word, value, known, row.value, row.known)
		}
	}
}
