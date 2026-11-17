// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"slices"
	"testing"
)

// TestANSICQuotedOperandNamesTheDecodedFile (rel-1-0-10:GAP-0351): an
// operand spelled as an ANSI-C quote ($'...') is the text bash makes of it,
// its escapes decoded, so the path fact names the file the command touches.
// The word was read as dynamic with no path fact at all, so a detection over
// the facts saw no file. A quote whose value is not certain (one with \c, or
// one that makes a NUL, where bash cuts the word) stays dynamic.
func TestANSICQuotedOperandNamesTheDecodedFile(t *testing.T) {
	const cwd = "/home/alice/proj"
	static := []struct{ command, want string }{
		{`touch $'\x2eenv'`, cwd + "/.env"},
		{`chmod 600 $'/home/alice/.ssh/id\x5frsa'`, "/home/alice/.ssh/id_rsa"},
		{`cp key.pub $'/home/alice/.ssh/authorized_keys'`, "/home/alice/.ssh/authorized_keys"},
		{`mv a.txt $'\056git/config'`, cwd + "/.git/config"},
		{`touch $'a'"b"c`, cwd + "/abc"},
		{`touch $'tab\there'`, cwd + "/tab\there"},
		{`touch $'A\x42'`, cwd + "/AB"},
	}
	for _, row := range static {
		facts := Analyze(Input{Tool: "Bash", Command: row.command, CWD: cwd, ActiveHome: "/home/alice", DialectHint: DialectPOSIX})
		var resolved []string
		for _, path := range facts.Paths {
			resolved = append(resolved, path.Resolved)
		}
		if !slices.Contains(resolved, row.want) {
			t.Errorf("%q: path facts %q, want one for %q", row.command, resolved, row.want)
		}
	}
	for _, command := range []string{`touch $'a\x00b'`, `touch $'a\cAb'`} {
		facts := Analyze(Input{Tool: "Bash", Command: command, CWD: cwd, ActiveHome: "/home/alice", DialectHint: DialectPOSIX})
		for _, path := range facts.Paths {
			if path.Resolved == cwd+"/a" || path.Resolved == cwd+"/ab" {
				t.Errorf("%q: static path fact %q for a quote with no certain value", command, path.Resolved)
			}
		}
		dynamic := false
		for _, fact := range facts.Commands {
			for _, argument := range fact.Arguments {
				dynamic = dynamic || argument.Expands
			}
		}
		if !dynamic {
			t.Errorf("%q: no dynamic argument, want the quote read as dynamic", command)
		}
	}
}
