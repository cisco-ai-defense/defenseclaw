// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"testing"
)

// TestBraceTouchAndPrintedRedirectTargetBlockEveryMode is rel-1-0-6
// GAP-0233 (a brace touch onto the keys file was allowed on both routes
// while the plain touch blocked) and GAP-0255 (a redirect whose target is
// a substitution that prints the keys path through a brace was allowed in
// all four modes). The hook client's whole-command decision now reads a
// fixed brace word as the words bash makes of it, so claudecode and codex
// block managed and per-user; the GAP-0151 long touch lists are not
// listed as targets and stay allowed (TestGAP0151LongOperandListKeepsProtectedTarget).
func TestBraceTouchAndPrintedRedirectTargetBlockEveryMode(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	blocked := []string{
		"touch ../.ssh/authorized_keys",
		"touch ../.ssh/authorized_key{s,x}",
		"touch ~/.ssh/authorized_key{s,x}",
		"touch ../.ssh/authorized_key{r..t}",
		`touch "../.ssh/authorized_key"{s,x}`,
		"touch $HOME/.ssh/authorized_key{s,x}",
		"touch keylink{,.x}",
		"echo x > $(echo ../.ssh/authorized_keys)",
		"echo x > $(echo ../.ssh/authorized_key{s..s})",
		`echo x >> "$(echo ../.ssh/authorized_key{s..s})"`,
		"echo x > `echo ../.ssh/authorized_key{s..s}`",
		"echo x > $(printf %s ../.ssh/authorized_key{s..s})",
	}
	allowed := []string{
		"touch ordinary/{a,b}",
		"touch $HOME/project/ordinary/{a,b}",
		"touch ordinary/x{1..300}",
		"echo x > $(echo ordinary/a{1..1})",
		"echo x > $(mktemp)",
		`echo x > "$(pwd)/notes.txt"`,
		"echo x > $(echo ../.ssh/authorized_keys.bak)",
	}
	check := func(command, want string) {
		payload := f.payload(t, command)
		header := f.clientHeader(t, payload)
		for _, call := range everyMode(command, payload, header) {
			mode := os.FileMode(0o700)
			if call.managed {
				mode = 0
			}
			if err := os.Chmod(f.homes, mode); err != nil {
				t.Fatal(err)
			}
			if call.verdict, call.body = f.serve(call); call.verdict != want {
				t.Errorf("%s: verdict %s, want %s; body %.200s", call.name, call.verdict, want, call.body)
			}
		}
		if err := os.Chmod(f.homes, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, command := range blocked {
		check(command, "block")
	}
	for _, command := range allowed {
		check(command, "allow")
	}
}
