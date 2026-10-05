// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

func TestTrustedHomeTildeOperandsMakeALoneCommandExact(t *testing.T) {
	facts := Analyze(Input{
		Tool: "shell", Command: "head -n 5 ~/.ssh/id_rsa", CWD: "/work/app",
		ActiveHome: "/sandbox", DialectHint: DialectPOSIX,
	})
	if !facts.Authoritative() || len(facts.Commands) != 1 {
		t.Fatalf("parse = %+v, commands = %d; want one complete command", facts.Parse, len(facts.Commands))
	}
	command := facts.Commands[0]
	if command.Effect != EffectExecute || !command.ArgvComplete ||
		len(command.Argv) != 4 || command.Argv[3] != "/sandbox/.ssh/id_rsa" {
		t.Fatalf("command = %+v, want an executed head of /sandbox/.ssh/id_rsa", command)
	}
	var read *PathFact
	for i := range facts.Paths {
		if facts.Paths[i].CommandID == command.ID && facts.Paths[i].Access == PathAccessRead {
			read = &facts.Paths[i]
		}
	}
	if read == nil || read.Value != "~/.ssh/id_rsa" || read.Normalized != "~/.ssh/id_rsa" ||
		read.Resolved != "/sandbox/.ssh/id_rsa" || read.Absolute {
		t.Fatalf("read path = %+v, want ~/.ssh/id_rsa resolved in the active home", read)
	}
}

func TestTrustedHomeTildeLeavesOtherShapesPartial(t *testing.T) {
	for _, tc := range []struct {
		name, command, home string
	}{
		{"no active home", "cat ~/.ssh/id_rsa", ""},
		{"home that is not a plain word", "cat ~/.ssh/id_rsa", "/home/a b"},
		{"pipeline", "cat ~/.ssh/id_rsa | base64", "/sandbox"},
		{"earlier command", "true; cat ~/.ssh/id_rsa", "/sandbox"},
		{"home changed first", "HOME=/tmp; cat ~/.ssh/id_rsa", "/sandbox"},
		{"prefix assignment", "HOME=/tmp cat ~/.ssh/id_rsa", "/sandbox"},
		{"other user", "cat ~alice/.ssh/id_rsa", "/sandbox"},
		{"glob", "cat ~/.ssh/id_*", "/sandbox"},
		{"other expansion", "cat ~/.ssh/id_rsa $EXTRA", "/sandbox"},
		{"tilde command name", "~/bin/tool --flag", "/sandbox"},
		{"background", "cat ~/.ssh/id_rsa &", "/sandbox"},
		{"redirect after a list", "true; echo x >> ~/.ssh/id_rsa", "/sandbox"},
		{"redirect to another user", "echo x >> ~alice/.ssh/id_rsa", "/sandbox"},
		{"redirect with a prefix assignment", "HOME=/tmp echo x >> ~/.ssh/id_rsa", "/sandbox"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			facts := Analyze(Input{
				Tool: "shell", Command: tc.command, CWD: "/work/app",
				ActiveHome: tc.home, DialectHint: DialectPOSIX,
			})
			if facts.Authoritative() {
				t.Fatalf("%q with home %q is complete: %+v", tc.command, tc.home, facts.Commands)
			}
		})
	}
}

func TestRewriteTrustedPOSIXHomeTilde(t *testing.T) {
	rewrite, ok := rewriteTrustedPOSIXHomeTilde(`cat ~ ~/a "~/b" ~/"c d" x~/e`, "/sandbox")
	if !ok || rewrite.source != `cat /sandbox /sandbox/a "~/b" /sandbox/"c d" x~/e` {
		t.Fatalf("rewrite = %q, %t", rewrite.source, ok)
	}
	want := map[string]string{"/sandbox": "~", "/sandbox/a": "~/a"}
	if len(rewrite.tildeOperands) != len(want) {
		t.Fatalf("tilde operands = %v, want %v", rewrite.tildeOperands, want)
	}
	for resolved, spelling := range want {
		if rewrite.tildeOperands[resolved] != spelling {
			t.Fatalf("tilde operands = %v, want %v", rewrite.tildeOperands, want)
		}
	}
	for _, source := range []string{"cat /etc/hosts", "cat '~/a'", "a; cat ~/b", "cat ~/a | wc -l"} {
		if got, ok := rewriteTrustedPOSIXHomeTilde(source, "/sandbox"); ok {
			t.Fatalf("%q rewritten to %q", source, got.source)
		}
	}
}

// GAP-1666: a "~/" redirect target of a lone command resolves in the
// trusted home, as its "~/" operands do.
func TestTrustedHomeTildeRedirectTarget(t *testing.T) {
	for _, tc := range []struct {
		command string
		access  PathAccess
		want    string
	}{
		{"echo dccert-block-marker >> ~/.ssh/id_ed25519", PathAccessAppend, "~/.ssh/id_ed25519"},
		{"echo dccert-block-marker > ~/.ssh/id_rsa", PathAccessWrite, "~/.ssh/id_rsa"},
		{"cat ~/.ssh/config > ~/.ssh/id_ed25519", PathAccessWrite, "~/.ssh/id_ed25519"},
	} {
		facts := Analyze(Input{
			Tool: "shell", Command: tc.command, CWD: "/work/app",
			ActiveHome: "/sandbox", DialectHint: DialectPOSIX,
		})
		if !facts.Authoritative() {
			t.Fatalf("%q is partial: %+v", tc.command, facts.Parse)
		}
		found := false
		for _, path := range facts.Paths {
			if path.Access == tc.access && path.Value == tc.want && path.Resolved == "/sandbox"+tc.want[1:] {
				found = true
			}
		}
		if !found {
			t.Fatalf("%q paths = %+v, want %s %s in the active home", tc.command, facts.Paths, tc.access, tc.want)
		}
	}
}
