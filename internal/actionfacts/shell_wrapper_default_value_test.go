// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

// TestBuiltinRunsItsNamedCommandAsCommandDoes pins that builtin NAME, with an
// optional leading --, projects the command it runs as a child of the
// wrapper, as command does, and that the action stays authoritative.
func TestBuiltinRunsItsNamedCommandAsCommandDoes(t *testing.T) {
	for _, wrapper := range []string{"command", "builtin", "builtin --", "command builtin"} {
		input := Input{Tool: "Bash", Command: wrapper + " echo x >> /tmp/out.txt", CWD: "/tmp"}
		facts := Analyze(input)
		if !facts.Authoritative() {
			t.Fatalf("%q: not authoritative", wrapper)
		}
		var echo *CommandFact
		for index := range facts.Commands {
			if facts.Commands[index].Program == "echo" {
				echo = &facts.Commands[index]
			}
		}
		if echo == nil || echo.ParentCommandID == 0 {
			t.Fatalf("%q: no echo child of the wrapper: %+v", wrapper, facts.Commands)
		}
	}
	// builtin takes no option: the next word is not a command to project.
	if facts := Analyze(Input{Tool: "Bash", Command: "builtin -x echo x", CWD: "/tmp"}); len(facts.Commands) != 1 {
		t.Fatalf("builtin with an option projected a child: %+v", facts.Commands)
	}
}

// TestSimpleCommandsReadTheDefaultOfAnUnsetName pins that ${NAME:-word} and
// ${NAME-word} read the static word when the walk holds no value for NAME,
// in a binding and in a lone statement, and the value of NAME when it has
// one; a default that is not static, and a name that is not a variable name,
// stay unread.
func TestSimpleCommandsReadTheDefaultOfAnUnsetName(t *testing.T) {
	for _, row := range []struct{ command, want string }{
		{"P=${P:-/etc/target}; echo x >> $P", "echo x >> '/etc/target'"},
		{"P=${P-/etc/target}; echo x >> $P", "echo x >> '/etc/target'"},
		{"echo x >> ${P:-/etc/target}", "echo x >> '/etc/target'"},
		{"P=/tmp/a; echo x >> ${P:-/etc/target}", "echo x >> '/tmp/a'"},
		{"echo x >> ${P:-$Q}", ""},
		{"echo x >> ${1:-/etc/target}", ""},
		{"echo x >> ${P:=/etc/target}", ""},
	} {
		input := Input{Tool: "Bash", Command: row.command, CWD: "/tmp"}
		got := ""
		for _, simple := range SimpleCommands(input, Analyze(input)) {
			if simple.Text != "" && simple.Text[0] == 'e' {
				got = simple.Text
			}
		}
		if got != row.want {
			t.Errorf("%q: simple command %q, want %q", row.command, got, row.want)
		}
	}
}
