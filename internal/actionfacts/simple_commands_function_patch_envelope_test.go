// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"strings"
	"testing"
)

// An apply_patch envelope in the body of a function is a simple command the
// child pass judges on its file headers, whether or not the text calls the
// function, and once when it does. The other commands of a function the text
// never runs stay unexposed (TestSimpleCommandsInertDefinitionsRunNothing).
func TestSimpleCommandsExposeTheEnvelopeOfAFunctionBodyOnce(t *testing.T) {
	const patch = "apply_patch <<\x27PATCH\x27\n*** Begin Patch\n*** Add File: /etc/ld.so.preload\n+/usr/local/lib/libreview.so\n*** End Patch\nPATCH"
	for _, tt := range []struct {
		name, command string
		envelopes     int
		ranRM         bool
	}{
		{"called", "f() {\n" + patch + "\n}\nf", 1, false},
		{"never called", "f() {\n" + patch + "\n}\n", 1, false},
		{"never called, with other commands", "f() {\n  rm -rf /\n" + patch + "\n}\necho done", 1, false},
		{"subshell body never called", "f() (\n" + patch + "\n)\n", 1, false},
		{"nested in a function never called", "g() {\n  f() {\n" + patch + "\n  }\n}\n", 1, false},
		{"nested in a function called", "g() {\n  f() {\n" + patch + "\n  }\n}\ng", 1, false},
		{"called twice", "f() {\n" + patch + "\n}\nf\nf", 2, false},
		{"no envelope", "f() {\n  echo ready\n  rm -rf /\n}\n", 0, false},
		{"not a here-document", "f() {\n  apply_patch --help\n}\n", 0, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			input := Input{Tool: "shell", Command: tt.command, CWD: "/repo", ActiveHome: "/home/alice"}
			envelopes := 0
			for _, child := range SimpleCommands(input, Analyze(input)) {
				if strings.HasPrefix(child.Text, "apply_patch <<") {
					envelopes++
				}
				if child.Text == "rm -rf /" {
					t.Errorf("a command of a function the text never runs is exposed: %q", child.Text)
				}
			}
			if envelopes != tt.envelopes {
				t.Errorf("envelopes exposed = %d, want %d", envelopes, tt.envelopes)
			}
		})
	}
}

// The envelope of a function the text never calls is judged in the directory
// and with the variables the text has where it defines the function, and in
// its own body (a cd or an assignment in the body), as a call would judge it.
// What the body sets stays out of the statements that follow it.
func TestSimpleCommandsWalkTheStateOfAFunctionBodyNeverCalled(t *testing.T) {
	const body = "<<\x27PATCH\x27\n*** Begin Patch\n*** Add File: ld.so.preload\n+/usr/local/lib/libreview.so\n*** End Patch\nPATCH"
	const patch = "apply_patch " + body
	const quotedPatch = "\"$p\" " + body
	for _, tt := range []struct {
		name, command string
		// probe is the text the checked command holds, and cwd the directory
		// it must be judged in.
		probe, cwd string
	}{
		{"cd in the body", "f() {\ncd /etc\n" + patch + "\n}\n", "<<", "/etc"},
		{"pushd in the body", "f() {\npushd /etc\n" + patch + "\n}\n", "<<", "/etc"},
		{"cd named by a variable", "c=cd\nf() {\n$c /etc\n" + patch + "\n}\n", "<<", "/etc"},
		{"directory of the definition", "cd /etc\nf() {\n" + patch + "\n}\n", "<<", "/etc"},
		{"directory changed after the definition", "cd /etc\nf() {\n" + patch + "\n}\ncd /tmp\n", "<<", "/etc"},
		{"program named by a variable", "p=apply_patch\nf() {\n" + quotedPatch + "\n}\n", "<<", "/repo"},
		{"variable set after the definition", "p=apply_patch\nf() {\n" + quotedPatch + "\n}\np=ls\n", "<<", "/repo"},
		{"variable set in the body", "f() {\np=apply_patch\n" + quotedPatch + "\n}\n", "<<", "/repo"},
		{"nested function", "g() {\n  cd /etc\n  f() {\n" + patch + "\n  }\n}\n", "<<", "/etc"},
		{"inside a condition of the body", "f() {\nif true; then\ncd /etc\n" + patch + "\nfi\n}\n", "<<", "/etc"},
		{"directory of a body never called does not leak", "f() {\ncd /etc\n}\npwd\n", "pwd", "/repo"},
		{"directory of a body never called does not leak to a later envelope", "f() {\ncd /etc\n}\n" + patch, "<<", "/repo"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			input := Input{Tool: "shell", Command: tt.command, CWD: "/repo", ActiveHome: "/home/alice"}
			found := false
			for _, child := range SimpleCommands(input, Analyze(input)) {
				if strings.Contains(child.Text, tt.probe) {
					found = true
					if child.CWD != tt.cwd {
						t.Errorf("%q judged in %q, want %q", child.Text, child.CWD, tt.cwd)
					}
				}
			}
			if !found {
				t.Errorf("no command holding %q exposed", tt.probe)
			}
		})
	}
}
