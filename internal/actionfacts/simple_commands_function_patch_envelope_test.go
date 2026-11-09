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
