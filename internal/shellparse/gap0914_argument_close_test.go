// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package shellparse

import (
	"slices"
	"testing"
)

// rel-1-0-10:GAP-0914. The opener of a script passed as one quoted argument
// keeps its body apart only while the argument is open: when the quote
// closes on a body line, the text after it is statements of the shell.
func TestReadSyntaxTailArgumentClosedInsideTheBodyReadsItsTail(t *testing.T) {
	for _, command := range []string{
		"fi\nsh -c 'cat <<'\"'\"'EOF'\"'\"'\ndata' ; touch y\nEOF",
		"fi\nsh -c 'cat <<'\"'\"'EOF'\"'\"'\ndata'\ntouch y\nEOF",
		"fi\nsh -c 'cat <<'\"'\"'EOF'\"'\"'\ndata' && touch y\nEOF",
	} {
		tail, ok := ReadSyntaxTail(command)
		if !ok {
			t.Fatalf("%q: not read", command)
		}
		if !slices.Contains(tail.Statements, "touch y") {
			t.Errorf("%q: statements %q, here-documents %+v; want touch y read as a statement",
				command, tail.Statements, tail.HereDocs)
		}
	}
	// The apostrophe of a word (it's) does not close the argument: the body stays its consumer's input.
	for _, command := range []string{
		gap0876Script("tool -", "cat > notes.txt", "echo data"),
		gap0876Script("tool -", "cat | sh", "echo data"),
	} {
		tail, ok := ReadSyntaxTail(command)
		if !ok || len(tail.HereDocs) != 1 {
			t.Errorf("%q: %+v, want one here-document", command, tail)
		}
	}
}
