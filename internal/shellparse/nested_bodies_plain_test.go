// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package shellparse

import (
	"math/rand/v2"
	"strings"
	"testing"
)

// TestNestedBodyWeightSkipsOnlyBodiesWithoutBodies is the exactness of the
// mayHoldBody check (rel-1-0-10:GAP-0299): the weight of a command is the
// same as when every nested body is parsed, for nested shells, here-documents
// fed to shells, escaped blanks, lone dollars, here-strings and random texts,
// and a large here-document of plain text is not parsed past the command.
func TestNestedBodyWeightSkipsOnlyBodiesWithoutBodies(t *testing.T) {
	always := func(string) bool { return true }
	pad := "\n: " + strings.Repeat("word ", 1000) + "\n"
	prose := strings.Repeat("Meeting notes: the team agreed on the next steps.\n", 100)
	commands := []string{
		"cat > notes.txt <<'EOF'\n" + prose + "EOF\n",
		"bash <<'EOF'\n" + prose + "bash -c 'sh -c \"eval x\\ y\"'\nEOF\n",
		"bash <<'EOF'\n" + prose + "echo 5$ a\\ b\nbash <<'X'\nsh -c 'a b'\nX\nEOF\n",
		"sh -c 'cat <<<\"a b\"'" + pad,
		"bash -c 'bash -c \"bash -c \\\"a; b\\\"\"'" + pad,
		nestedSingleQuoted(6, "bash", "echo a b") + pad,
		nestedSingleQuoted(9, "sh", prose) + pad,
	}
	pieces := []string{
		"bash -c ", "sh -c ", "eval ", "'", "\"", "\\ ", "\\", "$", "5$ ", " ", ";", "|", "x", "<<'E'\n", "\nE\n",
		"<<E\n", "<<<", "\n", "a b", "$(x)", "`x`", "(", ")",
	}
	random := rand.New(rand.NewPCG(299, 3))
	for range 3000 {
		var text strings.Builder
		for range 1 + random.IntN(24) {
			text.WriteString(pieces[random.IntN(len(pieces))])
		}
		commands = append(commands, text.String()+pad, pad+text.String())
	}
	weighed := 0
	for _, command := range commands {
		got, want := NestedBodyWeight(command), nestedBodyWeight(command, always)
		if got != want {
			t.Fatalf("NestedBodyWeight(%.200q) = %d, %d when every body is parsed", command, got, want)
		}
		if got > 0 {
			weighed++
		}
	}
	if weighed < 10 {
		t.Fatalf("only %d commands weigh anything: the corpus proves little", weighed)
	}
	parsed := 0
	nestedBodyWeight("cat > notes.txt <<'EOF'\n"+prose+prose+"EOF\n", func(string) bool { parsed++; return mayHoldBody("") })
	if parsed != 1 {
		t.Fatalf("a plain here-document is offered for parsing %d times, want 1 (and then not parsed)", parsed)
	}
}
