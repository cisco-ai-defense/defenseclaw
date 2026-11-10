// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

// The shell opens the redirects of a command in order and the last input
// redirect of descriptor 0 is its stdin. The content proofs read the
// here-document only when it is that last redirect, and a context line of an
// update hunk that shows an expansion is no file directive.
func TestContentProofsReadTheStdinTheLastRedirectLeaves(t *testing.T) {
	const lib = "/usr/local/lib/libreview.so"
	protected := "*** Begin Patch\n*** Add File: /etc/ld.so.preload\n+" + lib + "\n*** End Patch\n"
	withExpansion := "*** Begin Patch\n*** Add File: /etc/ld.so.preload\n+" + lib + "\n+# built by $USER\n*** End Patch\n"
	ordinary := "*** Begin Patch\n*** Add File: notes.txt\n+hello\n*** End Patch\n"
	rows := []struct {
		name, command string
		loader        bool
	}{
		{"document after a null input", "apply_patch </dev/null <<EOF\n" + protected + "EOF\n", true},
		{"document after a descriptor 0 input", "apply_patch 0< other.patch <<EOF\n" + protected + "EOF\n", true},
		{"document after a descriptor copy nothing opened", "apply_patch <&3 <<EOF\n" + protected + "EOF\n", false},
		{"document after a null input, expanding", "apply_patch </dev/null <<EOF\n" + withExpansion + "EOF\n", true},
		{"document after a null input, quoted", "apply_patch </dev/null <<\x27EOF\x27\n" + protected + "EOF\n", true},
		{"ordinary document after a null input", "apply_patch </dev/null <<EOF\n" + ordinary + "EOF\n", false},
		{"file after the document", "apply_patch <<EOF < ordinary.patch\n" + protected + "EOF\n", false},
		{"descriptor 0 file after the document", "apply_patch <<EOF 0< ordinary.patch\n" + protected + "EOF\n", false},
		{"file after the expanding document", "apply_patch <<EOF < ordinary.patch\n" + withExpansion + "EOF\n", false},
		{"descriptor 0 file after the expanding document", "apply_patch <<EOF 0< ordinary.patch\n" + withExpansion + "EOF\n", false},
		{"descriptor copy after the document", "apply_patch <<EOF <&3\n" + protected + "EOF\n", false},
		{"descriptor copy after the expanding document", "apply_patch <<EOF <&3\n" + withExpansion + "EOF\n", false},
		{"here-string after the document", "apply_patch <<EOF <<< ordinary\n" + protected + "EOF\n", false},
		{"two documents", "apply_patch <<A <<B\n" + protected + "A\n" + protected + "B\n", false},
		{"output redirect after the document", "apply_patch <<EOF > /dev/null\n" + protected + "EOF\n", true},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			for _, tool := range []string{"Bash", "exec_command"} {
				input := Input{Tool: tool, Command: row.command, CWD: "/tmp"}
				if got := ExactGlobalLDPreloadFileWrite(input, Analyze(input)); got != row.loader {
					t.Fatalf("%s: loader proof = %v, want %v", tool, got, row.loader)
				}
			}
		})
	}
}

// A context line of an update hunk begins with a space, so a line that shows
// an expansion behind it is content of the ordinary file, and a later literal
// directive for a protected file is still read.
func TestContentProofsReadAFileBesideAnExpandingContextLine(t *testing.T) {
	const lib = "/usr/local/lib/libreview.so"
	context := "*** Update File: notes.txt\n@@\n *** $USER\n+hello\n"
	loader := "*** Add File: /etc/ld.so.preload\n+" + lib + "\n"
	rows := []struct {
		name, body string
		loader     bool
	}{
		{"protected file after the context line", context + loader, true},
		{"ordinary file after the context line", context + "*** Add File: other.txt\n+hello\n", false},
		{"expansion in the directive of the protected file", context + "*** Add File: $DIR/ld.so.preload\n+" + lib + "\n", false},
		{"library chosen by an expansion", context + "*** Add File: /etc/ld.so.preload\n+$LIBPATH\n", false},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			input := Input{Tool: "exec_command", Command: "apply_patch <<EOF\n*** Begin Patch\n" + row.body + "*** End Patch\nEOF\n", CWD: "/tmp"}
			if got := ExactGlobalLDPreloadFileWrite(input, Analyze(input)); got != row.loader {
				t.Fatalf("loader proof = %v, want %v", got, row.loader)
			}
		})
	}
}
