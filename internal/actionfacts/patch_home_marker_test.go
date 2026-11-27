// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"strings"
	"testing"

	"mvdan.cc/sh/v3/syntax"
)

// TestPatchHeaderTargetPlacesOnlyALoneLeadingHome pins which header names of
// an expanding here-document are placed under the active home
// (rel-1-0-10:GAP-1094): a leading $HOME or ${HOME} before a relative name and
// no other expansion. Any other expansion, an absolute or home-form rest, or
// a body that holds the marker byte stays a name no reader places.
func TestPatchHeaderTargetPlacesOnlyALoneLeadingHome(t *testing.T) {
	for _, tc := range []struct {
		body, want string
		placed     bool
	}{
		{"*** Add File: $HOME/.ssh/authorized_keys\n", "~/.ssh/authorized_keys", true},
		{"*** Add File: ${HOME}/.bashrc\n", "~/.bashrc", true},
		{"*** Add File: $HOME$X/.bashrc\n", "", false},
		{"*** Add File: $HOME/$X\n", "", false},
		{"*** Add File: $HOME//etc/passwd\n", "", false},
		{"*** Add File: ${HOME:-/tmp}/.bashrc\n", "", false},
		{"*** Add File: ${#HOME}/.bashrc\n", "", false},
		{"*** Add File: $PWD/.bashrc\n", "", false},
		{"*** Add File: \\$HOME/.bashrc\n", "", false},
		{"*** Add File: $HOME/.bashrc\n+\x01\n", "", false},
	} {
		file := mustParsePOSIXHeredocBody(t, "apply_patch <<P\n"+tc.body+"P\n")
		text, _, _ := posixHeredocText(file, false, false)
		name := patchDirectivePath(firstLine(text), "*** Add File: ")
		got, placed := patchHeaderTarget(name, patchView{shellView: true})
		if placed != tc.placed || placed && got != tc.want {
			t.Errorf("%q: %q placed %v, want %q placed %v", tc.body, got, placed, tc.want, tc.placed)
		}
	}
	// The text of an envelope no shell expands is read as written.
	if got, placed := patchHeaderTarget(patchHomeMarker+"/.bashrc", patchView{}); placed && got == "~/.bashrc" {
		t.Errorf("a non-shell envelope placed the marker under the home: %q", got)
	}
}

func mustParsePOSIXHeredocBody(t *testing.T, source string) *syntax.Word {
	t.Helper()
	file, err := syntax.NewParser(syntax.Variant(syntax.LangPOSIX)).Parse(strings.NewReader(source), "")
	if err != nil || len(file.Stmts) != 1 || len(file.Stmts[0].Redirs) != 1 || file.Stmts[0].Redirs[0].Hdoc == nil {
		t.Fatalf("%q: not one here-document command: %v", source, err)
	}
	return file.Stmts[0].Redirs[0].Hdoc
}

func firstLine(text string) string {
	line, _, _ := strings.Cut(text, "\n")
	return line
}
