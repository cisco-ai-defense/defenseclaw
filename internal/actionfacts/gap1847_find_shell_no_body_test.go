// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

// rel-1-0-10:GAP-1847: a find -exec shell child with no -c body runs code
// the call does not show (its standard input, or the handed file as a
// script), so it may change the entries it is handed, as in 1.0.10; only a
// -c body the effects frontend reads can make it a reader (GAP-1327).
// Fail-before: red at det111/engine-train-2 b9afab1ef9 (a bare shell child
// read as "every effect a read").
func TestGAP1847FindShellChildWithoutInlineBodyMayChange(t *testing.T) {
	for _, argv := range [][]string{
		{"find", "/", "-name", "*.txt", "-exec", "/bin/sh", ";"},
		{"find", "/", "-name", "*.txt", "-exec", "sh", "{}", ";"},
		{"find", "/home/alice/.defenseclaw", "-type", "f", "-exec", "bash", "{}", "+"},
		{"find", "/home/alice/.defenseclaw", "-type", "f", "-exec", "sh", "-e", "{}", ";"},
		{"find", "/home/alice/.defenseclaw", "-type", "f", "-exec", "dash", "-s", ";"},
	} {
		if !FindHandedEntries(argv).MayChange {
			t.Errorf("%q: MayChange false, want true (the shell runs code the call does not show)", argv)
		}
	}
	// the GAP-1327 reader keeps its reading
	if FindHandedEntries([]string{"find", "/home/alice/.defenseclaw/hooks", "-type", "f", "-exec", "sh", "-c", `for f do printf "%s " "$f"; sha256sum "$f"; done`, "sh", "{}", "+"}).MayChange {
		t.Errorf("GAP-1327 read body: MayChange true, want false")
	}
}
