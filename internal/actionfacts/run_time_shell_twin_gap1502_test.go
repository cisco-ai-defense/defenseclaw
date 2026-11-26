// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"strings"
	"testing"
)

// TestGAP1502WrittenScriptTwin: a later statement that runs a file an earlier
// statement wrote from known text runs that text, so the twin runs it in
// place: bash -c TEXT for a shell or a path program, a group for source and .
// (rel-1-0-10:GAP-1502). The last write before the run counts; a write the
// reading does not know, a file run by another interpreter or never run, and
// a run before the write give no reading of the file.
func TestGAP1502WrittenScriptTwin(t *testing.T) {
	rows := []struct{ command, want string }{
		{"cat > x <<'EOF'\nmake\nEOF\nsh x", "bash -c 'make\n'"},
		{"cat > x <<'EOF'\nmake\nEOF\nsudo bash ./x", "bash -c 'make\n'"},
		{"cat > x <<'EOF'\nmake\nEOF\n. x", "{ make\n}"},
		{"cat > x <<'EOF'\nmake\nEOF\nbuiltin source x", "{ make\n}"},
		{"echo make > x; ./x", "bash -c 'make\n'"},
		{"tee x <<< make >/dev/null; sh x", "bash -c 'make\n'"},
		{"cat > x <<'EOF'\n#!/bin/bash\nmake\nEOF\n./x", "bash -c '#!/bin/bash\nmake\n'"},
		{"echo ls > x; echo make > x; sh x", "bash -c 'make\n'"},
	}
	for _, row := range rows {
		got, ok, _, _ := RunTimeShellTwin(row.command)
		if !ok || !strings.HasSuffix(got, row.want) {
			t.Errorf("RunTimeShellTwin(%q) = %q, %v; want it to end in %q", row.command, got, ok, row.want)
		}
	}
	for _, command := range []string{
		"cat > x <<'EOF'\nmake\nEOF\npython3 x",
		"cat > x <<'EOF'\n#!/usr/bin/env python3\nprint(1)\nEOF\n./x",
		"cat > x <<EOF\n$(date)\nEOF\nsh x",
		"sh x; echo make > x",
		"cat > x <<'EOF'\nmake\nEOF\nsh y",
		"cat f > x; sh x",
		"echo make > \"$F\"; sh x",
	} {
		if got, ok, _, _ := RunTimeShellTwin(command); ok {
			t.Errorf("RunTimeShellTwin(%q) = %q; want no reading", command, got)
		}
	}
}
