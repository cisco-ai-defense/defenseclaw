// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
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
		// An append adds to the text; a write that may not run adds its
		// text to the text before it; a run on the write's own line runs
		// the document the shell read with the line (CHK-RF-HOOKSHELL F4).
		{"cat > x <<'EOF'\nmake\nEOF\ncat >> x <<'EOF'\nmake install\nEOF\nsh x", "bash -c 'make\nmake install\n'"},
		{"echo make > x; echo 'make install' | tee -a x >/dev/null; sh x", "bash -c 'make\nmake install\n'"},
		{"cat > x <<'EOF'\nmake\nEOF\nif false; then echo ls > x; fi\nsh x", "bash -c 'make\nls\n'"},
		{"echo make > x; test -f y && echo ls > x; sh x", "bash -c 'make\nls\n'"},
		{"echo make > x; if c; then cat f > x; fi; sh x", "bash -c 'make\n'"},
		{"cat > x <<'EOF'; sh x\nmake\nEOF", "cat > x <<< 'make'; bash -c 'make\n'\n"},
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

// TestGAP1502WrittenScriptTwinIsBounded: every run of a written file copies
// its text into the twin, so the copies share one byte budget per reading
// (maxRunTimeShellCopiedBytes): a large written file run many times gives a
// twin of about the command plus the budget, the runs past it are read as
// written and the reading reports the bytes cap; what was read before the
// cap is kept (CHK-RF-HOOKSHELL F3).
func TestGAP1502WrittenScriptTwinIsBounded(t *testing.T) {
	var doc strings.Builder
	for doc.Len() < 32<<10 {
		doc.WriteString("echo building step\n")
	}
	command := "cat > s.sh <<'EOF'\n" + doc.String() + "EOF\n" + strings.Repeat("sh s.sh; ", 1000)
	started := time.Now()
	twin, ok, truncated, _ := RunTimeShellTwin(command)
	elapsed := time.Since(started)
	if !ok || !strings.Contains(twin, "bash -c 'echo building step") {
		t.Fatalf("the first run is not read: ok=%v twin starts %q", ok, twin[:min(len(twin), 80)])
	}
	if limit := len(command) + 2*maxRunTimeShellCopiedBytes; len(twin) > limit {
		t.Errorf("twin is %d bytes for a %d-byte command, want at most %d", len(twin), len(command), limit)
	}
	if !truncated.Has(bounded.Bytes) {
		t.Errorf("truncated = %v, want the bytes cap", truncated)
	}
	if elapsed > 5*time.Second {
		t.Errorf("twin took %v, want under 5s", elapsed)
	}
	// A few runs of a small file stay whole and untruncated.
	twin, ok, truncated, _ = RunTimeShellTwin("cat > s.sh <<'EOF'\nmake\nEOF\nsh s.sh; sh s.sh; sh s.sh")
	if !ok || strings.Count(twin, "bash -c 'make\n'") != 3 || truncated.Any() {
		t.Errorf("small file run three times: %q ok=%v truncated=%v", twin, ok, truncated)
	}
}
