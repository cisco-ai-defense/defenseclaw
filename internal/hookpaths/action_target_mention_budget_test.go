// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// GAP-2279: a benign heredoc of a few hundred KB missed the hook answer
// budget because the target scan resolved every word again, walking the
// whole path (and the home) once per occurrence. Each distinct word is now
// resolved once per scan; the decision for a protected word is unchanged.
func TestLongHeredocResolvesEachDistinctWordOnce(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX home layout")
	}
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	if err := os.MkdirAll(filepath.Join(home, ".defenseclaw", "policies"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	const lines = 2000
	var body strings.Builder
	body.WriteString("cat > notes.sh <<'EOF'\n")
	for range lines {
		body.WriteString("echo line ok\n")
	}
	body.WriteString("EOF\n")
	benign := body.String()

	before := writeTargetWalks.Load()
	if ActionStateTargetMention(benign, cwd, home) {
		t.Fatal("benign heredoc named active state")
	}
	if actionProtectedTargetMentionDepth(benign, cwd, home, 0, false, nil) {
		t.Fatal("benign heredoc named a protected key")
	}
	// About ten distinct words and the home: a few dozen walks, not one
	// (or three) per word occurrence (was more than 12,000).
	if walks := writeTargetWalks.Load() - before; walks > 100 {
		t.Fatalf("%d write-target walks for %d repeated lines; want each distinct word resolved once", walks, lines)
	}

	// Distinct words cost at most one walk each per scan, plus the home.
	var numbered strings.Builder
	numbered.WriteString("cat > notes.sh <<'EOF'\n")
	for i := range lines {
		fmt.Fprintf(&numbered, "echo line %d\n", i)
	}
	numbered.WriteString("EOF\n")
	before = writeTargetWalks.Load()
	if ActionStateTargetMention(numbered.String(), cwd, home) {
		t.Fatal("numbered heredoc named active state")
	}
	if walks := writeTargetWalks.Load() - before; walks > lines+100 {
		t.Fatalf("%d write-target walks for %d distinct numbers; want at most one per distinct word", walks, lines)
	}

	// The same protected word, repeated, still decides the scan.
	protected := strings.Replace(benign, "echo line ok\n", "echo line ok > ~/.defenseclaw/policies/x\n", 3)
	if !ActionStateTargetMention(protected, cwd, home) {
		t.Fatal("repeated active-state target was not found")
	}
	keys := strings.Replace(benign, "echo line ok\n", "echo ok >> ~/.ssh/authorized_keys\n", 3)
	if !actionProtectedTargetMentionDepth(keys, cwd, home, 0, false, nil) {
		t.Fatal("repeated authorized_keys target was not found")
	}
}
