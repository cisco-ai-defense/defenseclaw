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

// GAP-2279 on Windows: the Windows target scan (a Windows home) checked
// every word of a long heredoc again, and on Windows each check is a chain
// of file-system calls (about 1 ms), so a benign 100 KB body cost 21 s and
// a 450 KB body 94 s in the gateway. Each distinct candidate is now checked
// once per scan and directory; a repeated protected word still decides it.
func TestLongWindowsHeredocChecksEachDistinctCandidateOnce(t *testing.T) {
	const home = `C:\Users\Alice`
	const cwd = home + `\project`
	const lines = 2000
	var body strings.Builder
	body.WriteString("cat > /tmp/notes.sh <<EOF2\n")
	for range lines {
		body.WriteString("echo line benign filler for heredoc payload size\n")
	}
	body.WriteString("EOF2\n")
	benign := body.String()

	before := actionWindowsCandidateChecks.Load()
	if ActionStateTargetMention(benign, cwd, home) {
		t.Fatal("benign heredoc named active state")
	}
	if actionProtectedTargetMentionDepth(benign, cwd, home, 0, false, nil) {
		t.Fatal("benign heredoc named a protected key")
	}
	// About ten distinct words: a few dozen checks, not several per word
	// occurrence (was more than 30,000).
	if checks := actionWindowsCandidateChecks.Load() - before; checks > 200 {
		t.Fatalf("%d candidate checks for %d repeated lines; want each distinct candidate checked once", checks, lines)
	}

	const state = home + `\.defenseclaw\config.yaml`
	protected := strings.Replace(benign, "echo line benign filler for heredoc payload size\n", "echo "+state+"\n", 3)
	if !ActionStateTargetMention(protected, cwd, home) {
		t.Fatal("repeated active-state target was not found")
	}
	keys := strings.Replace(benign, "echo line benign filler for heredoc payload size\n", "echo ok >> "+home+`\.ssh\authorized_keys`+"\n", 3)
	if !actionProtectedTargetMentionDepth(keys, cwd, home, 0, false, nil) {
		t.Fatal("repeated authorized_keys target was not found")
	}
}

// GAP-2279 on Windows: the private-key read scan of a Windows command the
// word splitter cannot structure (a Bash heredoc read through cat) checked
// every word of the body as a read operand, each a chain of file-system
// calls on Windows. Each distinct operand is now checked once per
// statement; a protected key read still decides it.
func TestLongWindowsCatOperandsCheckEachDistinctOperandOnce(t *testing.T) {
	const home = `C:\Users\alice`
	const cwd = home + `\project`
	const lines = 2000
	var body strings.Builder
	body.WriteString("cat /tmp/notes.sh <<EOF2\n")
	for range lines {
		body.WriteString("echo line benign filler for heredoc payload size\n")
	}
	body.WriteString("EOF2\n")
	benign := body.String()
	before := actionPrivateReadChecks.Load()
	if ActionPrivateKeyRead(benign, cwd, home) {
		t.Fatal("benign heredoc read a private key")
	}
	if checks := actionPrivateReadChecks.Load() - before; checks > 100 {
		t.Fatalf("%d operand checks for %d repeated lines; want each distinct operand checked once", checks, lines)
	}
	keyRead := strings.Replace(benign, "echo line benign filler for heredoc payload size\n", `%USERPROFILE%\.ssh\id_ed25519`+"\n", 3)
	if !ActionPrivateKeyRead(keyRead, cwd, home) {
		t.Fatal("repeated private key operand was not found")
	}
}
