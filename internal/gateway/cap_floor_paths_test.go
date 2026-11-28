// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// capFloorGrepChain is a benign && chain of n reads of project files.
func capFloorGrepChain(n int) string {
	words := make([]string, n)
	for i := range words {
		words[i] = fmt.Sprintf("grep -n pattern%d src/file%d.go", i, i)
	}
	return strings.Join(words, " && ")
}

// TestCapFloorProjectPathPiecesAreNotTwins: past the analysis cap the floor
// judges the pieces that may name something outside the project, not every
// piece with a slash (rel-1-0-10:GAP-0844). A chain of reads of plain project
// paths has no piece twin in a per-user reading; a managed hook call, whose
// gateway does not read the user home, judges them all as before; and a
// project path that meets a link, a parent folder, an absolute path or a
// value built at run time is still a piece. On Windows the floor trusts no
// project path (capFloorRegion.mayLeave): every piece with a slash may leave,
// so a per-user reading judges them all as a managed one does
// (rel-1-0-10:GAP-1523).
func TestCapFloorProjectPathPiecesAreNotTwins(t *testing.T) {
	env := boundedLaneEnvAnyOS(t)
	command := capFloorGrepChain(200)
	head, tail, _ := capFloorPieces(command, env.home)
	if runtime.GOOS == "windows" {
		if picked, more := capFloorPick(head, tail, command, env.cwd, env.home, true, true, capFloorMaxTwins); len(picked) != capFloorMaxTwins || !more {
			t.Fatalf("per-user on Windows: %d piece twins (more %v), want %d and more", len(picked), more, capFloorMaxTwins)
		}
		region := &capFloorRegion{walk: true, cwd: env.cwd, home: env.home, paths: map[string]capFloorPathKind{}}
		for _, statement := range []string{
			"grep -n pattern0 src/file0.go", "cat keys/id_ed25519", "cat src/../../.ssh/id_ed25519", "cat /etc/hosts",
			"cat $HOME/x", "cat ~/x", "cat 'src/a b'", "cat src/*.go", "scp src/a host:b", "tar -C/tmp -xf src/a",
		} {
			if !region.mayLeave(statement) {
				t.Errorf("%q: a project path piece is trusted on Windows", statement)
			}
		}
		return
	}
	if picked, _ := capFloorPick(head, tail, command, env.cwd, env.home, true, true, capFloorMaxTwins); len(picked) != 0 {
		t.Fatalf("per-user: %d piece twins of plain project paths, want 0: %v", len(picked), picked[0].text(command))
	}
	if picked, more := capFloorPick(head, tail, command, env.cwd, env.home, true, false, capFloorMaxTwins); len(picked) != capFloorMaxTwins || !more {
		t.Fatalf("managed: %d piece twins (more %v), want %d and more", len(picked), more, capFloorMaxTwins)
	}
	if err := os.MkdirAll(filepath.Join(env.cwd, "src"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(env.home, ".ssh"), filepath.Join(env.cwd, "keys")); err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		"cat keys/id_ed25519", "cat src/../../.ssh/id_ed25519", "cat /etc/hosts", "cat $HOME/x", "cat ~/x",
		"cat 'src/a b'", "cat src/*.go", "scp src/a host:b", "tar -C/tmp -xf src/a",
	} {
		chained := capFloorGrepChain(100) + " && " + statement + " && " + capFloorGrepChain(100)
		head, tail, _ := capFloorPieces(chained, env.home)
		picked, _ := capFloorPick(head, tail, chained, env.cwd, env.home, true, true, capFloorMaxTwins)
		if len(picked) != 1 || picked[0].text(chained) != statement {
			var texts []string
			for _, p := range picked {
				texts = append(texts, p.text(chained))
			}
			t.Errorf("%q: piece twins %q, want just the statement", statement, texts)
		}
	}
}

// TestCapFloorLinkedProjectPathKeepsItsBlock: a read of a private key
// through a project link keeps its own verdict inside a call the analysis
// cannot read, as for the key named directly (GAP-0688, GAP-0844).
func TestCapFloorLinkedProjectPathKeepsItsBlock(t *testing.T) {
	env := boundedLaneEnvAnyOS(t)
	sshDir := filepath.Join(env.home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sshDir, "id_ed25519"), []byte("fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A Windows standard user may not create the link: the test runs in the
	// elevated native leg there (testenv.Symlink skips without the right).
	testenv.Symlink(t, sshDir, filepath.Join(env.cwd, "keys"))
	statement := "cat keys/id_ed25519"
	for _, tier := range boundedTestTiers {
		if tier.managed {
			continue
		}
		api := boundedTierAPI(t, tier.posture, tier.managed, tier.tier)
		alone, _ := boundedDecideClaudeCode(t, api, env, boundedShellCommand(statement))
		for name, command := range map[string]string{
			"nest": strings.Repeat("(", 64) + statement + strings.Repeat(")", 64),
			// Past the analysis depth, under the statement budget.
			"chain": capFloorGrepChain(40) + " && " + statement + " && " + capFloorGrepChain(40),
		} {
			action, findings := boundedDecideClaudeCode(t, api, env, boundedShellCommand(command))
			want := max(boundedParse(alone), bounded.Unknown(tier.tier))
			if got := boundedParse(action); got < want {
				t.Errorf("%s %s: action=%s, want at least %s (alone: %s); findings=%v", tier.name, name, action, want, alone, findings)
			}
		}
	}
}
