// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// gap1324Tree makes dir with folders empty folders b000...: the pattern
// dir/b*/c* reads dir and each of them, folders+1 directory reads.
func gap1324Tree(t *testing.T, dir string, folders int) {
	t.Helper()
	for index := 0; index < folders; index++ {
		if err := os.MkdirAll(filepath.Join(dir, fmt.Sprintf("b%03d", index)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

// GAP-1324: the target scan's pattern walk (actionExpandGlob) that stopped at
// its read bound (actionGlobMaxReads, 64 folders) held the pattern as a
// protected target, so a benign in-home cp into w/b*/c* past 64 folders was
// the CRITICAL authorized-keys block in every tier. A walk that read every
// folder it reached and stopped only at a counted bound, with no protected
// file among its matches, is now a TRUNCATED reading (the one bound rule):
// no protected target, the cap recorded on the hook call, and the managed
// hook client sends it under GlobCapFactPrefix (never as a GlobFactPrefix
// value, which a 1.0.10 gateway refuses), so a gateway behind ProtectHome
// reads the same.
func TestGAP1324GlobWalkCapIsTruncated(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "proj")
	ssh := filepath.Join(home, ".ssh")
	for _, dir := range []string{project, ssh} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(ssh, "authorized_keys"), []byte("ssh-ed25519 AAAA test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// 63 folders: 64 reads, at the bound. 64 folders: 65 reads, past it.
	gap1324Tree(t, filepath.Join(project, "at"), 63)
	gap1324Tree(t, filepath.Join(project, "past"), 64)
	// A folder alias of ~/.ssh among the folders under the bound is still
	// read and is still a protected target.
	alias := filepath.Join(project, "alias")
	gap1324Tree(t, alias, 10)
	if err := os.Symlink(ssh, filepath.Join(alias, "b999")); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		command, decision, fact string
	}{
		{"cp a.txt at/b*/c*", "", "0"},
		{"cp a.txt past/b*/c*", "", "cap"},
		{"cp a.txt alias/b*/a*", "protected-target", "1"},
	} {
		if got := ActionCommandDecision(row.command, project, home); got != row.decision {
			t.Errorf("%q: decision %q, want %q", row.command, got, row.decision)
		}
		facts := actionGlobFacts(row.command, project, home)
		var fact string
		for key, value := range facts {
			switch {
			case strings.HasPrefix(key, GlobFactPrefix):
				fact += value
			case strings.HasPrefix(key, GlobCapFactPrefix) && value == "1":
				fact += "cap"
			}
		}
		if fact != row.fact {
			t.Errorf("%q: hook client glob fact %q, want %q (facts %q)", row.command, fact, row.fact, facts)
		}
	}
}
