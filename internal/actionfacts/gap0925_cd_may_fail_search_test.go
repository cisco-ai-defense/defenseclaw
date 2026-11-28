//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestP2HookFSearchAfterACdThatMayFail pins the DET111 bar p2hookc benign
// windows (substrate-1:GAP-0925 follow-up): `cd P; grep -r ...` may run in
// the call's folder or in P. When both are static folders the search walks
// each, so an ordinary search in two credential-free folders reads nothing,
// as 1.0.10 read it; GAP-0925 read every such call as unplaced (the
// file-unknown read), and a later upload alerted chain.secret_read_then_egress.
// The attack rows still read the credentials file (now exactly, in the
// folder the cd reaches), and an unresolved cd, or an rg search, stays the
// file-unknown read.
func TestP2HookFSearchAfterACdThatMayFail(t *testing.T) {
	root := t.TempDir()
	proj := filepath.Join(root, "proj")
	home := filepath.Join(root, "home")
	for _, f := range []string{"proj/docs/a.md", "proj/src/main.go", "proj/plans/r1/COVERAGE.md",
		"home/notes/plans/r1/COVERAGE.md", "home/skills/t/reference/x.md",
		"home/.aws/credentials", "home/.config/gh/hosts.yml"} {
		p := filepath.Join(root, f)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cwd := proj
	reads := func(command string) []string {
		t.Helper()
		out := parsePOSIX(command, 1, 0)
		classifyOutput(&out)
		rec := resolveCredentialPathReadsWithin(NewCredentialWalkBudget(context.Background()), defaultCredentialPathLimits, out.credentialWords, cwd, home, out.commands, out.paths)
		var got []string
		if rec == nil {
			return nil
		}
		for _, read := range rec.reads {
			s := read.Resolved
			if s == "" {
				s = read.Value
			}
			if s == "" {
				s = "<unknown>"
			}
			got = append(got, strings.TrimPrefix(s, root))
		}
		return got
	}
	// Benign: red at 3c3fa4365f (a <unknown> read), none here.
	for _, command := range []string{
		// w64: a search of a skills folder, then a listing.
		"cd " + home + `/skills/t; grep -rn "Codex on Bedrock" --include=*.md . | head -5 | cut -c1-200; ls reference | head -30`,
		"cd " + home + `/skills/t; grep -rln "amazon-bedrock\|multi_agent" . 2>/dev/null | head;`,
		// w72: a cd to the call's own folder, then a search of it.
		"cd " + proj + `; grep -rn "exclude_groups" . 2>/dev/null | grep -v _test | head -8 | cut -c1-260`,
		// w208: a cd to a home folder, then a recursive search of one file.
		"cd ~/notes; ls plans | head -30; grep -n -i 'omnigent' plans/r1/COVERAGE.md | head -8; grep -rn -i 'omnigent' plans/r1/COVERAGE.md | head -5",
		// The bar's fixture: the cd target is not there.
		"cd " + root + "/nothere; grep -rn TODO .",
		"cd " + proj + "/docs; cd ../src; grep -rn TODO .",
	} {
		if got := reads(command); len(got) != 0 {
			t.Errorf("%q: reads %v, want none (1.0.10 reads none)", command, got)
		}
	}
	// The bar hook gave no folder (its transcript folder is not on the box):
	// the search that stays reads nothing there, as one that does not cd
	// does, and the folder the cd reaches is still walked.
	cwd = ""
	for _, command := range []string{
		"cd " + root + "/nothere; grep -rn TODO .",
		"cd " + proj + "; grep -rn exclude_groups . 2>/dev/null | head -8",
		"cd ~/notes; grep -rn -i omnigent plans/r1/COVERAGE.md | head -5",
		"grep -rn TODO .",
	} {
		if got := reads(command); len(got) != 0 {
			t.Errorf("no hook folder: %q: reads %v, want none (1.0.10 reads none)", command, got)
		}
	}
	if got := reads("cd ~/.config; grep -r oauth_token gh"); !slices.Contains(got, "/home/.config/gh/hosts.yml") {
		t.Errorf("no hook folder: the folder the cd reaches: reads %v, want /home/.config/gh/hosts.yml", got)
	}
	cwd = proj
	// Attack rows: the credentials file is read in the folder the cd reaches.
	for _, row := range []struct{ command, want string }{
		{"cd ~/.config; grep -r oauth_token gh", "/home/.config/gh/hosts.yml"},
		{"cd " + home + "; grep -r aws_secret_access_key .aws", "/home/.aws/credentials"},
		{"cd ~; grep -rl aws_secret_access_key .", "/home/.aws/credentials"},
		{"cd " + proj + "/docs; cd ../../home && grep -r aws_secret_access_key .aws", "/home/.aws/credentials"},
		// Unresolved folders and rg keep the file-unknown read.
		{`cd "$D"; grep -r oauth_token .`, "<unknown>"},
		{"cd " + proj + `/docs; cd "$D" && grep -r oauth_token .`, "<unknown>"},
		{"cd ~/.config; rg -uu oauth_token gh", "<unknown>"},
	} {
		if got := reads(row.command); !slices.Contains(got, row.want) {
			t.Errorf("%q: reads %v, want %s", row.command, got, row.want)
		}
	}
}
