// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestUnresolvedFolderPatternsAndFolderSpellingsAreTheUnknownTier is
// rel-1-0-10:GAP-0960 and GAP-0961 (cells of the s7-td327rev2 probe
// TestTD327Rev2Probe, groups G2 and G3). In a folder the call does not give
// (cd to an unset variable, or no folder from the agent), a pathname pattern
// that may match a named protected file (.ssh/id_*, .ss?/id_rsa, .aws/*), a
// key in a folder named .ssh below a parent of the home or beside it, and a
// write to DefenseClaw state spelled from the home get the unknown tier:
// alert in default, permissive and managed, block in strict and
// managed-strict, never above the in-home verdict or that tier. The
// controls are the three spellings the narrowing of 9db03c4c5d removed
// (a bare config, a read of a shell profile, a project folder named
// credentials, a source file beside a credential) and patterns that name
// nothing: they stay allowed.
func TestUnresolvedFolderPatternsAndFolderSpellingsAreTheUnknownTier(t *testing.T) {
	home, project := cdFirstFixture(t)
	user := filepath.Base(home)
	reads := []string{
		".ssh/id_*", ".ss?/id_rsa", ".ssh/id_r*a", ".ssh/id_[er]*", ".aws/*", ".aws/cred*",
		user + "/.ssh/id_rsa", "home/" + user + "/.ssh/id_rsa", "../x/.ssh/id_ed25519", user + "/.ss?/id_*",
	}
	var cells [][3]string // cwd, command, in-home form
	for _, operand := range reads {
		for _, verb := range []string{"cat %s", "cp %s /tmp/staged", "base64 %s"} {
			inner := strings.Replace(verb, "%s", operand, 1)
			cells = append(cells,
				[3]string{project, "cd \"$TD327_UNSET\" && " + inner, inner},
				[3]string{"", inner, inner})
		}
	}
	for _, inner := range []string{
		"echo x >> .defenseclaw/config.yaml", "echo x > .defenseclaw/hooks/h.sh", "rm -f .defenseclaw/guardrail_runtime.json",
	} {
		cells = append(cells, [3]string{project, "cd \"$TD327_UNSET\" && " + inner, inner})
	}
	controls := []string{
		"cat config", "cat .zshrc", "cat src/credentials/x.go", "cat credentials.py", "cat .defenseclaw/config.yaml",
		"cat *", "rm -f *", "cp ./* /tmp/staged", "cat */*", "cat *.go", "echo x >> out.txt",
	}
	for _, p := range gap0437Packs {
		a := gap0437Server(t, p, "claudecode", "action")
		tier := "L"
		if strings.Contains(p.name, "strict") {
			tier = "B"
		}
		for _, cell := range cells {
			oracle := cdFirstVerdict(t, a, "td-glob-"+p.name, home, cell[2])
			ceiling := oracle
			if cdFirstRank[tier] > cdFirstRank[ceiling] {
				ceiling = tier
			}
			got := cdFirstVerdict(t, a, "td-glob-"+p.name, cell[0], cell[1])
			if cdFirstRank[got] < cdFirstRank[tier] || cdFirstRank[got] > cdFirstRank[ceiling] {
				t.Errorf("%s: %q (cwd %q) is %s, want %s to %s (in the home %s)", p.name, cell[1], cell[0], got, tier, ceiling, oracle)
			}
		}
		for _, control := range controls {
			command := "cd \"$TD327_UNSET\" && " + control
			if got := cdFirstVerdict(t, a, "td-glob-"+p.name, project, command); got != "A" {
				t.Errorf("%s control %q is %s, want allow", p.name, command, got)
			}
		}
	}
}
