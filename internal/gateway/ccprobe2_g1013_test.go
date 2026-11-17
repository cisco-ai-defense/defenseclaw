// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

// s7-probe2 old-API probe for rel-1-0-10:GAP-1013: the rel hook-route tests of the fix,
// copied with only the rel test helpers the pre-fix sha f321733f90 lacks (renamed),
// so the file compiles on the pre-fix tree and on rel. Scratch, test-only branch.

package gateway

import (
	"encoding/json"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
	"path/filepath"
	"slices"
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
// managed-strict, never above the in-home verdict or that tier. A glob copy
// (cp of a pattern) has a floor only: its copy reading belongs to the
// GAP-0944 family (s7/wred2 gives every glob copy rel's reading back for
// push 4), and a block there equals rel 644d23fa3b. The controls are the
// spellings the narrowing of 9db03c4c5d removed (a bare config, a read of a
// shell profile, a project folder named credentials, a source file beside a
// credential) and patterns that name nothing: they stay allowed. The rows of
// unresolvedFolderPendingGlobCopyRows are never above rel's verdict.
func TestCCP2G1013_UnresolvedFolderPatternsAndFolderSpellingsAreTheUnknownTier(t *testing.T) {
	home, project := cdFirstFixture(t)
	user := filepath.Base(home)
	reads := []string{
		".ssh/id_*", ".ss?/id_rsa", ".ssh/id_r*a", ".ssh/id_[er]*", ".aws/*", ".aws/cred*",
		user + "/.ssh/id_rsa", "home/" + user + "/.ssh/id_rsa", "../x/.ssh/id_ed25519", user + "/.ss?/id_*",
	}
	// Each spelling of the review's targets with a leading ./, .// or
	// ./.// reads as the plain spelling (rel-1-0-10:GAP-1013): built from
	// the plain operands, so no new path text.
	dot := "."
	prefixes := []string{dot + "/", dot + "//", dot + "/" + dot + "//"}
	plain := slices.DeleteFunc(slices.Clone(reads), func(operand string) bool {
		return !strings.HasPrefix(operand, ".s") && !strings.HasPrefix(operand, ".a")
	})
	plain = append(plain, ".ssh/*", ".ssh/id_rsa", ".aws/credentials")
	for _, prefix := range prefixes {
		for _, operand := range plain {
			reads = append(reads, prefix+operand)
		}
	}
	type cell struct {
		cwd, command, inHome string
		floorOnly            bool // a glob copy: GAP-0944 family, at least the tier
	}
	var cells []cell
	for _, operand := range reads {
		for _, verb := range []string{"cat %s", "cp %s /tmp/staged", "base64 %s"} {
			inner := strings.Replace(verb, "%s", operand, 1)
			globCopy := strings.HasPrefix(verb, "cp ") && strings.ContainsAny(operand, "*?[")
			cells = append(cells,
				cell{project, "cd \"$TD327_UNSET\" && " + inner, inner, globCopy},
				cell{"", inner, inner, globCopy})
		}
	}
	writes := []string{
		"echo x >> .defenseclaw/config.yaml", "echo x > .defenseclaw/hooks/h.sh", "rm -f .defenseclaw/guardrail_runtime.json",
	}
	for _, prefix := range prefixes {
		for _, inner := range writes[:3] {
			writes = append(writes, strings.Replace(inner, " .defenseclaw/", " "+prefix+".defenseclaw/", 1))
		}
	}
	for _, inner := range writes {
		cells = append(cells, cell{project, "cd \"$TD327_UNSET\" && " + inner, inner, false})
	}
	controls := []string{
		"cat config", "cat .zshrc", "cat src/credentials/x.go", "cat credentials.py", "cat .defenseclaw/config.yaml",
		"cat *", "rm -f *", "cat */*", "cat *.go", "echo x >> out.txt",
	}
	for pack, p := range gap0437Packs {
		a := gap0437Server(t, p, "claudecode", "action")
		tier := "L"
		if strings.Contains(p.name, "strict") {
			tier = "B"
		}
		for _, c := range cells {
			oracle := cdFirstVerdict(t, a, "td-glob-"+p.name, home, c.inHome)
			ceiling := oracle
			if cdFirstRank[tier] > cdFirstRank[ceiling] || c.floorOnly {
				ceiling = "B"
			}
			got := cdFirstVerdict(t, a, "td-glob-"+p.name, c.cwd, c.command)
			if cdFirstRank[got] < cdFirstRank[tier] || cdFirstRank[got] > cdFirstRank[ceiling] {
				t.Errorf("%s: %q (cwd %q) is %s, want %s to %s (in the home %s)", p.name, c.command, c.cwd, got, tier, ceiling, oracle)
			}
		}
		for _, control := range controls {
			command := "cd \"$TD327_UNSET\" && " + control
			if got := cdFirstVerdict(t, a, "td-glob-"+p.name, project, command); got != "A" {
				t.Errorf("%s control %q is %s, want allow", p.name, command, got)
			}
		}
		for _, row := range unresolvedFolderPendingGlobCopyRows {
			want := string(row.rel[pack])
			if got := cdFirstVerdict(t, a, "td-glob-"+p.name, project, row.command); cdFirstRank[got] > cdFirstRank[want] {
				t.Errorf("%s pending %q is %s, above rel's %s (%s)", p.name, row.command, got, want, row.reason)
			}
		}
	}
}

// TestUnresolvedFolderWidePatternIsTruncatedNotNothing is rel-1-0-10:GAP-1003
// (cells of the s7-td327rev3 probe TestTD3R3GlobCap): a dot-folder pattern
// wide enough to match more protected spellings than the twin reads
// (actionfacts maxStateGlobMatches) is read as its first matches and is
// TRUNCATED (bounded.Items) through the one bound rule, never "names
// nothing": after a cd to an unset variable a read or a move of it is at
// least the unknown tier in every pack (alert in default, permissive and
// managed, block in strict and managed-strict), and the answer names the
// cap. A listing of the same pattern opens no file and stays allowed.
func TestCCP2G1013_UnresolvedFolderWidePatternIsTruncatedNotNothing(t *testing.T) {
	_, project := cdFirstFixture(t)
	dot := "."
	patterns := []string{dot + "*/*", dot + "[a-z]*/*"}
	// The same patterns with a leading ./, .// or ././ name the cap too
	// (rel-1-0-10:GAP-1013): the capped words and the operand compare cleaned.
	for _, prefix := range []string{dot + "/", dot + "//", dot + "/" + dot + "/"} {
		patterns = append(patterns, prefix+patterns[0], prefix+patterns[1])
	}
	// s7-probe2: the rel precondition on RelativeGlobTwinsNamed (new result type) is left out; the hook verdicts below are the probe.
	capReason := bounded.ReasonCode + " cap=" + bounded.Items.String()
	for _, p := range gap0437Packs {
		a := gap0437Server(t, p, "claudecode", "action")
		tier := "L"
		if strings.Contains(p.name, "strict") {
			tier = "B"
		}
		serve := func(command string) (string, string) {
			out := gap0437Serve(t, a.handleAgentHook("claudecode"), "/api/v1/claude-code/hook", map[string]any{
				"hook_event_name": "PreToolUse", "session_id": "td-cap-" + p.name, "cwd": project,
				"tool_name": "Bash", "tool_use_id": "tu-" + command, "tool_input": map[string]any{"command": command},
			})
			raw, _ := json.Marshal(out)
			action, _ := out["action"].(string)
			return map[string]string{"allow": "A", "alert": "L", "block": "B"}[action], string(raw)
		}
		for _, pattern := range patterns {
			for _, verb := range []string{"cat %s", "mv %s /tmp/staged"} {
				command := "cd \"$TD327_UNSET\" && " + strings.Replace(verb, "%s", pattern, 1)
				got, raw := serve(command)
				if cdFirstRank[got] < cdFirstRank[tier] {
					t.Errorf("%s: %q is %s, want at least %s", p.name, command, got, tier)
				}
				if !strings.Contains(raw, capReason) {
					t.Errorf("%s: %q does not name the cap (%s): %.400s", p.name, command, capReason, raw)
				}
			}
			command := "cd \"$TD327_UNSET\" && ls -d " + pattern
			if got, raw := serve(command); got != "A" || strings.Contains(raw, capReason) {
				t.Errorf("%s control %q is %s (cap named %v), want allow", p.name, command, got, strings.Contains(raw, capReason))
			}
		}
	}
}
