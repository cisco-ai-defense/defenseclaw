// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// gap1156OpenPad is gap1156Pad with two more pad kinds: tests of present
// links to an ordinary file in the folder ("link"), and tests of a missing
// file and of such a link ("test-link"). The statement is in the middle, so
// 44 present links come before it.
func gap1156OpenPad(kind, statement string) string {
	var out strings.Builder
	for i := range 88 {
		if i == 44 {
			out.WriteString(statement)
			out.WriteString("; ")
		}
		switch kind {
		case "link":
			fmt.Fprintf(&out, "test -e bl%d && :; ", i)
		case "test-link":
			fmt.Fprintf(&out, "test -e f%d && test -e bl%d && :; ", i, i)
		default:
			fmt.Fprintf(&out, "test -e f%d && :; ", i)
		}
	}
	out.WriteString(":")
	return out.String()
}

// TestGAP1156OverBudgetOpenFolderKeepsUnderBudgetAnswer: a Claude Code actor
// call past the statement budget run in a folder outside the actor's home
// (an opened project folder) is answered at least as the same statement
// alone is, naming its rules (substrate-1 GAP-1156, design item 4). There no
// missing pad word sits in a private home folder, so the kit's ask pass must
// itself count the words that may reach a protected file (a hard link, a
// place in the SSH folder), and a link to protected state must keep a late
// slot when present links to ordinary files fill the facts. The answer is
// never above the stronger of the statement alone and the budget answer
// without the kit facts.
func TestGAP1156OverBudgetOpenFolderKeepsUnderBudgetAnswer(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX gateway")
	}
	claude := gap0545Shapes()[0]
	keys := "authorized" + "_keys"
	state := "dc" + "-link"
	rows := []struct{ name, statement, pad string }{
		{"hard link write", strings.Join([]string{"echo", "k", ">>", "hl"}, " "), "test"},
		{"cd ssh folder write", strings.Join([]string{"cd", "~/" + ".ssh", "&&", "echo", "k", ">>", keys}, " "), "test"},
		{"shell string hard link write", strings.Join([]string{"sh", "-c", `"` + strings.Join([]string{"echo", "k", ">>", "hl"}, " ") + `"`}, " "), "test"},
		{"state link write link pad", strings.Join([]string{"echo", "x", ">>", state}, " "), "link"},
		{"state link write test-link pad", strings.Join([]string{"echo", "x", ">>", state}, " "), "test-link"},
	}
	for _, row := range rows {
		for _, c := range []struct{ pack, mode string }{
			{"default", "action"}, {"strict", "action"}, {"permissive", "action"}, {"default", "observe"},
		} {
			t.Run(row.name+"/"+c.pack+"/"+c.mode, func(t *testing.T) {
				api, actor, home, _ := gap0545API(t, "claudecode", c.pack)
				api.scannerCfg.Guardrail.Mode = c.mode
				work := filepath.Join(t.TempDir(), "work")
				if err := os.MkdirAll(work, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Link(filepath.Join(home, ".ssh", keys), filepath.Join(work, "hl")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(home, ".defenseclaw", "config.yaml"), filepath.Join(work, state)); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(work, "README.md"), []byte("r\n"), 0o644); err != nil {
					t.Fatal(err)
				}
				for i := range 88 {
					if err := os.Symlink("README.md", filepath.Join(work, fmt.Sprintf("bl%d", i))); err != nil {
						t.Fatal(err)
					}
				}
				verdict := func(command string, withFacts bool) (string, []string, *SubstrateFacts) {
					body, _ := json.Marshal(claude.body(command, work))
					var facts *SubstrateFacts
					if withFacts {
						facts = gap0545KitFacts(t, "claudecode", "PreToolUse", body, home)
					}
					a, r := gap0545Verdict(t, api, gap0545Actor(actor, "claudecode", "PreToolUse", body, facts), claude, body)
					return a, r, facts
				}
				padded := gap1156OpenPad(row.pad, row.statement)
				ua, ur, _ := verdict(row.statement, true)
				oa, or, facts := verdict(padded, true)
				ba, br, _ := verdict(padded, false)
				var proofs []string
				nf := 0
				if facts != nil {
					proofs, nf = facts.Proofs, len(facts.Paths)
				}
				t.Logf("alone %s %v, over budget %s %v (kit proofs %v, %d facts), without kit facts %s %v", ua, ur, oa, or, proofs, nf, ba, br)
				if gap0545Rank(ua, ur) < 2 {
					t.Fatalf("alone %s %v, want an alert or a block (the test layout is wrong)", ua, ur)
				}
				if gap0545Rank(oa, or) > max(gap0545Rank(ua, ur), gap0545Rank(ba, br)) {
					t.Errorf("over budget %s %v is stronger than alone %s %v and the budget answer %s %v", oa, or, ua, ur, ba, br)
				}
				if gap0545Rank(oa, or) < gap0545Rank(ua, ur) {
					t.Errorf("over budget %s %v is weaker than alone %s %v", oa, or, ua, ur)
				}
				// The key-write and state-write rules of the statement alone are named.
				for _, rule := range ur {
					named := rule == "persistence.ssh_authorized_keys_command" || rule == "tamper.detector_state_write"
					if named && !slices.Contains(or, rule) {
						t.Errorf("over budget %s %v does not name %s (alone %s %v)", oa, or, rule, ua, ur)
					}
				}
			})
		}
	}
}
