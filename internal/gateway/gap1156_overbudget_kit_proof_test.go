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

	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
)

// gap1156Pad is the padding that puts a statement past the statement
// budget: 88 statements of one pad kind, the statement in the middle.
func gap1156Pad(kind, statement string) string {
	var out strings.Builder
	for i := range 88 {
		if i == 44 {
			out.WriteString(statement)
			out.WriteString("; ")
		}
		switch kind {
		case "eval":
			out.WriteString("eval :; ")
		default:
			fmt.Fprintf(&out, "test -e f%d && :; ", i)
		}
	}
	out.WriteString(":")
	return out.String()
}

// TestGAP1156OverBudgetKitProofKeepsUnderBudgetAnswer: a Claude Code actor
// call past the statement budget whose command the kit proves a protected
// write or a private-key read of (in the actor file system) is answered at
// least as the same statement alone is, naming its rules: the budget refusal
// reads the kit whole-command proofs (substrate-1 GAP-1156). The forms are a
// write through a hard link, a write in the SSH folder after a cd, and a
// link write or read beside eval padding.
func TestGAP1156OverBudgetKitProofKeepsUnderBudgetAnswer(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX gateway")
	}
	claude := gap0545Shapes()[0]
	keys := "authorized" + "_keys"
	rows := []struct{ name, statement, pad string }{
		{"hard link write", strings.Join([]string{"echo", "k", ">>", "hl"}, " "), "test"},
		{"cd ssh folder write", strings.Join([]string{"cd", "~/" + ".ssh", "&&", "echo", "k", ">>", keys}, " "), "test"},
		{"link write eval pad", strings.Join([]string{"echo", "k", ">>", "ak" + "-link"}, " "), "eval"},
		{"link read eval pad", strings.Join([]string{"cat", "key" + "-link"}, " "), "eval"},
	}
	for _, row := range rows {
		for _, c := range []struct{ pack, mode string }{
			{"default", "action"}, {"strict", "action"}, {"permissive", "action"}, {"default", "observe"},
		} {
			t.Run(row.name+"/"+c.pack+"/"+c.mode, func(t *testing.T) {
				api, actor, home, app := gap0545API(t, "claudecode", c.pack)
				api.scannerCfg.Guardrail.Mode = c.mode
				if err := os.Link(filepath.Join(home, ".ssh", keys), filepath.Join(app, "hl")); err != nil {
					t.Fatal(err)
				}
				verdict := func(command string) (string, []string, []string) {
					host, _ := json.Marshal(claude.body(command, app))
					guest, _ := json.Marshal(claude.body(command, sandboxauth.SandboxHome+"/app"))
					facts := gap0545KitFacts(t, "claudecode", "PreToolUse", host, home)
					var proofs []string
					if facts != nil {
						proofs = facts.Proofs
					}
					a, r := gap0545Verdict(t, api, gap0545Actor(actor, "claudecode", "PreToolUse", guest, facts), claude, guest)
					return a, r, proofs
				}
				ua, ur, _ := verdict(row.statement)
				oa, or, proofs := verdict(gap1156Pad(row.pad, row.statement))
				t.Logf("alone %s %v, over budget %s %v, kit proofs %v", ua, ur, oa, or, proofs)
				if !slices.Contains(proofs, kit.ProofProtectedWrite) && !slices.Contains(proofs, kit.ProofPrivateKeyRead) {
					t.Fatalf("kit sent no whole-command proof over the budget: %v", proofs)
				}
				if gap0545Rank(ua, ur) < 2 {
					t.Fatalf("alone %s %v, want an alert or a block (the test layout is wrong)", ua, ur)
				}
				if gap0545Rank(oa, or) < gap0545Rank(ua, ur) {
					t.Errorf("over budget %s %v is weaker than alone %s %v", oa, or, ua, ur)
				}
				for _, rule := range ur {
					if rule != evaluationLimitRuleID && !slices.Contains(or, rule) {
						t.Errorf("over budget %s %v does not name %s (alone %s %v)", oa, or, rule, ua, ur)
					}
				}
			})
		}
	}
}
