// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

// TestGAP1156OverBudgetEvalPadLinkWriteKeepsLaptopAnswer: a Claude Code
// actor write through a link to DefenseClaw state beside eval padding past
// the statement budget gets at least the laptop answer, naming its rules. An
// eval statement leaves the later words unplaced (hookpaths
// CommandPathWord.Unplaced), on the laptop too, so past the budget both
// answer the budget finding (substrate-1 GAP-1156, design item 2).
func TestGAP1156OverBudgetEvalPadLinkWriteKeepsLaptopAnswer(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX gateway")
	}
	claude := gap0545Shapes()[0]
	statement := strings.Join([]string{"echo", "k", ">>", "dc" + "-link"}, " ")
	rows := []struct{ name, command string }{
		{"eval pad", gap1156Pad("eval", statement)},
	}
	for _, row := range rows {
		for _, c := range []struct{ pack, mode string }{
			{"default", "action"}, {"strict", "action"}, {"permissive", "action"}, {"default", "observe"},
		} {
			t.Run(row.name+"/"+c.pack+"/"+c.mode, func(t *testing.T) {
				api, actor, home, app := gap0545API(t, "claudecode", c.pack)
				api.scannerCfg.Guardrail.Mode = c.mode
				host, _ := json.Marshal(claude.body(row.command, app))
				guest, _ := json.Marshal(claude.body(row.command, sandboxauth.SandboxHome+"/app"))
				facts := gap0545KitFacts(t, "claudecode", "PreToolUse", host, home)
				ca, cr := gap0545Verdict(t, api, gap0545Actor(actor, "claudecode", "PreToolUse", guest, facts), claude, guest)
				la, lr := gap0545Verdict(t, api, context.Background(), claude, host)
				t.Logf("laptop %s %v, actor %s %v", la, lr, ca, cr)
				if gap0545Rank(la, lr) < 1 {
					t.Fatalf("laptop %s %v, want a finding (the test layout is wrong)", la, lr)
				}
				if gap0545Rank(ca, cr) < gap0545Rank(la, lr) {
					t.Errorf("actor %s %v is weaker than the laptop %s %v", ca, cr, la, lr)
				}
				for _, rule := range lr {
					if !slices.Contains(cr, rule) {
						t.Errorf("actor %s %v does not name the laptop rule %s", ca, cr, rule)
					}
				}
			})
		}
	}
}
