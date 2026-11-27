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

// TestGAP1156UnplacedLinkWordKeepsStateWrite: a Claude Code actor write
// through a link to DefenseClaw state after an eval statement, which leaves
// the word with no folder this gateway can place it in, names the state
// write as the same write alone does, under the statement budget (where the
// laptop names it too) and past it, beside eval padding. The gateway reads
// such a word at the one place the kit gives it (substrate-1 GAP-1156).
func TestGAP1156UnplacedLinkWordKeepsStateWrite(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX gateway")
	}
	claude := gap0545Shapes()[0]
	statement := strings.Join([]string{"echo", "k", ">>", "dc" + "-link"}, " ")
	rows := []struct{ name, command string }{
		{"one eval", "eval :; " + statement},
		{"eval pad", gap1156Pad("eval", statement)},
	}
	for _, row := range rows {
		for _, c := range []struct{ pack, mode string }{
			{"default", "action"}, {"strict", "action"}, {"permissive", "action"}, {"default", "observe"},
		} {
			t.Run(row.name+"/"+c.pack+"/"+c.mode, func(t *testing.T) {
				api, actor, home, app := gap0545API(t, "claudecode", c.pack)
				api.scannerCfg.Guardrail.Mode = c.mode
				verdict := func(command string) (string, []string) {
					host, _ := json.Marshal(claude.body(command, app))
					guest, _ := json.Marshal(claude.body(command, sandboxauth.SandboxHome+"/app"))
					facts := gap0545KitFacts(t, "claudecode", "PreToolUse", host, home)
					return gap0545Verdict(t, api, gap0545Actor(actor, "claudecode", "PreToolUse", guest, facts), claude, guest)
				}
				host, _ := json.Marshal(claude.body(row.command, app))
				la, lr := gap0545Verdict(t, api, context.Background(), claude, host)
				ua, ur := verdict(statement)
				ca, cr := verdict(row.command)
				t.Logf("laptop %s %v, alone %s %v, actor %s %v", la, lr, ua, ur, ca, cr)
				if !slices.Contains(ur, "tamper.detector_state_write") {
					t.Fatalf("alone %s %v, want the state write (the test layout is wrong)", ua, ur)
				}
				if !slices.Contains(cr, "tamper.detector_state_write") {
					t.Errorf("actor %s %v does not name the state write (alone %s %v)", ca, cr, ua, ur)
				}
				if gap0545Rank(ca, cr) < gap0545Rank(la, lr) {
					t.Errorf("actor %s %v is weaker than the laptop %s %v", ca, cr, la, lr)
				}
			})
		}
	}
}
