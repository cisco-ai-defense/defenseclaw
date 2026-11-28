// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
)

// gap1156PaddedCommand puts a protected alias after more than 32 distinct
// private-home path words and inside a call past the statement budget.
func gap1156PaddedCommand(statement string, wrapped bool) string {
	var out strings.Builder
	if wrapped {
		out.WriteString("w() { ")
	}
	for i := 0; i < 88; i++ {
		if i == 44 {
			out.WriteString(statement)
			out.WriteString(";")
		}
		fmt.Fprintf(&out, "test -e f%d && :;", i)
	}
	if wrapped {
		out.WriteString(" }; w")
	}
	return out.String()
}

func TestGAP1156OverBudgetActorLinkFactPriority(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX gateway")
	}
	rows := []struct {
		name, statement, factWord, rule string
		shape                           int
		wrapped                         bool
	}{
		{"ssh write", "echo x >> ak-link", "ak-link", "persistence.ssh_authorized_keys_command", 5, false},
		{"state and key", "echo x >> dc-link; cat a/b/ssh/id_ed25519", "a/b/ssh/id_ed25519", "PATH-SSH-KEY", 5, true},
		{"claude ssh write", "echo x >> ak-link", "ak-link", "persistence.ssh_authorized_keys_command", 0, false},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			s := gap0545Shapes()[row.shape]
			_, actor, home, app := gap0545API(t, s.connector, "default")
			command := gap1156PaddedCommand(row.statement, row.wrapped)
			host, _ := json.Marshal(s.body(command, app))
			guest, _ := json.Marshal(s.body(command, sandboxauth.SandboxHome+"/app"))
			facts := gap0545KitFacts(t, s.connector, s.event, host, home)
			if facts == nil || !facts.Truncated || !slices.ContainsFunc(facts.Paths, func(p SubstratePathFact) bool {
				return p.Field == kit.CommandWordField && p.Path == row.factWord && p.Resolved != ""
			}) {
				t.Fatalf("kit lost the protected alias fact: paths=%d truncated=%v", len(facts.Paths), facts.Truncated)
			}
			for _, c := range []struct{ pack, mode string }{
				{"default", "action"}, {"strict", "action"}, {"permissive", "action"}, {"default", "observe"},
			} {
				t.Run(c.pack+"/"+c.mode, func(t *testing.T) {
					api, _, _, _ := gap0545API(t, s.connector, c.pack)
					api.scannerCfg.Guardrail.Mode = c.mode
					action, rules := gap0545Verdict(t, api, gap0545Actor(actor, s.connector, s.event, guest, facts), s, guest)
					if action != "block" || !slices.Contains(rules, row.rule) {
						t.Errorf("actor %s %v, want block with %s", action, rules, row.rule)
					}
				})
			}
		})
	}
}
