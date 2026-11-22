// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// gap1308Rows write the Claude Code settings through a project link from a
// function body that runs in the project: the body's own cp, and a cd only
// after the call. plain names the settings file ({C}).
var gap1308Rows = []struct{ link, plain string }{
	{"f() { cp /tmp/x cfg-link; }; f", "f() { cp /tmp/x {C}; }; f"},
	{"f() { echo x > cfg-link; }; f; cd /tmp", "f() { echo x > {C}; }; f; cd /tmp"},
}

// TestGAP1308FunctionBodyLinkWritesFiveTiers: the GAP-1286 fix counted every
// change of the command for a word in a function body, so these writes were
// allowed with no finding in all five tiers on the Claude Code hook, where
// 880a799368 alerted (default) or blocked (strict, managed-strict)
// tamper.agent_hook_config_write (rel-1-0-10:GAP-1308). In each tier the
// call through the link gets the action and every rule of its plain form,
// which is no silent allow, and the GAP-1286 rows stay allowed.
func TestGAP1308FunctionBodyLinkWritesFiveTiers(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX gateway")
	}
	home, app := gap1243Layout(t)
	t.Setenv("HOME", home)
	plain := strings.NewReplacer("{C}", filepath.Join(home, ".claude", "settings.json"))
	rules := func(out map[string]any) []string {
		var ids []string
		list, _ := out["rule_ids"].([]any)
		for _, id := range list {
			if s, ok := id.(string); ok {
				ids = append(ids, s)
			}
		}
		slices.Sort(ids)
		return slices.Compact(ids)
	}
	for _, p := range gap0437Packs {
		hook := gap0437Server(t, p, "claudecode", "action")
		for i, row := range gap1308Rows {
			where := fmt.Sprintf("%s hook row %d %q", p.name, i, row.link)
			want := gap0437Hook(t, hook, app, fmt.Sprintf("gap1308-%s-p%d", p.name, i), plain.Replace(row.plain))
			got := gap0437Hook(t, hook, app, fmt.Sprintf("gap1308-%s-l%d", p.name, i), row.link)
			if want["action"] == "allow" && len(rules(want)) == 0 {
				t.Errorf("%s: plain form allowed with no finding, want a finding", where)
				continue
			}
			if got["action"] != want["action"] {
				t.Errorf("%s: action %v rules %v, want the plain form's %v rules %v",
					where, got["action"], rules(got), want["action"], rules(want))
				continue
			}
			for _, rule := range rules(want) {
				if !slices.Contains(rules(got), rule) {
					t.Errorf("%s: rules %v, want every rule of the plain form %v", where, rules(got), rules(want))
					break
				}
			}
		}
		for i, command := range gap1286Rows {
			out := gap0437Hook(t, hook, app, fmt.Sprintf("gap1308-%s-b%d", p.name, i), command)
			if out["action"] != "allow" || len(rules(out)) != 0 {
				t.Errorf("%s hook GAP-1286 row %d %q: action %v rules %v, want allow with no finding",
					p.name, i, command, out["action"], rules(out))
			}
		}
	}
}
