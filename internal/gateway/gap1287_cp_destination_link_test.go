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

// gap1287LinkRows write through a project link to the Claude Code settings
// in a cp mode that keeps links among the sources (-a, -P, -d, -R, -r): GNU
// cp still opens the destination through an existing link, so the settings
// change. Each row is checked against its plain form ({C} the settings file,
// {D} the settings folder).
var gap1287LinkRows = []struct{ link, plain string }{
	{"cp -a /tmp/x cfg-link", "cp -a /tmp/x {C}"},
	{"cp -P /tmp/x cfg-link", "cp -P /tmp/x {C}"},
	{"cp -r /tmp/x cfg-link", "cp -r /tmp/x {C}"},
	{"cp -dR /tmp/x cfg-link", "cp -dR /tmp/x {C}"},
	{"cp --archive -- /tmp/x cfg-link", "cp --archive -- /tmp/x {C}"},
	{"cp -a -t claude-link /tmp/settings.json", "cp -a -t {D} /tmp/settings.json"},
	{"cp -at claude-link /tmp/settings.json", "cp -at {D} /tmp/settings.json"},
	{"cp -a --target-directory=claude-link /tmp/settings.json", "cp -a --target-directory={D} /tmp/settings.json"},
	{"sudo cp -a /tmp/x cfg-link", "sudo cp -a /tmp/x {C}"},
}

// gap1287KeptRows leave the settings alone, as on rel: the link is a source
// cp copies as a link, or the destination entry is removed and made anew.
var gap1287KeptRows = []string{
	"cp -a cfg-link /tmp/y",
	"cp -P cfg-link /tmp/y",
	"cp -a --remove-destination /tmp/x cfg-link",
	"cp -as /tmp/x cfg-link-new",
}

// TestGAP1287CpDestinationLinkFollowedInEveryModeFiveTiers: the link twin
// marked every cp operand as not following its link once -a/-P/-d/-R/-r was
// given, so a cp in those modes onto a project link to the Claude Code
// settings was allowed with no finding in every tier while its plain form
// alerts (default) or blocks (strict, managed-strict)
// tamper.agent_hook_config_write (rel-1-0-10:GAP-1287). On the hook and on
// /inspect/tool each row gets its plain form's action, and the kept rows
// stay allowed on the hook.
func TestGAP1287CpDestinationLinkFollowedInEveryModeFiveTiers(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX gateway")
	}
	home, app := gap1243Layout(t)
	if err := os.Symlink("../.claude", filepath.Join(app, "claude-link")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	plain := strings.NewReplacer("{C}", filepath.Join(home, ".claude", "settings.json"),
		"{D}", filepath.Join(home, ".claude"))
	rules := func(out map[string]any) []string {
		var ids []string
		list, _ := out["rule_ids"].([]any)
		for _, id := range list {
			if s, ok := id.(string); ok {
				ids = append(ids, s)
			}
		}
		return ids
	}
	sawFinding := false
	for _, p := range gap0437Packs {
		hook := gap0437Server(t, p, "claudecode", "action")
		inspect := gap0437Server(t, p, "openclaw", "action")
		for i, row := range gap1287LinkRows {
			want := gap0437Hook(t, hook, app, fmt.Sprintf("gap1287-%s-p%d", p.name, i), plain.Replace(row.plain))
			got := gap0437Hook(t, hook, app, fmt.Sprintf("gap1287-%s-l%d", p.name, i), row.link)
			if slices.Contains(rules(want), "tamper.agent_hook_config_write") {
				sawFinding = true
			}
			if got["action"] != want["action"] {
				t.Errorf("%s hook row %d %q: action %v rules %v, want the plain form's %v rules %v",
					p.name, i, row.link, got["action"], rules(got), want["action"], rules(want))
			}
			wantInspect := gap0437Inspect(t, inspect, app, plain.Replace(row.plain))
			gotInspect := gap0437Inspect(t, inspect, app, row.link)
			if gotInspect["action"] != wantInspect["action"] {
				t.Errorf("%s inspect row %d %q: action %v rules %v, want the plain form's %v rules %v",
					p.name, i, row.link, gotInspect["action"], rules(gotInspect), wantInspect["action"],
					rules(wantInspect))
			}
		}
		for i, command := range gap1287KeptRows {
			out := gap0437Hook(t, hook, app, fmt.Sprintf("gap1287-%s-k%d", p.name, i), command)
			if out["action"] != "allow" || slices.Contains(rules(out), "tamper.agent_hook_config_write") {
				t.Errorf("%s hook kept row %d %q: action %v rules %v, want allow with no hook config finding",
					p.name, i, command, out["action"], rules(out))
			}
		}
	}
	if !sawFinding {
		t.Fatal("no plain form produced tamper.agent_hook_config_write: the rows do not test the link twin")
	}
}
