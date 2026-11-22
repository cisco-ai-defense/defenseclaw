// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"fmt"
	"os"
	"slices"
	"testing"
)

// gap1286Rows write to a project link (cfg-link to the Claude Code settings)
// where the shell does not reach the settings through it: builtin cd moves
// the call to /tmp, the function body runs after the later cd, and install
// replaces the link and leaves the settings alone. rel allows them on the
// hook in every tier.
var gap1286Rows = []string{
	"builtin cd /tmp && echo x > cfg-link",
	"f() { echo x > cfg-link; }; cd /tmp; f",
	"install /tmp/x cfg-link",
}

// TestGAP1286LinkTwinLeavesWordsRunElsewhereFiveTiers: the GAP-1243 link
// twin read these words in the hook's folder and alerted (default) or
// blocked (strict, managed-strict) tamper.agent_hook_config_write on the
// Claude Code hook where rel allows (rel-1-0-10:GAP-1286). In each of the
// five tiers the hook allows them with no finding, and /inspect/tool adds no
// hook config finding (it reads them as on rel).
func TestGAP1286LinkTwinLeavesWordsRunElsewhereFiveTiers(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX gateway")
	}
	home, app := gap1243Layout(t)
	t.Setenv("HOME", home)
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
	for _, p := range gap0437Packs {
		hook := gap0437Server(t, p, "claudecode", "action")
		inspect := gap0437Server(t, p, "openclaw", "action")
		for i, command := range gap1286Rows {
			out := gap0437Hook(t, hook, app, fmt.Sprintf("gap1286-%s-%d", p.name, i), command)
			if out["action"] != "allow" || len(rules(out)) != 0 {
				t.Errorf("%s hook row %d %q: action %v rules %v, want allow with no finding",
					p.name, i, command, out["action"], rules(out))
			}
			out = gap0437Inspect(t, inspect, app, command)
			if slices.Contains(rules(out), "tamper.agent_hook_config_write") {
				t.Errorf("%s inspect row %d %q: rules %v, want no hook config finding", p.name, i, command, rules(out))
			}
		}
	}
}
