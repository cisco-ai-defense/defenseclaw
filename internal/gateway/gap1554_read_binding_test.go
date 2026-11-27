// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"path/filepath"
	"strings"
	"testing"
)

// rel-1-0-10:GAP-1554 class 2: a read from a here-string binds the variable
// the next command uses (the path, the program, or the whole command for
// bash -c or a bash read loop), so the call takes the plain delete cell in
// every tier. The guardrail evaluates
// these calls; it never executes their commands.
func TestGAP1554ReadBindingFiveTiers(t *testing.T) {
	home := det111R1Home(t)
	cwd := filepath.Join(home, "proj")
	rows := []struct{ name, command string }{
		{"read binds the path", `read -r x <<< /home/alice/.defenseclaw; rm -rf "$x"`},
		{"read binds the program", `read -r s <<< bash; "$s" <<< 'rm -rf /home/alice/.defenseclaw'`},
		{"read binds the command for bash -c", `read -r x <<< 'rm -rf /home/alice/.defenseclaw'; bash -c "$x"`},
		{"read loop feeds each line to bash", `while read -r l; do bash <<< "$l"; done <<< 'rm -rf /home/alice/.defenseclaw'`},
	}
	benign := []struct{ name, command string }{
		{"read binds a project path", `read -r x <<< /home/alice/proj/tmp; rm -rf "$x"`},
		{"read binds the protected path for printf", `read -r x <<< /home/alice/.defenseclaw; printf '%s\n' "$x"`},
		{"read binds a project command for bash -c", `read -r x <<< 'rm -rf /home/alice/proj/tmp'; bash -c "$x"`},
	}
	for _, tier := range boundedTestTiers {
		for _, route := range det111R1Routes() {
			api := det111R1API(t, route.connector, tier.posture, tier.managed, tier.tier)
			useDefaultEffectsLane(t)
			plain := route.decide(t, api, t.Context(), cwd, "rm -rf "+filepath.Join(home, ".defenseclaw"))
			for _, row := range rows {
				got := route.decide(t, api, t.Context(), cwd, strings.ReplaceAll(row.command, "/home/alice", home))
				if got != plain {
					t.Errorf("%s %s %s: %s, want plain delete cell %s", tier.name, route.name, row.name, got, plain)
				}
			}
			for _, row := range benign {
				useEffectsRulesMode(t, "off")
				off := route.decide(t, api, t.Context(), cwd, strings.ReplaceAll(row.command, "/home/alice", home))
				useDefaultEffectsLane(t)
				on := route.decide(t, api, t.Context(), cwd, strings.ReplaceAll(row.command, "/home/alice", home))
				if on != off {
					t.Errorf("%s %s benign %s: lane-on %s, lane-off %s", tier.name, route.name, row.name, on, off)
				}
			}
		}
	}
}
