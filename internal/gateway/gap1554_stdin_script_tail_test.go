// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"path/filepath"
	"strings"
	"testing"
)

// The guardrail evaluates these calls; it never executes their commands.
func TestGAP1554StdinScriptTailFiveTiers(t *testing.T) {
	home := det111R1Home(t)
	cwd := filepath.Join(home, "proj")
	rows := []struct{ name, command string }{
		{"xargs consumes remaining script input", "bash <<'EOF'\nxargs rm -rf\n/home/alice/.defenseclaw\nEOF"},
		{"read consumes next script line", "bash <<'EOF'\nread -r p; rm -rf \"$p\"\n/home/alice/.defenseclaw\nEOF"},
	}
	benign := []struct{ name, command string }{
		{"xargs reads project path", "bash <<'EOF'\nxargs rm -rf\n/home/alice/proj/tmp\nEOF"},
		{"read prints protected path", "bash <<'EOF'\nread -r p; printf '%s\\n' \"$p\"\n/home/alice/.defenseclaw\nEOF"},
		{"literal command with no consumer", "bash <<'EOF'\nprintf '%s\\n' done\n/home/alice/.defenseclaw\nEOF"},
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
