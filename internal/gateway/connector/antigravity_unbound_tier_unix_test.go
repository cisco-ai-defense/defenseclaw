// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-1321 (balanced defaults): a per-user Antigravity hook whose
// registration lost its event lets a possible tool call run, with a warning
// and an audit entry, in the default and permissive tiers (this account's
// config opens an outage), and denies it under strict availability, in a
// closed tier and while this account's installer holds its data directory.
// The gateway, which requires the event, is never asked.
func TestPerUserAntigravityUnboundToolCallFollowsTheTier(t *testing.T) {
	holdInstall := func(dataDir string) {
		if err := os.Mkdir(filepath.Join(dataDir, ".install.lock"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name    string
		env     []string
		prepare func(string)
		open    bool
	}{
		{name: "default tier", env: []string{"DC_COLD_OUTAGE_MODE=open"}, open: true},
		{name: "default tier with an inherited open fail mode", env: []string{"DC_COLD_OUTAGE_MODE=open", "DEFENSECLAW_FAIL_MODE=open"}, open: true},
		{name: "closed tier", env: []string{"DC_COLD_OUTAGE_MODE=closed"}},
		{name: "strict availability", env: []string{"DC_COLD_OUTAGE_MODE=open", "DEFENSECLAW_STRICT_AVAILABILITY=1"}},
		{name: "install window", env: []string{"DC_COLD_OUTAGE_MODE=open"}, prepare: holdInstall},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run := runHookForColdStart(t, NewAntigravityConnector(), "antigravity-hook.sh", nil, tc.prepare, tc.env...)
			if run.err != nil {
				t.Fatalf("hook: %v stdout=%q stderr=%q", run.err, run.stdout, run.stderr)
			}
			if got := readColdStartCapture(t, run.capDir, "count"); got != "" {
				t.Fatalf("the gateway was asked %q times; an unbound call never reaches it", got)
			}
			rows := hookFailureRecords(t, run.dataDir)
			if len(rows) != 1 || !strings.Contains(rows[0]["reason"], "Antigravity hook event binding") {
				t.Fatalf("hook-failures rows %+v, want one binding row\nstderr=%q", rows, run.stderr)
			}
			if tc.open {
				if !strings.Contains(run.stdout, `"decision":"allow"`) || !strings.Contains(run.stdout, "defenseclaw setup antigravity") ||
					!strings.Contains(run.stderr, "runs unchecked (fail mode open)") || rows[0]["fail_mode"] != "open" {
					t.Fatalf("stdout=%q stderr=%q rows=%+v, want an allow with the warning and an open audit row", run.stdout, run.stderr, rows)
				}
				return
			}
			if !strings.Contains(run.stdout, `"decision":"deny"`) || !strings.Contains(run.stdout, "defenseclaw setup antigravity") ||
				rows[0]["fail_mode"] != "closed" {
				t.Fatalf("stdout=%q stderr=%q rows=%+v, want Antigravity's deny naming the repair and a closed audit row", run.stdout, run.stderr, rows)
			}
		})
	}
}

// GAP-1321 (review R20-F1): the unbound marker is the hook's own state. A
// bound PreToolUse call whose environment carries _DC_UNBOUND_TOOL_INPUT=1
// still asks the gateway, in every tier, and never gets the unbound answer.
func TestPerUserAntigravityBoundCallIgnoresAnInheritedUnboundMarker(t *testing.T) {
	for _, mode := range []string{"open", "closed"} {
		t.Run(mode, func(t *testing.T) {
			run := runHookForColdStart(t, NewAntigravityConnector(), "antigravity-hook.sh", []string{"PreToolUse"}, nil,
				"DC_COLD_OUTAGE_MODE="+mode, "_DC_UNBOUND_TOOL_INPUT=1")
			if got := strings.TrimSpace(readColdStartCapture(t, run.capDir, "count")); got != "1" {
				t.Fatalf("the gateway was asked %q times, want 1\nstdout=%q stderr=%q", got, run.stdout, run.stderr)
			}
			if strings.Contains(run.stdout, "registered without an Antigravity event") || strings.Contains(run.stderr, "registered without") {
				t.Fatalf("a bound call got the unbound answer: stdout=%q stderr=%q", run.stdout, run.stderr)
			}
		})
	}
}
