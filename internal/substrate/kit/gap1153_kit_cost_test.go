// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows && !race

package kit

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// gap1153Fit repeats unit ({k} counts up) between prefix and suffix up to
// 8190 bytes: the BISECT-1153 S1..S8 scripts.
func gap1153Fit(prefix, unit, suffix string) string {
	var out strings.Builder
	out.WriteString(prefix)
	for k := 0; ; k++ {
		piece := strings.ReplaceAll(unit, "{k}", fmt.Sprint(k))
		if out.Len()+len(piece)+len(suffix) > 8190 {
			break
		}
		out.WriteString(piece)
	}
	return out.String() + suffix
}

func gap1153Bash(t *testing.T, command, cwd string) []byte {
	t.Helper()
	payload, err := json.Marshal(map[string]any{"session_id": "s", "cwd": cwd, "hook_event_name": "PreToolUse",
		"tool_name": "Bash", "tool_input": map[string]any{"command": command}, "tool_use_id": "t"})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

// TestGAP1153KitOverBudgetCost bounds the hook facts cost by the live
// headroom left by the published 1.0.10 actor baseline. The gateway and
// actor path still need a paired live timing after this local red/green gate.
// p47b makes the protected-target decision faster, so a ratio to that
// decision is no longer a stable budget across bases.
func TestGAP1153KitOverBudgetCost(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	home, _ := os.UserHomeDir()
	o20, c20 := strings.Repeat("for i in 1; do ", 20), strings.Repeat("done; ", 20)
	for _, shape := range []struct {
		name    string
		command string
		a64     float64
	}{
		{"S1", gap1153Fit("for i in 1; do ", "$C;f{k}(){ :;};", "done"), 107.0},
		{"S2", gap1153Fit("", "$C;f{k}(){ :;};", "true"), 107.4},
		{"S5", gap1153Fit(o20, "$C;f{k}(){ :;};", c20+"true"), 114.8},
		{"S8", gap1153Fit("for i in 1; do ", "$C;f{k}(){ :;};f{k};", "done"), 108.1},
	} {
		payload := gap1153Bash(t, shape.command, "/work")
		budget := time.Duration(0.12 * shape.a64 * float64(time.Millisecond))
		least := func(run func()) time.Duration {
			run()
			best := time.Duration(1 << 62)
			for range 3 {
				start := time.Now()
				run()
				best = min(best, time.Since(start))
			}
			return best
		}
		facts := least(func() { CollectFacts("claudecode", "PreToolUse", payload, 1<<20) })
		proofs := least(func() {
			_ = hookpaths.ActionPrivateKeyReadWithDialect(shape.command, "/work", home, actionfacts.DialectPOSIX) ||
				hookpaths.ActionMakePrivateKeyRead(shape.command, "/work", home)
			_ = hookpaths.ActionCommandDecisionWithDialectAndGlobFacts(shape.command, "/work", home, actionfacts.DialectPOSIX, nil)
		})
		t.Logf("%s: kit facts %v, full proofs %v, headroom %v", shape.name, facts, proofs, budget)
		if facts > budget {
			t.Errorf("%s: kit facts cost %v exceeds the 1.0.10 live headroom %v (substrate-1 GAP-1153)", shape.name, facts, budget)
		}
	}
}
