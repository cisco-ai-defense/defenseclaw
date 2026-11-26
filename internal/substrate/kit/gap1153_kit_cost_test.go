// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

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

// TestGAP1153KitOverBudgetCost: the kit's facts of the BISECT-1153 8 KB
// strict scripts cost no more than the live bar allows. Live in an actor,
// rel/1.0.11 dfb6d9c707's hook took S1/S2/S5/S8 261.8/260.9/258.8/401.0 ms
// against 107.0/107.4/114.8/108.1 ms for 1.0.10 a64bfdb931, whose kit made
// no shell proof (its in-process facts of these calls are only the payload
// decode): rel's whole-command proofs cost rel - a64 live, and the bar
// (p99 <= 1.12 x a64) leaves 0.12 x a64 of it. So the kit's facts may cost
// at most 0.12 x a64 / (rel - a64) of those proofs measured in the same
// process: 0.083, 0.083, 0.096 and 0.044. Rel's facts make the proofs, so
// they cost more than the proofs alone (substrate-1 GAP-1153).
func TestGAP1153KitOverBudgetCost(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	home, _ := os.UserHomeDir()
	o20, c20 := strings.Repeat("for i in 1; do ", 20), strings.Repeat("done; ", 20)
	for _, shape := range []struct {
		name     string
		command  string
		a64, rel float64
	}{
		{"S1", gap1153Fit("for i in 1; do ", "$C;f{k}(){ :;};", "done"), 107.0, 261.8},
		{"S2", gap1153Fit("", "$C;f{k}(){ :;};", "true"), 107.4, 260.9},
		{"S5", gap1153Fit(o20, "$C;f{k}(){ :;};", c20+"true"), 114.8, 258.8},
		{"S8", gap1153Fit("for i in 1; do ", "$C;f{k}(){ :;};f{k};", "done"), 108.1, 401.0},
	} {
		payload := gap1153Bash(t, shape.command, "/work")
		allowed := 0.12 * shape.a64 / (shape.rel - shape.a64)
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
		ratio := float64(facts) / float64(proofs)
		t.Logf("%s: kit facts %v, rel's whole-command proofs %v: %.3f of them (allowed %.3f)", shape.name, facts, proofs, ratio, allowed)
		if ratio > allowed {
			t.Errorf("%s: kit facts cost %v, %.3f of rel's proofs (%v); the live bar allows %.3f (substrate-1 GAP-1153)",
				shape.name, facts, ratio, proofs, allowed)
		}
	}
}
