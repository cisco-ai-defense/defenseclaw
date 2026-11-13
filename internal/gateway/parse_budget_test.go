// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// The two P1 probes of the hook (GAP-0254, GAP-0255) and their variants:
// a call past the reading budget is opaque to the readers, so it takes the
// evaluation-limit path. It alerts outside the strict tier, with the reason
// parse_budget_exceeded, and the strict tier blocks it (managed included).
// Each is generated from a small template, and each is decided within a
// bounded time and memory.
var parseBudgetRows = []struct {
	name, unit, tail string
	n                int
}{
	{"pipeline of 33,577 stages", "a|", "a", 33577},
	{"left-deep || list of 166,443", "a||", "a", 166443},
	{"&& list of 100,000", "a&&", "a", 100000},
	{"mixed chain", "a|b&&c||", "d", 60000},
	{"flat words", "a ", "", 200000},
	{"flat statements", "a;", "a", 200000},
}

func TestParseBudgetCallsTakeTheEvaluationLimitPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX homes and a mode 0 homes folder")
	}
	var rows []readingBoundRow
	for _, row := range parseBudgetRows {
		rows = append(rows, readingBoundRow{row.name, "Bash", strings.Repeat(row.unit, row.n) + row.tail, guardrailActionAlert})
	}
	readingBoundCells(t, rows, 5*time.Second)
}

// TestParseBudgetReasonIsExplicit pins the reason of the finding.
func TestParseBudgetReasonIsExplicit(t *testing.T) {
	findings := trustedActionBudgetFindings(true)
	if len(findings) != 1 || findings[0].RuleID != "ACTION-COMPOUND-LIMIT" || findings[0].Evidence != "parse_budget_exceeded" {
		t.Fatalf("findings = %+v", findings)
	}
	if action := guardrailActionForProfile(findings, false, func() bool { return false }, func(string) string { return guardrailActionBlock }); action != guardrailActionAlert {
		t.Fatalf("default tier: %s, want alert", action)
	}
	if action := guardrailActionForProfile(findings, false, func() bool { return true }, func(string) string { return guardrailActionBlock }); action != guardrailActionBlock {
		t.Fatalf("strict tier: %s, want block", action)
	}
}

// TestParseBudgetProbesStayBounded asserts the memory and the time of the
// hook on each probe, and that a pipeline just inside the budget still
// grows linearly. Before the budget the 67 KB pipeline held 6 GiB and the
// 499 KB list killed the process.
func TestParseBudgetProbesStayBounded(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX homes")
	}
	home := filepath.Join(t.TempDir(), "alice")
	cwd := filepath.Join(home, "project")
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	api := readingBoundTierTestAPI(t, "claudecode", config.HookPolicyTierDefault)
	const memory, window = 256 << 20, 3 * time.Second
	rows := append([]struct {
		name, unit, tail string
		n                int
	}{{"pipeline inside the budget", "a|", "a", 4000}}, parseBudgetRows...)
	for _, row := range rows {
		command := strings.Repeat(row.unit, row.n) + row.tail
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		start := time.Now()
		action := gap0568ToolHookAction(t, api, "claudecode", "Bash", home, cwd, command, true, false)
		took := time.Since(start)
		runtime.ReadMemStats(&after)
		if alloc := after.TotalAlloc - before.TotalAlloc; alloc > memory || took > window {
			t.Errorf("%s (%d bytes): %d MiB allocated in %s", row.name, len(command), alloc>>20, took)
		}
		if action != guardrailActionAlert {
			t.Errorf("%s: action=%s, want alert", row.name, action)
		}
	}
}
