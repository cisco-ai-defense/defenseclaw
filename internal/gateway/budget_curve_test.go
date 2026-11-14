// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// TestParseBudgetCostCurve prints the cost of the hook on every shape
// family at every size (PARSE_BUDGET_CURVE=1; not a gate). The caps of the
// reading budget are set from this curve: a call at a cap must stay near
// 100 ms and 64 MiB. One line per cell: shape, units, bytes, median
// milliseconds of three runs, MiB allocated, action.
func TestParseBudgetCostCurve(t *testing.T) {
	if os.Getenv("PARSE_BUDGET_CURVE") == "" {
		t.Skip("set PARSE_BUDGET_CURVE=1 to print the curve")
	}
	home := filepath.Join(t.TempDir(), "alice")
	cwd := filepath.Join(home, "project")
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	api := readingBoundTierTestAPI(t, "claudecode", config.HookPolicyTierDefault)
	only := os.Getenv("PARSE_BUDGET_SHAPE")
	for _, shape := range budgetShapes {
		if only != "" && only != shape.name {
			continue
		}
		for _, n := range shape.sizes {
			command := shape.command(n)
			var millis []float64
			var alloc uint64
			action := ""
			for range 3 {
				var before, after runtime.MemStats
				runtime.GC()
				runtime.ReadMemStats(&before)
				start := time.Now()
				action = gap0568ToolHookAction(t, api, "claudecode", "Bash", home, cwd, command, true, false)
				millis = append(millis, float64(time.Since(start).Microseconds())/1000)
				runtime.ReadMemStats(&after)
				alloc = max(alloc, after.TotalAlloc-before.TotalAlloc)
			}
			slices.Sort(millis)
			t.Logf("CURVE %-14s n=%-6d bytes=%-8d ms=%-9.1f MiB=%-6d action=%s", shape.name, n, len(command), millis[1], alloc>>20, action)
		}
	}
}
