// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// gap0299MiBCostPin is the pinned bound of one hook call on a benign 1 MiB
// here-document (rel-1-0-10:GAP-0299, a documented limit per the owner's
// 11-18 ruling): twice the cost measured on 5e93cafe74 (about 279 ms and
// 91-95 MiB on a c7i.16xlarge), so a regression fails while the known limit
// holds. Time is a ratio to the hook's time on a small reference command on
// the same host (parseBudgetTimeBound's reference), so the pin does not
// depend on the host's speed.
const (
	gap0299MiBAllocPin = 192 << 20
	gap0299MiBTimePin  = 2 * gap0299MiBTimeRatio
)

// gap0299MiBTimeRatio is the measured ratio of the 1 MiB call to the
// reference call (median of the shapes below on dc-s7-bench7).
const gap0299MiBTimeRatio = 12.2

func TestGAP0299MiBHereDocumentCostIsPinned(t *testing.T) {
	if testing.Short() {
		t.Skip("cost pin: not in -short")
	}
	home := filepath.Join(t.TempDir(), "alice")
	cwd := filepath.Join(home, "project")
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	api := readingBoundTierTestAPI(t, "claudecode", config.HookPolicyTierDefault)
	hook := func(command string) {
		gap0568ToolHookAction(t, api, "claudecode", "Bash", home, cwd, command, true, false)
	}
	var reference []time.Duration
	for run := range 5 {
		command := budgetShapeNamed("flat-words").command(500 + run)
		start := time.Now()
		hook(command)
		reference = append(reference, time.Since(start))
	}
	slices.Sort(reference)
	ref := reference[2]
	words := strings.Fields("the release notes describe how the team reviewed every change before the build and what the next steps are for the docs site and the support matrix")
	prose := func(seed int) string {
		var b strings.Builder
		fmt.Fprintf(&b, "cat > notes-%d.md <<'EOF'\n", seed)
		for i := 0; b.Len() < 1<<20; i++ {
			for j := 0; j < 12; j++ {
				b.WriteString(words[(i*7+j*3+seed)%len(words)])
				b.WriteByte(' ')
			}
			fmt.Fprintf(&b, "line %d.\n", i)
		}
		b.WriteString("EOF\n")
		return b.String()
	}
	lines := budgetShapeNamed("heredoc-lines").command
	n := 65536
	for len(lines(n)) < 1<<20 {
		n += 8192
	}
	shapes := []struct {
		name    string
		command func(int) string
	}{
		{"prose here-document", prose},
		{"heredoc-lines", func(seed int) string { return fmt.Sprintf("# run %d\n", seed) + lines(n) }},
	}
	for _, shape := range shapes {
		var took []time.Duration
		var allocs []uint64
		for run := range 3 {
			command := shape.command(run) // a distinct command per call
			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)
			start := time.Now()
			hook(command)
			took = append(took, time.Since(start))
			runtime.ReadMemStats(&after)
			allocs = append(allocs, after.TotalAlloc-before.TotalAlloc)
		}
		slices.Sort(took)
		slices.Sort(allocs)
		ratio := float64(took[1]) / float64(ref)
		t.Logf("%s 1 MiB: %s, %d MiB; reference %s; ratio %.1f (pin %.1f)", shape.name, took[1], allocs[1]>>20, ref, ratio, float64(gap0299MiBTimePin))
		if allocs[1] > gap0299MiBAllocPin {
			t.Errorf("%s 1 MiB: %d MiB allocated, pin %d MiB", shape.name, allocs[1]>>20, gap0299MiBAllocPin>>20)
		}
		if ratio > gap0299MiBTimePin {
			t.Errorf("%s 1 MiB: %s is %.1fx the reference call %s, pin %.1fx", shape.name, took[1], ratio, ref, float64(gap0299MiBTimePin))
		}
	}
}
