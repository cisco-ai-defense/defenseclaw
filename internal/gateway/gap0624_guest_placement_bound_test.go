// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

// TestGAP0624GuestPlacementListStaysAtTheBound: a here-string call within
// the placement's 8 KB with 64 cd steps after $CMD and 600 statements that
// each may name a path elsewhere (touch .fN) listed every reading of every
// statement in every folder, ~77k, before the placement cut them: 17.9 MiB
// for one pass at 87e2e5a488 with 400 statements (substrate-1 GAP-0624;
// GAP-0364 allocation class). The list stays at maxSandboxGuestPlacements
// now: the call is still cut, and its allocation stays below the ceiling.
func TestGAP0624GuestPlacementListStaysAtTheBound(t *testing.T) {
	var b strings.Builder
	b.WriteString("cd .cache\nbash <<< 'true'\n$CMD\n")
	for i := range 64 {
		fmt.Fprintf(&b, "cd s%d\n", i)
	}
	for i := range 600 {
		fmt.Fprintf(&b, "touch .f%d\n", i)
	}
	command := b.String()
	args, _ := json.Marshal(map[string]any{"command": command})
	input := actionfacts.Input{Tool: "Bash", Args: args, Command: command, CWD: sandboxauth.SandboxHome, ActiveHome: sandboxauth.SandboxHome}
	facts := actionfacts.Analyze(input)
	for _, statementBudget := range []bool{false, true} {
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		placements, cut := new(guestReadingMemo).plan(input, facts).placements(statementBudget)
		runtime.ReadMemStats(&after)
		allocated := after.TotalAlloc - before.TotalAlloc
		t.Logf("GAP0624 bytes=%d budget=%v placements=%d cut=%v allocated=%d KiB", len(command), statementBudget, len(placements), cut, allocated>>10)
		if !cut || len(placements) == 0 {
			t.Errorf("budget=%v: %d placements cut=%v, want the call read and cut", statementBudget, len(placements), cut)
		}
		if len(placements) > 3*maxSandboxGuestPlacements {
			t.Errorf("budget=%v: %d placements, over three passes of the bound", statementBudget, len(placements))
		}
		const ceiling = 16 << 20
		if allocated > ceiling {
			t.Errorf("budget=%v: allocated %d MiB, ceiling %d MiB", statementBudget, allocated>>20, ceiling>>20)
		}
	}
}
