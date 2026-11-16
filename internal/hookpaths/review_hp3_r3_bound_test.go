// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func hp3r3Conds(k int) string {
	var b strings.Builder
	for i := 1; i <= k; i++ {
		fmt.Fprintf(&b, "if [ -n \"$A%d\" ]; then a%d=1; fi; ", i, i)
	}
	return b.String()
}

// hp3r3Kept runs the kept tracker over command and returns the candidate
// count after each top-level statement.
func hp3r3Kept(t *testing.T, command string) []int {
	t.Helper()
	file, ok := parseShell(command)
	if !ok {
		t.Fatalf("parse %q", command)
	}
	kept := []actionValues{{"HOME": "/h", "PWD": "/h/p"}}
	steps := 0
	var counts []int
	for _, stmt := range file.Stmts {
		kept = actionUpdateValuesKept(stmt, kept, "/h/p", "/h", &steps)
		if actionKeptSaturated(kept) {
			counts = append(counts, 0)
		} else {
			counts = append(counts, len(kept))
		}
	}
	return counts
}

// TestHP3R3KeptCandidateBound is the deterministic work counter of the kept
// tracker: k independent unknown conditionals make 2^k candidates until
// saturation is explicit. Work on the benign generator stays bounded.
func TestHP3R3KeptCandidateBound(t *testing.T) {
	for k := 0; k <= 12; k++ {
		counts := hp3r3Kept(t, hp3r3Conds(k)+"true")
		got := counts[len(counts)-1]
		want := 1 << k
		if want > actionMaxValueCandidates {
			want = 0 // explicit saturation, never a truncated candidate list
		}
		if got != want {
			t.Errorf("k=%d: %d kept candidates (0=saturated), want %d", k, got, want)
		}
	}
	for _, n := range []int{50, 200, 1000} {
		for _, many := range []bool{true, false} {
			counts := hp3r3Kept(t, hp3r3Script(n, many))
			steps, maxc, reached := 0, 0, -1
			for i, c := range counts {
				steps += c
				if c > maxc {
					maxc = c
				}
				if c == 0 && reached < 0 {
					reached = i + 1
				}
			}
			t.Logf("HP3R3WORK n=%d many=%v statements=%d steps=%d max=%d bound_at_statement=%d", n, many, len(counts), steps, maxc, reached)
			if maxc > actionMaxValueCandidates || steps > actionMaxValueCandidates*len(counts) {
				t.Errorf("n=%d many=%v: max %d steps %d over the bound", n, many, maxc, steps)
			}
		}
	}
}

func TestHP3R3Gen200AllocationCeiling(t *testing.T) {
	home, project := hp3r3Home(t)
	t.Setenv("HOME", home)
	payload, err := json.Marshal(map[string]any{"session_id": "bound", "hook_event_name": "PreToolUse", "cwd": project,
		"tool_name": "Bash", "tool_input": map[string]any{"command": hp3r3Script(200, true)}})
	if err != nil {
		t.Fatal(err)
	}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_ = Resolve(payload)
	runtime.ReadMemStats(&after)
	const ceiling = 512 << 20
	if got := after.TotalAlloc - before.TotalAlloc; got > ceiling {
		t.Errorf("gen:200:many allocated %d MiB, ceiling %d MiB", got>>20, ceiling>>20)
	}
}

// hp3r3ConcreteWrite is the concrete-write proof the decision runs for this
// home: a POSIX shell with a native Windows home (Git Bash) on a Windows
// host, the POSIX home elsewhere. Both read the redirect with the bounded
// kept tracker; the POSIX-home entry declines a Windows home by design.
func hp3r3ConcreteWrite(command, cwd, home string) bool {
	return actionConcreteProtectedWriteOn(command, cwd, home, actionWindowsHome(home))
}

// TestHP3R3BoundKeepsProtectedCandidate: a candidate that reaches the keys
// file must not be cut by the bound (fail closed at the bound).
func TestHP3R3BoundKeepsProtectedCandidate(t *testing.T) {
	home, project := hp3r3Home(t)
	t.Setenv("HOME", home)
	for _, row := range []struct{ name, command string }{
		{"under-cap", `f=keylink; if [ -n "$X" ]; then f=a.txt; fi; ` + hp3r3Conds(8) + `echo m >> "$f"`},
		{"cap-before", `f=keylink; if [ -n "$X" ]; then f=a.txt; fi; ` + hp3r3Conds(9) + `echo m >> "$f"`},
		{"cap-else", `f=a.txt; if [ -n "$X" ]; then f=b.txt; else f=keylink; fi; ` + hp3r3Conds(9) + `echo m >> "$f"`},
		{"cap-after", `f=a.txt; ` + hp3r3Conds(9) + `if [ -n "$X" ]; then f=keylink; fi; echo m >> "$f"`},
	} {
		got := hp3r3ConcreteWrite(row.command, project, home)
		t.Logf("HP3R3BOUND %s concrete=%v", row.name, got)
		if !got {
			t.Errorf("%s: the concrete-write proof lost the keys candidate", row.name)
		}
	}
}

// The step cap can be reached with fewer than the shell statement limit and
// without crossing the candidate cap. The assignment at that step must not
// disappear from the later redirect proof.
func TestHP3R4StepCapKeepsProtectedCandidate(t *testing.T) {
	home, project := hp3r3Home(t)
	command := `f=a.txt; ` + hp3r3Conds(5) + strings.Repeat(":; ", 13) + `if true; then f=keylink; fi; echo m >> "$f"`
	file, ok := parseShell(command)
	if !ok {
		t.Fatal("step-cap command did not parse")
	}
	kept := []actionValues{{"HOME": home, "PWD": project}}
	steps := 0
	for _, stmt := range file.Stmts[:len(file.Stmts)-1] {
		kept = actionUpdateValuesKept(stmt, kept, project, home, &steps)
	}
	if steps <= actionMaxValueSteps || !actionKeptSaturated(kept) {
		t.Fatalf("step cap not reached: steps=%d saturated=%v", steps, actionKeptSaturated(kept))
	}
	if !hp3r3ConcreteWrite(command, project, home) {
		t.Fatal("step-cap assignment lost the protected candidate")
	}
}
