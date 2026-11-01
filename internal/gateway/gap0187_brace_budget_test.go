// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestGAP0187BraceExpansionBudget is rel-1-0-6 GAP-0187: one short hook
// command with a huge brace range made every shell reader build all of its
// fields in memory; a range of 10^8 pinned a per-user gateway at a 2 GiB
// cap. The cost is now read from the text before anything expands
// (shellparse.BraceExpansionTooLarge): a command over the budget takes the
// over-limit path and blocks with ACTION-COMPOUND-LIMIT in action mode, in
// well under a second and without growing memory, per-user and managed,
// for both connectors. Small brace forms stay allowed.
func TestGAP0187BraceExpansionBudget(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	heavy := []string{
		"echo {1..100000} > out.txt",
		"echo {1..100000000} > out.txt",
		"echo {1..3000}{1..3000} > out.txt",
		"echo {1..40}{1..40}{1..40}{1..40}{1..40} > out.txt",
		"echo ok; echo {a,b}{1..20000}{x,y} > out.txt",
	}
	benign := []string{
		"mkdir -p src/{a,b,c}/{x,y}",
		"echo src/{a,b,c}.go > list.txt",
		"echo {1..100} > out.txt",
		"echo '{1..100000000}' > out.txt",
	}
	commands := append(append([]string(nil), heavy...), benign...)
	payloads := make([][]byte, len(commands))
	for i, command := range commands {
		payloads[i] = f.payload(t, command)
	}
	var before runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	start := time.Now()
	headers := f.clientHeaders(t, payloads)
	var calls []*hookCall
	for i, command := range commands {
		calls = append(calls, everyMode(command, payloads[i], headers[i])...)
	}
	f.answerAll(t, calls)
	took := time.Since(start)
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	for i, call := range calls {
		switch over := i/4 < len(heavy); {
		case over && (call.verdict != "block" || !strings.Contains(call.body, "ACTION-COMPOUND-LIMIT")):
			t.Errorf("%s: verdict %s, want block by ACTION-COMPOUND-LIMIT; body %.200s", call.name, call.verdict, call.body)
		case !over && call.verdict != "allow":
			t.Errorf("%s: verdict %s, want allow; body %.200s", call.name, call.verdict, call.body)
		}
	}
	allocated := (after.TotalAlloc - before.TotalAlloc) >> 20
	t.Logf("%d hook calls (client headers included) in %s, %d MiB allocated", len(calls), took.Round(time.Millisecond), allocated)
	// The table allocated gigabytes before the bound (10^5 alone is about
	// 1 GiB per call); with it, the heavy rows cost no more than the benign.
	if allocated > 2048 {
		t.Errorf("table allocated %d MiB, want under 2048", allocated)
	}
}
