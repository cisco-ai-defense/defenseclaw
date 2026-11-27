// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"encoding/json"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// gap1157Batch is a call holding the hidden actions items: one {"command":
// item} reading each.
func gap1157Batch(t *testing.T, items ...string) substrateMCPJudgedCall {
	t.Helper()
	var parts []string
	for _, it := range items {
		parts = append(parts, `{"command":`+hiddenJSON(t, it)+`}`)
	}
	return substrateMCPJudgedCall{tool: "read_file", args: []json.RawMessage{json.RawMessage(`{"items":[` + strings.Join(parts, ",") + `]}`)}}
}

// gap1157Denied is the rule deny of tixgCommand, with its own rule id.
func gap1157Denied(v SubstrateCalloutVerdict) bool {
	return v.Verdict == "deny" && slices.ContainsFunc(v.Findings, func(f string) bool { return strings.HasPrefix(f, "CMD-RM-RF") })
}

func gap1157Bridge(t *testing.T) *substrateMCPBridge {
	t.Helper()
	tb := newTixgBridge(t, false)
	return &substrateMCPBridge{a: tb.fixture.api, st: tb.fixture.api.substrateState(), reg: tb.reg, s: &substrateStream{target: "notes"}}
}

// GAP-1157 perf pin: a call's hidden-action readings run beside one
// another and beside its full reading, so a call with N hidden actions waits
// for the slowest reading, not their sum. The pin counts readings in flight
// at once (the lane hook runs once per rules reading); it reads no clock for
// its verdict. At 43a3933faf the readings ran one by one: never 2 at once.
func TestGAP1157HiddenReadingsRunTogether(t *testing.T) {
	if runtime.GOMAXPROCS(0) < 4 {
		defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(4))
	}
	b := gap1157Bridge(t)
	var mu sync.Mutex
	active, most := 0, 0
	trustedToolLaneFaultHook = func(trustedActionRequest) {
		mu.Lock()
		active++
		most = max(most, active)
		mu.Unlock()
		deadline := time.Now().Add(250 * time.Millisecond)
		for time.Now().Before(deadline) {
			mu.Lock()
			n := active
			mu.Unlock()
			if n >= 4 {
				break
			}
			time.Sleep(time.Millisecond)
		}
		mu.Lock()
		active--
		mu.Unlock()
	}
	t.Cleanup(func() { trustedToolLaneFaultHook = nil })
	var items []string
	for i := 0; i < 6; i++ {
		items = append(items, "echo step"+strconv.Itoa(i))
	}
	v := b.judge(t.Context(), "tools/call", gap1157Batch(t, items...))
	trustedToolLaneFaultHook = nil
	if v.Verdict != "allow" {
		t.Fatalf("benign batch: %+v", v)
	}
	if most < 4 {
		t.Fatalf("hidden readings in flight at once: %d, want >= 4 (one by one: the call pays their sum)", most)
	}
}

// GAP-1157: every hidden action is still read and the strictest verdict
// wins wherever the denied action sits, with its own rule id. A candidate
// whose quote or here-doc never closes is a reading of its own: it never
// swallows the next one.
func TestGAP1157HiddenReadingsIsolatedAndComplete(t *testing.T) {
	b := gap1157Bridge(t)
	openers := []string{"echo \x27unterminated", "echo \"unterminated", "cat <<EOF", "echo $(", "echo `"}
	for pos := 0; pos <= len(openers); pos++ {
		items := slices.Clone(openers)
		items = slices.Insert(items, pos, tixgCommand)
		v := b.judge(t.Context(), "tools/call", gap1157Batch(t, items...))
		if !gap1157Denied(v) {
			t.Fatalf("denied action at %d behind unclosed neighbours: %+v", pos, v)
		}
	}
	for n := 1; n <= 12; n++ {
		var items []string
		for i := 0; i < n; i++ {
			items = append(items, "echo step"+strconv.Itoa(i))
		}
		if v := b.judge(t.Context(), "tools/call", gap1157Batch(t, items...)); v.Verdict != "allow" {
			t.Fatalf("benign batch of %d raised: %+v", n, v)
		}
		for pos := 0; pos < n; pos += max(1, n/3) {
			denied := slices.Clone(items)
			denied[pos] = tixgCommand
			v := b.judge(t.Context(), "tools/call", gap1157Batch(t, denied...))
			if !gap1157Denied(v) {
				t.Fatalf("batch of %d, denied action at %d: %+v", n, pos, v)
			}
		}
	}
}

// GAP-1157: a hidden reading that panics is the evaluation-fault deny, and
// a call that stops early (an earlier deny) ends its readings before it
// returns.
func TestGAP1157HiddenReadingFaultAndStop(t *testing.T) {
	scan := substrateMCPArgumentScan{candidates: []json.RawMessage{json.RawMessage(`{"command":"a"}`), json.RawMessage(`{"command":"b"}`), json.RawMessage(`{"command":"c"}`)}}
	judged := map[string]bool{`{"command":"b"}`: true}
	rd := substrateMCPReading{scan: &scan, judged: judged}
	var mu sync.Mutex
	var read []string
	h := startSubstrateMCPHiddenReadings(t.Context(), rd, func(_ context.Context, c json.RawMessage) SubstrateCalloutVerdict {
		mu.Lock()
		read = append(read, string(c))
		mu.Unlock()
		if string(c) == `{"command":"c"}` {
			panic("gap1157 injected reading fault")
		}
		return SubstrateCalloutVerdict{V: "1", Verdict: "allow"}
	})
	got := h.wait()
	if len(got) != 2 || got[0].Verdict != "allow" || got[1].Verdict != "deny" || !slices.Contains(got[1].Findings, parseFailureRuleID) {
		t.Fatalf("verdicts: %+v", got)
	}
	slices.Sort(read)
	if strings.Join(read, " ") != `{"command":"a"} {"command":"c"}` || !judged[`{"command":"a"}`] || !judged[`{"command":"c"}`] {
		t.Fatalf("read %v judged %v: an already judged candidate is read again, or a new one is not marked", read, judged)
	}
	if startSubstrateMCPHiddenReadings(t.Context(), rd, nil) != nil {
		t.Fatal("every candidate judged: no readings to start")
	}

	release := make(chan struct{})
	ended := make(chan struct{}, 8)
	slow := substrateMCPArgumentScan{candidates: []json.RawMessage{json.RawMessage(`{"command":"x"}`), json.RawMessage(`{"command":"y"}`)}}
	h = startSubstrateMCPHiddenReadings(t.Context(), substrateMCPReading{scan: &slow}, func(ctx context.Context, _ json.RawMessage) SubstrateCalloutVerdict {
		defer func() { ended <- struct{}{} }()
		select {
		case <-ctx.Done():
		case <-release:
		}
		return SubstrateCalloutVerdict{V: "1", Verdict: "allow"}
	})
	stopped := make(chan struct{})
	go func() { h.stop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("stop did not end the readings")
	}
	if len(ended) != 2 {
		t.Fatalf("readings ended before stop returned: %d of 2", len(ended))
	}
}
