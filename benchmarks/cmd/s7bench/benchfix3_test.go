// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build s7bench

package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway"
)

// parseLayers is the one reading of -layers for the harness and the -dm-fill guard (rel-1-0-10:GAP-0617 P4).
func TestParseLayers(t *testing.T) {
	for _, tc := range []struct {
		in        string
		dm, judge bool
		bad       bool
	}{
		{"", false, false, false},
		{"dm", true, false, false},
		{"judge", false, true, false},
		{"dm,judge", true, true, false},
		{"judge,dm", true, true, false},
		{"dm+judge", true, true, false},
		{"dm;judge", true, true, false},
		{"dm judge", true, true, false},
		{" dm , ,judge ", true, true, false},
		{"judges", false, false, true},
		{"DM", false, false, true},
		{"dm,llm", false, false, true},
		{"nojudge", false, false, true},
	} {
		dm, judge, err := parseLayers(tc.in)
		if (err != nil) != tc.bad {
			t.Fatalf("%q: error %v, want error=%v", tc.in, err, tc.bad)
		}
		if err == nil && (dm != tc.dm || judge != tc.judge) {
			t.Fatalf("%q: dm=%v judge=%v, want dm=%v judge=%v", tc.in, dm, judge, tc.dm, tc.judge)
		}
	}
}

// The guard refuses exactly the values the harness would turn the judge layer on for, and no other: the two read -layers through parseLayers.
func TestDMFillGuardAndHarnessAgreeOnJudgeInLayers(t *testing.T) {
	for _, v := range []string{"", "dm", "judge", "dm,judge", "judge,dm", "dm+judge", "dm;judge", "dm judge", "judge;dm"} {
		_, judge, err := parseLayers(v)
		if err != nil {
			t.Fatalf("%q: %v", v, err)
		}
		refused := dmFillJudgeRefused(true, "", "", v) != nil
		if refused != judge {
			t.Fatalf("-layers %q: the harness turns the judge on=%v, the -dm-fill guard refuses=%v", v, judge, refused)
		}
		if dmFillJudgeRefused(false, "", "", v) != nil {
			t.Fatalf("-layers %q: the guard must not act without -dm-fill", v)
		}
	}
	// A value the harness would not start with is refused by the guard too, before anything boots.
	if err := dmFillJudgeRefused(true, "", "", "judges"); err == nil || !strings.Contains(err.Error(), "unknown entry") {
		t.Fatalf("unknown -layers entry under -dm-fill: %v", err)
	}
	// The judge model and URL are still refused on their own.
	if err := dmFillJudgeRefused(true, "gemma", "", "dm"); err == nil || !strings.Contains(err.Error(), "-judge-model") {
		t.Fatalf("-judge-model under -dm-fill: %v", err)
	}
}

// A tool-call session's opening prompt is charged to the prompt: its judge requests and hook latency are their own fields on the idx 0 row
// (rel-1-0-10:GAP-0650), absent when the session had no opening prompt.
func TestRecordCarriesPromptJudgeCallsApart(t *testing.T) {
	r := record{Case: "c", Idx: 0, N: 2,
		JudgeCalls:       []gateway.S7JudgeCall{{LatencyMs: 90, Parsed: true, InTokens: 500, OutTokens: 20}},
		PromptJudgeCalls: []gateway.S7JudgeCall{{LatencyMs: 1100, Parsed: true, InTokens: 800, OutTokens: 60, ReqChars: 2400}, {LatencyMs: 3000, Err: "context deadline exceeded", Cancelled: true, ReqChars: 2600, MaxTok: 1024}},
		PromptLatUs:      3_100_000}
	b, _ := json.Marshal(r)
	var back map[string]any
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if n := len(back["judge_calls"].([]any)); n != 1 {
		t.Fatalf("the tool call's own judge_calls must hold only its own request, got %d: %s", n, b)
	}
	pj := back["prompt_judge_calls"].([]any)
	if len(pj) != 2 || pj[1].(map[string]any)["req_chars"].(float64) != 2600 || pj[1].(map[string]any)["max_tok"].(float64) != 1024 {
		t.Fatalf("prompt_judge_calls: %s", b)
	}
	if back["prompt_lat_us"].(float64) != 3_100_000 {
		t.Fatalf("prompt_lat_us: %s", b)
	}
	b2, _ := json.Marshal(record{Case: "c", Idx: 1, N: 2})
	if strings.Contains(string(b2), "prompt_judge_calls") || strings.Contains(string(b2), "prompt_lat_us") {
		t.Fatalf("a row with no opening prompt must not carry prompt fields: %s", b2)
	}
}
