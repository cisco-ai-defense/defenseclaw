// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// These tests pin the Verdicts-source behaviour introduced in Phase 3
// (TUI overhaul). They exercise:
//   - parseVerdictRow: tolerant JSONL parsing
//   - loadVerdicts: file ingestion + action-filter gating
//   - cycleVerdictAction: key 'a' rotation
//   - SelectedVerdict: cursor selection
//   - renderVerdictLine: compact per-row view
//   - verdictDetailPairs: modal contents on Enter

func TestParseVerdictRow_VerdictEventExtractsTypedFields(t *testing.T) {
	line := `{
		"ts":"2026-04-16T12:34:56Z",
		"event_type":"verdict",
		"severity":"HIGH",
		"model":"gpt-4",
		"direction":"prompt",
		"verdict":{"stage":"final","action":"block","reason":"pii-detected"}
	}`
	// loadVerdicts strips whitespace first — do the same here.
	line = strings.Join(strings.Fields(line), "")

	row, ok := parseVerdictRow(line)
	if !ok {
		t.Fatal("parseVerdictRow returned !ok on valid input")
	}
	if row.eventType != "verdict" || row.action != "block" ||
		row.severity != "HIGH" || row.stage != "final" ||
		row.reason != "pii-detected" || row.direction != "prompt" ||
		row.model != "gpt-4" {
		t.Fatalf("unexpected row: %#v", row)
	}
	if row.timestamp.IsZero() {
		t.Fatal("timestamp not parsed")
	}
}

func TestParseVerdictRow_JudgeEventFallsBackToJudgeAction(t *testing.T) {
	line := `{"ts":"2026-04-16T12:00:00Z","event_type":"judge","severity":"MEDIUM",` +
		`"judge":{"kind":"pii","action":"alert","latency_ms":42}}`
	row, ok := parseVerdictRow(line)
	if !ok {
		t.Fatal("parse failed")
	}
	if row.kind != "pii" || row.action != "alert" || row.eventType != "judge" {
		t.Fatalf("judge row wrong: %#v", row)
	}
}

func TestParseVerdictRow_MalformedReturnsNotOK(t *testing.T) {
	if _, ok := parseVerdictRow("not json"); ok {
		t.Fatal("should reject non-JSON")
	}
	if _, ok := parseVerdictRow(""); ok {
		t.Fatal("should reject empty")
	}
	if _, ok := parseVerdictRow(`{"ts":"bad-date","event_type":"verdict"}`); ok {
		t.Fatal("should reject invalid timestamp")
	}
}

func TestLoadVerdicts_ReadsAndFiltersByAction(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gateway.jsonl")
	content := strings.Join([]string{
		`{"ts":"2026-04-16T12:00:00Z","event_type":"verdict","severity":"INFO","verdict":{"stage":"final","action":"allow","reason":"clean"}}`,
		`{"ts":"2026-04-16T12:00:01Z","event_type":"verdict","severity":"MEDIUM","verdict":{"stage":"final","action":"alert","reason":"pii-med"}}`,
		`{"ts":"2026-04-16T12:00:02Z","event_type":"verdict","severity":"HIGH","verdict":{"stage":"final","action":"block","reason":"pii-hi"}}`,
		`# this line is not JSON and must be skipped`,
		``,
		`{"ts":"2026-04-16T12:00:03Z","event_type":"judge","severity":"MEDIUM","judge":{"kind":"injection","action":"alert"}}`,
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	p := &LogsPanel{}
	p.source = logSourceVerdicts

	// No filter: keep all 4 parseable events (3 verdicts + 1 judge).
	p.verdictAction = ""
	p.loadVerdicts(path)
	if got := len(p.verdicts); got != 4 {
		t.Fatalf("no-filter verdicts=%d want 4: %+v", got, p.verdicts)
	}

	// block filter: drop non-block verdicts. Judge events are not
	// action-filtered (loadVerdicts only filters when eventType=="verdict").
	p.verdictAction = "block"
	p.loadVerdicts(path)
	var verdictCount, judgeCount int
	for _, r := range p.verdicts {
		switch r.eventType {
		case "verdict":
			verdictCount++
			if r.action != "block" {
				t.Errorf("block filter leaked action=%q", r.action)
			}
		case "judge":
			judgeCount++
		}
	}
	if verdictCount != 1 || judgeCount != 1 {
		t.Fatalf("filtered verdicts=%d judges=%d want 1/1", verdictCount, judgeCount)
	}
}

func TestLoadVerdicts_MissingFilePopulatesError(t *testing.T) {
	p := &LogsPanel{}
	p.source = logSourceVerdicts
	p.loadVerdicts("/does/not/exist.jsonl")
	if p.errMsgs[logSourceVerdicts] == "" {
		t.Fatal("expected error message for missing file")
	}
	if len(p.verdicts) != 0 {
		t.Fatal("verdicts must be cleared on load error")
	}
}

func TestCycleVerdictAction_RotatesThroughAllThenWrapsToEmpty(t *testing.T) {
	p := &LogsPanel{}
	// Start at default empty -> first cycle must land on "block".
	p.cycleVerdictAction()
	if p.verdictAction != "block" {
		t.Fatalf("step1=%q want block", p.verdictAction)
	}
	p.cycleVerdictAction()
	if p.verdictAction != "alert" {
		t.Fatalf("step2=%q want alert", p.verdictAction)
	}
	p.cycleVerdictAction()
	if p.verdictAction != "allow" {
		t.Fatalf("step3=%q want allow", p.verdictAction)
	}
	p.cycleVerdictAction()
	if p.verdictAction != "" {
		t.Fatalf("step4=%q want empty (wrap)", p.verdictAction)
	}
}

func TestSelectedVerdict_ReturnsNilOnWrongSource(t *testing.T) {
	p := &LogsPanel{source: logSourceGateway}
	p.verdicts = []verdictRow{{eventType: "verdict", action: "block"}}
	if got := p.SelectedVerdict(); got != nil {
		t.Fatal("SelectedVerdict must be nil when source != verdicts")
	}
}

func TestSelectedVerdict_ReturnsNilOnEmpty(t *testing.T) {
	p := &LogsPanel{source: logSourceVerdicts}
	if got := p.SelectedVerdict(); got != nil {
		t.Fatal("expected nil on empty verdicts")
	}
}

func TestSelectedVerdict_ReturnsLastWhenCursorAtBottom(t *testing.T) {
	p := &LogsPanel{source: logSourceVerdicts, height: 24, width: 80}
	p.verdicts = []verdictRow{
		{eventType: "verdict", action: "allow"},
		{eventType: "verdict", action: "alert"},
		{eventType: "verdict", action: "block"},
	}
	// filteredLines() reads from p.lines[source]; populate rendered
	// parallel to p.verdicts so indices line up.
	p.lines[logSourceVerdicts] = []string{"allow", "alert", "block"}
	got := p.SelectedVerdict()
	if got == nil {
		t.Fatal("unexpected nil")
	}
	// Default selection is the most recent event (last in slice).
	if got.action != "block" {
		t.Fatalf("action=%q want block (most recent)", got.action)
	}
}

func TestRenderVerdictLine_Verdict(t *testing.T) {
	r := verdictRow{
		eventType: "verdict",
		timestamp: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		action:    "block", severity: "HIGH",
		stage: "final", direction: "prompt", model: "gpt-4",
		reason: "injection detected",
	}
	got := renderVerdictLine(r)
	for _, needle := range []string{"VERDICT", "BLOCK", "HIGH", "final", "prompt", "gpt-4", "injection"} {
		if !strings.Contains(got, needle) {
			t.Errorf("rendered line missing %q: %q", needle, got)
		}
	}
}

func TestRenderVerdictLine_JudgeAndLifecycleAndError(t *testing.T) {
	base := verdictRow{timestamp: time.Now()}

	j := base
	j.eventType = "judge"
	j.kind = "pii"
	j.action = "alert"
	j.severity = "MEDIUM"
	if got := renderVerdictLine(j); !strings.Contains(got, "JUDGE") || !strings.Contains(got, "kind=pii") {
		t.Errorf("judge render: %q", got)
	}

	l := base
	l.eventType = "lifecycle"
	l.raw = `{"transition":"init"}`
	if got := renderVerdictLine(l); !strings.Contains(got, "LIFECYCLE") {
		t.Errorf("lifecycle render: %q", got)
	}

	e := base
	e.eventType = "error"
	e.raw = `{"code":"boom"}`
	if got := renderVerdictLine(e); !strings.Contains(got, "ERROR") {
		t.Errorf("error render: %q", got)
	}
}

func TestTruncateVerdictReason(t *testing.T) {
	if got := truncateVerdictReason("abc", 10); got != "abc" {
		t.Fatalf("short string mutated: %q", got)
	}
	got := truncateVerdictReason("abcdefghij", 5)
	if !strings.HasSuffix(got, "…") {
		t.Fatalf("missing ellipsis: %q", got)
	}
	// One byte for '…' is 3 bytes UTF-8 — byte length is n-1 + len("…")
	// which rendering-wise still fits "about" n chars. Just assert it
	// did truncate.
	if strings.HasPrefix(got, "abcdefghij") {
		t.Fatalf("did not truncate: %q", got)
	}
}

func TestNonEmpty(t *testing.T) {
	if nonEmpty("", "dflt") != "dflt" {
		t.Fatal("empty did not fall back")
	}
	if nonEmpty("val", "dflt") != "val" {
		t.Fatal("non-empty was replaced")
	}
}

func TestVerdictDetailPairs_IncludesRequiredFields(t *testing.T) {
	r := verdictRow{
		raw:       `{"event_type":"verdict"}`,
		timestamp: time.Date(2026, 4, 16, 12, 34, 56, 0, time.UTC),
		action:    "block", severity: "HIGH",
		stage: "final", direction: "prompt", model: "gpt-4",
		reason: "pii-detected", eventType: "verdict",
	}
	pairs := verdictDetailPairs(r)

	got := map[string]string{}
	for _, p := range pairs {
		got[p[0]] = p[1]
	}
	for _, k := range []string{"Timestamp", "Event type", "Severity", "Action",
		"Stage", "Direction", "Model", "Reason", "Raw JSON"} {
		if _, ok := got[k]; !ok {
			t.Errorf("missing pair key %q: %+v", k, got)
		}
	}
	if got["Action"] != "block" || got["Severity"] != "HIGH" {
		t.Fatalf("wrong values: %+v", got)
	}
	if got["Raw JSON"] == "" {
		t.Fatal("Raw JSON must be populated")
	}
}

func TestVerdictDetailPairs_OmitsKindAndReasonWhenEmpty(t *testing.T) {
	r := verdictRow{eventType: "lifecycle", timestamp: time.Now()}
	pairs := verdictDetailPairs(r)
	for _, p := range pairs {
		if p[0] == "Judge kind" {
			t.Fatal("Judge kind must be omitted when empty")
		}
		if p[0] == "Reason" {
			t.Fatal("Reason must be omitted when empty")
		}
	}
}
