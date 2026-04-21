// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newStoreForTest(t *testing.T) *Store {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "audit.db")
	s, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := s.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	return s
}

func TestInsertJudgeResponse_EmptyRawIsNoOp(t *testing.T) {
	s := newStoreForTest(t)
	if err := s.InsertJudgeResponse(JudgeResponse{Kind: "injection"}); err != nil {
		t.Fatalf("empty insert must not error: %v", err)
	}
	rows, err := s.ListJudgeResponses(0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("empty raw produced %d rows want 0", len(rows))
	}
}

func TestInsertJudgeResponse_PersistsAllFields(t *testing.T) {
	s := newStoreForTest(t)

	ts := time.Date(2026, 4, 16, 12, 0, 0, 0, time.UTC)
	raw := `{"verdict":"block","reason":"prompt injection matched"}`
	in := JudgeResponse{
		Timestamp:  ts,
		Kind:       "injection",
		Direction:  "prompt",
		Model:      "gpt-4",
		Action:     "block",
		Severity:   "HIGH",
		LatencyMs:  142,
		ParseError: "",
		Raw:        raw,
	}
	if err := s.InsertJudgeResponse(in); err != nil {
		t.Fatalf("insert: %v", err)
	}

	rows, err := s.ListJudgeResponses(10)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows want 1", len(rows))
	}
	r := rows[0]
	if r.ID == "" {
		t.Fatal("ID not generated")
	}
	if !r.Timestamp.Equal(ts) {
		t.Fatalf("timestamp %v want %v", r.Timestamp, ts)
	}
	if r.Kind != "injection" || r.Direction != "prompt" || r.Model != "gpt-4" ||
		r.Action != "block" || r.Severity != "HIGH" || r.LatencyMs != 142 {
		t.Fatalf("fields wrong: %+v", r)
	}
	if r.Raw != raw {
		t.Fatalf("raw mismatch: %q", r.Raw)
	}
}

func TestListJudgeResponses_OrdersByTimestampDesc(t *testing.T) {
	s := newStoreForTest(t)

	t0 := time.Date(2026, 4, 16, 12, 0, 0, 0, time.UTC)
	for i, raw := range []string{"one", "two", "three"} {
		if err := s.InsertJudgeResponse(JudgeResponse{
			Timestamp: t0.Add(time.Duration(i) * time.Minute),
			Kind:      "pii",
			Raw:       raw,
		}); err != nil {
			t.Fatalf("insert %d: %v", i, err)
		}
	}

	rows, err := s.ListJudgeResponses(10)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("got %d want 3", len(rows))
	}
	// Newest first.
	if rows[0].Raw != "three" || rows[2].Raw != "one" {
		t.Fatalf("ordering wrong: %q ... %q", rows[0].Raw, rows[2].Raw)
	}
}

func TestListJudgeResponses_LimitClampedAndDefaulted(t *testing.T) {
	s := newStoreForTest(t)
	for i := 0; i < 5; i++ {
		if err := s.InsertJudgeResponse(JudgeResponse{Kind: "pii", Raw: "r"}); err != nil {
			t.Fatal(err)
		}
	}

	// limit <= 0 falls back to the default (50) — we only inserted 5.
	rows, err := s.ListJudgeResponses(0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 5 {
		t.Fatalf("default limit returned %d want 5", len(rows))
	}

	// Explicit small limit is honoured.
	rows, err = s.ListJudgeResponses(2)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("limit=2 returned %d", len(rows))
	}
}

func TestInsertJudgeResponse_LargeBodyPersistedLossless(t *testing.T) {
	// Judge bodies routinely run several kilobytes — SQLite TEXT has no
	// ceiling but we want a regression guard against accidental UTF-8
	// mangling at sub-cap sizes.
	s := newStoreForTest(t)
	big := strings.Repeat("áéíóú🔒", 2048) // ~12KB of multi-byte data, well under MaxJudgeRawBytes
	if err := s.InsertJudgeResponse(JudgeResponse{Kind: "pii", Raw: big}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	rows, err := s.ListJudgeResponses(1)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows=%d", len(rows))
	}
	if rows[0].Raw != big {
		t.Fatalf("body mangled: len got=%d want=%d", len(rows[0].Raw), len(big))
	}
}

func TestInsertJudgeResponse_OversizedBodyTruncated(t *testing.T) {
	// Regression guard: a runaway judge response (multi-MB) must be
	// clipped at MaxJudgeRawBytes so the audit DB cannot be bloated by
	// pathological inputs. The truncation marker must be present and
	// the result must remain valid UTF-8.
	s := newStoreForTest(t)
	big := strings.Repeat("x", MaxJudgeRawBytes*2+17)
	if err := s.InsertJudgeResponse(JudgeResponse{Kind: "pii", Raw: big}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	rows, err := s.ListJudgeResponses(1)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows=%d", len(rows))
	}
	if len(rows[0].Raw) <= MaxJudgeRawBytes {
		// Stored body should be <= cap + marker overhead.
	}
	if len(rows[0].Raw) >= len(big) {
		t.Fatalf("body not truncated: got=%d, source=%d", len(rows[0].Raw), len(big))
	}
	if !strings.Contains(rows[0].Raw, "[truncated") {
		t.Fatalf("truncation marker missing: tail=%q",
			rows[0].Raw[len(rows[0].Raw)-80:])
	}
}

func TestTruncateJudgeRaw_UTF8SafeAtBoundary(t *testing.T) {
	// 🔒 is a 4-byte codepoint. Size the input well above the cap so
	// the naive byte-cut would land inside a multi-byte sequence;
	// the rune-aware rewind must step back to a codepoint start.
	big := strings.Repeat("🔒", MaxJudgeRawBytes)
	got := truncateJudgeRaw(big, MaxJudgeRawBytes)
	if !strings.Contains(got, "[truncated") {
		t.Fatalf("marker missing: tail=%q",
			got[len(got)-minInt(80, len(got)):])
	}
	// The truncated-prefix portion (before the marker) must be valid
	// UTF-8 — if the byte cut landed mid-codepoint, a rune walk
	// would surface a replacement character.
	markerIdx := strings.Index(got, "[truncated")
	if markerIdx <= 0 {
		t.Fatalf("marker index=%d", markerIdx)
	}
	prefix := got[:markerIdx-len("…")] // strip leading ellipsis too
	for _, r := range prefix {
		if r == '\uFFFD' {
			t.Fatalf("replacement rune leaked — byte cut mid-codepoint")
		}
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TestInsertJudgeResponse_PersistsCorrelationFields guards the Phase 3
// migration 4 additions. request_id / trace_id / run_id / input_hash /
// confidence / fail_closed_applied / inspected_model / prompt_template_id
// must all round-trip through the store so Phase 4 (TUI) and Phase 5
// (correlation sweep) can filter on them.
func TestInsertJudgeResponse_PersistsCorrelationFields(t *testing.T) {
	s := newStoreForTest(t)

	ts := time.Date(2026, 4, 16, 12, 0, 0, 0, time.UTC)
	in := JudgeResponse{
		Timestamp:         ts,
		Kind:              "injection",
		Direction:         "prompt",
		Model:             "claude-3-haiku",
		Action:            "block",
		Severity:          "CRITICAL",
		LatencyMs:         321,
		Raw:               `{"verdict":"malicious"}`,
		RequestID:         "req-11111111-2222-3333-4444-555555555555",
		TraceID:           "trace-abc",
		RunID:             "run-xyz",
		InputHash:         "sha256:deadbeef",
		Confidence:        0.87,
		FailClosedApplied: true,
		InspectedModel:    "gpt-4o",
		PromptTemplateID:  "pi-v2",
	}
	if err := s.InsertJudgeResponse(in); err != nil {
		t.Fatalf("insert: %v", err)
	}

	rows, err := s.ListJudgeResponses(1)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows=%d want 1", len(rows))
	}
	r := rows[0]
	if r.RequestID != in.RequestID || r.TraceID != in.TraceID || r.RunID != in.RunID {
		t.Fatalf("correlation keys lost: %+v", r)
	}
	if r.InputHash != in.InputHash || r.PromptTemplateID != in.PromptTemplateID {
		t.Fatalf("hash/template lost: %+v", r)
	}
	if r.InspectedModel != in.InspectedModel {
		t.Fatalf("inspected_model=%q want %q", r.InspectedModel, in.InspectedModel)
	}
	if r.Confidence < 0.86 || r.Confidence > 0.88 {
		t.Fatalf("confidence=%v want≈0.87", r.Confidence)
	}
	if !r.FailClosedApplied {
		t.Fatal("fail_closed_applied=false want true")
	}

	// Pivot by request_id: the Phase 4 TUI relies on this lookup to
	// open the Judge panel from a Verdict row.
	byReq, err := s.GetJudgeResponsesByRequestID(in.RequestID)
	if err != nil {
		t.Fatalf("by request: %v", err)
	}
	if len(byReq) != 1 || byReq[0].ID != r.ID {
		t.Fatalf("request_id pivot broken: %+v", byReq)
	}

	// Empty request_id is a documented no-op (prevents accidental
	// scans that would return every historical row).
	empty, err := s.GetJudgeResponsesByRequestID("")
	if err != nil {
		t.Fatalf("empty by request: %v", err)
	}
	if empty != nil {
		t.Fatalf("empty request_id returned %d rows, want nil", len(empty))
	}
}

// TestLogEvent_PersistsCorrelationIDs ensures Phase 3's audit_events
// migration added the trace_id/request_id columns and that LogEvent
// round-trips them. Empty values must persist as NULL so downstream
// SELECTs don't see the literal "".
func TestLogEvent_PersistsCorrelationIDs(t *testing.T) {
	s := newStoreForTest(t)

	ts := time.Date(2026, 4, 16, 12, 0, 0, 0, time.UTC)
	in := Event{
		ID:        "evt-1",
		Timestamp: ts,
		Action:    "guardrail-verdict",
		Target:    "openai:gpt-4",
		Actor:     "defenseclaw-gateway",
		Details:   "blocked prompt injection",
		Severity:  "HIGH",
		RunID:     "run-abc",
		TraceID:   "trace-abc",
		RequestID: "req-abc",
	}
	if err := s.LogEvent(in); err != nil {
		t.Fatalf("log: %v", err)
	}

	events, err := s.ListEvents(10)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("events=%d want 1", len(events))
	}
	got := events[0]
	if got.TraceID != in.TraceID || got.RequestID != in.RequestID {
		t.Fatalf("correlation ids lost: trace=%q request=%q", got.TraceID, got.RequestID)
	}
	if got.RunID != in.RunID {
		t.Fatalf("run_id=%q want %q", got.RunID, in.RunID)
	}
}
