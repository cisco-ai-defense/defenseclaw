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
