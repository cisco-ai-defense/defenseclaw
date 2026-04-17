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
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

// Phase 4: the "J" key on the Verdicts tab opens a modal that
// renders recent audit.JudgeResponse rows from SQLite. The
// formatting helper must surface correlation IDs so forensic
// investigators can cross-reference with OTEL + Splunk, and must
// keep the redacted raw body at the bottom so the identification
// block isn't scrolled off-screen.

func TestJudgeResponsesDetailPairs_SurfacesCorrelationFields(t *testing.T) {
	rows := []audit.JudgeResponse{{
		Timestamp:         time.Date(2026, 4, 16, 12, 34, 56, 0, time.UTC),
		Kind:              "injection",
		Direction:         "prompt",
		Model:             "claude-3-haiku",
		Action:            "block",
		Severity:          "CRITICAL",
		LatencyMs:         321,
		Raw:               `{"verdict":"malicious","redacted":"<email>"}`,
		RequestID:         "req-abc",
		TraceID:           "trace-def",
		RunID:             "run-xyz",
		InputHash:         "sha256:deadbeef",
		Confidence:        0.87,
		FailClosedApplied: true,
		InspectedModel:    "gpt-4o",
		PromptTemplateID:  "pi-v2",
	}}
	pairs := judgeResponsesDetailPairs(rows)

	// Build a flat map for easy assertions; the helper prefixes
	// each key with "[1] " for the first row so the modal can
	// render multiple responses without key collisions.
	got := map[string]string{}
	for _, p := range pairs {
		got[p[0]] = p[1]
	}

	required := []string{
		"[1] Timestamp", "[1] Kind", "[1] Direction", "[1] Action",
		"[1] Severity", "[1] Latency (ms)", "[1] Request ID",
		"[1] Trace ID", "[1] Run ID", "[1] Input hash",
		"[1] Confidence", "[1] Inspected model", "[1] Judge model",
		"[1] Prompt template", "[1] Fail-closed", "[1] Raw (redacted)",
	}
	for _, k := range required {
		if _, ok := got[k]; !ok {
			t.Errorf("missing key %q; got=%#v", k, got)
		}
	}
	if got["[1] Action"] != "block" {
		t.Errorf("action=%q", got["[1] Action"])
	}
	if got["[1] Raw (redacted)"] == "" {
		t.Fatal("raw redacted body must be rendered")
	}
	if got["[1] Request ID"] != "req-abc" {
		t.Errorf("request_id=%q", got["[1] Request ID"])
	}
}

func TestJudgeResponsesDetailPairs_MultipleRowsSeparated(t *testing.T) {
	rows := []audit.JudgeResponse{
		{Timestamp: time.Now(), Kind: "pii", Direction: "prompt", Action: "alert", Raw: "{}"},
		{Timestamp: time.Now(), Kind: "injection", Direction: "completion", Action: "block", Raw: "{}"},
	}
	pairs := judgeResponsesDetailPairs(rows)
	// Helper emits a blank separator between rows so long redacted
	// bodies don't visually bleed into each other in the modal.
	// Count rows by checking for the row-prefix markers rather than
	// relying on exact indices.
	var blanks int
	var firstRow, secondRow bool
	for _, p := range pairs {
		if p[0] == "" && p[1] == "" {
			blanks++
		}
		if strings.HasPrefix(p[0], "[1] ") {
			firstRow = true
		}
		if strings.HasPrefix(p[0], "[2] ") {
			secondRow = true
		}
	}
	if !firstRow || !secondRow {
		t.Fatalf("expected both row prefixes; pairs=%#v", pairs)
	}
	if blanks < 1 {
		t.Fatalf("expected at least one separator between rows; pairs=%#v", pairs)
	}
}

func TestJudgeResponsesDetailPairs_OmitsEmptyOptionalFields(t *testing.T) {
	rows := []audit.JudgeResponse{{
		Timestamp: time.Now(),
		Kind:      "pii",
		Direction: "prompt",
		Action:    "alert",
		Raw:       "{}",
	}}
	pairs := judgeResponsesDetailPairs(rows)
	for _, p := range pairs {
		switch p[0] {
		case "[1] Request ID", "[1] Trace ID", "[1] Run ID",
			"[1] Input hash", "[1] Prompt template",
			"[1] Inspected model", "[1] Judge model",
			"[1] Confidence", "[1] Fail-closed", "[1] Parse error":
			t.Fatalf("expected optional key %q to be omitted when empty", p[0])
		}
	}
}
