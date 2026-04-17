// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
)

// Phase 6 integration test. Drives N synthetic audit events through
// the full audit.Logger → auditBridge → gatewaylog.Writer stack and
// asserts the resulting gateway.jsonl:
//
//  1. Has exactly one line per non-skipped event (guardrail-verdict
//     is intentionally skipped by the bridge because the hot-path
//     emits that event directly).
//  2. Every line is valid JSON with the canonical envelope
//     (ts / event_type / severity).
//  3. The ts field parses as RFC3339Nano and falls within the test's
//     own execution window.
//  4. The request_id, when emitted, is a valid UUID v4 or the empty
//     string (for events that have no correlation context).
//
// This locks down the contract the Phase 6 CI script relies on: if a
// future refactor breaks the audit→JSONL pipeline this test fails
// with a precise line-number error message, instead of the CI step
// succeeding silently on an empty file.

var phase6UUIDv4 = regexp.MustCompile(
	`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`,
)

func TestAuditToJSONL_EndToEnd_50Events(t *testing.T) {
	tmp := t.TempDir()
	dbPath := filepath.Join(tmp, "audit.db")
	jsonlPath := filepath.Join(tmp, "gateway.jsonl")

	store, err := audit.NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()
	if err := store.Init(); err != nil {
		t.Fatalf("store.Init: %v", err)
	}

	writer, err := gatewaylog.New(gatewaylog.Config{JSONLPath: jsonlPath})
	if err != nil {
		t.Fatalf("gatewaylog.New: %v", err)
	}
	defer writer.Close()

	logger := audit.NewLogger(store)
	bridge := newAuditBridge(writer)
	logger.SetStructuredEmitter(bridge)
	defer logger.Close()

	// Drive 50 synthetic events. Mix the action verbs so the
	// subsystem/transition mapping gets exercised across
	// enforcement, watcher, api, and gateway. Every other event
	// carries a real v4 UUID; the rest carry none — the validator
	// must accept both.
	start := time.Now().UTC().Add(-time.Second)
	actions := []string{
		"skill-install", "api-skill-scan", "watcher-block",
		"sidecar-connected", "gateway-ready", "api-plugin-disable",
	}
	for i := 0; i < 50; i++ {
		var reqID string
		// deterministic but syntactically-valid v4 UUIDs
		if i%2 == 0 {
			reqID = fmt.Sprintf("00000000-0000-4000-8000-%012x", i+1)
		}
		action := actions[i%len(actions)]
		if err := logger.LogActionWithCorrelation(
			action,
			fmt.Sprintf("target-%d", i),
			fmt.Sprintf("iteration=%d", i),
			"",
			reqID,
		); err != nil {
			t.Fatalf("LogActionWithCorrelation[%d]: %v", i, err)
		}
	}
	// Close flushes any pending sink fanout; we don't need it for the
	// JSONL assertion (the writer is synchronous on Emit) but it keeps
	// the test symmetric with how the real sidecar shuts down.
	logger.Close()

	end := time.Now().UTC().Add(time.Second)

	f, err := os.Open(jsonlPath)
	if err != nil {
		t.Fatalf("open jsonl: %v", err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNo := 0
	parsed := 0
	for sc.Scan() {
		lineNo++
		raw := strings.TrimSpace(sc.Text())
		if raw == "" {
			continue
		}
		var env struct {
			Timestamp time.Time `json:"ts"`
			EventType string    `json:"event_type"`
			Severity  string    `json:"severity"`
			RequestID string    `json:"request_id"`
		}
		if err := json.Unmarshal([]byte(raw), &env); err != nil {
			t.Fatalf("line %d: invalid JSON: %v\nraw=%s", lineNo, err, raw)
		}
		if env.EventType == "" {
			t.Fatalf("line %d: event_type missing", lineNo)
		}
		if env.Severity == "" {
			t.Fatalf("line %d: severity missing", lineNo)
		}
		if env.Timestamp.Before(start) || env.Timestamp.After(end) {
			t.Fatalf("line %d: ts %s outside [%s, %s]", lineNo, env.Timestamp, start, end)
		}
		if env.RequestID != "" && !phase6UUIDv4.MatchString(env.RequestID) {
			t.Fatalf("line %d: request_id=%q is not a v4 UUID", lineNo, env.RequestID)
		}
		parsed++
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scanner error: %v", err)
	}

	// The bridge skips guardrail-verdict; none of our 50 actions
	// hit that skip list, so we expect exactly 50 JSONL lines.
	if parsed != 50 {
		t.Fatalf("expected 50 JSONL events, got %d (lines read=%d)", parsed, lineNo)
	}
}

// TestAuditToJSONL_SkipsGuardrailVerdict asserts the bridge's skip
// list: guardrail-verdict emissions never hit gateway.jsonl via the
// bridge because the hot-path already emits a structured verdict
// event directly. Double-emission would inflate operator dashboards.
func TestAuditToJSONL_SkipsGuardrailVerdict(t *testing.T) {
	tmp := t.TempDir()
	dbPath := filepath.Join(tmp, "audit.db")
	jsonlPath := filepath.Join(tmp, "gateway.jsonl")

	store, err := audit.NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()
	if err := store.Init(); err != nil {
		t.Fatalf("store.Init: %v", err)
	}

	writer, err := gatewaylog.New(gatewaylog.Config{JSONLPath: jsonlPath})
	if err != nil {
		t.Fatalf("gatewaylog.New: %v", err)
	}
	defer writer.Close()

	logger := audit.NewLogger(store)
	logger.SetStructuredEmitter(newAuditBridge(writer))
	defer logger.Close()

	if err := logger.LogActionWithCorrelation(
		"guardrail-verdict", "gpt-5", "direction=prompt action=block", "", "aaaabbbb-cccc-4ddd-8eee-ffff00001111",
	); err != nil {
		t.Fatalf("LogActionWithCorrelation: %v", err)
	}
	// One non-skipped event to assert the writer is actually functional.
	if err := logger.LogActionWithCorrelation(
		"sidecar-connected", "", "port=8100", "", "",
	); err != nil {
		t.Fatalf("LogActionWithCorrelation: %v", err)
	}
	logger.Close()

	data, err := os.ReadFile(jsonlPath)
	if err != nil {
		t.Fatalf("read jsonl: %v", err)
	}
	if strings.Contains(string(data), `"guardrail-verdict"`) {
		t.Fatalf("gateway.jsonl bridged a guardrail-verdict event:\n%s", string(data))
	}
	if !strings.Contains(string(data), `"sidecar-connected"`) {
		t.Fatalf("gateway.jsonl missing sidecar-connected control event:\n%s", string(data))
	}
}
