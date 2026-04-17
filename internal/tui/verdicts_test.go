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

	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
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

	// block filter: keep only rows whose .action == "block". Both
	// verdict and judge rows carry an action; lifecycle/error rows
	// don't, so they get hidden. The previous semantics let judge
	// rows through regardless of the chip — users complained that
	// filtering for "block" still showed "alert" judge rows.
	p.verdictAction = "block"
	p.loadVerdicts(path)
	for _, r := range p.verdicts {
		if r.action != "block" {
			t.Errorf("block filter leaked action=%q type=%q",
				r.action, r.eventType)
		}
	}
	if got := len(p.verdicts); got != 1 {
		t.Fatalf("filtered row count=%d want 1 (only the block verdict)", got)
	}
}

func TestLoadVerdicts_ActionFilterKeepsMatchingJudgeRows(t *testing.T) {
	// The action chip is case-insensitive against the row's action
	// field, and a judge row whose .action matches must survive.
	dir := t.TempDir()
	path := filepath.Join(dir, "gateway.jsonl")
	content := strings.Join([]string{
		`{"ts":"2026-04-16T12:00:00Z","event_type":"verdict","severity":"HIGH","verdict":{"stage":"final","action":"block","reason":"pii"}}`,
		`{"ts":"2026-04-16T12:00:01Z","event_type":"judge","severity":"HIGH","judge":{"kind":"pii","action":"block"}}`,
		`{"ts":"2026-04-16T12:00:02Z","event_type":"judge","severity":"LOW","judge":{"kind":"injection","action":"allow"}}`,
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	p := &LogsPanel{source: logSourceVerdicts, verdictAction: "block"}
	p.loadVerdicts(path)
	if got := len(p.verdicts); got != 2 {
		t.Fatalf("rows=%d want 2 (verdict+judge, both action=block)", got)
	}
	for _, r := range p.verdicts {
		if r.action != "block" {
			t.Errorf("leaked action=%q type=%q", r.action, r.eventType)
		}
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

// Phase 4 additions — event-type chip cycling + filtering.
//
// Schema-level enumeration: we intentionally require every
// gatewaylog.EventType to be reachable by cycling. If a new event
// type is added to the schema without being added to the chip
// list this test fails, which is precisely the point — the TUI
// must expose every schema event type or the "Verdicts" tab
// silently hides a category of operator-relevant data.
func TestCycleVerdictEventType_RotatesThroughAllThenWrapsToEmpty(t *testing.T) {
	p := &LogsPanel{}
	want := []string{"verdict", "judge", "lifecycle", "error", "diagnostic", ""}
	for i, exp := range want {
		p.cycleVerdictEventType()
		if p.verdictEventType != exp {
			t.Fatalf("step%d=%q want %q", i+1, p.verdictEventType, exp)
		}
	}
}

func TestLoadVerdicts_EventTypeFilterHidesJudgeRowsWhenVerdictOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gateway.jsonl")
	content := strings.Join([]string{
		`{"ts":"2026-04-16T12:00:00Z","event_type":"verdict","severity":"HIGH","verdict":{"stage":"final","action":"block","reason":"pii"}}`,
		`{"ts":"2026-04-16T12:00:01Z","event_type":"judge","severity":"HIGH","judge":{"kind":"pii","action":"block"}}`,
		`{"ts":"2026-04-16T12:00:02Z","event_type":"lifecycle","severity":"INFO"}`,
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	p := &LogsPanel{source: logSourceVerdicts, verdictEventType: "verdict"}
	p.loadVerdicts(path)
	if got := len(p.verdicts); got != 1 {
		t.Fatalf("rows=%d want 1 (verdict-only chip active)", got)
	}
	if p.verdicts[0].eventType != "verdict" {
		t.Fatalf("leaked eventType=%q", p.verdicts[0].eventType)
	}
}

func TestLoadVerdicts_EventTypeAndActionFilterCombine(t *testing.T) {
	// Both filters AND together. A judge row that happens to
	// block must survive "type=judge × action=block" but drop
	// out of "type=verdict × action=block".
	dir := t.TempDir()
	path := filepath.Join(dir, "gateway.jsonl")
	content := strings.Join([]string{
		`{"ts":"2026-04-16T12:00:00Z","event_type":"verdict","severity":"HIGH","verdict":{"stage":"final","action":"block","reason":"pii"}}`,
		`{"ts":"2026-04-16T12:00:01Z","event_type":"judge","severity":"HIGH","judge":{"kind":"pii","action":"block"}}`,
		`{"ts":"2026-04-16T12:00:02Z","event_type":"judge","severity":"LOW","judge":{"kind":"injection","action":"allow"}}`,
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Judge × block => 1 row (the judge block).
	p := &LogsPanel{source: logSourceVerdicts, verdictEventType: "judge", verdictAction: "block"}
	p.loadVerdicts(path)
	if got := len(p.verdicts); got != 1 {
		t.Fatalf("judge×block rows=%d want 1", got)
	}
	if p.verdicts[0].eventType != "judge" || p.verdicts[0].action != "block" {
		t.Fatalf("leaked row: %+v", p.verdicts[0])
	}

	// Verdict × block => 1 row (the verdict-final block).
	p = &LogsPanel{source: logSourceVerdicts, verdictEventType: "verdict", verdictAction: "block"}
	p.loadVerdicts(path)
	if got := len(p.verdicts); got != 1 {
		t.Fatalf("verdict×block rows=%d want 1", got)
	}
	if p.verdicts[0].eventType != "verdict" {
		t.Fatalf("leaked eventType=%q", p.verdicts[0].eventType)
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
	if strings.HasPrefix(got, "abcdefghij") {
		t.Fatalf("did not truncate: %q", got)
	}
}

func TestTruncateVerdictReason_UTF8Safe(t *testing.T) {
	// Regression guard: the previous byte-indexed truncate could
	// slice inside a multi-byte codepoint and emit invalid UTF-8.
	// With rune-aware truncation, the result must always be valid
	// UTF-8 even when the cut point falls mid-codepoint.
	in := "héllo wörld ☃☃☃☃☃☃☃☃"
	got := truncateVerdictReason(in, 5)
	if !strings.HasSuffix(got, "…") {
		t.Fatalf("missing ellipsis: %q", got)
	}
	// 4 runes + 1 ellipsis rune — every rune must round-trip.
	runes := []rune(got)
	if len(runes) != 5 {
		t.Fatalf("rune count=%d want 5: %q", len(runes), got)
	}
	// No replacement character means no invalid byte sequences.
	for _, r := range got {
		if r == '\uFFFD' {
			t.Fatalf("replacement rune leaked — byte slice mid-codepoint: %q", got)
		}
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

// ---------------------------------------------------------------------
// Schema-coverage tests — every field on gatewaylog.Event that the TUI
// claims to surface must survive a parse → render → detail round-trip.
// These tests were added when the Verdicts tab was extended to expose
// request_id/run_id/categories/latency and the lifecycle/error/
// diagnostic subpayloads. Without them, a schema change that renames
// one of those fields would silently break the modal.
// ---------------------------------------------------------------------

// TestParseVerdictRow_CorrelationFields pins the envelope-level
// identifiers. Losing any of these breaks the "pivot from TUI into
// Splunk/SQLite" workflow, so they're a regression guard.
func TestParseVerdictRow_CorrelationFields(t *testing.T) {
	line := `{"ts":"2026-04-16T12:34:56Z","event_type":"verdict","severity":"HIGH",` +
		`"request_id":"req-123","run_id":"run-abc","session_id":"sess-xyz",` +
		`"provider":"bedrock","model":"claude","direction":"prompt",` +
		`"verdict":{"stage":"final","action":"block","reason":"pii","categories":["pii.email","injection.system"],"latency_ms":37}}`
	row, ok := parseVerdictRow(line)
	if !ok {
		t.Fatal("parse failed")
	}
	if row.requestID != "req-123" || row.runID != "run-abc" ||
		row.sessionID != "sess-xyz" || row.provider != "bedrock" {
		t.Fatalf("envelope IDs wrong: %+v", row)
	}
	if len(row.categories) != 2 ||
		row.categories[0] != "pii.email" ||
		row.categories[1] != "injection.system" {
		t.Fatalf("categories wrong: %+v", row.categories)
	}
	if row.latencyMs != 37 {
		t.Fatalf("latency=%d want 37", row.latencyMs)
	}
}

// TestParseVerdictRow_JudgeRichFields guards the full judge payload
// shape — the detail modal depends on input_bytes/severity/findings/
// raw_response/parse_error being populated.
func TestParseVerdictRow_JudgeRichFields(t *testing.T) {
	line := `{"ts":"2026-04-16T12:00:00Z","event_type":"judge","severity":"HIGH",` +
		`"model":"gpt-4",` +
		`"judge":{"kind":"pii","action":"block","severity":"CRITICAL","input_bytes":512,"latency_ms":90,` +
		`"findings":[{"category":"pii.email","severity":"HIGH","rule":"R1","source":"regex","confidence":0.95}],` +
		`"raw_response":"{\"action\":\"block\"}","parse_error":""}}`
	row, ok := parseVerdictRow(line)
	if !ok {
		t.Fatal("parse failed")
	}
	if row.judgeSeverity != "CRITICAL" {
		t.Fatalf("judgeSeverity=%q want CRITICAL", row.judgeSeverity)
	}
	if row.judgeInputBytes != 512 {
		t.Fatalf("judgeInputBytes=%d want 512", row.judgeInputBytes)
	}
	if row.latencyMs != 90 {
		t.Fatalf("latencyMs=%d want 90 (populated from judge.latency_ms)", row.latencyMs)
	}
	if len(row.judgeFindings) != 1 {
		t.Fatalf("findings=%d want 1", len(row.judgeFindings))
	}
	if row.judgeFindings[0].Category != "pii.email" ||
		row.judgeFindings[0].Rule != "R1" ||
		row.judgeFindings[0].Source != "regex" ||
		row.judgeFindings[0].Conf < 0.94 {
		t.Fatalf("finding details wrong: %+v", row.judgeFindings[0])
	}
	if row.judgeRaw == "" {
		t.Fatal("raw_response must survive parse")
	}
}

// TestParseVerdictRow_LifecycleAndErrorAndDiagnostic asserts that
// the three non-verdict payloads (lifecycle / error / diagnostic)
// are parsed into typed fields instead of being dumped into r.raw
// verbatim. This is what makes renderVerdictLine produce a clean
// "LIFECYCLE subsystem TRANSITION" row instead of a raw JSON blob.
func TestParseVerdictRow_LifecycleAndErrorAndDiagnostic(t *testing.T) {
	cases := []struct {
		name     string
		line     string
		validate func(t *testing.T, r verdictRow)
	}{
		{
			name: "lifecycle",
			line: `{"ts":"2026-04-16T12:00:00Z","event_type":"lifecycle","severity":"INFO",` +
				`"lifecycle":{"subsystem":"gateway","transition":"ready","details":{"port":"8081","host":"localhost"}}}`,
			validate: func(t *testing.T, r verdictRow) {
				if r.lifecycleSubsystem != "gateway" || r.lifecycleTransition != "ready" {
					t.Fatalf("lifecycle fields wrong: %+v", r)
				}
				if r.lifecycleDetails["port"] != "8081" {
					t.Fatalf("details not parsed: %+v", r.lifecycleDetails)
				}
			},
		},
		{
			name: "error",
			line: `{"ts":"2026-04-16T12:00:00Z","event_type":"error","severity":"HIGH",` +
				`"error":{"subsystem":"opa","code":"compile_failed","message":"bad rego","cause":"syntax"}}`,
			validate: func(t *testing.T, r verdictRow) {
				if r.errorSubsystem != "opa" || r.errorCode != "compile_failed" ||
					r.errorMessage != "bad rego" || r.errorCause != "syntax" {
					t.Fatalf("error fields wrong: %+v", r)
				}
			},
		},
		{
			name: "diagnostic",
			line: `{"ts":"2026-04-16T12:00:00Z","event_type":"diagnostic","severity":"INFO",` +
				`"diagnostic":{"component":"sinks","message":"pipeline initialised"}}`,
			validate: func(t *testing.T, r verdictRow) {
				if r.diagnosticComponent != "sinks" || r.diagnosticMessage != "pipeline initialised" {
					t.Fatalf("diagnostic fields wrong: %+v", r)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			row, ok := parseVerdictRow(tc.line)
			if !ok {
				t.Fatal("parse failed")
			}
			tc.validate(t, row)
		})
	}
}

// TestRenderVerdictLine_StructuredLifecycleAndError confirms the
// renderer promotes subsystem/transition/code/message into the
// compact line instead of dumping raw JSON. This is the operator-
// visible contract: scanning the Verdicts tab should read like a
// table, not a log file.
func TestRenderVerdictLine_StructuredLifecycleAndError(t *testing.T) {
	ts := time.Date(2026, 4, 16, 3, 4, 5, 0, time.UTC)

	l := verdictRow{
		timestamp:           ts,
		eventType:           "lifecycle",
		lifecycleSubsystem:  "gateway",
		lifecycleTransition: "ready",
		lifecycleDetails:    map[string]string{"port": "8081", "host": "localhost"},
	}
	got := renderVerdictLine(l)
	for _, needle := range []string{"LIFECYCLE", "GATEWAY", "READY", "host=localhost", "port=8081"} {
		if !strings.Contains(got, needle) {
			t.Errorf("lifecycle render missing %q: %q", needle, got)
		}
	}

	e := verdictRow{
		timestamp:      ts,
		eventType:      "error",
		errorSubsystem: "opa",
		errorCode:      "compile_failed",
		errorMessage:   "bad rego",
	}
	got = renderVerdictLine(e)
	for _, needle := range []string{"ERROR", "OPA", "code=compile_failed", "msg=bad rego"} {
		if !strings.Contains(got, needle) {
			t.Errorf("error render missing %q: %q", needle, got)
		}
	}

	d := verdictRow{
		timestamp:           ts,
		eventType:           "diagnostic",
		diagnosticComponent: "sinks",
		diagnosticMessage:   "pipeline initialised",
	}
	got = renderVerdictLine(d)
	for _, needle := range []string{"DIAG", "SINKS", "pipeline initialised"} {
		if !strings.Contains(got, needle) {
			t.Errorf("diagnostic render missing %q: %q", needle, got)
		}
	}
}

// TestRenderVerdictLine_VerdictIncludesCategoriesAndLatency checks
// that the compact line surfaces categories (capped at 2) and
// latency — without them the Verdicts tab hides "why" and "how
// fast" behind a modal press.
func TestRenderVerdictLine_VerdictIncludesCategoriesAndLatency(t *testing.T) {
	r := verdictRow{
		timestamp:  time.Date(2026, 4, 16, 3, 4, 5, 0, time.UTC),
		eventType:  "verdict",
		action:     "block",
		severity:   "HIGH",
		stage:      "final",
		direction:  "prompt",
		model:      "gpt-4",
		reason:     "injection",
		categories: []string{"injection.system", "pii.email", "policy.custom"},
		latencyMs:  42,
	}
	got := renderVerdictLine(r)
	for _, needle := range []string{"BLOCK", "HIGH", "injection", "(42ms)"} {
		if !strings.Contains(got, needle) {
			t.Errorf("line missing %q: %q", needle, got)
		}
	}
	// First two categories rendered, third collapsed into "+1more".
	if !strings.Contains(got, "injection.system") || !strings.Contains(got, "pii.email") {
		t.Errorf("first two categories missing: %q", got)
	}
	if !strings.Contains(got, "+1more") {
		t.Errorf("overflow indicator missing: %q", got)
	}
}

// TestTrimCategories_OverflowSignalsRemainder verifies the
// truncation contract used by the compact renderer: once we
// exceed the cap, operators should see an explicit +Nmore signal
// instead of a silently-truncated list.
func TestTrimCategories_OverflowSignalsRemainder(t *testing.T) {
	got := trimCategories([]string{"a", "b", "c", "d"}, 2)
	if len(got) != 3 {
		t.Fatalf("len=%d want 3 (2 shown + marker)", len(got))
	}
	if got[2] != "+2more" {
		t.Fatalf("marker=%q want +2more", got[2])
	}
	// Cap equal to slice length -> no marker.
	got = trimCategories([]string{"a", "b"}, 2)
	if len(got) != 2 {
		t.Fatalf("no-overflow len=%d want 2", len(got))
	}
	// Empty input -> nil result.
	if got := trimCategories(nil, 3); got != nil {
		t.Fatalf("nil in, got %+v", got)
	}
}

// ---------------------------------------------------------------------
// Severity chip — new in this revision. Cycles, filter semantics,
// and the HIGH+ meta-filter.
// ---------------------------------------------------------------------

func TestCycleVerdictSeverity_RotatesThroughAllThenWrapsToEmpty(t *testing.T) {
	p := &LogsPanel{}
	want := []string{"CRITICAL", "HIGH", "HIGH+", "MEDIUM", "LOW", "INFO", ""}
	for i, exp := range want {
		p.cycleVerdictSeverity()
		if p.verdictSeverity != exp {
			t.Fatalf("step%d=%q want %q", i+1, p.verdictSeverity, exp)
		}
	}
}

func TestLoadVerdicts_SeverityFilterExactMatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gateway.jsonl")
	content := strings.Join([]string{
		`{"ts":"2026-04-16T12:00:00Z","event_type":"verdict","severity":"HIGH","verdict":{"stage":"final","action":"block","reason":"x"}}`,
		`{"ts":"2026-04-16T12:00:01Z","event_type":"verdict","severity":"MEDIUM","verdict":{"stage":"final","action":"alert","reason":"y"}}`,
		`{"ts":"2026-04-16T12:00:02Z","event_type":"verdict","severity":"CRITICAL","verdict":{"stage":"final","action":"block","reason":"z"}}`,
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	p := &LogsPanel{source: logSourceVerdicts, verdictSeverity: "HIGH"}
	p.loadVerdicts(path)
	if len(p.verdicts) != 1 {
		t.Fatalf("HIGH rows=%d want 1", len(p.verdicts))
	}
	if !strings.EqualFold(p.verdicts[0].severity, "HIGH") {
		t.Fatalf("leaked severity=%q", p.verdicts[0].severity)
	}
}

// TestLoadVerdicts_SeverityFilterHighPlus is the most common
// incident-response pattern — "show me the stuff worth paging on".
// HIGH+ must keep HIGH and CRITICAL and drop everything else.
func TestLoadVerdicts_SeverityFilterHighPlus(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gateway.jsonl")
	content := strings.Join([]string{
		`{"ts":"2026-04-16T12:00:00Z","event_type":"verdict","severity":"HIGH","verdict":{"stage":"final","action":"block","reason":"x"}}`,
		`{"ts":"2026-04-16T12:00:01Z","event_type":"verdict","severity":"MEDIUM","verdict":{"stage":"final","action":"alert","reason":"y"}}`,
		`{"ts":"2026-04-16T12:00:02Z","event_type":"verdict","severity":"CRITICAL","verdict":{"stage":"final","action":"block","reason":"z"}}`,
		`{"ts":"2026-04-16T12:00:03Z","event_type":"verdict","severity":"LOW","verdict":{"stage":"final","action":"allow","reason":"w"}}`,
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	p := &LogsPanel{source: logSourceVerdicts, verdictSeverity: "HIGH+"}
	p.loadVerdicts(path)
	if len(p.verdicts) != 2 {
		t.Fatalf("HIGH+ rows=%d want 2 (HIGH+CRITICAL)", len(p.verdicts))
	}
	for _, r := range p.verdicts {
		if severityRank(r.severity) < severityRank("HIGH") {
			t.Fatalf("leaked sub-HIGH severity=%q", r.severity)
		}
	}
}

// TestLoadVerdicts_DiagnosticRowsSurviveFilter ensures diagnostic
// events (newly added to the chip list) are actually filterable.
// Regression guard: if diagnostic is in the chip but loadVerdicts
// drops the event_type on the floor, the chip's "Diagnostic"
// position would silently match nothing.
func TestLoadVerdicts_DiagnosticRowsSurviveFilter(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gateway.jsonl")
	content := strings.Join([]string{
		`{"ts":"2026-04-16T12:00:00Z","event_type":"diagnostic","severity":"INFO","diagnostic":{"component":"sinks","message":"init"}}`,
		`{"ts":"2026-04-16T12:00:01Z","event_type":"verdict","severity":"HIGH","verdict":{"stage":"final","action":"block","reason":"x"}}`,
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	p := &LogsPanel{source: logSourceVerdicts, verdictEventType: "diagnostic"}
	p.loadVerdicts(path)
	if len(p.verdicts) != 1 {
		t.Fatalf("rows=%d want 1 (diagnostic only)", len(p.verdicts))
	}
	if p.verdicts[0].eventType != "diagnostic" {
		t.Fatalf("leaked eventType=%q", p.verdicts[0].eventType)
	}
}

// TestSeverityRank_KnownAndUnknown pins the ordering that HIGH+
// depends on. An unknown string must rank below INFO on purpose;
// surfacing noise when an operator asked for HIGH+ would be worse
// than dropping it.
func TestSeverityRank_KnownAndUnknown(t *testing.T) {
	if severityRank("CRITICAL") <= severityRank("HIGH") {
		t.Fatal("CRITICAL must outrank HIGH")
	}
	if severityRank("high") != severityRank("HIGH") {
		t.Fatal("rank must be case-insensitive")
	}
	if severityRank("NOT_A_LEVEL") != 0 {
		t.Fatal("unknown must rank 0 (below INFO)")
	}
}

// ---------------------------------------------------------------------
// Detail modal enrichment — the modal is the "pivot into Splunk"
// surface, so the tests below pin every newly-surfaced key.
// ---------------------------------------------------------------------

func TestVerdictDetailPairs_IncludesCorrelationIDs(t *testing.T) {
	r := verdictRow{
		eventType: "verdict", timestamp: time.Now(),
		requestID: "req-1", runID: "run-1", sessionID: "sess-1", provider: "bedrock",
	}
	got := map[string]string{}
	for _, p := range verdictDetailPairs(r) {
		got[p[0]] = p[1]
	}
	for _, k := range []string{"Provider", "Request ID", "Run ID", "Session ID"} {
		if _, ok := got[k]; !ok {
			t.Errorf("missing %q: %+v", k, got)
		}
	}
}

func TestVerdictDetailPairs_IncludesVerdictExtras(t *testing.T) {
	r := verdictRow{
		eventType: "verdict", timestamp: time.Now(),
		action: "block", severity: "HIGH", stage: "final",
		categories: []string{"pii.email", "injection"},
		latencyMs:  123,
	}
	got := map[string]string{}
	for _, p := range verdictDetailPairs(r) {
		got[p[0]] = p[1]
	}
	if got["Categories"] != "pii.email, injection" {
		t.Errorf("Categories=%q", got["Categories"])
	}
	if got["Latency (ms)"] != "123" {
		t.Errorf("Latency=%q", got["Latency (ms)"])
	}
}

func TestVerdictDetailPairs_IncludesJudgeExtras(t *testing.T) {
	r := verdictRow{
		eventType:       "judge",
		timestamp:       time.Now(),
		severity:        "HIGH",
		judgeSeverity:   "CRITICAL",
		judgeInputBytes: 2048,
		judgeRaw:        `{"action":"block"}`,
		judgeParseError: "",
		judgeFindings: []judgeFinding{
			{Category: "pii.email", Severity: "HIGH", Rule: "R1", Source: "regex", Conf: 0.95},
		},
	}
	got := map[string]string{}
	for _, p := range verdictDetailPairs(r) {
		got[p[0]] = p[1]
	}
	if got["Judge severity"] != "CRITICAL" {
		t.Errorf("Judge severity=%q", got["Judge severity"])
	}
	if got["Judge input bytes"] != "2048" {
		t.Errorf("Judge input bytes=%q", got["Judge input bytes"])
	}
	if got["Judge raw response"] == "" {
		t.Errorf("Judge raw response missing")
	}
	if got["Finding 1"] == "" {
		t.Errorf("Finding 1 missing")
	}
	if !strings.Contains(got["Finding 1"], "pii.email") {
		t.Errorf("Finding 1 malformed: %q", got["Finding 1"])
	}
}

// TestVerdictDetailPairs_SuppressesRedundantJudgeSeverity checks
// that when envelope.Severity already matches judge.Severity we
// skip the "Judge severity" row — the duplicate is visual noise.
func TestVerdictDetailPairs_SuppressesRedundantJudgeSeverity(t *testing.T) {
	r := verdictRow{
		eventType: "judge", timestamp: time.Now(),
		severity: "HIGH", judgeSeverity: "HIGH",
	}
	for _, p := range verdictDetailPairs(r) {
		if p[0] == "Judge severity" {
			t.Fatalf("redundant Judge severity row leaked: %+v", p)
		}
	}
}

func TestVerdictDetailPairs_LifecycleDetailsOrderedAlphabetically(t *testing.T) {
	// Pin stable ordering so the modal doesn't shuffle between
	// opens when iterating a Go map.
	r := verdictRow{
		eventType:           "lifecycle",
		timestamp:           time.Now(),
		lifecycleSubsystem:  "gateway",
		lifecycleTransition: "ready",
		lifecycleDetails:    map[string]string{"z_zebra": "1", "a_alpha": "2", "m_mid": "3"},
	}
	pairs := verdictDetailPairs(r)
	var keys []string
	for _, p := range pairs {
		if strings.HasPrefix(p[0], "Detail: ") {
			keys = append(keys, p[0])
		}
	}
	want := []string{"Detail: a_alpha", "Detail: m_mid", "Detail: z_zebra"}
	if len(keys) != len(want) {
		t.Fatalf("detail keys=%v want %v", keys, want)
	}
	for i, k := range want {
		if keys[i] != k {
			t.Errorf("order[%d]=%q want %q", i, keys[i], k)
		}
	}
}

func TestVerdictDetailPairs_IncludesErrorAndDiagnostic(t *testing.T) {
	r := verdictRow{
		eventType:           "error",
		timestamp:           time.Now(),
		errorSubsystem:      "opa",
		errorCode:           "compile_failed",
		errorMessage:        "bad rego",
		errorCause:          "syntax",
		diagnosticComponent: "sinks",
		diagnosticMessage:   "init",
	}
	got := map[string]string{}
	for _, p := range verdictDetailPairs(r) {
		got[p[0]] = p[1]
	}
	for _, k := range []string{"Error subsystem", "Error code", "Error message", "Error cause", "Diagnostic component", "Diagnostic message"} {
		if _, ok := got[k]; !ok {
			t.Errorf("missing %q: %+v", k, got)
		}
	}
}

// TestRenderDetailsInline_StableAndCapped pins the two contracts
// the compact renderer relies on: alphabetical ordering (stable
// across runs) and an explicit n-cap.
func TestRenderDetailsInline_StableAndCapped(t *testing.T) {
	m := map[string]string{"b": "2", "a": "1", "c": "3", "d": "4"}
	got := renderDetailsInline(m, 2)
	// Ordering: alphabetical by key.
	if got != "a=1 b=2" {
		t.Fatalf("got %q want %q", got, "a=1 b=2")
	}
	if got := renderDetailsInline(nil, 2); got != "" {
		t.Fatalf("nil in, got %q", got)
	}
}

// TestRenderDetailsInline_EdgeCaps exercises the caps we deliberately
// short-circuit on. Without the n <= 0 guard a negative cap panics
// via keys[:n]; without the empty-map short-circuit we still return
// the empty string, but the explicit branch keeps the hot path
// allocation-free. These cases are easy to regress, so pin them.
func TestRenderDetailsInline_EdgeCaps(t *testing.T) {
	m := map[string]string{"a": "1"}
	if got := renderDetailsInline(m, 0); got != "" {
		t.Fatalf("n=0 got %q want empty", got)
	}
	if got := renderDetailsInline(m, -1); got != "" {
		t.Fatalf("n=-1 got %q want empty (guard missing?)", got)
	}
	if got := renderDetailsInline(map[string]string{}, 3); got != "" {
		t.Fatalf("empty map got %q want empty", got)
	}
	// n larger than the map is a no-op cap — every entry should
	// still render.
	got := renderDetailsInline(m, 10)
	if got != "a=1" {
		t.Fatalf("n larger than map: got %q want %q", got, "a=1")
	}
}

// TestTrimCategories_EdgeCaps pins the same short-circuit paths
// renderDetailsInline relies on, since both funcs front-load n<=0
// to keep render branches panic-free.
func TestTrimCategories_EdgeCaps(t *testing.T) {
	if got := trimCategories(nil, 3); got != nil {
		t.Fatalf("nil in, got %v want nil", got)
	}
	if got := trimCategories([]string{"a", "b"}, 0); got != nil {
		t.Fatalf("n=0 got %v want nil", got)
	}
	if got := trimCategories([]string{"a", "b"}, -1); got != nil {
		t.Fatalf("n=-1 got %v want nil (guard missing?)", got)
	}
}

// TestTrimCategories_DoesNotMutateCaller guards against an easy
// aliasing bug: append on cats[:n:n] must allocate because cap is
// exhausted, so the caller's backing array is never touched. If a
// future refactor loses the triple-index slice, this test fails —
// the overflow marker would leak into the caller's slice.
func TestTrimCategories_DoesNotMutateCaller(t *testing.T) {
	original := []string{"alpha", "beta", "gamma", "delta"}
	snapshot := append([]string(nil), original...)
	_ = trimCategories(original, 2)
	for i := range snapshot {
		if original[i] != snapshot[i] {
			t.Fatalf("caller slice mutated at %d: got %q want %q",
				i, original[i], snapshot[i])
		}
	}
}

// TestVerdictEventTypeFiltersMatchSchema is the drift-detection
// sentinel promised by the comment on verdictEventTypeFilters. If a
// new gatewaylog.EventType is added and this test is not updated
// alongside the chip list, the new type will silently be
// unfilterable in the TUI — an annoying dead end for operators. We
// prefer a loud test failure over a quiet UX regression.
func TestVerdictEventTypeFiltersMatchSchema(t *testing.T) {
	schemaTypes := []gatewaylog.EventType{
		gatewaylog.EventVerdict,
		gatewaylog.EventJudge,
		gatewaylog.EventLifecycle,
		gatewaylog.EventError,
		gatewaylog.EventDiagnostic,
	}
	for _, et := range schemaTypes {
		found := false
		for _, f := range verdictEventTypeFilters {
			if f == string(et) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("gatewaylog.EventType %q has no matching chip in verdictEventTypeFilters — add it to the chip list and label map", et)
		}
	}
	// Also verify every chip (except the "all events" sentinel) is
	// a real schema constant, so stale chips can't linger after a
	// rename.
	knownSchema := map[string]struct{}{}
	for _, et := range schemaTypes {
		knownSchema[string(et)] = struct{}{}
	}
	for _, f := range verdictEventTypeFilters {
		if f == "" {
			continue
		}
		if _, ok := knownSchema[f]; !ok {
			t.Errorf("chip %q is not a gatewaylog.EventType — was the schema renamed?", f)
		}
	}
	// Every chip must have a display label, else the View() lookup
	// renders "" and operators lose the chip name.
	for _, f := range verdictEventTypeFilters {
		if _, ok := verdictEventTypeLabels[f]; !ok {
			t.Errorf("chip %q has no entry in verdictEventTypeLabels", f)
		}
	}
}

// TestVerdictSeverityLabelsCoverFilters is the same drift guard for
// the severity chip: every filter value must have a display label,
// because the View() loop renders verdictSeverityLabels[s] without
// a fallback.
func TestVerdictSeverityLabelsCoverFilters(t *testing.T) {
	for _, s := range verdictSeverityFilters {
		if _, ok := verdictSeverityLabels[s]; !ok {
			t.Errorf("severity chip %q has no entry in verdictSeverityLabels", s)
		}
	}
}
