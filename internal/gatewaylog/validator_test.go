// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gatewaylog

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// repoSchemasDir returns the on-disk `schemas/` directory of the
// repo — used so the validator tests exercise the same schema files
// the production binary loads. The test binary runs from the
// internal/gatewaylog package dir so we climb up two levels.
func repoSchemasDir(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "schemas")
}

func newRepoValidator(t *testing.T) *Validator {
	t.Helper()
	v, err := NewValidatorFromDir(repoSchemasDir(t))
	if err != nil {
		t.Fatalf("NewValidatorFromDir: %v", err)
	}
	return v
}

// TestEmbeddedSchemasMatchRepo pins the four JSON-schema files
// embedded into the gatewaylog binary to the canonical copies in
// schemas/ at the repo root. Drift is a release-blocking bug —
// runtime validation against a stale envelope would silently let
// malformed events through. If you intentionally changed the
// schema, run `cp schemas/*.json internal/gatewaylog/schemas/` and
// re-run the tests.
func TestEmbeddedSchemasMatchRepo(t *testing.T) {
	_, thisFile, _, _ := runtime.Caller(0)
	repoSchemas := filepath.Join(filepath.Dir(thisFile), "..", "..", "schemas")
	embedDir := filepath.Join(filepath.Dir(thisFile), "schemas")
	for _, name := range []string{
		"gateway-event-envelope.json",
		"scan-event.json",
		"scan-finding-event.json",
		"activity-event.json",
	} {
		repo, err := os.ReadFile(filepath.Join(repoSchemas, name))
		if err != nil {
			t.Fatalf("read repo %s: %v", name, err)
		}
		em, err := os.ReadFile(filepath.Join(embedDir, name))
		if err != nil {
			t.Fatalf("read embed %s: %v", name, err)
		}
		if !bytes.Equal(repo, em) {
			t.Fatalf("embedded schema %q has drifted from repo copy — re-run:\n  cp schemas/*.json internal/gatewaylog/schemas/", name)
		}
	}
}

func TestNewDefaultValidatorSucceeds(t *testing.T) {
	v, err := NewDefaultValidator()
	if err != nil {
		t.Fatalf("NewDefaultValidator: %v", err)
	}
	if v == nil {
		t.Fatal("NewDefaultValidator returned nil")
	}
	if err := v.Validate(validVerdict()); err != nil {
		t.Fatalf("default validator rejected valid event: %v", err)
	}
}

func TestValidator_NilIsNoop(t *testing.T) {
	var v *Validator
	if err := v.Validate(Event{}); err != nil {
		t.Fatalf("nil validator should be a no-op, got %v", err)
	}
}

func TestValidator_AcceptsValidVerdict(t *testing.T) {
	v := newRepoValidator(t)
	e := validVerdict()
	if err := v.Validate(e); err != nil {
		t.Fatalf("valid verdict rejected: %v", err)
	}
}

func TestValidator_LocalModelMetadataContract(t *testing.T) {
	v := newRepoValidator(t)
	base := Event{
		Timestamp: time.Now().UTC(), EventType: EventAIDiscovery,
		Severity: SeverityInfo, SchemaVersion: 7,
		AIDiscovery: &AIDiscoveryPayload{
			ScanID: "scan-model", Category: "local_model", State: "new",
			Model: &AIDiscoveryModel{ID: "Qwen3-0.6B-GGUF", Status: "installed", Format: "gguf"},
		},
	}
	if err := v.Validate(base); err != nil {
		t.Fatalf("valid local model event rejected: %v", err)
	}

	redacted := base
	redacted.AIDiscovery = &AIDiscoveryPayload{ScanID: "scan-redacted", Category: "local_model", State: "new"}
	if err := v.Validate(redacted); err != nil {
		t.Fatalf("redacted local model event without model block rejected: %v", err)
	}

	invalid := base
	invalid.AIDiscovery = &AIDiscoveryPayload{
		ScanID: "scan-invalid", Category: "local_model", State: "new",
		Model: &AIDiscoveryModel{ID: "Qwen3-0.6B-GGUF"},
	}
	if err := v.Validate(invalid); err == nil {
		t.Fatal("local model event without a valid status was accepted")
	}
}

func TestValidator_AcceptsHookDecision(t *testing.T) {
	v := newRepoValidator(t)
	e := Event{
		Timestamp:     time.Now().UTC(),
		EventType:     EventHookDecision,
		Severity:      SeverityHigh,
		SchemaVersion: 7,
		SessionID:     "session-1",
		AgentID:       "agent-1",
		Connector:     "codex",
		HookDecision: &HookDecisionPayload{
			Connector:  "codex",
			Event:      "PreToolUse",
			Result:     "ok",
			Action:     "block",
			RawAction:  "block",
			Severity:   SeverityHigh,
			Mode:       "action",
			WouldBlock: false,
			Enforced:   true,
			StepIdx:    3,
		},
	}
	if err := v.Validate(e); err != nil {
		t.Fatalf("valid hook decision rejected: %v", err)
	}
}

func TestValidator_AcceptsGuardrailRuntimeActions(t *testing.T) {
	v := newRepoValidator(t)

	for _, action := range []string{"allow", "warn", "alert", "confirm", "block"} {
		e := validVerdict()
		e.Verdict.Action = action
		if err := v.Validate(e); err != nil {
			t.Fatalf("valid verdict action %q rejected: %v", action, err)
		}
	}
}

// TestValidator_AcceptsRuntimeFindingScannerEnums covers the
// scanner enum values used by runtime finding emitters fanned out
// through EmitInspectFindings (hook handlers, /api/v1/inspect/*,
// proxy guardrail, mid-stream, tool-call-inspect, watcher rescan).
// Each value must validate on both EventScan and EventScanFinding;
// a regression here causes events to be dropped at the writer's
// schema gate.
func TestValidator_AcceptsRuntimeFindingScannerEnums(t *testing.T) {
	v := newRepoValidator(t)

	runtimeScanners := []string{
		"skill", "mcp", "plugin", "aibom", "codeguard",
		"hook-rules", "inline-codeguard", "ai-defense", "asset-policy",
		"tool-call-inspect", "inspect-http", "guardrail-llm", "mid-stream", "rescan",
	}
	for _, sc := range runtimeScanners {
		scan := Event{
			Timestamp:     time.Now().UTC(),
			EventType:     EventScan,
			Severity:      SeverityInfo,
			SchemaVersion: 7,
			Scan: &ScanPayload{
				ScanID:  "scan-1",
				Scanner: sc,
				Target:  "synthetic",
			},
		}
		if err := v.Validate(scan); err != nil {
			t.Fatalf("EventScan with scanner=%q rejected: %v", sc, err)
		}
		finding := Event{
			Timestamp:     time.Now().UTC(),
			EventType:     EventScanFinding,
			Severity:      SeverityInfo,
			SchemaVersion: 7,
			ScanFinding: &ScanFindingPayload{
				ScanID:  "scan-1",
				Scanner: sc,
				Target:  "synthetic",
			},
		}
		if err := v.Validate(finding); err != nil {
			t.Fatalf("EventScanFinding with scanner=%q rejected: %v", sc, err)
		}
	}
}

// TestValidator_RejectsUnknownScannerEnum guards the writer's
// schema gate: any new scanner value added in the future must be
// declared in both scan-event.json and scan-finding-event.json
// before code emits it.
func TestValidator_RejectsUnknownScannerEnum(t *testing.T) {
	v := newRepoValidator(t)
	bad := Event{
		Timestamp:     time.Now().UTC(),
		EventType:     EventScanFinding,
		Severity:      SeverityInfo,
		SchemaVersion: 7,
		ScanFinding: &ScanFindingPayload{
			ScanID:  "scan-1",
			Scanner: "definitely-not-a-real-scanner",
			Target:  "synthetic",
		},
	}
	if err := v.Validate(bad); err == nil {
		t.Fatal("expected validation error for unknown scanner enum value")
	}
}

// TestValidator_AcceptsVerdictEvaluationJoinKeys covers the new
// evaluation_id + rule_ids fields on VerdictPayload that the
// runtime finding emitters stamp so SIEM can join verdicts to
// their per-finding scan_findings rows.
func TestValidator_AcceptsVerdictEvaluationJoinKeys(t *testing.T) {
	v := newRepoValidator(t)
	e := validVerdict()
	e.Verdict.EvaluationID = "eval-abc"
	e.Verdict.RuleIDs = []string{"SECRET-AWS-AKIA", "PII-EMAIL"}
	if err := v.Validate(e); err != nil {
		t.Fatalf("verdict with evaluation_id+rule_ids rejected: %v", err)
	}
}

// TestValidator_AcceptsScanFindingConfidenceAndEvaluationID covers
// the new optional confidence + evaluation_id fields on
// ScanFindingPayload.
func TestValidator_AcceptsScanFindingConfidenceAndEvaluationID(t *testing.T) {
	v := newRepoValidator(t)
	conf := 0.87
	_ = conf
	e := Event{
		Timestamp:     time.Now().UTC(),
		EventType:     EventScanFinding,
		Severity:      SeverityHigh,
		SchemaVersion: 7,
		ScanFinding: &ScanFindingPayload{
			ScanID:       "scan-1",
			Scanner:      "hook-rules",
			Target:       "claudecode:PreToolUse",
			RuleID:       "SECRET-AWS-AKIA",
			Severity:     SeverityHigh,
			Confidence:   0.87,
			EvaluationID: "eval-abc",
		},
	}
	if err := v.Validate(e); err != nil {
		t.Fatalf("scan_finding with confidence+evaluation_id rejected: %v", err)
	}
}

func TestValidator_AcceptsValidError(t *testing.T) {
	v := newRepoValidator(t)
	e := Event{
		Timestamp:     time.Now().UTC(),
		EventType:     EventError,
		Severity:      SeverityMedium,
		SchemaVersion: 7,
		Error: &ErrorPayload{
			Subsystem: "gatewaylog",
			Code:      "SCHEMA_VIOLATION",
			Message:   "validation failed",
		},
	}
	if err := v.Validate(e); err != nil {
		t.Fatalf("valid error event rejected: %v", err)
	}
}

func TestValidator_AcceptsLLMEvents(t *testing.T) {
	v := newRepoValidator(t)
	exitCode := 0
	events := []Event{
		{
			Timestamp:     time.Now().UTC(),
			EventType:     EventLLMPrompt,
			Severity:      SeverityInfo,
			SchemaVersion: 7,
			Direction:     DirectionPrompt,
			Model:         "gpt-4o",
			Provider:      "openai",
			UserID:        "alice",
			AgentType:     "codex",
			LLMPrompt: &LLMPromptPayload{
				PromptID: "prompt-1",
				Prompt:   "hello",
				Source:   "codex",
			},
		},
		{
			Timestamp:     time.Now().UTC(),
			EventType:     EventLLMResponse,
			Severity:      SeverityInfo,
			SchemaVersion: 7,
			Direction:     DirectionCompletion,
			Model:         "gpt-4o",
			Provider:      "openai",
			LLMResponse: &LLMResponsePayload{
				ResponseID:      "response-1",
				ReplyToPromptID: "prompt-1",
				Response:        "hello back",
				Source:          "codex",
			},
		},
		{
			Timestamp:     time.Now().UTC(),
			EventType:     EventToolInvocation,
			Severity:      SeverityInfo,
			SchemaVersion: 7,
			Direction:     DirectionToolCall,
			ToolName:      "shell",
			ToolID:        "call-1",
			Tool: &ToolPayload{
				ToolCallID: "call-1",
				Phase:      "result",
				Tool:       "shell",
				ToolOutput: "ok",
				ExitCode:   &exitCode,
				Source:     "codex",
			},
		},
	}
	for _, e := range events {
		if err := v.Validate(e); err != nil {
			t.Fatalf("%s event rejected: %v", e.EventType, err)
		}
	}
}

func TestValidator_RejectsMissingEventType(t *testing.T) {
	v := newRepoValidator(t)
	bad := validVerdict()
	bad.EventType = ""
	err := v.Validate(bad)
	if err == nil {
		t.Fatal("expected validation error for missing event_type")
	}
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("expected *ValidationError, got %T: %v", err, err)
	}
}

func TestValidator_RejectsUnknownEventType(t *testing.T) {
	v := newRepoValidator(t)
	bad := validVerdict()
	bad.EventType = "not_a_real_type"
	if err := v.Validate(bad); err == nil {
		t.Fatal("expected validation error for unknown event_type")
	}
}

func TestValidator_RejectsEventWithoutPayload(t *testing.T) {
	// The envelope enforces oneOf across the 8 payload branches, so
	// an event_type=verdict without a verdict payload (and with no
	// other payload) must be rejected.
	v := newRepoValidator(t)
	bad := Event{
		Timestamp:     time.Now().UTC(),
		EventType:     EventVerdict,
		Severity:      SeverityInfo,
		SchemaVersion: 7,
	}
	if err := v.Validate(bad); err == nil {
		t.Fatal("expected validation error when no payload is set")
	}
}

func TestValidator_ValidateBytesRejectsInvalidJSON(t *testing.T) {
	v := newRepoValidator(t)
	if err := v.ValidateBytes([]byte("not json")); err == nil {
		t.Fatal("expected decode error from ValidateBytes")
	}
}

func TestValidator_ErrorMessageCarriesEventType(t *testing.T) {
	v := newRepoValidator(t)
	bad := validVerdict()
	bad.Verdict.Action = ""
	bad.Verdict.Stage = ""
	bad.Verdict = nil
	err := v.Validate(bad)
	if err == nil {
		t.Fatal("expected validation error")
	}
	if !strings.Contains(err.Error(), "verdict") {
		t.Fatalf("error message should mention the event_type: %q", err.Error())
	}
}

// validVerdict builds the minimal-well-formed VERDICT event used by
// several tests. Every caller mutates exactly one field to force a
// specific schema failure.
func validVerdict() Event {
	return Event{
		Timestamp:     time.Now().UTC(),
		EventType:     EventVerdict,
		Severity:      SeverityHigh,
		SchemaVersion: 7,
		Provider:      "openai",
		Model:         "gpt-4",
		Direction:     DirectionPrompt,
		RequestID:     "req-1",
		Verdict: &VerdictPayload{
			Stage:     StageRegex,
			Action:    "block",
			Reason:    "pii.email detected",
			LatencyMs: 3,
		},
	}
}

// --- Writer integration ----------------------------------------------------

func TestWriter_StrictMode_DropsInvalidAndEmitsError(t *testing.T) {
	var pretty bytes.Buffer
	v := newRepoValidator(t)
	w, err := New(Config{Pretty: &pretty, Validator: v})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	var got []Event
	w.WithFanout(func(e Event) { got = append(got, e) })

	// An invalid verdict (missing payload) must be dropped; the
	// operator sees a single EventError on every tier.
	w.Emit(Event{
		EventType: EventVerdict,
		Severity:  SeverityHigh,
		RequestID: "req-bad-1",
	})

	if n := len(got); n != 1 {
		t.Fatalf("expected exactly one fanout event (the EventError), got %d: %+v", n, got)
	}
	ev := got[0]
	if ev.EventType != EventError || ev.Error == nil {
		t.Fatalf("expected EventError, got %+v", ev)
	}
	if ev.Error.Code != string(ErrCodeSchemaViolation) || ev.Error.Subsystem != string(SubsystemGatewaylog) {
		t.Fatalf("EventError code/subsystem unexpected: %+v", ev.Error)
	}
	if w.SchemaViolationsCount() != 1 {
		t.Fatalf("schema violations count: got %d want 1", w.SchemaViolationsCount())
	}
	if !strings.Contains(pretty.String(), "DROP (schema violation") {
		t.Fatalf("pretty sink missing DROP line:\n%s", pretty.String())
	}
}

func TestWriter_StrictMode_ValidEventPassesThrough(t *testing.T) {
	v := newRepoValidator(t)
	w, err := New(Config{Validator: v})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	var got []Event
	w.WithFanout(func(e Event) { got = append(got, e) })

	w.Emit(validVerdict())
	if len(got) != 1 || got[0].EventType != EventVerdict {
		t.Fatalf("valid verdict did not pass through: %+v", got)
	}
	if w.SchemaViolationsCount() != 0 {
		t.Fatalf("unexpected schema violation on valid event: %d", w.SchemaViolationsCount())
	}
}

// TestValidator_PreviousPhaseUnknownRejected_EmptyAllowed locks in the
// agent_previous_phase contract that a past bug violated: the enum permits the
// real phases or null, but NOT the "unknown" sentinel. llm_event_emit once
// defaulted the first (predecessor-less) phase to "unknown", which made
// gatewaylog reject and DROP the whole lifecycle/llm_prompt event — so it never
// reached the audit or OTEL / Cisco AI Defense sinks. The fix leaves it empty
// (=> null via omitempty); this test guards both directions.
func TestValidator_PreviousPhaseUnknownRejected_EmptyAllowed(t *testing.T) {
	v := newRepoValidator(t)
	base := func() Event {
		return Event{
			EventType:     EventLifecycle,
			Severity:      SeverityInfo,
			SchemaVersion: 7,
			Lifecycle:     &LifecyclePayload{Subsystem: "gateway", Transition: "start"},
			AgentPhase:    "planning",
		}
	}

	ok := base()
	ok.AgentPreviousPhase = "" // omitted => null => valid (no predecessor)
	if err := v.Validate(ok); err != nil {
		t.Fatalf("empty agent_previous_phase must be valid: %v", err)
	}

	bad := base()
	bad.AgentPreviousPhase = "unknown"
	if err := v.Validate(bad); err == nil {
		t.Fatal(`agent_previous_phase="unknown" must be rejected by the schema`)
	}
}

func TestWriter_StrictMode_ObserverInvoked(t *testing.T) {
	v := newRepoValidator(t)
	w, err := New(Config{Validator: v})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	var calls int
	var gotType EventType
	var gotCode string
	w.OnSchemaViolation(func(t EventType, code, _ string) {
		calls++
		gotType = t
		gotCode = code
	})
	// Invalid event: scan_finding with no payload.
	w.Emit(Event{EventType: EventScanFinding})
	if calls != 1 {
		t.Fatalf("observer calls: got %d want 1", calls)
	}
	if gotType != EventScanFinding {
		t.Fatalf("observer event_type: got %q want %q", gotType, EventScanFinding)
	}
	if gotCode != string(ErrCodeSchemaViolation) {
		t.Fatalf("observer code: got %q want %q", gotCode, ErrCodeSchemaViolation)
	}
}

func TestWriter_StrictMode_ObserverPanicRecovered(t *testing.T) {
	v := newRepoValidator(t)
	var pretty bytes.Buffer
	w, err := New(Config{Pretty: &pretty, Validator: v})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	w.OnSchemaViolation(func(_ EventType, _, _ string) { panic("boom") })

	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("observer panic leaked to Emit: %v", r)
			}
		}()
		w.Emit(Event{EventType: EventVerdict})
	}()
	if !strings.Contains(pretty.String(), "schema-violation observer panic") {
		t.Fatalf("panic not surfaced on pretty sink:\n%s", pretty.String())
	}
}

// TestWriter_StrictMode_ViolationErrorAttribution verifies that when a
// scan_finding event is dropped for schema reasons, the synthesised
// EventError carries the broken payload's rule_id + evaluation_id so
// SIEM/dashboard filters keyed on those fields (a) still see the drop
// and (b) can pivot back to the upstream evaluation. Without this,
// schema-gate drops would look like anonymous infrastructure errors
// even when the source clearly identified itself.
func TestWriter_StrictMode_ViolationErrorAttribution(t *testing.T) {
	v := newRepoValidator(t)
	w, err := New(Config{Validator: v})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	var got []Event
	w.WithFanout(func(e Event) { got = append(got, e) })

	// Emit a scan_finding that is malformed on purpose (missing
	// required Finding.title/severity) but carries rule_id and
	// evaluation_id. The strict validator will drop it; the
	// synthesised EventError must echo both correlation keys.
	w.Emit(Event{
		EventType: EventScanFinding,
		Severity:  SeverityHigh,
		ScanFinding: &ScanFindingPayload{
			RuleID:       "PII.EMAIL",
			EvaluationID: "eval-abc-123",
		},
	})

	if len(got) != 1 || got[0].EventType != EventError {
		t.Fatalf("expected exactly one EventError on fanout, got %+v", got)
	}
	ep := got[0].Error
	if ep == nil {
		t.Fatalf("EventError has nil Error payload: %+v", got[0])
	}
	if ep.RuleID != "PII.EMAIL" {
		t.Fatalf("EventError.Error.RuleID: got %q want %q", ep.RuleID, "PII.EMAIL")
	}
	if ep.EvaluationID != "eval-abc-123" {
		t.Fatalf("EventError.Error.EvaluationID: got %q want %q", ep.EvaluationID, "eval-abc-123")
	}
}

// TestWriter_StrictMode_ViolationErrorAttributionVerdict mirrors the
// scan_finding case for verdict drops: a verdict missing required
// fields still surfaces its evaluation_id + the first rule_id on the
// EventError so verdict-failure alerts retain SIEM pivot keys.
func TestWriter_StrictMode_ViolationErrorAttributionVerdict(t *testing.T) {
	v := newRepoValidator(t)
	w, err := New(Config{Validator: v})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	var got []Event
	w.WithFanout(func(e Event) { got = append(got, e) })

	w.Emit(Event{
		EventType: EventVerdict,
		Severity:  SeverityHigh,
		Verdict: &VerdictPayload{
			// Stage/Action intentionally omitted to fail schema.
			EvaluationID: "eval-verdict-42",
			RuleIDs:      []string{"INJ.OVERRIDE", "INJ.SUFFIX"},
		},
	})

	if len(got) != 1 || got[0].EventType != EventError {
		t.Fatalf("expected exactly one EventError on fanout, got %+v", got)
	}
	ep := got[0].Error
	if ep == nil {
		t.Fatalf("EventError has nil Error payload: %+v", got[0])
	}
	if ep.RuleID != "INJ.OVERRIDE" {
		t.Fatalf("EventError.Error.RuleID: got %q want %q", ep.RuleID, "INJ.OVERRIDE")
	}
	if ep.EvaluationID != "eval-verdict-42" {
		t.Fatalf("EventError.Error.EvaluationID: got %q want %q", ep.EvaluationID, "eval-verdict-42")
	}
}

func TestWriter_StrictMode_NoRecursionOnViolationEvent(t *testing.T) {
	// Regression: the synthesised EventError must itself bypass the
	// validator so we never recurse. We prove this by using a
	// validator whose schema we corrupted in-memory — the only way
	// an EventError would pass is via the recursion guard.
	docs := map[string][]byte{}
	for _, name := range []string{"gateway-event-envelope.json", "scan-event.json", "scan-finding-event.json", "activity-event.json"} {
		b, err := readFile(t, filepath.Join(repoSchemasDir(t), name))
		if err != nil {
			t.Fatalf("read schema %s: %v", name, err)
		}
		docs[mustSchemaID(t, b)] = b
	}
	v, err := NewValidatorFromDocs(docs)
	if err != nil {
		t.Fatalf("NewValidatorFromDocs: %v", err)
	}

	w, err := New(Config{Validator: v})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	var events []Event
	w.WithFanout(func(e Event) { events = append(events, e) })

	// Force a double failure: the first event fails; inside
	// handleSchemaViolation we emit an EventError — if recursion
	// wasn't guarded we'd keep emitting forever. Instead we should
	// see exactly one EventError on fanout.
	w.Emit(Event{EventType: EventVerdict})
	if len(events) != 1 {
		t.Fatalf("recursion guard failed — got %d events, want 1", len(events))
	}
}

// readFile + mustSchemaID are tiny helpers that avoid a full JSON
// decode in tests by extracting just the "$id" from the schema file.
func readFile(t *testing.T, path string) ([]byte, error) {
	t.Helper()
	return os.ReadFile(path)
}

func mustSchemaID(t *testing.T, raw []byte) string {
	t.Helper()
	key := []byte("\"$id\":")
	i := bytes.Index(raw, key)
	if i < 0 {
		t.Fatalf("no $id in schema")
	}
	rest := raw[i+len(key):]
	q := bytes.IndexByte(rest, '"')
	if q < 0 {
		t.Fatal("malformed $id")
	}
	rest = rest[q+1:]
	q2 := bytes.IndexByte(rest, '"')
	if q2 < 0 {
		t.Fatal("malformed $id close")
	}
	return string(rest[:q2])
}
