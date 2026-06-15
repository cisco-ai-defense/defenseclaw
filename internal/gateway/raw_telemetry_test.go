// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/redaction"
)

func TestAppendRawTelemetryDetailsOnlyWhenRedactionDisabled(t *testing.T) {
	redaction.SetDisableAll(false)
	t.Cleanup(func() { redaction.SetDisableAll(false) })

	base := "action=allow"
	if got := appendRawTelemetryDetails(base, "raw_payload", []byte("hello\nsecret")); got != base {
		t.Fatalf("raw details appended while redaction was enabled: %q", got)
	}

	redaction.SetDisableAll(true)
	got := appendRawTelemetryDetails(base, "raw_payload", []byte("hello\nsecret"))
	if !strings.Contains(got, `raw_payload="hello\nsecret"`) {
		t.Fatalf("raw details missing quoted payload: %q", got)
	}
}

func TestRawOTLPDetailsOmitsFullyDuplicateHookPrompt(t *testing.T) {
	redaction.SetDisableAll(true)
	t.Cleanup(func() { redaction.SetDisableAll(false) })

	a := &APIServer{}
	eventID := a.rememberRawHookEvent("codex", "prompt", "sess-1", "turn-1", "", []byte("hello raw"))
	body := []byte(`{
		"resourceLogs": [{
			"resource": {"attributes": [{"key": "service.name", "value": {"stringValue": "codex"}}]},
			"scopeLogs": [{"logRecords": [{
				"attributes": [
					{"key": "event.name", "value": {"stringValue": "codex.user_prompt"}},
					{"key": "session.id", "value": {"stringValue": "sess-1"}},
					{"key": "turn_id", "value": {"stringValue": "turn-1"}},
					{"key": "prompt", "value": {"stringValue": "hello raw"}}
				]
			}]}]
		}]
	}`)

	got := a.appendRawOTLPDetails("summary", "codex", otelSignalLogs, body)
	if !strings.Contains(got, "raw_duplicate_of="+eventID) || !strings.Contains(got, "raw_body_omitted=duplicate") {
		t.Fatalf("duplicate OTLP prompt was not marked/omitted: %s", got)
	}
	if strings.Contains(got, "hello raw") || strings.Contains(got, "raw_body=") {
		t.Fatalf("duplicate raw OTLP body leaked despite hook canonical event: %s", got)
	}
}

func TestRawOTLPDetailsDedupesOnlyDuplicateFieldsInMixedBatch(t *testing.T) {
	redaction.SetDisableAll(true)
	t.Cleanup(func() { redaction.SetDisableAll(false) })

	a := &APIServer{}
	eventID := a.rememberRawHookEvent("claudecode", "prompt", "sess-1", "", "", []byte("hello raw"))
	body := []byte(`{
		"resourceLogs": [{
			"resource": {"attributes": [{"key": "service.name", "value": {"stringValue": "claude-code"}}]},
			"scopeLogs": [{"logRecords": [
				{"attributes": [
					{"key": "event.name", "value": {"stringValue": "claude_code.user_prompt"}},
					{"key": "session.id", "value": {"stringValue": "sess-1"}},
					{"key": "prompt", "value": {"stringValue": "hello raw"}}
				]},
				{"attributes": [
					{"key": "event.name", "value": {"stringValue": "claude_code.user_prompt"}},
					{"key": "session.id", "value": {"stringValue": "sess-2"}},
					{"key": "prompt", "value": {"stringValue": "new raw"}}
				]}
			]}]
		}]
	}`)

	got := a.appendRawOTLPDetails("summary", "claudecode", otelSignalLogs, body)
	if !strings.Contains(got, "raw_duplicate_of="+eventID) || !strings.Contains(got, "raw_body_deduped=") {
		t.Fatalf("mixed OTLP batch was not deduped as expected: %s", got)
	}
	if strings.Contains(got, `\"prompt\":\"hello raw\"`) || strings.Contains(got, `"hello raw"`) {
		t.Fatalf("duplicate prompt survived deduped raw body: %s", got)
	}
	if !strings.Contains(got, "new raw") {
		t.Fatalf("non-duplicate prompt was not retained in deduped raw body: %s", got)
	}
}
