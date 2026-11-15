// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	collectorlogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
)

const claudeUserPromptMatch = "otlp.claudecode.user_prompt.v1.log.model.request"

// claudeUserPromptAttributes is a user_prompt log as Claude Code 2.1.322
// exports it (names and value types read from its event logger): event.name
// without the claude_code. prefix, prompt_length as a string, and prompt and
// prompt_text set to the redaction marker unless OTEL_LOG_USER_PROMPTS is set.
func claudeUserPromptAttributes(prompt string) []*commonpb.KeyValue {
	return []*commonpb.KeyValue{
		otlpClassifierStringAttribute("user.id", "3f1d2c7b9a8e"),
		otlpClassifierStringAttribute("session.id", nativeUsageSession),
		otlpClassifierStringAttribute("terminal.type", "tmux"),
		otlpClassifierStringAttribute("event.name", "user_prompt"),
		otlpClassifierStringAttribute("event.timestamp", "2026-11-12T10:00:00.000Z"),
		otlpClassifierIntAttribute("event.sequence", 3),
		otlpClassifierStringAttribute("prompt.id", nativeUsagePrompt),
		otlpClassifierStringAttribute("prompt_length", "26"),
		otlpClassifierStringAttribute("prompt", prompt),
		otlpClassifierStringAttribute("prompt_text", prompt),
	}
}

func claudeUserPromptLog(now time.Time, attributes []*commonpb.KeyValue) *collectorlogspb.ExportLogsServiceRequest {
	return &collectorlogspb.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{{
		Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{
			otlpClassifierStringAttribute("service.name", "claude-code"),
			otlpClassifierStringAttribute("service.version", "2.1.322"),
		}},
		ScopeLogs: []*logspb.ScopeLogs{{
			Scope: &commonpb.InstrumentationScope{Name: "com.anthropic.claude_code.events", Version: "2.1.322"},
			LogRecords: []*logspb.LogRecord{{
				TimeUnixNano: uint64(now.Add(-time.Second).UnixNano()),
				Body:         &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: "claude_code.user_prompt"}},
				Attributes:   attributes,
			}},
		}},
	}}}
}

// GAP-0039: the class matched only event.name claude_code.user_prompt, which
// Claude Code puts in the log body, never in event.name.
func TestClaudeCodeUserPromptDiscriminatorMatchesRealEventName(t *testing.T) {
	classifier := mustOTLPInboundClassifierV8(t)
	now := time.Now().UTC()
	shape := claudeUserPromptAttributes(claudeCodeRedactedPrompt)
	for _, test := range []struct {
		name       string
		attributes []*commonpb.KeyValue
		source     string
		want       otlpInboundIdentityState
	}{
		{"real event name", shape, "claudecode", otlpInboundIdentityMatched},
		{"body-style event name is not what Claude Code sends", withNativeAttribute(shape, "event.name",
			otlpClassifierStringAttribute("event.name", "claude_code.user_prompt")), "claudecode", otlpInboundIdentityUnsupported},
		{"other connector", shape, "codex", otlpInboundIdentityUnsupported},
	} {
		t.Run(test.name, func(t *testing.T) {
			leaf := firstNativeLogLeaf(t, claudeUserPromptLog(now, test.attributes))
			result, err := classifier.classify(leaf, test.source)
			if err != nil || result.identityState != test.want {
				t.Fatalf("state=%d err=%v want=%d", result.identityState, err, test.want)
			}
			if test.want == otlpInboundIdentityMatched && result.match.ID() != claudeUserPromptMatch {
				t.Fatalf("match=%q", result.match.ID())
			}
		})
	}
}

func TestClaudeCodeUserPromptImportsOneRequestAndNeverTheRedactionMarker(t *testing.T) {
	for _, test := range []struct {
		name, prompt, state string
		reported            bool
	}{
		{"default redacted prompt is not reported", claudeCodeRedactedPrompt, "not_reported", false},
		{"OTEL_LOG_USER_PROMPTS prompt is preserved", "list the files in this repo", "preserved", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newCodexNativeOTLPFixture(t)
			api := &APIServer{}
			api.bindOTLPObservabilityRuntime(fixture.runtime)
			now := time.Now().UTC()
			accounting, err := api.importDecodedOTLPRequestV8(context.Background(),
				claudeUserPromptLog(now, claudeUserPromptAttributes(test.prompt)), otelSignalLogs, "claudecode", now)
			if err != nil || !accounting.valid() || accounting.imported != 1 {
				t.Fatalf("accounting=%+v err=%v", accounting, err)
			}
			if got := codexNativeStoredEventCount(t, fixture.path, "model.request"); got != 1 {
				t.Fatalf("model.request records=%d want 1", got)
			}
			record := inboundStoredProjectedRecord(t, fixture.path, "claudecode", "model.request")
			correlation, _ := record["correlation"].(map[string]any)
			if correlation["session_id"] != nativeUsageSession || correlation["turn_id"] != nativeUsagePrompt {
				t.Fatalf("correlation=%#v", record["correlation"])
			}
			body, _ := record["body"].(map[string]any)
			if body["defenseclaw.telemetry.input.reported"] != test.reported ||
				body["defenseclaw.content.input.state"] != test.state {
				t.Fatalf("content flags=%#v", body)
			}
			encoded, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			for _, leaked := range []string{"REDACTED", "claude_code.user_prompt"} {
				if strings.Contains(string(encoded), leaked) {
					t.Fatalf("record carries %q as content: %s", leaked, encoded)
				}
			}
		})
	}
}
