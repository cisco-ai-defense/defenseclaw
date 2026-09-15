// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package benchmark

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestToolResultCaseValidationAcceptsExactLifecycleShapes(t *testing.T) {
	tests := []struct {
		connector   string
		preEvent    string
		resultEvent string
	}{
		{connector: "amp", preEvent: "tool.call", resultEvent: "tool.result"},
		{connector: "claudecode", preEvent: "PreToolUse", resultEvent: "PostToolUse"},
		{connector: "codex", preEvent: "PreToolUse", resultEvent: "PostToolUse"},
		{connector: "opencode", preEvent: "tool.execute.before", resultEvent: "tool.execute.after"},
	}
	for _, test := range tests {
		t.Run(test.connector, func(t *testing.T) {
			benchmarkCase := validToolResultCase()
			benchmarkCase.Payload.ToolResult.Invocation.Connector = test.connector
			benchmarkCase.Payload.ToolResult.Invocation.Event = test.preEvent
			benchmarkCase.Payload.ToolResult.Result.Connector = test.connector
			benchmarkCase.Payload.ToolResult.Result.Event = test.resultEvent
			if err := benchmarkCase.Validate(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestToolResultCaseValidationRejectsMalformedOrAmbiguousCases(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Case)
	}{
		{"missing payload", func(c *Case) { c.Payload.ToolResult = nil }},
		{"mixed legacy payload", func(c *Case) { c.Payload.Command = "printf status" }},
		{"connector mismatch", func(c *Case) { c.Payload.ToolResult.Result.Connector = "amp" }},
		{"non-lowercase connector", func(c *Case) {
			c.Payload.ToolResult.Invocation.Connector = "ClaudeCode"
			c.Payload.ToolResult.Result.Connector = "ClaudeCode"
		}},
		{"session mismatch", func(c *Case) { c.Payload.ToolResult.Result.SessionID = "other-session" }},
		{"invocation mismatch", func(c *Case) { c.Payload.ToolResult.Result.InvocationID = "other-invocation" }},
		{"unknown outcome", func(c *Case) { c.Payload.ToolResult.Result.Outcome = "unknown" }},
		{"event outcome mismatch", func(c *Case) {
			c.Payload.ToolResult.Result.Outcome = "failed"
			c.Payload.ToolResult.Result.Event = "PostToolUse"
		}},
		{"wrong connector event", func(c *Case) { c.Payload.ToolResult.Invocation.Event = "tool.call" }},
		{"non-object args", func(c *Case) { c.Payload.ToolResult.Invocation.Args = json.RawMessage(`[]`) }},
		{"malformed args", func(c *Case) { c.Payload.ToolResult.Invocation.Args = json.RawMessage(`{"command":`) }},
		{"oversized result", func(c *Case) {
			c.Payload.ToolResult.Result.Content = strings.Repeat("x", maxToolResultContentBytes+1)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			benchmarkCase := validToolResultCase()
			test.mutate(&benchmarkCase)
			if err := benchmarkCase.Validate(); err == nil {
				t.Fatal("malformed tool_result case was accepted")
			}
		})
	}

	legacy := minimalCase("legacy-with-tool-result", TruthBenign, DispositionAllow)
	legacy.Payload.ToolResult = validToolResultCase().Payload.ToolResult
	if err := legacy.Validate(); err == nil {
		t.Fatal("non-tool_result surface accepted payload.tool_result")
	}
}

func TestToolResultCaseSchemaIsAdditiveAndRejectsMixedPayload(t *testing.T) {
	repoRoot := filepath.Clean(filepath.Join("..", "..", ".."))
	schema := compileSchema(t, filepath.Join(repoRoot, "benchmarks", "schema", "case-v1.schema.json"))

	validate := func(t *testing.T, benchmarkCase Case) error {
		t.Helper()
		data, err := json.Marshal(benchmarkCase)
		if err != nil {
			t.Fatal(err)
		}
		var value any
		if err := json.Unmarshal(data, &value); err != nil {
			t.Fatal(err)
		}
		return schema.Validate(value)
	}

	if err := validate(t, validToolResultCase()); err != nil {
		t.Fatalf("valid tool_result case failed schema validation: %v", err)
	}
	legacy := minimalCase("legacy-action", TruthBenign, DispositionAllow)
	if err := validate(t, legacy); err != nil {
		t.Fatalf("existing action case lost compatibility: %v", err)
	}
	mixed := validToolResultCase()
	mixed.Payload.Command = "printf status"
	if err := validate(t, mixed); err == nil {
		t.Fatal("schema accepted ambiguous mixed tool_result payload")
	}
	mismatchedConnector := validToolResultCase()
	mismatchedConnector.Payload.ToolResult.Result.Connector = "amp"
	if err := validate(t, mismatchedConnector); err == nil {
		t.Fatal("schema accepted mismatched connector identity")
	}
	wrongEvent := validToolResultCase()
	wrongEvent.Payload.ToolResult.Invocation.Event = "tool.call"
	if err := validate(t, wrongEvent); err == nil {
		t.Fatal("schema accepted connector/event mismatch")
	}
}

func TestToolResultRunnerUsesGatewayAdapterWithoutDisclosingResult(t *testing.T) {
	sensitiveSentinel := "$krb5tgs$23$*svc$EXAMPLE.TEST$example.test/svc*$" +
		strings.Repeat("a", 32) + "$" + strings.Repeat("b", 128)
	benchmarkCase := validToolResultCase()
	benchmarkCase.Payload.ToolResult.Invocation.Args = json.RawMessage(
		`{"command":"impacket-GetUserSPNs -request EXAMPLE.TEST/user:secret"}`,
	)
	benchmarkCase.Payload.ToolResult.Result.Content = sensitiveSentinel
	runner := Runner{RunID: "tool-result-adapter-test", Timeout: time.Second}
	prediction := runner.runCase(
		context.Background(), "default", "default", "", "benchmark-default",
		nil, nil, benchmarkCase,
	)
	if prediction.Engine != "gateway-tool-result" || prediction.Action != "allow" ||
		!prediction.Detected || prediction.FindingCount != 1 ||
		prediction.DetectOnlyFindingCount != 1 ||
		len(prediction.RuleIDs) != 1 ||
		prediction.RuleIDs[0] != "credential.returned_kerberos_tgs" {
		t.Fatalf("prediction=%+v", prediction)
	}
	if err := prediction.Validate(); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(prediction)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), sensitiveSentinel) {
		t.Fatalf("raw result entered prediction artifact: %s", encoded)
	}
}

func TestToolResultRunnerAbstainsOnBenignAndFailedResults(t *testing.T) {
	for _, test := range []struct {
		name    string
		outcome string
		content string
		event   string
	}{
		{name: "ordinary success", outcome: "succeeded", content: "no accounts matched", event: "PostToolUse"},
		{name: "empty success", outcome: "succeeded", content: "", event: "PostToolUse"},
		{name: "failed credential-shaped output", outcome: "failed", content: "$krb5tgs$23$*not-complete", event: "PostToolUseFailure"},
	} {
		t.Run(test.name, func(t *testing.T) {
			benchmarkCase := validToolResultCase()
			benchmarkCase.Payload.ToolResult.Invocation.Args = json.RawMessage(
				`{"command":"impacket-GetUserSPNs -request EXAMPLE.TEST/user:secret"}`,
			)
			benchmarkCase.Payload.ToolResult.Result.Outcome = test.outcome
			benchmarkCase.Payload.ToolResult.Result.Event = test.event
			benchmarkCase.Payload.ToolResult.Result.Content = test.content
			if err := benchmarkCase.Validate(); err != nil {
				t.Fatal(err)
			}
			prediction := (Runner{RunID: "tool-result-negative", Timeout: time.Second}).runCase(
				context.Background(), "default", "default", "", "benchmark-default",
				nil, nil, benchmarkCase,
			)
			if prediction.Detected || prediction.FindingCount != 0 || prediction.Action != "allow" {
				t.Fatalf("prediction=%+v", prediction)
			}
		})
	}
}

func validToolResultCase() Case {
	return Case{
		SchemaVersion: SchemaVersion,
		ID:            "tool-result/exact-success",
		Source: Source{
			Dataset: "test", Revision: "1", OriginalID: "exact-success",
			License: "test", Redistribution: "vendored",
		},
		Split:   "test",
		Surface: "tool_result",
		Payload: Payload{ToolResult: &ToolResultCase{
			Invocation: ToolResultInvocation{
				Connector: "claudecode", Event: "PreToolUse",
				SessionID: "session-1", InvocationID: "invocation-1",
				ToolName: "shell", Args: json.RawMessage(`{"command":"credential audit fixture"}`),
			},
			Result: ToolResultTerminal{
				Connector: "claudecode", Event: "PostToolUse",
				SessionID: "session-1", InvocationID: "invocation-1",
				Outcome: "succeeded", Content: "synthetic result fixture",
			},
		}},
		Truth: Truth{
			SourceTruth: TruthMalicious, DeterministicTruth: DeterministicMalicious,
			LabelConfidence: "high", LabelSource: "test.fixture",
			Applicability: InScope, ExpectedDisposition: DispositionDetectOnly,
		},
	}
}
