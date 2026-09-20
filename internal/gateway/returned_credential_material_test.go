// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func returnedTGSFixture() string {
	return "$krb5tgs$23$*svc$EXAMPLE.TEST$example.test/svc*$" +
		strings.Repeat("a", 32) + "$" + strings.Repeat("b", 128)
}

func TestEvaluateDeterministicToolResultUsesClosedConnectorProofs(t *testing.T) {
	credential := returnedTGSFixture()
	for _, test := range []struct {
		name, connector, preEvent, resultEvent, tool string
		args                                         json.RawMessage
	}{
		{"claude-acquisition", "claudecode", "PreToolUse", "PostToolUse", "shell", json.RawMessage(`{"command":"impacket-GetUserSPNs -request EXAMPLE.TEST/user:secret"}`)},
		{"claude-file-read", "claudecode", "PreToolUse", "PostToolUse", "shell", json.RawMessage(`{"command":"cat /tmp/kerberoast.txt"}`)},
		{"opencode", "opencode", "tool.execute.before", "tool.execute.after", "bash", json.RawMessage(`{"command":"impacket-GetUserSPNs -request EXAMPLE.TEST/user:secret"}`)},
		{"amp", "amp", "tool.call", "tool.result", "Bash", json.RawMessage(`{"command":"impacket-GetUserSPNs -request EXAMPLE.TEST/user:secret"}`)},
		{"codex", "codex", "PreToolUse", "PostToolUse", "mcp__directory__kerberoast", json.RawMessage(`{"domain":"example.test","target_user":"svc"}`)},
	} {
		t.Run(test.name, func(t *testing.T) {
			result, err := EvaluateDeterministicToolResult(
				t.Context(),
				DeterministicToolResultInput{
					Connector: test.connector, PreEvent: test.preEvent,
					ResultEvent: test.resultEvent, SessionID: "session-1",
					InvocationID: "invocation-1", Outcome: "succeeded",
					ToolName: test.tool, ToolArgs: test.args, ResultContent: credential,
				},
				"default",
			)
			if err != nil || len(result.Findings) != 1 ||
				result.RuleIDs[0] != "credential.returned_kerberos_tgs" ||
				result.Action != guardrailActionAllow ||
				result.Findings[0].ContributesToEnforcement {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			encoded, err := json.Marshal(result)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(encoded), credential) {
				t.Fatalf("credential entered benchmark evaluation: %s", encoded)
			}
		})
	}
}

func TestEvaluateDeterministicToolResultRejectsIncompleteProofs(t *testing.T) {
	credential := returnedTGSFixture()
	base := DeterministicToolResultInput{
		Connector: "claudecode", PreEvent: "PreToolUse", ResultEvent: "PostToolUse",
		SessionID: "session-1", InvocationID: "invocation-1", Outcome: "succeeded",
		ToolName:      "shell",
		ToolArgs:      json.RawMessage(`{"command":"impacket-GetUserSPNs -request EXAMPLE.TEST/user:secret"}`),
		ResultContent: credential,
	}
	for _, mutate := range []func(*DeterministicToolResultInput){
		func(input *DeterministicToolResultInput) {
			input.Outcome = "failed"
			input.ResultEvent = "PostToolUseFailure"
		},
		func(input *DeterministicToolResultInput) { input.ResultContent = "ordinary output" },
		func(input *DeterministicToolResultInput) {
			input.ToolArgs = json.RawMessage(`{"command":"impacket-GetNPUsers EXAMPLE.TEST/user -no-pass -request"}`)
		},
	} {
		input := base
		mutate(&input)
		result, err := EvaluateDeterministicToolResult(t.Context(), input, "strict")
		if err != nil || len(result.Findings) != 0 || result.Action != guardrailActionAllow {
			t.Fatalf("result=%+v err=%v", result, err)
		}
	}
	for _, command := range []string{
		"cat /tmp/one /tmp/two",
		"cat /tmp/kerberoast.txt | head -1",
		"cat ~/kerberoast.txt",
	} {
		input := base
		args, err := json.Marshal(map[string]string{"command": command})
		if err != nil {
			t.Fatal(err)
		}
		input.ToolArgs = args
		result, err := EvaluateDeterministicToolResult(t.Context(), input, "default")
		if err != nil || len(result.Findings) != 0 || result.Action != guardrailActionAllow {
			t.Fatalf("command=%q result=%+v err=%v", command, result, err)
		}
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := EvaluateDeterministicToolResult(cancelled, base, "default"); err == nil {
		t.Fatal("cancelled benchmark context was accepted")
	}
}

func TestRedactReturnedCredentialTelemetry(t *testing.T) {
	credential := returnedTGSFixture()
	for name, value := range map[string]string{
		"scalar":    credential,
		"multiline": "tool output follows\n" + credential + "\ncompleted",
		"structured Codex result": structuredHookContentString(map[string]interface{}{
			"content": []interface{}{map[string]interface{}{
				"type": "text", "text": credential,
			}},
		}),
		"oversized":    strings.Repeat("x", actionfacts.MaxReturnedCredentialResultBytes+1) + credential,
		"nul-prefixed": "prefix\x00\n" + credential,
	} {
		if got := redactReturnedCredentialTelemetry(value); got != returnedCredentialTelemetryRedaction ||
			strings.Contains(got, credential) {
			t.Fatalf("%s credential telemetry was not reduced to the fixed marker: %q", name, got)
		}
	}
	const ordinary = "build completed successfully"
	if got := redactReturnedCredentialTelemetry(ordinary); got != ordinary {
		t.Fatalf("ordinary output changed: %q", got)
	}
	oversizedOrdinary := strings.Repeat("x", actionfacts.MaxReturnedCredentialResultBytes+1)
	if got := redactReturnedCredentialTelemetry(oversizedOrdinary); got != oversizedOrdinary {
		t.Fatal("ordinary oversized output was redacted")
	}
}

func TestExactReturnedCredentialResultBytes(t *testing.T) {
	credential := returnedTGSFixture()
	tests := []agentHookRequest{
		{ConnectorName: "claudecode", HookEventName: "PostToolUse", Payload: map[string]interface{}{"tool_response": credential}},
		{ConnectorName: "opencode", HookEventName: "tool.execute.after", Payload: map[string]interface{}{"tool_response": map[string]interface{}{"output": credential, "metadata": map[string]interface{}{"exit": 0}}}},
		{ConnectorName: "amp", HookEventName: "tool.result", Payload: map[string]interface{}{"tool_response": credential, "status": "done"}},
		{ConnectorName: "codex", HookEventName: "PostToolUse", ToolName: "mcp__directory__roast", Payload: map[string]interface{}{"tool_name": "mcp__directory__roast", "tool_input": map[string]interface{}{}, "tool_response": map[string]interface{}{"content": []interface{}{map[string]interface{}{"type": "text", "text": credential}}}}},
	}
	for _, request := range tests {
		got, ok := exactReturnedCredentialResultBytes(request, connector.ToolLifecycleOutcomeSuccess)
		if !ok || string(got) != credential {
			t.Fatalf("connector=%s ok=%t result=%q", request.ConnectorName, ok, got)
		}
	}
}

func TestExactReturnedCredentialResultBytesAbstains(t *testing.T) {
	credential := returnedTGSFixture()
	for _, test := range []struct {
		name    string
		request agentHookRequest
		outcome connector.ToolLifecycleOutcome
	}{
		{"failed", agentHookRequest{ConnectorName: "claudecode", HookEventName: "PostToolUse", Payload: map[string]interface{}{"tool_response": credential}}, connector.ToolLifecycleOutcomeFailure},
		{"claude-batch", agentHookRequest{ConnectorName: "claudecode", HookEventName: "PostToolBatch", Payload: map[string]interface{}{"tool_response": credential}}, connector.ToolLifecycleOutcomeSuccess},
		{"opencode-malformed", agentHookRequest{ConnectorName: "opencode", HookEventName: "tool.execute.after", Payload: map[string]interface{}{"tool_response": map[string]interface{}{"output": 7}}}, connector.ToolLifecycleOutcomeSuccess},
		{"amp-error", agentHookRequest{ConnectorName: "amp", HookEventName: "tool.result", Payload: map[string]interface{}{"tool_response": credential, "status": "done", "error": "failed"}}, connector.ToolLifecycleOutcomeSuccess},
		{"codex-shell", agentHookRequest{ConnectorName: "codex", HookEventName: "PostToolUse", ToolName: "shell", Payload: map[string]interface{}{"tool_name": "shell", "tool_response": credential}}, connector.ToolLifecycleOutcomeSuccess},
	} {
		if got, ok := exactReturnedCredentialResultBytes(test.request, test.outcome); ok || got != nil {
			t.Fatalf("%s accepted: %q", test.name, got)
		}
	}
}

func TestReturnedCredentialMaterialFindingsAreValueFreeAndDetectionOnly(t *testing.T) {
	findings := returnedCredentialMaterialFindings(
		actionfacts.ReturnedCredentialSourceKerberoast,
		actionfacts.ReturnedCredentialKerberosTGS,
	)
	if len(findings) != 1 || findings[0].Evidence != "" ||
		findings[0].contributesToEnforcement() || findings[0].RuleID == "" {
		t.Fatalf("findings=%+v", findings)
	}
	if got := returnedCredentialMaterialFindings(
		actionfacts.ReturnedCredentialSourceKerberoast,
		actionfacts.ReturnedCredentialKerberosASREP,
	); got != nil {
		t.Fatalf("mismatched result produced findings=%+v", got)
	}
}

func TestReturnedCredentialFileReadEmitsEachMaterialClassAtLowerConfidence(t *testing.T) {
	findings := returnedCredentialMaterialFindings(
		actionfacts.ReturnedCredentialSourceFileRead,
		actionfacts.ReturnedCredentialKerberosTGS|
			actionfacts.ReturnedCredentialKerberosASREP|
			actionfacts.ReturnedCredentialNTDSRecord,
	)
	if len(findings) != 3 {
		t.Fatalf("findings=%+v", findings)
	}
	for _, finding := range findings {
		if finding.Severity != "MEDIUM" || finding.Confidence != 0.90 ||
			finding.contributesToEnforcement() || finding.Evidence != "" {
			t.Fatalf("finding=%+v", finding)
		}
	}
}
