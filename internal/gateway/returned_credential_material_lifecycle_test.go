// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestReturnedCredentialMaterialLifecycleRequiresExactSuccessfulRebind(t *testing.T) {
	installCorrelationHMACForTest()
	installDefaultProfileConnector(t, "claudecode")
	store, logger := testStoreAndV8Logger(t)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, store, logger, cfg)
	handler := http.HandlerFunc(api.handleAgentHook("claudecode"))

	const command = "impacket-GetUserSPNs -dc-ip 192.0.2.12 -request EXAMPLE.TEST/user:secret"
	credential := returnedTGSFixture()
	pre := map[string]interface{}{
		"hook_event_name": "PreToolUse",
		"session_id":      "returned-credential-success",
		"tool_use_id":     "returned-credential-call",
		"tool_name":       "Bash",
		"tool_input":      map[string]interface{}{"command": command},
	}
	preResponse := callAgentHookForTest(t, handler, pre)
	if slices.Contains(preResponse.RuleIDs, "credential.returned_kerberos_tgs") {
		t.Fatalf("pre-tool proposal emitted result-backed finding: %+v", preResponse)
	}

	result := cloneStringAnyMap(pre)
	result["hook_event_name"] = "PostToolUse"
	result["tool_response"] = credential
	resultResponse := callAgentHookForTest(t, handler, result)
	if !slices.Contains(resultResponse.RuleIDs, "credential.returned_kerberos_tgs") ||
		resultResponse.Action == guardrailActionBlock {
		t.Fatalf("result response=%+v", resultResponse)
	}
	encoded, err := json.Marshal(resultResponse)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), credential) {
		t.Fatalf("credential entered hook response: %s", encoded)
	}

	database, err := sql.Open("sqlite", store.DatabasePath())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	var persisted string
	if err := database.QueryRow(`SELECT COALESCE(GROUP_CONCAT(
		COALESCE(details, '') || COALESCE(structured_json, '') ||
		COALESCE(projected_record_json, ''), ''), '') FROM audit_events`).Scan(&persisted); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(persisted, credential) {
		t.Fatal("credential entered the audit database")
	}

	replay := callAgentHookForTest(t, handler, result)
	if slices.Contains(replay.RuleIDs, "credential.returned_kerberos_tgs") {
		t.Fatalf("terminal replay emitted duplicate result-backed finding: %+v", replay)
	}
}

func TestReturnedCredentialMaterialLifecycleAcceptsOneExactFileRead(t *testing.T) {
	installCorrelationHMACForTest()
	installDefaultProfileConnector(t, "claudecode")
	store, logger := testStoreAndV8Logger(t)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, store, logger, cfg)
	profile := api.hookProfileForConnector("claudecode")
	pre := map[string]interface{}{
		"hook_event_name": "PreToolUse",
		"session_id":      "returned-credential-file-read",
		"tool_use_id":     "returned-credential-file-read-call",
		"tool_name":       "Bash",
		"tool_input":      map[string]interface{}{"command": "cat /tmp/kerberoast.txt"},
	}
	runSQLLifecycleGatewayStage(t, api, profile, pre)
	result := cloneStringAnyMap(pre)
	result["hook_event_name"] = "PostToolUse"
	result["tool_response"] = returnedTGSFixture()
	_, response := runSQLLifecycleGatewayStage(t, api, profile, result)
	if !slices.Contains(response.RuleIDs, "credential.returned_kerberos_tgs") ||
		response.Action == guardrailActionBlock {
		t.Fatalf("response=%+v", response)
	}
}

func TestReturnedCredentialMaterialLifecycleAbstainsWithoutCompleteProof(t *testing.T) {
	installCorrelationHMACForTest()
	installDefaultProfileConnector(t, "claudecode")
	store, logger := testStoreAndV8Logger(t)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, store, logger, cfg)
	profile := api.hookProfileForConnector("claudecode")
	credential := returnedTGSFixture()

	tests := []struct {
		name          string
		preCommand    string
		preSession    string
		preInvocation string
		resultSession string
		resultID      string
		resultEvent   string
		resultValue   interface{}
	}{
		{
			name:          "source material mismatch",
			preCommand:    "impacket-GetNPUsers EXAMPLE.TEST/user -dc-ip 192.0.2.12 -no-pass -request -format hashcat",
			preSession:    "returned-credential-mismatch",
			preInvocation: "mismatch-call",
			resultSession: "returned-credential-mismatch",
			resultID:      "mismatch-call",
			resultEvent:   "PostToolUse",
			resultValue:   credential,
		},
		{
			name:          "failed result",
			preCommand:    "impacket-GetUserSPNs -request EXAMPLE.TEST/user:secret",
			preSession:    "returned-credential-failed",
			preInvocation: "failed-call",
			resultSession: "returned-credential-failed",
			resultID:      "failed-call",
			resultEvent:   "PostToolUseFailure",
			resultValue:   credential,
		},
		{
			name:          "invocation mismatch",
			preCommand:    "impacket-GetUserSPNs -request EXAMPLE.TEST/user:secret",
			preSession:    "returned-credential-id-mismatch",
			preInvocation: "prepared-call",
			resultSession: "returned-credential-id-mismatch",
			resultID:      "other-call",
			resultEvent:   "PostToolUse",
			resultValue:   credential,
		},
		{
			name:          "malformed result envelope",
			preCommand:    "impacket-GetUserSPNs -request EXAMPLE.TEST/user:secret",
			preSession:    "returned-credential-malformed",
			preInvocation: "malformed-call",
			resultSession: "returned-credential-malformed",
			resultID:      "malformed-call",
			resultEvent:   "PostToolUse",
			resultValue:   map[string]interface{}{"output": credential},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pre := map[string]interface{}{
				"hook_event_name": "PreToolUse",
				"session_id":      test.preSession,
				"tool_use_id":     test.preInvocation,
				"tool_name":       "Bash",
				"tool_input":      map[string]interface{}{"command": test.preCommand},
			}
			runSQLLifecycleGatewayStage(t, api, profile, pre)
			result := cloneStringAnyMap(pre)
			result["hook_event_name"] = test.resultEvent
			result["session_id"] = test.resultSession
			result["tool_use_id"] = test.resultID
			result["tool_response"] = test.resultValue
			_, response := runSQLLifecycleGatewayStage(t, api, profile, result)
			for _, ruleID := range response.RuleIDs {
				if strings.HasPrefix(ruleID, "credential.returned_") {
					t.Fatalf("incomplete proof emitted %q: %+v", ruleID, response)
				}
			}
		})
	}
}

func TestReturnedCredentialMaterialLifecycleSupportedConnectorContracts(t *testing.T) {
	installCorrelationHMACForTest()
	const command = "impacket-GetUserSPNs -request EXAMPLE.TEST/user:secret"
	credential := returnedTGSFixture()
	tests := []struct {
		connector string
		pre       map[string]interface{}
		result    map[string]interface{}
	}{
		{
			connector: "opencode",
			pre: openCodeToolEvent(
				"tool.execute.before", "returned-opencode", "opencode-call", command,
			),
			result: func() map[string]interface{} {
				payload := openCodeToolEvent(
					"tool.execute.after", "returned-opencode", "opencode-call", command,
				)
				payload["tool_response"] = map[string]interface{}{
					"output":   credential,
					"metadata": map[string]interface{}{"exit": 0},
				}
				return payload
			}(),
		},
		{
			connector: "amp",
			pre:       ampToolCall("returned-amp", "amp-call", command),
			result: func() map[string]interface{} {
				payload := ampToolResult("returned-amp", "amp-call", "done")
				payload["tool_input"] = map[string]interface{}{"command": command}
				payload["tool_response"] = credential
				return payload
			}(),
		},
		{
			connector: "codex",
			pre: map[string]interface{}{
				"hook_event_name": "PreToolUse",
				"session_id":      "returned-codex",
				"tool_use_id":     "codex-call",
				"tool_name":       "mcp__directory__kerberoast",
				"mcp_server_name": "directory",
				"tool_input": map[string]interface{}{
					"domain": "example.test", "target_user": "svc",
				},
			},
			result: map[string]interface{}{
				"hook_event_name": "PostToolUse",
				"session_id":      "returned-codex",
				"tool_use_id":     "codex-call",
				"tool_name":       "mcp__directory__kerberoast",
				"mcp_server_name": "directory",
				"tool_input": map[string]interface{}{
					"domain": "example.test", "target_user": "svc",
				},
				"tool_response": map[string]interface{}{
					"content": []interface{}{map[string]interface{}{
						"type": "text", "text": credential,
					}},
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.connector, func(t *testing.T) {
			installDefaultProfileConnector(t, test.connector)
			store, logger := testStoreAndV8Logger(t)
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = test.connector
			api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, store, logger, cfg)
			profile := api.hookProfileForConnector(test.connector)
			runSQLLifecycleGatewayStageForConnector(
				t, api, profile, test.connector, test.pre,
			)
			_, response := runSQLLifecycleGatewayStageForConnector(
				t, api, profile, test.connector, test.result,
			)
			if !slices.Contains(response.RuleIDs, "credential.returned_kerberos_tgs") ||
				response.Action == guardrailActionBlock {
				t.Fatalf("response=%+v", response)
			}
		})
	}
}
