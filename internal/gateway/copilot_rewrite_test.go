// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func managedCopilotGatewayProfile(t *testing.T) connector.HookProfile {
	t.Helper()
	profile := connector.NewCopilotEnterpriseConnector().HookProfile(connector.SetupOpts{
		ManagedEnterprise: true,
		AgentVersion:      connector.CopilotEnterpriseMinVersion,
		HookContractID:    connector.CopilotEnterpriseHookContractID,
	})
	if profile.CompatibilityStatus != connector.HookCompatibilityKnown {
		t.Fatalf("managed Copilot profile is unavailable: %+v", profile)
	}
	return profile
}

func TestManagedCopilotPromptAndResultBlocksRemainRewrites(t *testing.T) {
	profile := managedCopilotGatewayProfile(t)
	for _, test := range []struct {
		name       string
		event      string
		outputKey  string
		rewriteTag string
	}{
		{name: "prompt", event: "userPromptTransformed", outputKey: "modifiedTransformedPrompt", rewriteTag: "prompt"},
		{name: "tool result", event: "postToolUse", outputKey: "modifiedResult", rewriteTag: "tool_result"},
	} {
		t.Run(test.name, func(t *testing.T) {
			action, wouldBlock := mapHookActionForProfile(
				"block", "action", test.event, profile.Capabilities, profile, nil,
			)
			if action != "allow" || !wouldBlock {
				t.Fatalf("mapped action/would_block=%q/%v, want allow/true", action, wouldBlock)
			}
			resp := agentHookResponseForProfile(
				profile,
				agentHookRequest{ConnectorName: "copilot", HookEventName: test.event},
				action,
				"block",
				"HIGH",
				"untrusted free-form reason must not reach the model",
				[]string{"CISCO-UNKNOWN", "CISCO-VIOLENCE"},
				"action",
				wouldBlock,
				profile.Capabilities,
			)
			if resp.Action != "allow" || resp.RawAction != "block" || !resp.WouldBlock {
				t.Fatalf("response accounting=%q/%q/%v, want allow/block/true", resp.Action, resp.RawAction, resp.WouldBlock)
			}
			if _, ok := resp.HookOutput[test.outputKey]; !ok {
				t.Fatalf("response missing %s: %+v", test.outputKey, resp.HookOutput)
			}
			serialized := connectorSafeJSONForTest(resp.HookOutput)
			if strings.Contains(serialized, "untrusted free-form") {
				t.Fatalf("untrusted server reason reached model-facing output: %s", serialized)
			}
			if got := copilotModelInputRewriteRequested(resp); got != test.rewriteTag {
				t.Fatalf("rewrite audit tag=%q want %q", got, test.rewriteTag)
			}
		})
	}
}

func TestManagedCopilotPreToolUseIsNativeDeny(t *testing.T) {
	profile := managedCopilotGatewayProfile(t)
	action, wouldBlock := mapHookActionForProfile(
		"block", "action", "preToolUse", profile.Capabilities, profile, nil,
	)
	if action != "block" || wouldBlock {
		t.Fatalf("mapped action/would_block=%q/%v, want block/false", action, wouldBlock)
	}
	resp := agentHookResponseForProfile(
		profile,
		agentHookRequest{ConnectorName: "copilot", HookEventName: "preToolUse", ToolName: "shell"},
		action, "block", "HIGH", "rule", []string{"CISCO-CODE"}, "action", wouldBlock, profile.Capabilities,
	)
	if resp.HookOutput["permissionDecision"] != "deny" {
		t.Fatalf("preToolUse output=%+v, want native deny", resp.HookOutput)
	}
	if got := copilotModelInputRewriteRequested(resp); got != "" {
		t.Fatalf("native deny incorrectly recorded as rewrite %q", got)
	}
}

func TestManagedCopilotObserveModeNeverRewrites(t *testing.T) {
	profile := managedCopilotGatewayProfile(t)
	action, wouldBlock := mapHookActionForProfile(
		"block", "observe", "userPromptTransformed", profile.Capabilities, profile, nil,
	)
	resp := agentHookResponseForProfile(
		profile,
		agentHookRequest{ConnectorName: "copilot", HookEventName: "userPromptTransformed"},
		action, "block", "HIGH", "rule", []string{"CISCO-PII"}, "observe", wouldBlock, profile.Capabilities,
	)
	if resp.Action != "allow" || resp.RawAction != "block" || !resp.WouldBlock || resp.HookOutput != nil {
		t.Fatalf("observe response=%+v, want allow/block/would-block with no mutation", resp)
	}
}

func TestManagedCopilotProfileRequiresTrustedDeploymentAndBoundHeaders(t *testing.T) {
	request := func(event, contract, managedHeader string) *http.Request {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/copilot/hook", nil)
		req.Header.Set(connector.CopilotEnterpriseHookEventHeader, event)
		req.Header.Set(connector.CopilotEnterpriseHookContractHeader, contract)
		req.Header.Set(connector.CopilotEnterpriseManagedHeader, managedHeader)
		return req
	}
	api := &APIServer{scannerCfg: &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}}
	profile, event, err := api.hookProfileForRequest(
		"copilot",
		request("preToolUse", connector.CopilotEnterpriseHookContractID, "true"),
	)
	if err != nil || event != "preToolUse" || profile.ContractID != connector.CopilotEnterpriseHookContractID {
		t.Fatalf("trusted binding profile/event/error=%q/%q/%v", profile.ContractID, event, err)
	}

	unmanaged := &APIServer{scannerCfg: &config.Config{DeploymentMode: string(config.DeploymentModeUnmanagedBYOD)}}
	if _, _, err := unmanaged.hookProfileForRequest(
		"copilot",
		request("preToolUse", connector.CopilotEnterpriseHookContractID, "true"),
	); err == nil {
		t.Fatal("unmanaged deployment selected privileged Copilot profile")
	}
	if _, _, err := api.hookProfileForRequest(
		"copilot",
		request("madeUpEvent", connector.CopilotEnterpriseHookContractID, "true"),
	); err == nil {
		t.Fatal("unreviewed Copilot event selected privileged profile")
	}
}

func TestManagedCopilotAuthenticatedHTTPBlocksUseV2ResponseContract(t *testing.T) {
	const gatewayToken = "managed-copilot-http-test-token"

	tests := []struct {
		name             string
		event            string
		payload          map[string]interface{}
		wantContent      string
		assertHookOutput func(*testing.T, map[string]interface{})
	}{
		{
			name:  "transformed prompt is inspected and replaced",
			event: "userPromptTransformed",
			payload: map[string]interface{}{
				"transformedPrompt": "model-facing transformed prompt",
				"prompt":            "untransformed prompt",
			},
			wantContent: "model-facing transformed prompt",
			assertHookOutput: func(t *testing.T, output map[string]interface{}) {
				t.Helper()
				if replacement, _ := output["modifiedTransformedPrompt"].(string); replacement == "" {
					t.Fatalf("hook_output=%+v, want modifiedTransformedPrompt", output)
				}
			},
		},
		{
			name:  "nested tool result is inspected and replaced",
			event: "postToolUse",
			payload: map[string]interface{}{
				"toolName": "shell",
				"toolResult": map[string]interface{}{
					"resultType":       "success",
					"textResultForLlm": "model-facing nested tool output",
					"metadata":         "must not be scanned as model content",
				},
			},
			wantContent: "model-facing nested tool output",
			assertHookOutput: func(t *testing.T, output map[string]interface{}) {
				t.Helper()
				modified, ok := output["modifiedResult"].(map[string]interface{})
				if !ok {
					t.Fatalf("hook_output=%+v, want modifiedResult object", output)
				}
				if replacement, _ := modified["textResultForLlm"].(string); replacement == "" {
					t.Fatalf("modifiedResult=%+v, want textResultForLlm replacement", modified)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			inspector := &stubAIDInspector{verdict: blockVerdict()}
			cfg := &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}
			cfg.Gateway.Token = gatewayToken
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = "copilot"
			api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
			api.SetCiscoInspector(inspector)

			body, err := json.Marshal(test.payload)
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodPost, "/api/v1/copilot/hook", strings.NewReader(string(body)))
			req.Header.Set("Authorization", "Bearer "+gatewayToken)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set(connector.CopilotEnterpriseHookEventHeader, test.event)
			req.Header.Set(connector.CopilotEnterpriseHookContractHeader, connector.CopilotEnterpriseHookContractID)
			req.Header.Set(connector.CopilotEnterpriseManagedHeader, "true")

			recorder := httptest.NewRecorder()
			api.tokenAuth(api.handleAgentHook("copilot")).ServeHTTP(recorder, req)
			if recorder.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			if inspector.calls != 1 || len(inspector.messages) != 1 || inspector.messages[0].Content != test.wantContent {
				t.Fatalf("inspector calls/messages=%d/%+v, want exact content %q", inspector.calls, inspector.messages, test.wantContent)
			}

			var response map[string]interface{}
			if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
				t.Fatalf("decode response: %v (body=%s)", err, recorder.Body.String())
			}
			if response["action"] != "allow" || response["raw_action"] != "block" || response["would_block"] != true {
				t.Fatalf("response accounting=%+v, want allow/block/would_block", response)
			}
			output, ok := response["hook_output"].(map[string]interface{})
			if !ok {
				t.Fatalf("response=%+v, want managed v2 hook_output", response)
			}
			test.assertHookOutput(t, output)
		})
	}
}

func TestManagedCopilotAuthenticatedHTTPDoesNotInspectEmptyModelResultFallbacks(t *testing.T) {
	const gatewayToken = "managed-copilot-empty-result-test-token"
	inspector := &stubAIDInspector{verdict: blockVerdict()}
	cfg := &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}
	cfg.Gateway.Token = gatewayToken
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "copilot"
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	api.SetCiscoInspector(inspector)

	body := `{
		"toolName":"shell",
		"toolResult":{
			"resultType":"success",
			"textResultForLlm":"",
			"metadata":"nested decoy must not be inspected"
		},
		"result":"top-level decoy must not be inspected"
	}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/copilot/hook", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+gatewayToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(connector.CopilotEnterpriseHookEventHeader, "postToolUse")
	req.Header.Set(connector.CopilotEnterpriseHookContractHeader, connector.CopilotEnterpriseHookContractID)
	req.Header.Set(connector.CopilotEnterpriseManagedHeader, "true")

	recorder := httptest.NewRecorder()
	api.tokenAuth(api.handleAgentHook("copilot")).ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if inspector.calls != 0 || len(inspector.messages) != 0 {
		t.Fatalf("inspector calls/messages=%d/%+v, want no inspection for authoritative empty result", inspector.calls, inspector.messages)
	}
	var response map[string]interface{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v (body=%s)", err, recorder.Body.String())
	}
	if response["action"] != "allow" || response["raw_action"] != "allow" || response["would_block"] != false {
		t.Fatalf("response accounting=%+v, want allow/allow/not-would-block", response)
	}
	if _, present := response["hook_output"]; present {
		t.Fatalf("response=%+v, authoritative empty result must not be rewritten", response)
	}
}

func TestManagedCopilotAuthenticatedHTTPDoesNotInspectAbsentModelResultFallbacks(t *testing.T) {
	const gatewayToken = "managed-copilot-absent-result-test-token"
	inspector := &stubAIDInspector{verdict: blockVerdict()}
	cfg := &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}
	cfg.Gateway.Token = gatewayToken
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "copilot"
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	api.SetCiscoInspector(inspector)

	body := `{
		"toolName":"shell",
		"toolResult":{
			"resultType":"success",
			"metadata":"nested decoy must not be inspected"
		},
		"result":"top-level result decoy must not be inspected",
		"output":"top-level output decoy must not be inspected",
		"content":"top-level content decoy must not be inspected"
	}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/copilot/hook", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+gatewayToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(connector.CopilotEnterpriseHookEventHeader, "postToolUse")
	req.Header.Set(connector.CopilotEnterpriseHookContractHeader, connector.CopilotEnterpriseHookContractID)
	req.Header.Set(connector.CopilotEnterpriseManagedHeader, "true")

	recorder := httptest.NewRecorder()
	api.tokenAuth(api.handleAgentHook("copilot")).ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if inspector.calls != 0 || len(inspector.messages) != 0 {
		t.Fatalf("inspector calls/messages=%d/%+v, want no inspection for absent model-facing result", inspector.calls, inspector.messages)
	}
	var response map[string]interface{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v (body=%s)", err, recorder.Body.String())
	}
	if response["action"] != "allow" || response["raw_action"] != "allow" || response["would_block"] != false {
		t.Fatalf("response accounting=%+v, want allow/allow/not-would-block", response)
	}
	if _, present := response["hook_output"]; present {
		t.Fatalf("response=%+v, absent model-facing result must not be rewritten", response)
	}
}

func TestManagedCopilotAuthenticatedHTTPPreToolUseReturnsNativeDeny(t *testing.T) {
	const gatewayToken = "managed-copilot-tool-deny-test-token"
	inspector := &stubAIDInspector{verdict: blockVerdict()}
	cfg := &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}
	cfg.Gateway.Token = gatewayToken
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "copilot"
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	api.SetCiscoInspector(inspector)

	body := `{"toolName":"shell","toolInput":{"command":"dangerous command"}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/copilot/hook", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+gatewayToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(connector.CopilotEnterpriseHookEventHeader, "preToolUse")
	req.Header.Set(connector.CopilotEnterpriseHookContractHeader, connector.CopilotEnterpriseHookContractID)
	req.Header.Set(connector.CopilotEnterpriseManagedHeader, "true")

	recorder := httptest.NewRecorder()
	api.tokenAuth(api.handleAgentHook("copilot")).ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response map[string]interface{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v (body=%s)", err, recorder.Body.String())
	}
	output, ok := response["hook_output"].(map[string]interface{})
	if response["action"] != "block" || !ok || output["permissionDecision"] != "deny" {
		t.Fatalf("response=%+v, want action=block and native permissionDecision=deny", response)
	}
}

func connectorSafeJSONForTest(value interface{}) string {
	// The production encoder is exercised by hookexec tests. This compact test
	// helper intentionally uses the same JSON-safe values without involving I/O.
	body, _ := json.Marshal(value)
	return strings.TrimSpace(string(body))
}
