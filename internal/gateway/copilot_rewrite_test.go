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

func connectorSafeJSONForTest(value interface{}) string {
	// The production encoder is exercised by hookexec tests. This compact test
	// helper intentionally uses the same JSON-safe values without involving I/O.
	body, _ := json.Marshal(value)
	return strings.TrimSpace(string(body))
}
