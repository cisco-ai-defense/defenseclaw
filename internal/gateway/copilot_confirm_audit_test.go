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
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// Copilot CLI omits prompt availability from its hook body. In -p and
// autopilot an ask is denied without a prompt, so the response and audit
// action must both be block until the vendor provides trusted mode evidence.
func TestCopilotCLIConfirmDeniesAndAuditsTheDeliveredDecision(t *testing.T) {
	profile := connector.NewCopilotConnector().HookProfile(connector.SetupOpts{})
	for _, payload := range []map[string]interface{}{
		nil,
		{"mode": "autopilot"},
		{"permission_mode": "manual"},
	} {
		action, wouldBlock := mapHookActionForProfile("confirm", "action", "preToolUse", profile.Capabilities, profile, payload)
		if action != "block" || wouldBlock {
			t.Fatalf("Copilot CLI with payload %+v: action=%q wouldBlock=%t, want block", payload, action, wouldBlock)
		}
		req := agentHookRequest{ConnectorName: "copilot", HookEventName: "preToolUse", ToolName: "bash", Payload: payload}
		response := agentHookResponseForProfile(profile, req, action, "confirm", "HIGH", "policy requires confirmation", nil, "action", wouldBlock, profile.Capabilities)
		if response.Action != "block" || response.RawAction != "confirm" || !strings.Contains(response.Reason, "cannot verify") {
			t.Fatalf("Copilot CLI audit response %+v", response)
		}
		if got := response.HookOutput["permissionDecision"]; got != "deny" {
			t.Fatalf("Copilot CLI delivered %v, audit action=%s", got, response.Action)
		}
	}
	local := connector.CopilotVSCodeLocalProfile(profile)
	action, wouldBlock := mapHookActionForProfile("confirm", "action", "PreToolUse", local.Capabilities, local, nil)
	if action != "confirm" || wouldBlock {
		t.Fatalf("VS Code Local action=%s wouldBlock=%t, want native ask", action, wouldBlock)
	}
	secureClient := connector.NewCopilotConnector().HookProfile(connector.SetupOpts{SecureClientHookDelivery: true})
	action, wouldBlock = mapHookActionForProfile("confirm", "action", "preToolUse", secureClient.Capabilities, secureClient, nil)
	if action != "confirm" || wouldBlock {
		t.Fatalf("Secure Client action=%s wouldBlock=%t, want its established ask", action, wouldBlock)
	}
	secureClient = (&APIServer{scannerCfg: &config.Config{DeploymentMode: "managed_enterprise"}}).hookProfileForConnector("copilot")
	action, wouldBlock = mapHookActionForProfile("confirm", "action", "preToolUse", secureClient.Capabilities, secureClient, nil)
	if action != "confirm" || wouldBlock {
		t.Fatalf("Secure Client gateway action=%s wouldBlock=%t, want its established ask", action, wouldBlock)
	}
}
