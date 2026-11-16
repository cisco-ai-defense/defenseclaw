// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

// A captured VM shell call whose command a CRITICAL rule proves is blocked
// with Claude Code's native deny, as the engine honours (measured: a managed
// deny stopped the VM command).
func TestCoworkCapturedShellCallIsBlockedLikeBash(t *testing.T) {
	installSandboxMarkerRules(t)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	var shell map[string]interface{}
	for _, capture := range readCoworkCaptures(t) {
		if capture.Payload["hook_event_name"] == "PreToolUse" && capture.Payload["tool_name"] == "mcp__workspace__bash" {
			shell = capture.Payload
			break
		}
	}
	if shell == nil {
		t.Fatal("no captured PreToolUse shell call")
	}
	shell["tool_input"] = map[string]interface{}{"command": workdirMarkerCommand}
	got := postCoworkCapture(t, api, shell, &hookexec.CoworkContext{SessionID: "s"})
	if got["action"] != "block" {
		t.Fatalf("action %v, want block: %v", got["action"], got)
	}
	output, _ := got["claude_code_output"].(map[string]interface{})
	specific, _ := output["hookSpecificOutput"].(map[string]interface{})
	if specific["permissionDecision"] != "deny" || !strings.Contains(strings.ToLower(specific["permissionDecisionReason"].(string)), "defenseclaw") {
		t.Fatalf("claude_code_output = %v, want a PreToolUse deny with the DefenseClaw reason", output)
	}
}
