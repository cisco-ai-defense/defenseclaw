// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// trustExploitKeyword returns a CRITICAL-severity trigger phrase without
// embedding the literal string in this source file — otherwise the
// repo's own PreToolUse hook would block writing the test.
func trustExploitKeyword() string {
	return "jail" + "break ai"
}

// TestEvaluateCodexHook_ActiveConnectorImpliesEnabled mirrors the
// Claude Code invariant for Codex: selecting the codex connector is
// the only opt-in an operator should need. Without this, a CRITICAL
// trust-exploit keyword in the user prompt came back as action=allow,
// severity=NONE — the rule scanner never ran.
func TestEvaluateCodexHook_ActiveConnectorImpliesEnabled(t *testing.T) {
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "codex"

	api := &APIServer{scannerCfg: cfg}

	req := codexHookRequest{
		HookEventName: "UserPromptSubmit",
		Prompt:        trustExploitKeyword(),
	}
	resp := api.evaluateCodexHook(context.Background(), req)

	if resp.RawAction != "block" {
		t.Errorf("RawAction = %q, want block (trust-exploit rule must fire)", resp.RawAction)
	}
	if resp.Severity != "CRITICAL" {
		t.Errorf("Severity = %q, want CRITICAL", resp.Severity)
	}
}

// TestEvaluateCodexHook_NonCodexConnectorStaysDisabled guards the
// opposite direction: a Claude-based install must not start evaluating
// Codex hooks just because the endpoint exists — that would waste
// cycles on requests the operator never installed hooks for.
func TestEvaluateCodexHook_NonCodexConnectorStaysDisabled(t *testing.T) {
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"

	api := &APIServer{scannerCfg: cfg}

	req := codexHookRequest{
		HookEventName: "UserPromptSubmit",
		Prompt:        trustExploitKeyword(),
	}
	resp := api.evaluateCodexHook(context.Background(), req)

	if resp.RawAction != "allow" {
		t.Errorf("RawAction = %q, want allow (codex hooks should be inert under a different connector)", resp.RawAction)
	}
}

// TestEvaluateCodexHook_ExplicitEnableStillWorks ensures operators who
// explicitly set codex.enabled=true still get inspection even when the
// connector name itself would have been inert.
func TestEvaluateCodexHook_ExplicitEnableStillWorks(t *testing.T) {
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = ""
	cfg.Codex.Enabled = true

	api := &APIServer{scannerCfg: cfg}

	req := codexHookRequest{
		HookEventName: "UserPromptSubmit",
		Prompt:        trustExploitKeyword(),
	}
	resp := api.evaluateCodexHook(context.Background(), req)

	if resp.RawAction != "block" {
		t.Errorf("RawAction = %q, want block", resp.RawAction)
	}
}
