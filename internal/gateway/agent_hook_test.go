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
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func TestMapHookAction_ConfirmRequiresNativeAskSurface(t *testing.T) {
	copilot := connector.NewCopilotConnector().HookCapabilities(connector.SetupOpts{})
	action, wouldBlock := mapHookAction("confirm", "action", "PreToolUse", copilot)
	if action != "confirm" || wouldBlock {
		t.Fatalf("copilot PreToolUse confirm = (%q,%v), want (confirm,false)", action, wouldBlock)
	}

	windsurf := connector.NewWindsurfConnector().HookCapabilities(connector.SetupOpts{})
	action, wouldBlock = mapHookAction("confirm", "action", "pre_run_command", windsurf)
	if action != "alert" || wouldBlock {
		t.Fatalf("windsurf confirm = (%q,%v), want explicit alert downgrade", action, wouldBlock)
	}

	cursor := connector.NewCursorConnector().HookCapabilities(connector.SetupOpts{})
	action, wouldBlock = mapHookAction("confirm", "action", "preToolUse", cursor)
	if action != "alert" || wouldBlock {
		t.Fatalf("cursor preToolUse confirm = (%q,%v), want alert because ask is not documented for that surface", action, wouldBlock)
	}
}

func TestMapHookAction_ObserveAndUnsupportedBlock(t *testing.T) {
	hermes := connector.NewHermesConnector().HookCapabilities(connector.SetupOpts{})
	action, wouldBlock := mapHookAction("block", "observe", "pre_tool_call", hermes)
	if action != "allow" || !wouldBlock {
		t.Fatalf("observe block = (%q,%v), want allow/would_block", action, wouldBlock)
	}

	action, wouldBlock = mapHookAction("block", "action", "post_tool_call", hermes)
	if action != "allow" || !wouldBlock {
		t.Fatalf("unsupported block event = (%q,%v), want allow/would_block", action, wouldBlock)
	}
}

func TestNormalizeAgentHookMode_EnforceAlias(t *testing.T) {
	if got := normalizeAgentHookMode("enforce"); got != "action" {
		t.Fatalf("normalizeAgentHookMode(enforce) = %q, want action", got)
	}
	if got := normalizeAgentHookMode("warn"); got != "observe" {
		t.Fatalf("normalizeAgentHookMode(warn) = %q, want observe", got)
	}
}
