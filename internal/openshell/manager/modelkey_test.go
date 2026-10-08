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

package manager

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell/profiles"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// TestARejectedModelKeyIsNamed (GAP-0271): a sandbox whose Bedrock key the
// model API rejected showed only Claude Code's "Please run /login · API
// Error: 401", and DefenseClaw said nothing. Claude Code's StopFailure hook
// names the failure: one finding on the feed and the status say the key
// was rejected and how a fresh one reaches the sandbox, until a turn ends
// normally.
func TestARejectedModelKeyIsNamed(t *testing.T) {
	e := newEnv(t, nil)
	e.live(sandboxapi.CreateRequest{Name: "keybox",
		LLM: &sandboxapi.LLMCredential{Profile: profiles.ClaudeBedrockMantleID, Credentials: map[string]string{"ANTHROPIC_API_KEY": "dccert-block-marker"}}})
	turnEnd := func(event, class string, status int) {
		e.m.ObserveHookDecision(HookDecision{BindingID: e.binding("keybox").ID, SandboxName: "keybox", Event: event, Action: "allow",
			ModelError: class, ModelStatus: status})
	}
	turnEnd("StopFailure", "rate_limit", 429)
	if h := e.get("keybox").Hooks; h.ModelKeyRejected != "" {
		t.Fatalf("a rate limit reads as a rejected key: %q", h.ModelKeyRejected)
	}
	turnEnd("StopFailure", "authentication_failed", 401)
	turnEnd("StopFailure", "authentication_failed", 401)
	want := "⚠ Amazon Bedrock rejected the sandbox's model credential (HTTP 401), so Claude Code gets no answers: " +
		"put a fresh AWS_BEARER_TOKEN_BEDROCK in your shell, end the session (`defenseclaw sandbox stop keybox` for a detached run), " +
		"then run `defenseclaw sandbox connect keybox` from that shell, which hands the sandbox the new key"
	if got := e.events("keybox", sandboxapi.ActivityFinding, sandboxapi.ReasonModelKeyRejected); len(got) != 1 || got[0].Message != want {
		t.Fatalf("feed = %+v, want one %q", got, want)
	}
	if h := e.get("keybox").Hooks; "⚠ "+h.ModelKeyRejected != want || h.ModelKeyRejectedAt.IsZero() {
		t.Fatalf("status = %q at %v", h.ModelKeyRejected, h.ModelKeyRejectedAt)
	}
	turnEnd("Stop", "", 0)
	if h := e.get("keybox").Hooks; h.ModelKeyRejected != "" {
		t.Fatalf("a turn that ended normally kept %q", h.ModelKeyRejected)
	}
}
