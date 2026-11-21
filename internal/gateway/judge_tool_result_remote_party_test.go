// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"strings"
	"testing"
)

// TestToolResultPIIScopeNeedsAnOwnerRequest: on Hermes and OpenClaw a turn's
// "user" text can be a remote chat party's, so it never tells the PII judge
// which personal data a tool's output may carry: the judge gets no scope note
// and asks the original question. Claude Code and Codex prompts are the
// installing user's and keep the scope (rel-1-0-10:GAP-0714).
func TestToolResultPIIScopeNeedsAnOwnerRequest(t *testing.T) {
	scopeMark := "is the expected content of the output"
	if !strings.Contains(toolResultPIIScope, scopeMark) {
		t.Fatalf("toolResultPIIScope no longer says %q", scopeMark)
	}
	for _, tc := range []struct {
		connector string
		scoped    bool
	}{
		{"hermes", false}, {"openclaw", false}, {"claudecode", true}, {"codex", true},
	} {
		t.Run(tc.connector, func(t *testing.T) {
			mock := &mockLLMProvider{response: &ChatResponse{Choices: []ChatChoice{{Message: &ChatMessage{Role: "assistant", Content: cleanInjectionJudgeJSON}}}}}
			j := newMockJudge(t, mock)
			j.cfg.PII, j.cfg.PIICompletion = true, true
			ctx := withAuthenticatedHookConnector(ContextWithSessionID(context.Background(), "sess-0714-"+tc.connector), tc.connector)
			j.ObserveSessionPrompt(ctx, "list the customer records")
			ctx = withToolResultCall(ctx, "list_records", map[string]any{"limit": 10})
			j.RunJudges(ctx, "completion", `{"name": "Ana Example", "email": "ana@example.com", "phone": "+1 555 0100"}`, "message")
			pii := 0
			for _, req := range mock.captured {
				sys := req.Messages[0].Content
				if !strings.Contains(sys, "personal") && !strings.Contains(sys, "PII") {
					continue
				}
				pii++
				if got := strings.Contains(sys, scopeMark); got != tc.scoped {
					t.Errorf("%s PII judge scope note present %v, want %v", tc.connector, got, tc.scoped)
				}
			}
			if pii == 0 {
				t.Fatal("no PII judge call")
			}
		})
	}
}
