// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability"
)

// TestOpenClawPromptBlockMarksTheTurn pins GAP-2231: the turn of an
// OpenClaw prompt the proxy blocked has a blocked outcome and the user on
// its invoke_agent and chat spans, so Galileo shows the block. It was only
// on apply_guardrail root traces, which never reach Galileo.
func TestOpenClawPromptBlockMarksTheTurn(t *testing.T) {
	openClawPromptBlocks.mu.Lock()
	openClawPromptBlocks.entries = nil
	openClawPromptBlocks.mu.Unlock()
	t.Cleanup(func() {
		openClawPromptBlocks.mu.Lock()
		openClawPromptBlocks.entries = nil
		openClawPromptBlocks.mu.Unlock()
	})

	msg := blockMessage("", "prompt", "matched: R6-PROMPT-MARKER:marker")
	rememberOpenClawPromptBlock(msg, AgentIdentity{UserID: "1001", UserIDKind: "posix_uid", UserName: "dcr-qvc5a"})

	allowed := hookModelV8Observation{response: `[{"type":"text","text":"ok"}]`}
	applyOpenClawPromptBlock(&allowed)
	if allowed.outcome != "" {
		t.Fatalf("an allowed turn was marked %q", allowed.outcome)
	}

	content, _ := json.Marshal([]map[string]string{{"type": "text", "text": msg}})
	blocked := hookModelV8Observation{response: string(content)}
	blocked.meta.Source = eventRouterToolConnector
	applyOpenClawPromptBlock(&blocked)
	if blocked.outcome != observability.OutcomeBlocked {
		t.Fatalf("outcome = %q, want blocked", blocked.outcome)
	}
	agent := eventRouterAgentInputV8(blocked)
	if agent.Outcome != observability.OutcomeBlocked {
		t.Fatalf("agent outcome = %q, want blocked", agent.Outcome)
	}
	if name, _ := agent.DefenseClawUserName.Get(); name != "dcr-qvc5a" {
		t.Fatalf("agent user = %q, want dcr-qvc5a", name)
	}
	if chat := hookModelV8ModelInput(blocked); chat.Outcome != observability.OutcomeBlocked {
		t.Fatalf("chat outcome = %q, want blocked", chat.Outcome)
	}

	// The decision is taken once: a later turn that repeats the text is
	// not marked again.
	again := hookModelV8Observation{response: msg}
	applyOpenClawPromptBlock(&again)
	if again.outcome != "" {
		t.Fatalf("a repeated turn was marked %q", again.outcome)
	}
}

// TestOpenClawAllowedTurnNamesTheLocalUser pins GAP-2287: an allowed
// OpenClaw turn names the gateway's own user on an unmanaged install, as a
// blocked turn and every other connector's turns do; a user the stream
// named is kept.
func TestOpenClawAllowedTurnNamesTheLocalUser(t *testing.T) {
	_, wantName := localProcessUser()
	if wantName == "" {
		t.Skip("no local process user on this host")
	}
	allowed := hookModelV8Observation{response: "ok"}
	applyOpenClawPromptBlock(&allowed)
	if allowed.outcome != "" {
		t.Fatalf("an allowed turn was marked %q", allowed.outcome)
	}
	if allowed.meta.UserName != wantName {
		t.Fatalf("allowed turn user = %q, want %q", allowed.meta.UserName, wantName)
	}
	// A Windows HOST\user name fails the v8 identifier check (GAP-2366).
	if hookModelV8Identifier(wantName) {
		if name, _ := eventRouterAgentInputV8(allowed).DefenseClawUserName.Get(); name != wantName {
			t.Fatalf("allowed turn span user = %q, want %q", name, wantName)
		}
	}
	named := hookModelV8Observation{response: "ok"}
	named.meta.UserName = "stream-user"
	applyOpenClawPromptBlock(&named)
	if named.meta.UserName != "stream-user" {
		t.Fatalf("stream user replaced by %q", named.meta.UserName)
	}
}
