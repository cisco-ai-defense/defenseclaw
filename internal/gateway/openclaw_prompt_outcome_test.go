// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
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
	rememberOpenClawPromptBlock(msg, AgentIdentity{UserID: "1001", UserIDKind: "posix_uid", UserName: "dcr-qvc5a"},
		&ScanVerdict{Action: "block", Severity: "HIGH", RuleIDs: []string{"R6-PROMPT-MARKER"}})

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
	chat := hookModelV8ModelInput(blocked)
	if chat.Outcome != observability.OutcomeBlocked {
		t.Fatalf("chat outcome = %q, want blocked", chat.Outcome)
	}
	// GAP-2332: both spans name the rule, severity and action of the block.
	for family, got := range map[string][3]observability.Optional[string]{
		"agent": {agent.DefenseClawGuardrailAction, agent.DefenseClawGuardrailRuleID, agent.DefenseClawGuardrailSeverity},
		"chat":  {chat.DefenseClawGuardrailAction, chat.DefenseClawGuardrailRuleID, chat.DefenseClawGuardrailSeverity},
	} {
		action, _ := got[0].Get()
		rule, _ := got[1].Get()
		severity, _ := got[2].Get()
		if action != "block" || rule != "R6-PROMPT-MARKER" || severity != "HIGH" {
			t.Fatalf("%s guardrail = %q/%q/%q, want block/R6-PROMPT-MARKER/HIGH", family, action, rule, severity)
		}
	}
	if action := hookModelV8ModelInput(allowed).DefenseClawGuardrailAction; action.IsPresent() {
		t.Fatalf("an allowed turn carries a guardrail action")
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
	if name, _ := eventRouterAgentInputV8(allowed).DefenseClawUserName.Get(); name != wantName {
		t.Fatalf("allowed turn span user = %q, want %q", name, wantName)
	}
	named := hookModelV8Observation{response: "ok"}
	named.meta.UserName = "stream-user"
	applyOpenClawPromptBlock(&named)
	if named.meta.UserName != "stream-user" {
		t.Fatalf("stream user replaced by %q", named.meta.UserName)
	}
}

// TestBareAccountNameKeepsTheV8UserName pins GAP-2366 and GAP-0064: the
// Windows HOST\user name and the SSSD alice@realm name are reduced to the
// bare account name, which passes the v8 identifier check, so
// defenseclaw.user.name is not dropped.
func TestBareAccountNameKeepsTheV8UserName(t *testing.T) {
	for in, want := range map[string]string{
		`runnervm\runneradmin`:  "runneradmin",
		`DOMAIN\dcw-std1`:       "dcw-std1",
		"dcad-alice@dclab.test": "dcad-alice",
		"dcr-std1":              "dcr-std1",
		`trailing\`:             `trailing\`,
	} {
		if got := useridentity.BareAccountName(in); got != want {
			t.Fatalf("BareAccountName(%q) = %q, want %q", in, got, want)
		}
	}
	if got := newTrustedLLMEventUser("1005", "dcad-alice@dclab.test").Name; !hookModelV8Identifier(got) {
		t.Fatalf("trusted SSSD account name %q fails the v8 identifier check", got)
	}
}

// TestOpenClawAgentSpanCarriesTheReply pins GAP-2495: the invoke_agent
// openclaw root carries the turn's reply as its output, as the chat span
// does, so the agent node in Galileo is not blank.
func TestOpenClawAgentSpanCarriesTheReply(t *testing.T) {
	turn := hookModelV8Observation{response: `[{"type":"text","text":"ready"}]`}
	agent := eventRouterAgentInputV8(turn)
	if !agent.DefenseClawTelemetryOutputReported || agent.DefenseClawContentOutputState != "preserved" {
		t.Fatalf("agent output reported=%v state=%q, want true/preserved",
			agent.DefenseClawTelemetryOutputReported, agent.DefenseClawContentOutputState)
	}
	got, ok := agent.GenAIOutputMessages.Get()
	want, _ := hookModelV8ModelInput(turn).GenAIOutputMessages.Get()
	if !ok || len(got.Items) != 1 || len(got.Items[0].Parts.Items) == 0 {
		t.Fatalf("agent output messages = %+v, want the reply", got)
	}
	gotJSON, _ := json.Marshal(got)
	wantJSON, _ := json.Marshal(want)
	if string(gotJSON) != string(wantJSON) {
		t.Fatalf("agent output = %s, want the chat output %s", gotJSON, wantJSON)
	}

	silent := eventRouterAgentInputV8(hookModelV8Observation{})
	if silent.DefenseClawTelemetryOutputReported || silent.GenAIOutputMessages.IsPresent() {
		t.Fatalf("an empty reply was reported as output")
	}
}

// TestOpenClawReplyTextIsTheReplyNotTheBlockJSON pins the GAP-2495 reopen:
// the chat and agent spans carry the reply text of an OpenClaw content
// array, not the raw block JSON, with the assistant role.
func TestOpenClawReplyTextIsTheReplyNotTheBlockJSON(t *testing.T) {
	for _, tc := range []struct{ content, want string }{
		{`[{"type":"text","text":"ready"}]`, "ready"},
		{`[{"type":"thinking","thinking":"x"},{"type":"text","text":"a"},{"type":"text","text":"b"}]`, "a\nb"},
		{`[{"type":"toolCall","id":"c1","name":"exec","arguments":{"command":"ls"}}]`, "[tool call] exec"},
		{"[DefenseClaw] blocked", "[DefenseClaw] blocked"},
		{"plain reply", "plain reply"},
	} {
		if got := openClawReplyText(tc.content); got != tc.want {
			t.Errorf("openClawReplyText(%s) = %q, want %q", tc.content, got, tc.want)
		}
	}
	turn := hookModelV8Observation{response: openClawReplyText(`[{"type":"text","text":"ready"}]`)}
	got, ok := eventRouterAgentInputV8(turn).GenAIOutputMessages.Get()
	if !ok || len(got.Items) != 1 || got.Items[0].Role != "assistant" {
		t.Fatalf("agent output messages = %+v, want one assistant message", got)
	}
	gotJSON, _ := json.Marshal(got)
	if strings.Contains(string(gotJSON), `\"type\"`) || !strings.Contains(string(gotJSON), `"ready"`) {
		t.Fatalf("agent output = %s, want the reply text without block JSON", gotJSON)
	}
}
