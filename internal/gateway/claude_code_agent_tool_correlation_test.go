// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// claudeCodeAgentToolFixture is one interactive Claude Code 2.1.156 session
// against a scripted mock model, recorded by a hook that logged each
// payload's keys, types and string lengths and a digest of each ID (#957).
// The fixture rebuilds those payloads with synthetic values: every key and
// every ID equality is as measured. In order it holds one Agent call whose
// subagent runs a Bash command; two parallel Agent calls next to a Bash call
// of the main agent; an Agent call of an unknown subagent type (a
// PostToolUseFailure); a subagent whose command fails; a subagent whose
// command the user refused at the permission prompt (no PostToolUse at
// all, only its PostToolBatch); a subagent interrupted with Esc (no
// PostToolUse, SubagentStop, PostToolBatch or Stop follows); and a
// backgrounded Agent call (its PostToolUse reports async_launched before
// the subagent's hooks arrive).
const claudeCodeAgentToolFixture = "testdata/claudecode/agent-tool-2.1.156.jsonl"

func readClaudeCodeAgentToolFixture(t *testing.T) []map[string]interface{} {
	t.Helper()
	f, err := os.Open(claudeCodeAgentToolFixture)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var events []map[string]interface{}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for scanner.Scan() {
		var event map[string]interface{}
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatalf("fixture line %d: %v", len(events)+1, err)
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return events
}

// correlateClaudeCodeFixture correlates each fixture hook in order under
// profile, as the hook handler does, and returns the correlated requests.
func correlateClaudeCodeFixture(t *testing.T, profile connector.HookProfile, events []map[string]interface{}) []agentHookRequest {
	t.Helper()
	installCorrelationHMACForTest()
	server, store := newHookCorrelationServer(t, filepath.Join(t.TempDir(), "audit.db"))
	t.Cleanup(func() { _ = store.Close() })
	out := make([]agentHookRequest, 0, len(events))
	for i, payload := range events {
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		req := normalizeAgentHookRequestWithProfile("claudecode", payload, profile)
		_, req, err = server.correlateHookOccurrence(t.Context(), profile, req, raw)
		if err != nil || req.SuppressCorrelationEmit {
			t.Fatalf("fixture line %d (%v %v): err %v, suppressed %t", i+1, payload["hook_event_name"], payload["tool_name"], err, req.SuppressCorrelationEmit)
		}
		out = append(out, req)
	}
	return out
}

// A tool result that reports no agent continues the cursor of the agent its
// pending start names, also where no profile rule resolves an agentless
// hook: the fixture's first Agent call, whose PostToolUse follows its
// subagent's hooks, under a Claude Code profile without
// CorrelationInferenceAgentlessMainAgent. A fresh cursor for that agent
// used to lose to the stored one on every attempt (audit: stale correlation
// state), and the result was not exported.
func TestHookResultContinuesItsPendingAgentsCursor(t *testing.T) {
	profile := (&APIServer{}).hookProfileForConnector("claudecode")
	var rules []connector.CorrelationInferenceRule
	for _, rule := range profile.Correlation.AllowedInferenceRules {
		if rule != connector.CorrelationInferenceAgentlessMainAgent {
			rules = append(rules, rule)
		}
	}
	profile.Correlation.AllowedInferenceRules = rules
	events := readClaudeCodeAgentToolFixture(t)
	if events[8]["hook_event_name"] != "PostToolUse" || events[8]["tool_name"] != "Agent" {
		t.Fatalf("fixture line 9 is %v %v, want the Agent call's PostToolUse", events[8]["hook_event_name"], events[8]["tool_name"])
	}
	reqs := correlateClaudeCodeFixture(t, profile, events[:9])
	if reqs[8].AgentID == "" || reqs[8].AgentID != reqs[2].AgentID {
		t.Fatalf("the Agent call's result belongs to %q, its PreToolUse to %q", reqs[8].AgentID, reqs[2].AgentID)
	}
}

// Claude Code's main agent reports no agent_id, and its subagents' cursors
// stay active next to its own (until SessionEnd; an interrupted subagent
// never sends SubagentStop). Every agentless hook of the measured session
// still resolves to one main agent: the root cursor. Before, each later
// prompt minted the main agent a new ID and its other hooks had none.
func TestClaudeCodeAgentlessHooksKeepTheMainAgent(t *testing.T) {
	events := readClaudeCodeAgentToolFixture(t)
	reqs := correlateClaudeCodeFixture(t, (&APIServer{}).hookProfileForConnector("claudecode"), events)
	main := ""
	for i, req := range reqs {
		if subagent, ok := events[i]["agent_id"].(string); ok {
			if req.AgentID != subagent {
				t.Fatalf("fixture line %d: subagent hook correlated to %q, want %q", i+1, req.AgentID, subagent)
			}
			continue
		}
		if main == "" {
			main = req.AgentID
		}
		if req.AgentID == "" || req.AgentID != main {
			t.Fatalf("fixture line %d (%v): main agent %q, want %q", i+1, events[i]["hook_event_name"], req.AgentID, main)
		}
	}
}

// Two users who send the same Claude Code session id keep apart. The ledger is
// keyed by connector, not by user, so an agentless hook takes its own user's
// main agent and cursor, not the one the other user's hooks left under that
// session id (GAP-0232).
func TestClaudeCodeAgentlessHooksStayPerUser(t *testing.T) {
	agentIdentityTestSetup(t)
	installCorrelationHMACForTest()
	server, store := newHookCorrelationServer(t, filepath.Join(t.TempDir(), "audit.db"))
	t.Cleanup(func() { _ = store.Close() })
	profile := (&APIServer{}).hookProfileForConnector("claudecode")
	events := readClaudeCodeAgentToolFixture(t)[:3] // SessionStart, UserPromptSubmit, PreToolUse
	const session = "gap-0232-shared-session"
	const alice, bob = "agt-0000000000000a11", "agt-0000000000000b22"
	hook := func(identity string, payload map[string]interface{}) agentHookRequest {
		payload["session_id"] = session
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		req := normalizeAgentHookRequestWithCorrelationEvent("claudecode", payload, profile.Correlation, "", identity)
		_, req, err = server.correlateHookOccurrence(t.Context(), profile, req, raw)
		if err != nil || req.SuppressCorrelationEmit {
			t.Fatalf("%v: err %v, suppressed %t", payload["hook_event_name"], err, req.SuppressCorrelationEmit)
		}
		// The hook path registers the session under its agent identity after
		// correlating it.
		SharedAgentRegistry().ResolveForAgentIdentity(t.Context(), identity, session, "")
		return req
	}
	wantAlice := agentNodeID(alice, "claudecode", session, "root")
	wantBob := agentNodeID(bob, "claudecode", session, "root")
	for _, payload := range events {
		a, b := hook(alice, payload), hook(bob, payload)
		if a.AgentID != wantAlice || b.AgentID != wantBob || wantAlice == wantBob {
			t.Fatalf("%v: alice's main agent %q, bob's %q; want %q and %q",
				payload["hook_event_name"], a.AgentID, b.AgentID, wantAlice, wantBob)
		}
	}
}
