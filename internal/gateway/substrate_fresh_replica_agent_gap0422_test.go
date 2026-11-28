//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/sandboxreg"
)

// TestSubstrateFreshReplicaHookRowsNameTheAgentGAP0422 (substrate-1:GAP-0422,
// IB5-E2, TST-2569): two gateway replicas, each with its own audit store. The
// session starts on replica 1 (SessionStart and UserPromptSubmit, which mint
// the session's root agent in replica 1's correlation cursor). Replica 2 sees
// the actor for the first time on a PreToolUse and has no cursor. Before the
// fix its connector-hook rows had agent_id empty while its hook_decision rows
// of the same events (hookLLMEventMeta), and every row of replica 1, named
// agent-<hash>. Every connector-hook row of the verified actor now names the
// agent hook_decision derives (the session's root under the actor's agt-),
// on both replicas.
func TestSubstrateFreshReplicaHookRowsNameTheAgentGAP0422(t *testing.T) {
	installCorrelationHMACForTest(t)
	installDefaultProfileConnector(t, "claudecode")
	_, chains := newTestChainLeaderService(t)
	r1 := chartReplica{newSubstrateFixture(t, func(c *SubstrateConfig) { c.Chains = chains })}
	r2 := chartReplica{newSubstrateFixture(t, func(c *SubstrateConfig) { c.Chains, c.Registrations = chains, r1.f.regs })}
	for _, r := range []chartReplica{r1, r2} {
		r.f.api.store, r.f.api.logger = testStoreAndV8Logger(t)
	}
	const session = "gap0422-fresh-replica"
	r1.hook(t, "tok-alice", map[string]any{"hook_event_name": "SessionStart", "session_id": session, "source": "startup"})
	r1.hook(t, "tok-alice", map[string]any{"hook_event_name": "UserPromptSubmit", "session_id": session, "prompt": "list the files"})
	r1.hook(t, "tok-alice", claudeToolEvent("PreToolUse", session, "list-1", "ls -la"))
	// Replica 2's first contact with the actor and the session.
	r2.hook(t, "tok-alice", claudeToolEvent("PreToolUse", session, "read-1", "cat ~/.aws/credentials"))
	r2.hook(t, "tok-alice", claudeToolResult("PostToolUse", session, "read-1"))

	agents := func(name string, r chartReplica) map[string]map[string]int {
		t.Helper()
		events, err := r.f.api.store.ListEvents(500)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]map[string]int{}
		for _, e := range events {
			if e.SessionID != session || e.Action != string(audit.ActionConnectorHook) {
				continue
			}
			if out[e.Action] == nil {
				out[e.Action] = map[string]int{}
			}
			out[e.Action][e.AgentID]++
		}
		if len(out[string(audit.ActionConnectorHook)]) == 0 {
			t.Fatalf("%s: rows by action and agent %v, want connector-hook rows", name, out)
		}
		return out
	}
	// The agent hookLLMEventMeta derives for the session's hook_decision rows.
	key, err := sandboxreg.SubstrateKey("eng-web", subUID1)
	if err != nil {
		t.Fatal(err)
	}
	actorCtx := withSubstrateActor(context.Background(), verifiedSubstrateActor("eng-web", "alice-1", subUID1, "actor/eng-web/alice-1", key))
	if reg, ok, err := r1.f.regs.Get(context.Background(), "eng-web", subUID1); err != nil || !ok {
		t.Fatalf("registration alice-1: ok=%v err=%v", ok, err)
	} else {
		actorCtx = context.WithValue(actorCtx, substrateRegistrationKey{}, reg)
	}
	facts := resolveHookAgentIdentity(actorCtx, agentHookRequest{ConnectorName: "claudecode", SessionID: session})
	if facts.ID == "" || !facts.Verified {
		t.Fatalf("alice-1 agent identity %+v, want a verified agt- id", facts)
	}
	want := agentNodeID(facts.ID, "claudecode", session, "root")
	for name, r := range map[string]chartReplica{"replica 1": r1, "replica 2 (fresh)": r2} {
		for action, byAgent := range agents(name, r) {
			for agent, n := range byAgent {
				if agent != want {
					t.Errorf("%s: %d %s rows have agent_id %q, want the session's root agent %q", name, n, action, agent, want)
				}
			}
		}
	}
}
