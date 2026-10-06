// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/google/uuid"

	"github.com/defenseclaw/defenseclaw/internal/agentidentity"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
)

func agentIdentityTestSetup(t *testing.T) {
	t.Helper()
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	setAgentIdentityConfig(nil)
	t.Cleanup(func() { setAgentIdentityConfig(nil) })
	InstallSharedAgentRegistry("", "")
}

// The agent identity comes from verified facts only: forged identity headers
// and a claimed config dir in the payload change neither it nor the session
// instance, which is keyed by (agent identity, session) and survives a
// restart. A sub-agent sharing its parent's session gets a derived instance.
func TestHookAgentIdentityIgnoresClaimsAndKeysInstances(t *testing.T) {
	agentIdentityTestSetup(t)
	home := t.TempDir()
	alice := withManagedHookPeer(context.Background(), managedHookPeer{UID: 4242, Name: "alice", Home: home})
	req := agentHookRequest{
		ConnectorName: "claudecode", SessionID: "sess-shared", HookEventName: "PreToolUse",
		CorrelationProfileVersion: connector.CorrelationProfileClaudeCodeV1,
		Payload:                   map[string]interface{}{},
	}
	first := agentIdentityForGenericHook(alice, req)

	machine, machineVerified := agentidentity.HostMachineHash()
	want := agentidentity.AgentID(agentidentity.Inputs{
		MachineHash: machine, UserID: "4242", Connector: "claudecode", InstallFP: filepath.Join(home, ".claude"),
	})
	if first.IdentityID == "" || first.IdentityID != want || first.IdentityVerified != machineVerified {
		t.Fatalf("identity = %q verified=%v, want %q verified=%v", first.IdentityID, first.IdentityVerified, want, machineVerified)
	}
	if id, verified := agentIdentityFromContext(ContextWithAgentIdentity(context.Background(), first)); id != want || verified != machineVerified {
		t.Fatalf("agentIdentityFromContext = %q, %v", id, verified)
	}
	if first.AgentInstanceID != agentidentity.InstanceID(want, "sess-shared") {
		t.Fatalf("instance = %q, want ais- derived from (agent, session)", first.AgentInstanceID)
	}

	// Forged headers and a claimed config root move nothing; the claim is
	// kept as a hint.
	claimed := ContextWithAgentIdentity(alice, AgentIdentity{UserID: "999", UserName: "mallory"})
	claimedReq := req
	claimedReq.Payload = map[string]interface{}{
		"transcript_path": "/srv/elsewhere/.claude/projects/p/s.jsonl",
	}
	again := agentIdentityForGenericHook(claimed, claimedReq)
	if again.IdentityID != want || again.AgentInstanceID != first.AgentInstanceID {
		t.Fatalf("claims moved the identity: %q/%q, want %q/%q", again.IdentityID, again.AgentInstanceID, want, first.AgentInstanceID)
	}
	if _, hints := sharedAgentIdentities.snapshot(); hints[want] != "/srv/elsewhere/.claude" {
		t.Fatalf("install hint = %q", hints[want])
	}

	// Another user sending the same session id gets another instance.
	bob := withManagedHookPeer(context.Background(), managedHookPeer{UID: 4343, Name: "bob", Home: t.TempDir()})
	if other := agentIdentityForGenericHook(bob, req); other.AgentInstanceID == first.AgentInstanceID || other.IdentityID == want {
		t.Fatalf("two users collided on one session: %+v", other)
	}

	// A restarted gateway derives the same instance.
	restarted, minted := NewAgentRegistry("", "").ResolveForAgentIdentity(alice, want, "sess-shared", "")
	if !minted || restarted.AgentInstanceID != first.AgentInstanceID {
		t.Fatalf("instance after restart = %q, want %q", restarted.AgentInstanceID, first.AgentInstanceID)
	}

	// An agent id correlation minted for the main agent (not in the
	// payload) keeps the session's instance.
	mintedAgent := req
	mintedAgent.AgentID = "019a0000-0000-7000-8000-000000000001"
	if got := agentIdentityForGenericHook(alice, mintedAgent).AgentInstanceID; got != first.AgentInstanceID {
		t.Fatalf("minted agent id moved the instance: %q, want %q", got, first.AgentInstanceID)
	}

	sub := req
	sub.AgentID = "subagent-1"
	sub.Payload = map[string]interface{}{"agent_id": "subagent-1"}
	if got := agentIdentityForGenericHook(alice, sub).AgentInstanceID; got != agentidentity.SubagentInstanceID(first.AgentInstanceID, "subagent-1") {
		t.Fatalf("sub-agent instance = %q", got)
	}

	rec := httptest.NewRecorder()
	(&APIServer{}).handleAgentIdentities(rec, httptest.NewRequest(http.MethodGet, "/api/v1/agents/identities?user=alice&connector=claudecode", nil))
	var body struct {
		Enabled    bool               `json:"enabled"`
		Identities []agentIdentityRow `json:"identities"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || !body.Enabled {
		t.Fatalf("identities response %d %s", rec.Code, rec.Body.String())
	}
	found := false
	for _, row := range body.Identities {
		if row.AgentID == want {
			found = row.UserID == "4242" && row.InstallHint == "/srv/elsewhere/.claude" && row.SessionsSeen >= 1
		}
		if row.UserID != "4242" {
			t.Fatalf("user filter returned %+v", row)
		}
	}
	if !found {
		t.Fatalf("identity %s missing from %+v", want, body.Identities)
	}
}

// The session registry is in memory, so a session resumed after a gateway
// restart is minted again; it is not counted twice. Doctor's hook probe is
// not agent use and is not recorded (GAP-0086).
func TestAgentIdentitySessionsSurviveRestartAndSkipDoctorProbe(t *testing.T) {
	agentIdentityTestSetup(t)
	store, err := inventory.NewInventoryStore(filepath.Join(t.TempDir(), "inventory.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ctx := context.Background()
	recorder := &agentIdentityRecorder{pending: map[string]*inventory.AgentIdentityRecord{}, hints: map[string]string{}}
	facts := agentIdentityFacts{ID: "agt-00000000000000c1", UserID: "4545", Connector: "claudecode", MachineHash: "m"}
	recorder.observe(facts, "sess-a", true)
	if err := recorder.flush(ctx, store); err != nil {
		t.Fatal(err)
	}
	// After the restart: session A resumed, then a new session B.
	recorder.observe(facts, "sess-a", true)
	recorder.observe(facts, "sess-a", false)
	recorder.observe(facts, "sess-b", true)
	stored, err := store.ListAgentIdentities(ctx, inventory.AgentIdentityFilter{})
	if err != nil {
		t.Fatal(err)
	}
	pending, _ := recorder.snapshot()
	if rows := mergeAgentIdentityRows(stored, pending, nil, inventory.AgentIdentityFilter{}); len(rows) != 1 || rows[0].SessionsSeen != 2 {
		t.Fatalf("buffered view = %+v, want 2 sessions", rows)
	}
	if err := recorder.flush(ctx, store); err != nil {
		t.Fatal(err)
	}
	if rows, err := store.ListAgentIdentities(ctx, inventory.AgentIdentityFilter{}); err != nil || len(rows) != 1 ||
		rows[0].SessionsSeen != 2 || rows[0].LastSessionID != "sess-b" {
		t.Fatalf("stored rows = %+v, err %v; want 2 sessions, last sess-b", rows, err)
	}

	dave := withManagedHookPeer(ctx, managedHookPeer{UID: 4646, Name: "dave", Home: t.TempDir()})
	probe := agentIdentityForGenericHook(dave, agentHookRequest{
		ConnectorName: "claudecode", SessionID: doctorProbeSessionID, HookEventName: "SessionStart",
		Payload: map[string]interface{}{},
	})
	if pending, _ := sharedAgentIdentities.snapshot(); probe.IdentityID == "" || pending[probe.IdentityID].AgentID != "" {
		t.Fatalf("doctor probe recorded identity %q: %+v", probe.IdentityID, pending[probe.IdentityID])
	}
}

// Under the Secure Client integration nothing changes: instances stay random
// UUIDs, no agent identity is derived or recorded, and the API reports the
// feature off.
func TestHookAgentIdentitySecureClientUnchanged(t *testing.T) {
	agentIdentityTestSetup(t)
	setManagedEnterpriseRedactionPosture(true)
	t.Cleanup(func() { setManagedEnterpriseRedactionPosture(false) })
	ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 4444, Name: "carol", Home: t.TempDir()})
	pendingBefore := sharedAgentIdentities.pendingCount()
	got := agentIdentityForGenericHook(ctx, agentHookRequest{ConnectorName: "claudecode", SessionID: "sess-sc", AgentID: "sub", HookEventName: "SubagentStart"})
	if got.IdentityID != "" || got.IdentityVerified {
		t.Fatalf("Secure Client derived an agent identity: %+v", got)
	}
	if _, err := uuid.Parse(got.AgentInstanceID); err != nil {
		t.Fatalf("Secure Client instance %q is not a UUID", got.AgentInstanceID)
	}
	if agentIdentityV8FromContext(ContextWithAgentIdentity(ctx, got)).IsPresent() {
		t.Fatalf("Secure Client record would carry defenseclaw.agent.identity.id")
	}
	if sharedAgentIdentities.pendingCount() != pendingBefore {
		t.Fatalf("Secure Client recorded an agent identity")
	}
	rec := httptest.NewRecorder()
	(&APIServer{}).handleAgentIdentities(rec, httptest.NewRequest(http.MethodGet, "/api/v1/agents/identities", nil))
	if rec.Body.String() != "{\"enabled\":false,\"identities\":[]}\n" {
		t.Fatalf("Secure Client identities response = %q", rec.Body.String())
	}
}
