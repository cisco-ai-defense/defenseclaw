// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func gap0537Registry(t *testing.T) {
	t.Helper()
	sharedRegMu.Lock()
	previousRegistry := sharedReg
	sharedReg = NewAgentRegistry("", "")
	sharedRegMu.Unlock()
	t.Cleanup(func() {
		sharedRegMu.Lock()
		sharedReg = previousRegistry
		sharedRegMu.Unlock()
	})
}

func TestGAP0537HermesSparseAgentIDKeepsSessionAuditIdentity(t *testing.T) {
	previousPosture := ManagedEnterpriseActive()
	SetManagedEnterpriseActive(false)
	t.Cleanup(func() { SetManagedEnterpriseActive(previousPosture) })
	gap0537Registry(t)

	firstPeer := withManagedHookPeer(context.Background(), managedHookPeer{UID: 4242, Name: "alice", Home: t.TempDir()})
	secondPeer := withManagedHookPeer(context.Background(), managedHookPeer{UID: 4343, Name: "bob", Home: t.TempDir()})
	hook := func(ctx context.Context, session, agentID string) audit.CorrelationEnvelope {
		t.Helper()
		req := agentHookRequest{ConnectorName: "hermes", SessionID: session, AgentID: agentID}
		return audit.EnvelopeFromContext(enrichAgentHookContext(ctx, req))
	}
	first := hook(firstPeer, "hermes-session", "agent-main")
	if first.AgentID != "agent-main" || first.AgentInstanceID == "" {
		t.Fatalf("first event identity = %+v", first)
	}
	for i := 0; i < 3; i++ {
		later := hook(firstPeer, "hermes-session", "")
		if later.AgentID != first.AgentID || later.AgentInstanceID != first.AgentInstanceID {
			t.Fatalf("sparse event %d identity = %+v, want %q/%q", i, later, first.AgentID, first.AgentInstanceID)
		}
	}
	// An explicit child id wins for its event; a later event without an id
	// still belongs to the first reported agent in this session.
	if child := hook(firstPeer, "hermes-session", "agent-child"); child.AgentID != "agent-child" {
		t.Fatalf("explicit child identity = %+v", child)
	}
	if later := hook(firstPeer, "hermes-session", ""); later.AgentID != "agent-main" {
		t.Fatalf("later root identity = %+v", later)
	}
	if other := hook(firstPeer, "other-session", ""); other.AgentID != "" {
		t.Fatalf("another session inherited an id: %+v", other)
	}
	if other := hook(secondPeer, "hermes-session", ""); other.AgentID != "" || other.AgentInstanceID == first.AgentInstanceID {
		t.Fatalf("another account inherited an id or instance: %+v", other)
	}

	// A normal tool call in this session still receives its ordinary allow.
	store, logger := testStoreAndLogger(t)
	cfg := &config.Config{}
	cfg.Guardrail.Mode, cfg.Guardrail.Connector = "action", "hermes"
	api := &APIServer{scannerCfg: cfg, store: store, logger: logger}
	profile := connector.NewHermesConnector().HookProfile(connector.SetupOpts{})
	request := normalizeAgentHookRequestWithProfile("hermes", map[string]interface{}{
		"hook_event_name": "pre_tool_call", "session_id": "hermes-session",
		"tool_name": "terminal", "tool_input": map[string]interface{}{"command": "ls -la"},
	}, profile)
	ctx := enrichAgentHookContext(firstPeer, request)
	if env := audit.EnvelopeFromContext(ctx); env.AgentID != "agent-main" {
		t.Fatalf("benign tool audit identity = %+v", env)
	}
	if answer := api.evaluateAgentHook(ctx, request); answer.Action != "allow" {
		t.Fatalf("benign tool action = %q, want allow", answer.Action)
	}
}

func TestGAP0537SecureClientHermesIdentityBehaviorUnchanged(t *testing.T) {
	previousPosture := ManagedEnterpriseActive()
	SetManagedEnterpriseActive(true)
	t.Cleanup(func() { SetManagedEnterpriseActive(previousPosture) })
	gap0537Registry(t)
	request := agentHookRequest{ConnectorName: "hermes", SessionID: "secure-session", AgentID: "agent-reported"}
	first := audit.EnvelopeFromContext(enrichAgentHookContext(context.Background(), request))
	request.AgentID = ""
	second := audit.EnvelopeFromContext(enrichAgentHookContext(context.Background(), request))
	if first.AgentID != "agent-reported" || second.AgentID != "" || first.AgentInstanceID != second.AgentInstanceID {
		t.Fatalf("Secure Client identities = %+v / %+v", first, second)
	}
}
