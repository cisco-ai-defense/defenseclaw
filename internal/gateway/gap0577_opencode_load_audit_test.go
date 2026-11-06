// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestOpenCodeLoadIsLifecycleBeforeFirstSessionDecision(t *testing.T) {
	agentIdentityTestSetup(t)
	store, logger := testStoreAndLogger(t)
	api := &APIServer{store: store, logger: logger}
	allow := agentHookResponse{Action: "allow", RawAction: "allow", Mode: "observe"}
	caller := withManagedHookPeer(context.Background(), managedHookPeer{
		UID: 4242, Name: "opencode-user", Home: t.TempDir(),
	})

	load := agentHookRequest{
		ConnectorName: "opencode", HookEventName: "defenseclaw.plugin.loaded",
		Payload: map[string]interface{}{"load_heartbeat": true},
	}
	loadCtx := enrichAgentHookContext(caller, load)
	if _, _, ok := api.hookDecisionMeta(loadCtx, load); ok {
		t.Fatal("a sessionless plugin load became a hook decision")
	}
	if !api.finalizeAgentHook(loadCtx, "opencode", load, allow, nil, []byte(`{}`), time.Millisecond, false, nil).AuditPersisted {
		t.Fatal("plugin load audit row was not persisted")
	}

	tool := agentHookRequest{
		ConnectorName: "opencode", HookEventName: "tool.execute.before",
		SessionID: "ses-first", ToolName: "read", Payload: map[string]interface{}{},
	}
	toolCtx := enrichAgentHookContext(caller, tool)
	_, _, ok := api.hookDecisionMeta(toolCtx, tool)
	instance := AgentIdentityFromContext(toolCtx).AgentInstanceID
	if !ok || instance == "" {
		t.Fatalf("first session tool decision has no agent instance: ok=%t instance=%q", ok, instance)
	}
	if !api.finalizeAgentHook(toolCtx, "opencode", tool, allow, nil, []byte(`{}`), time.Millisecond, false, nil).AuditPersisted {
		t.Fatal("tool audit row was not persisted")
	}

	events, err := store.ListEvents(20)
	if err != nil {
		t.Fatal(err)
	}
	loadRows, toolRows := 0, 0
	for _, event := range events {
		switch {
		case event.Target == load.HookEventName && event.Action == string(audit.ActionConnectorHook):
			loadRows++
		case event.Target == tool.HookEventName && event.Action == string(audit.ActionConnectorHook):
			toolRows++
			if event.AgentInstanceID == "" {
				t.Fatal("tool audit row has no agent instance")
			}
		}
	}
	if loadRows != 1 || toolRows != 1 {
		t.Fatalf("load audit rows=%d, tool hook rows=%d; want one each", loadRows, toolRows)
	}
}

func TestSecureClientOpenCodeLoadKeepsHookDecision(t *testing.T) {
	agentIdentityTestSetup(t)
	cfg := &config.Config{DeploymentMode: "managed_enterprise", Enterprise: config.EnterpriseConfig{Profile: "secure_client"}}
	if !cfg.SecureClientIntegration() {
		t.Fatal("Secure Client fixture was not selected")
	}
	store, logger := testStoreAndLogger(t)
	api := &APIServer{scannerCfg: cfg, store: store, logger: logger}
	req := agentHookRequest{ConnectorName: "opencode", HookEventName: "defenseclaw.plugin.loaded", Payload: map[string]interface{}{"load_heartbeat": true}}
	if _, _, ok := api.hookDecisionMeta(context.Background(), req); !ok {
		t.Fatal("Secure Client load decision was suppressed")
	}
}

func TestManagedStandaloneOpenCodeLoadKeepsHookDecision(t *testing.T) {
	agentIdentityTestSetup(t)
	cfg := &config.Config{DeploymentMode: "managed_enterprise", Enterprise: config.EnterpriseConfig{Profile: "standalone"}}
	if cfg.SecureClientIntegration() {
		t.Fatal("standalone fixture selected Secure Client")
	}
	store, logger := testStoreAndLogger(t)
	api := &APIServer{scannerCfg: cfg, store: store, logger: logger}
	req := agentHookRequest{ConnectorName: "opencode", HookEventName: "defenseclaw.plugin.loaded", Payload: map[string]interface{}{"load_heartbeat": true}}
	if _, _, ok := api.hookDecisionMeta(context.Background(), req); !ok {
		t.Fatal("managed standalone load decision was suppressed")
	}
}
