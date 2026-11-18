// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"testing"
)

// substrate-1 GAP-0269: an argumentless native Copilot permissionRequest is
// bound to the call of the actor's last allowed preToolUse. Each gateway
// replica kept that join in its own process, and an actor's hooks are spread
// over the replicas, so a callback that landed on another replica than its
// preToolUse was never bound (it kept its own unparsed decision). With the
// Substrate chains on, an actor's join is the leader's.
func TestGAP0269CopilotPermissionJoinAcrossReplicas(t *testing.T) {
	useSubstrateChains(newTestChainLeader(t))
	t.Cleanup(func() { useSubstrateChains(nil) })
	args := json.RawMessage(`"*** Begin Patch\n*** Add File: README.md\n+x\n*** End Patch\n"`)
	pre := agentHookRequest{ConnectorName: "copilot", HookEventName: "preToolUse", SessionID: "native",
		CWD: "/work", ToolName: "apply_patch", ToolArgs: args}
	permission := agentHookRequest{ConnectorName: "copilot", HookEventName: "permissionRequest",
		SessionID: "native", CWD: "/work", ToolName: "edit", ToolCallUnparsed: true,
		Payload: map[string]any{"hookName": "permissionRequest", "toolName": "edit", "toolInput": map[string]any{}}}
	raw := []byte(`{"hookName":"permissionRequest","toolName":"edit","toolInput":{}}`)
	actor := withSubstrateActor(context.Background(), *f14Actor(t, "gap0269-a", "3b6c2d1e-8f4a-4b9c-a1d2-5e6f7a8b9c0d"))
	other := withSubstrateActor(context.Background(), *f14Actor(t, "gap0269-b", "9a1f3c5e-2b7d-4e8f-a0c6-1d3b5f7e9a55"))

	t.Run("callback on the other replica is bound", func(t *testing.T) {
		var replicaA, replicaB copilotPermissionJoin
		replicaA.record(actor, pre, true)
		tool, bound, ok := replicaB.match(actor, permission, raw)
		if !ok || tool != "apply_patch" || string(bound) != string(args) {
			t.Fatalf("replica B: match=%v %s %s, want the preToolUse call replica A recorded", ok, tool, bound)
		}
		if _, _, ok := replicaA.match(actor, permission, raw); ok {
			t.Fatal("replica A reused the call replica B's callback consumed")
		}
	})
	t.Run("another actor's callback is not bound", func(t *testing.T) {
		var replicaA, replicaB copilotPermissionJoin
		replicaA.record(actor, pre, true)
		if _, _, ok := replicaB.match(other, permission, raw); ok {
			t.Fatal("another actor's callback was bound to this actor's call")
		}
	})
	t.Run("a block on one replica is not bound on the other", func(t *testing.T) {
		var replicaA, replicaB copilotPermissionJoin
		replicaA.record(actor, pre, false)
		if _, _, ok := replicaB.match(actor, permission, raw); ok {
			t.Fatal("a refused preToolUse was bound")
		}
	})
	t.Run("two preToolUse calls on two replicas are ambiguous", func(t *testing.T) {
		var replicaA, replicaB copilotPermissionJoin
		replicaA.record(actor, pre, true)
		replicaB.record(actor, pre, true)
		if _, _, ok := replicaA.match(actor, permission, raw); ok {
			t.Fatal("an ambiguous callback was bound")
		}
	})
	t.Run("a host call stays process-local", func(t *testing.T) {
		var replicaA, replicaB copilotPermissionJoin
		host := context.Background()
		replicaA.record(host, pre, true)
		if _, _, ok := replicaB.match(host, permission, raw); ok {
			t.Fatal("a host callback was bound to another process's call")
		}
		if _, _, ok := replicaA.match(host, permission, raw); !ok {
			t.Fatal("a host callback was not bound on its own process")
		}
	})
}
