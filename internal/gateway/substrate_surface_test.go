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

package gateway

import (
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

func TestHookIngressSurface(t *testing.T) {
	actor := substrateActor{Atespace: "eng-web", Name: "cc-1", UID: "25a1da0f-1c9b-4ef7-8248-c276138c7f77",
		Subject: "actor/eng-web/cc-1", RegistrationKey: "substrate:eng-web/25a1da0f-1c9b-4ef7-8248-c276138c7f77"}
	sandbox := sandboxauth.WithRequest(context.Background(), sandboxauth.Binding{ID: "b1", Connector: "claudecode"}, nil)
	for name, tc := range map[string]struct {
		ctx  context.Context
		want string
	}{
		"host":              {context.Background(), hookIngressHost},
		"nil":               {nil, hookIngressHost},
		"openshell":         {sandbox, hookIngressOpenShell},
		"substrate":         {withSubstrateActor(context.Background(), actor), hookIngressSubstrate},
		"substrate wins":    {withSubstrateActor(sandbox, actor), hookIngressSubstrate},
		"actor without uid": {withSubstrateActor(context.Background(), substrateActor{Atespace: "eng-web"}), hookIngressHost},
	} {
		if got := hookIngressSurface(tc.ctx); got != tc.want {
			t.Errorf("%s: surface %q, want %q", name, got, tc.want)
		}
	}
	got, ok := substrateActorFrom(withSubstrateActor(context.Background(), actor))
	if !ok || got != actor {
		t.Fatalf("actor round trip: %+v %t", got, ok)
	}
}

// A verified Substrate actor's hook runs in a sandbox: the require-sandbox
// gate never refuses it as a host run, whatever the floor requires. The
// same hook without the actor is refused.
func TestRequireSandboxNeverRefusesASubstrateActor(t *testing.T) {
	useSandboxAvailability(t, sandboxDevicesUsable)
	peer := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Name: "alice"})
	api, _ := requireSandboxTestAPI(t, "", "claudecode", "codex")
	if got := api.requireSandboxDecision(peer, "claudecode", "UserPromptSubmit", "/p", ""); got.Outcome != requireSandboxRefused {
		t.Fatalf("host run not refused: %+v", got)
	}
	req := agentHookRequest{ConnectorName: "codex", HookEventName: "SessionStart", CWD: "/p"}
	sessionStart := func(ctx context.Context) bool {
		_, _, gated := api.requireSandboxHostRun(ctx, api.hookProfileForConnector("codex"), "codex", req,
			[]byte(`{"hook_event_name":"SessionStart"}`), map[string]any{"hook_event_name": "SessionStart"}, "cli")
		return gated
	}
	if !sessionStart(peer) {
		t.Fatal("host SessionStart not gated")
	}
	actor := withSubstrateActor(peer, substrateActor{Atespace: "eng-web", Name: "cc-1", UID: "25a1da0f-1c9b-4ef7-8248-c276138c7f77"})
	if got := api.requireSandboxDecision(actor, "claudecode", "UserPromptSubmit", "/p", ""); got.Outcome != "" {
		t.Fatalf("substrate actor gated: %+v", got)
	}
	if sessionStart(actor) {
		t.Fatal("substrate actor's SessionStart gated")
	}
}
