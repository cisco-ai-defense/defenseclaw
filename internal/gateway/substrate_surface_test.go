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
	"errors"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/intentstore"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

func TestHookIngressSurface(t *testing.T) {
	actor := verifiedSubstrateActor("eng-web", "cc-1", "25a1da0f-1c9b-4ef7-8248-c276138c7f77",
		"actor/eng-web/cc-1", "substrate:eng-web/25a1da0f-1c9b-4ef7-8248-c276138c7f77")
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
	// A forged actor context (a substrateActor not built by the verifier
	// path, or one whose key, UID or subject disagree) is a host run.
	const uid = "25a1da0f-1c9b-4ef7-8248-c276138c7f77"
	good := verifiedSubstrateActor("eng-web", "cc-1", uid, "actor/eng-web/cc-1", "substrate:eng-web/"+uid)
	forged := map[string]substrateActor{
		"unsealed":       {Atespace: "eng-web", Name: "cc-1", UID: uid, Subject: "actor/eng-web/cc-1", RegistrationKey: "substrate:eng-web/" + uid},
		"uid only":       {Atespace: "eng-web", Name: "cc-1", UID: uid},
		"no key":         verifiedSubstrateActor("eng-web", "cc-1", uid, "actor/eng-web/cc-1", ""),
		"other atespace": verifiedSubstrateActor("eng-web", "cc-1", uid, "actor/eng-web/cc-1", "substrate:eng-evil/"+uid),
		"other uid":      verifiedSubstrateActor("eng-web", "cc-1", uid, "actor/eng-web/cc-1", "substrate:eng-web/35a1da0f-1c9b-4ef7-8248-c276138c7f77"),
		"openshell key":  verifiedSubstrateActor("eng-web", "cc-1", uid, "actor/eng-web/cc-1", "reg-0123456789abcdef"),
		"bad subject":    verifiedSubstrateActor("eng-web", "cc-1", uid, "worker-for-actor/eng-web/cc-1", "substrate:eng-web/"+uid),
		"not a uuid":     verifiedSubstrateActor("eng-web", "cc-1", "x", "actor/eng-web/cc-1", "substrate:eng-web/x"),
	}
	for name, f := range forged {
		ctx := withSubstrateActor(peer, f)
		if isSubstrateActorRequest(ctx) {
			t.Errorf("%s: forged actor accepted", name)
		}
		if got := api.requireSandboxDecision(ctx, "claudecode", "UserPromptSubmit", "/p", ""); got.Outcome != requireSandboxRefused {
			t.Errorf("%s: forged actor not refused as a host run: %+v", name, got)
		}
		if !sessionStart(ctx) {
			t.Errorf("%s: forged actor's SessionStart not gated", name)
		}
	}
	actor := withSubstrateActor(peer, good)
	if got := api.requireSandboxDecision(actor, "claudecode", "UserPromptSubmit", "/p", ""); got.Outcome != "" {
		t.Fatalf("substrate actor gated: %+v", got)
	}
	if sessionStart(actor) {
		t.Fatal("substrate actor's SessionStart gated")
	}
}

// sharedIntentStore stands in for a store several replicas share.
type sharedIntentStore struct {
	intent  string
	fail    bool
	appends []string
	resets  []string
}

func (s *sharedIntentStore) ObservePrompt(_ context.Context, _ string, intent string) error {
	s.intent = intent
	return nil
}

func (s *sharedIntentStore) AppendToolCall(_ context.Context, key string, call intentstore.ToolCall) (intentstore.Snapshot, error) {
	s.appends = append(s.appends, key+"/"+call.Tool)
	if s.fail {
		return intentstore.Snapshot{}, errors.New("leader unreachable")
	}
	return intentstore.Snapshot{UserIntent: s.intent, Prior: []intentstore.ToolCall{{Tool: "Read", Args: "README"}}}, nil
}

func (s *sharedIntentStore) Reset(_ context.Context, key string) error {
	s.resets = append(s.resets, key)
	return nil
}

// The judge reads and writes a session's intent only through its store: a
// store set with SetIntentStore is the one every call sees, and a store
// that fails leaves the call judged on its own.
func TestLLMJudgeUsesItsIntentStore(t *testing.T) {
	store := &sharedIntentStore{}
	judge := &LLMJudge{}
	judge.SetIntentStore(store)
	ctx := ContextWithSessionID(context.Background(), "s1")
	judge.ObserveSessionPrompt(ctx, "deploy the web app")
	sample := judge.toolJudgeContextSample(ctx, "Bash", `{"command":"make deploy"}`)
	for _, want := range []string{"deploy the web app", `<RECENT_TOOL_CALL index=1 tool="Read">`, "README", "make deploy"} {
		if !strings.Contains(sample, want) {
			t.Fatalf("sample lacks %q:\n%s", want, sample)
		}
	}
	judge.ResetToolJudgeSession("s1")
	if len(store.appends) != 1 || store.appends[0] != "s1/Bash" || len(store.resets) != 1 || store.resets[0] != "s1" {
		t.Fatalf("store calls: appends %v resets %v", store.appends, store.resets)
	}

	store.fail = true
	sample = judge.toolJudgeContextSample(ctx, "Bash", `{"command":"ls"}`)
	if strings.Contains(sample, "SESSION_USER_INTENT") || strings.Contains(sample, "RECENT_TOOL_CALL") || !strings.Contains(sample, "ls") {
		t.Fatalf("failed store sample:\n%s", sample)
	}

	// A judge built as a literal keeps its own process-local context.
	plain := &LLMJudge{}
	plain.ObserveSessionPrompt(ctx, "local intent")
	if sample := plain.toolJudgeContextSample(ctx, "Bash", "{}"); !strings.Contains(sample, "local intent") {
		t.Fatalf("default store lost the intent:\n%s", sample)
	}
}
