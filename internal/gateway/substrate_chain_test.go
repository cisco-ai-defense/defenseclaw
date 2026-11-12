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
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/substrate/chainstate"
	"github.com/defenseclaw/defenseclaw/internal/substrate/leader"
)

func newTestChainLeader(t *testing.T) *chainstate.Client {
	t.Helper()
	svc, err := chainstate.New(chainstate.Options{Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	ls := &leader.Server{IsLeader: func() bool { return true }}
	svc.Register(ls)
	srv := httptest.NewServer(ls)
	t.Cleanup(func() { srv.Close(); _ = svc.Close() })
	return &chainstate.Client{Leader: &leader.Client{BaseURL: srv.URL, HTTP: srv.Client(), Retry: time.Second}}
}

// A verified actor's chain windows are the leader's (session and actor
// scope); without a leader client there is no chain state for an actor; a
// host call keeps the local repository and no root window.
func TestToolChainStoresRouteActorsToTheLeader(t *testing.T) {
	store, err := audit.NewStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	a := &APIServer{store: store}
	req := agentHookRequest{ConnectorName: "claudecode", SessionID: "s1", HookEventName: "PreToolUse"}

	session, root, ok := a.toolChainStores(context.Background(), req)
	if !ok || root != nil {
		t.Fatalf("host: ok=%v root=%v", ok, root)
	}
	if _, local := session.(*audit.ToolChainRepository); !local {
		t.Fatalf("host session store %T", session)
	}

	ctx := withSubstrateActor(context.Background(), testSubstrateActor())
	if _, _, ok := a.toolChainStores(ctx, req); ok {
		t.Fatal("an actor got chain state without a leader")
	}
	a.substrate = &substrateState{cfg: SubstrateConfig{Chains: newTestChainLeader(t)}}
	session, root, ok = a.toolChainStores(ctx, req)
	if !ok {
		t.Fatal("no chain state for an actor with a leader")
	}
	s, isBinding := session.(*chainstate.Binding)
	r, rootIsBinding := root.(*chainstate.Binding)
	if !isBinding || !rootIsBinding || s.Scope() != audit.ToolChainScopeSession || r.Scope() != audit.ToolChainScopeRoot {
		t.Fatalf("actor stores %T %T", session, root)
	}
}

// With Substrate chains on, a judge's intent for an actor's call is the
// leader's: a second judge (another replica) sees the first one's prompt;
// the decision judge keeps its own context; a host call stays local.
func TestJudgeIntentIsSharedThroughTheLeader(t *testing.T) {
	useSubstrateChains(newTestChainLeader(t))
	t.Cleanup(func() { useSubstrateChains(nil) })
	ctx := withSubstrateActor(ContextWithSessionID(context.Background(), "s1"), testSubstrateActor())

	replica1, replica2 := &LLMJudge{}, &LLMJudge{}
	replica1.ObserveSessionPrompt(ctx, "deploy the web app")
	sample := replica2.toolJudgeContextSample(ctx, "Bash", `{"command":"make deploy"}`)
	if !strings.Contains(sample, "deploy the web app") {
		t.Fatalf("replica 2 lacks replica 1's intent:\n%s", sample)
	}
	decision := &LLMJudge{decisionOnly: true}
	if sample := decision.toolJudgeContextSample(ctx, "Bash", "{}"); strings.Contains(sample, "deploy the web app") {
		t.Fatalf("the decision judge shares the guardrail judge's context:\n%s", sample)
	}
	replica1.ResetToolJudgeSession(ctx, sandboxSessionStateKey(ctx, "s1"))
	if sample := replica2.toolJudgeContextSample(ctx, "Bash", "{}"); strings.Contains(sample, "deploy the web app") {
		t.Fatalf("reset did not reach the leader:\n%s", sample)
	}

	host := ContextWithSessionID(context.Background(), "h1")
	replica1.ObserveSessionPrompt(host, "local only")
	if sample := replica2.toolJudgeContextSample(host, "Bash", "{}"); strings.Contains(sample, "local only") {
		t.Fatalf("a host call's intent left the process:\n%s", sample)
	}
}

func TestSetToolValueLineageKey(t *testing.T) {
	saved := activeToolValueLineageProcessKey
	t.Cleanup(func() { activeToolValueLineageProcessKey = saved })
	if err := SetToolValueLineageKey(make([]byte, 16)); err == nil {
		t.Fatal("short key accepted")
	}
	if err := SetToolValueLineageKey(make([]byte, 32)); err == nil {
		t.Fatal("zero key accepted")
	}
	key := []byte(strings.Repeat("k", 32))
	if err := SetToolValueLineageKey(key); err != nil || !activeToolValueLineageProcessKey.available ||
		string(activeToolValueLineageProcessKey.material[:]) != string(key) {
		t.Fatalf("key not set: %v", err)
	}
}
