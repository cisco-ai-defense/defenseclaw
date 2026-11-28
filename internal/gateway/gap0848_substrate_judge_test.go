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

	"github.com/defenseclaw/defenseclaw/internal/substrate/chainstate"
	"github.com/defenseclaw/defenseclaw/internal/substrate/leader"
)

// With Substrate chains on, a tool-result judge of an actor's call reads the
// turn's request from the leader (rel-1-0-10:GAP-0848 on feat/substrate): a
// replica that did not see the prompt gives the one another replica recorded,
// in the judge's SESSION_USER_INTENT section. Each actor sees only its own
// request (another actor with the same session id gets none), the decision
// judge only its own role's, and a host call only this process's.
func TestSubstrateToolResultJudgeSeesTheUserRequest(t *testing.T) {
	useSubstrateChains(newTestChainLeader(t))
	t.Cleanup(func() { useSubstrateChains(nil) })
	ctx := withSubstrateActor(ContextWithSessionID(context.Background(), "s1"), chainTestActor())

	replica1, replica2 := &LLMJudge{}, &LLMJudge{}
	replica1.ObserveSessionPrompt(ctx, "summarize the open tickets")
	if got := replica2.sessionUserIntent(ctx); got != "summarize the open tickets" {
		t.Fatalf("a Substrate-role tool-result judge got request %q, want the actor's prompt", got)
	}
	sections := replica2.toolResultJudgeSections(withToolResultCall(ctx, "Bash", `{"command":"cat tickets.txt"}`), "Bash")
	if !strings.Contains(sections.sections, "SESSION_USER_INTENT") || !strings.Contains(sections.sections, "summarize the open tickets") {
		t.Fatalf("the judge's sections lack the user request:\n%s", sections.sections)
	}

	other := withSubstrateActor(ContextWithSessionID(context.Background(), "s1"),
		verifiedSubstrateActor("eng-web", "bob-1", "6b0c8a2e-3d4f-4a51-9c7e-0d2f1b3a4c5d", "actor/eng-web/bob-1",
			"substrate:eng-web/6b0c8a2e-3d4f-4a51-9c7e-0d2f1b3a4c5d"))
	if got := replica2.sessionUserIntent(other); got != "" {
		t.Fatalf("another actor's judge read %q", got)
	}
	decision := &LLMJudge{decisionOnly: true}
	if got := decision.sessionUserIntent(ctx); got != "" {
		t.Fatalf("the decision judge read the guardrail judge's request %q", got)
	}

	host := ContextWithSessionID(context.Background(), "h1")
	replica1.ObserveSessionPrompt(host, "local only")
	if got := replica1.sessionUserIntent(host); got != "local only" {
		t.Fatalf("a host call's own judge got %q", got)
	}
	if got := replica2.sessionUserIntent(host); got != "" {
		t.Fatalf("a host call's request left the process: %q", got)
	}
}

// With the leader down (a leader change), a tool-result judge of an actor's
// call judges promptly without the user request: its lookup gives up in
// about a second, not after the leader client's 45 s retry window (the
// gateway's client has Retry zero), and the judge still builds its prompt.
func TestSubstrateToolResultJudgeLeaderDownJudgesWithoutTheRequest(t *testing.T) {
	srv := httptest.NewServer(nil)
	url, hc := srv.URL, srv.Client()
	srv.Close() // the leader refuses connections from now on
	useSubstrateChains(&chainstate.Client{Leader: &leader.Client{BaseURL: url, HTTP: hc}})
	t.Cleanup(func() { useSubstrateChains(nil) })
	ctx := withSubstrateActor(ContextWithSessionID(context.Background(), "s1"), chainTestActor())
	judge := &LLMJudge{}
	start := time.Now()
	if got := judge.sessionUserIntent(ctx); got != "" {
		t.Fatalf("the judge read %q with the leader down", got)
	}
	sections := judge.toolResultJudgeSections(withToolResultCall(ctx, "Bash", `{"command":"ls"}`), "Bash")
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("two judge reads with the leader down took %s, want about 2 s", elapsed)
	}
	if sections.sections == "" || strings.Contains(sections.sections, "SESSION_USER_INTENT") {
		t.Fatalf("the judge's sections with the leader down:\n%s", sections.sections)
	}
}
