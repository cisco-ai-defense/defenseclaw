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
	"testing"
	"time"
)

// GAP-1047: Copilot session IDs are caller-supplied and can repeat across
// accounts. A sub-agent start does not take the retained session of another
// agent identity, or of another user under the same identity, as its parent.
func TestCopilotSubagentStartDoesNotTakeAnotherAccountsParent(t *testing.T) {
	const session = "6b5c0000-0000-4000-8000-000000001047"
	cases := []struct {
		name                     string
		parentIdentity, identity string
		parentUser, user         string
	}{
		{"another agent identity", "agt-00000000000a1047", "agt-00000000000b1047", "1047", "1047"},
		{"another user under one identity", "agt-00000000000a1047", "agt-00000000000a1047", "1047", "2047"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			api := &APIServer{}
			api.rememberHookSessionState(t.Context(), llmEventMeta{
				Source: "copilot", SessionID: session, AgentIdentityID: tc.parentIdentity, UserID: tc.parentUser,
				AgentID: agentNodeID(tc.parentIdentity, "copilot", session, "root"), LifecycleEvent: "session_start",
			})
			api.noteCopilotSubagentStart(llmEventMeta{
				Source: "copilot", SessionID: session, AgentIdentityID: tc.identity, UserID: tc.user,
			}, time.Now())
			api.llmPromptMu.Lock()
			pending := len(api.copilotSubagents)
			api.llmPromptMu.Unlock()
			if pending != 0 {
				t.Fatalf("a sub-agent start of %s/%s took the session of %s/%s as its parent",
					tc.identity, tc.user, tc.parentIdentity, tc.parentUser)
			}
		})
	}
	// The account's own session still parents its sub-agent.
	api := &APIServer{}
	api.rememberHookSessionState(t.Context(), llmEventMeta{
		Source: "copilot", SessionID: session, AgentIdentityID: cases[0].parentIdentity, UserID: "1047",
		AgentID: agentNodeID(cases[0].parentIdentity, "copilot", session, "root"), LifecycleEvent: "session_start",
	})
	api.noteCopilotSubagentStart(llmEventMeta{
		Source: "copilot", SessionID: session, AgentIdentityID: cases[0].parentIdentity, UserID: "1047",
	}, time.Now())
	if len(api.copilotSubagents) != 1 {
		t.Fatal("the account's own session did not parent its sub-agent")
	}
}
