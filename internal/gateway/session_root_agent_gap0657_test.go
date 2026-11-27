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

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

// substrate-1:GAP-0657: a session's root agent is one rule, agentNodeID over
// the agent identity, the connector and the session, reached from three
// places: the connector-hook audit envelope (withHookSessionRootAgent), the
// hook_decision and model records (hookLLMEventMeta) and a native Codex OTLP
// notify (codexNotifyAgentID). They must name the same agent for the same
// verified identity and session, so a join on agent_id never splits.
func TestSessionRootAgentIsOneRuleForHooksAndNativeOTLPGAP0657(t *testing.T) {
	const session = "gap0657-session"
	ctx := ContextWithAgentIdentity(context.Background(), AgentIdentity{IdentityID: "agt-gap0657"})
	want := agentNodeID("agt-gap0657", "codex", session, "root")

	envelope := audit.EnvelopeFromContext(withHookSessionRootAgent(ctx, agentHookRequest{ConnectorName: "codex", SessionID: session})).AgentID
	if envelope != want {
		t.Errorf("connector-hook envelope agent = %q, want %q", envelope, want)
	}
	meta := hookLLMEventMeta(ctx, "codex", session, "", "", "", "", "", "", map[string]interface{}{}).AgentID
	if meta != want {
		t.Errorf("hook_decision agent = %q, want %q", meta, want)
	}
	notify := (&APIServer{}).codexNotifyAgentID(ctx, session)
	if notify != want {
		t.Errorf("native OTLP notify agent = %q, want %q", notify, want)
	}
}
