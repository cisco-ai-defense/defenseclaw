// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// Session promotion mints the agent instance but must keep the caller's
// verified identity. Before, a session header cleared it, and the
// agent-controlled payload fields were attributed instead.
func TestPromoteSessionKeepsVerifiedUserIdentity(t *testing.T) {
	registry := NewAgentRegistry("", "")
	ctx := ContextWithSessionID(context.Background(), "session-1")
	ctx = ContextWithAgentIdentity(ctx, AgentIdentity{UserID: "1001", UserIDKind: useridentity.KindPOSIXUID, UserName: "alice"})
	ctx = contextWithPendingAgentRegistry(ctx, registry, "")
	promoted := AgentIdentityFromContext(PromoteSessionIfAuthenticated(ctx))
	if promoted.AgentInstanceID == "" {
		t.Fatal("promotion did not mint the agent instance")
	}
	if promoted.UserID != "1001" || promoted.UserIDKind != useridentity.KindPOSIXUID || promoted.UserName != "alice" {
		t.Fatalf("promotion dropped the verified identity: %+v", promoted)
	}
	user := resolveHookUser(PromoteSessionIfAuthenticated(ctx), map[string]interface{}{"user_id": "1002"})
	if user.ID != "1001" {
		t.Fatalf("payload identity %q won over the verified one", user.ID)
	}
}
