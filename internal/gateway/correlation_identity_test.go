// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
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

func TestSecureClientKeepsQualifiedTrustedHookName(t *testing.T) {
	setManagedEnterpriseRedactionPosture(true)
	t.Cleanup(func() { setManagedEnterpriseRedactionPosture(false) })
	const qualified = "alice@corp.example"
	if got := newTrustedLLMEventUser("1001", qualified).Name; got != qualified {
		t.Fatalf("trusted name = %q, want %q", got, qualified)
	}
	registry := NewAgentRegistry("", "")
	request := httptest.NewRequest(http.MethodPost, "/api/v1/inspect/tool", nil)
	request.RemoteAddr = "127.0.0.1:40000"
	request.Header.Set(llmEventUserNameHeader, qualified)
	var got string
	CorrelationMiddleware(registry)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got = AgentIdentityFromContext(r.Context()).UserName
	})).ServeHTTP(httptest.NewRecorder(), request)
	if got != qualified {
		t.Fatalf("loopback name = %q, want %q", got, qualified)
	}
}
