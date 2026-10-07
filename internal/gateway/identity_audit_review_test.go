// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"testing"
)

func TestVerifiedManagedHookAuditNameMatchesV8Name(t *testing.T) {
	setIdentityFactsEnabled(true)
	t.Cleanup(func() { setIdentityFactsEnabled(false) })
	ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Name: "alice@realm"})
	ctx = ContextWithAgentIdentity(ctx, AgentIdentity{UserID: "1001", UserName: "alice"})
	if got := auditCallerIdentity(ctx).Name; got != "alice" {
		t.Fatalf("managed audit name = %q, want alice", got)
	}
	setIdentityFactsEnabled(false)
	if got := auditCallerIdentity(ctx).Name; got != "alice@realm" {
		t.Fatalf("Secure Client audit name = %q, want qualified name", got)
	}
}
