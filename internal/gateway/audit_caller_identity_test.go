// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"testing"
)

// TestAuditCallerIdentityTrustsOnlyVerifiedCallersOnAStandaloneGateway: a
// standalone gateway attributes rows to the kernel-verified peer or the
// account of a per-user credential, never to an identity a request only
// claimed; a per-user gateway keeps the correlation identity its
// hook_decision rows carry.
func TestAuditCallerIdentityTrustsOnlyVerifiedCallersOnAStandaloneGateway(t *testing.T) {
	claimed := ContextWithAgentIdentity(context.Background(), AgentIdentity{UserID: "1001", UserIDKind: "posix_uid", UserName: "claimed"})
	if caller := auditCallerIdentity(withServiceAccountGateway(claimed)); caller != (auditCaller{}) {
		t.Fatalf("standalone gateway attributed a claimed identity: %+v", caller)
	}
	if caller := auditCallerIdentity(claimed); caller.ID != "1001" || caller.Name != "claimed" {
		t.Fatalf("per-user gateway caller = %+v", caller)
	}
	peer := withManagedHookPeer(withServiceAccountGateway(claimed), managedHookPeer{UID: 1002, Name: "bob"})
	if caller := auditCallerIdentity(peer); caller.ID != "1002" || caller.Name != "bob" || caller.principalRef() != "uid:1002" {
		t.Fatalf("hook-socket caller = %+v", caller)
	}
	bound := context.WithValue(withServiceAccountGateway(claimed), verifiedUserScopedIdentityContextKey{}, "S-1-5-21-1111-2222-3333-1003")
	if caller := auditCallerIdentity(bound); caller.ID != "S-1-5-21-1111-2222-3333-1003" || caller.Name != "" ||
		caller.principalRef() != "sid:S-1-5-21-1111-2222-3333-1003" {
		t.Fatalf("per-user credential caller = %+v", caller)
	}
}

func TestAuthenticationFailureFactsNameOnlyAVerifiedCaller(t *testing.T) {
	claimed := ContextWithAgentIdentity(context.Background(), AgentIdentity{UserID: "1001", UserName: "claimed"})
	if facts := apiAuthenticationFailureFactsFor(claimed, "/api/v1/inspect/tool", ""); facts.Principal != "" || facts.AuthnMethod != "" || facts.Caller.ID != "" {
		t.Fatalf("an unauthenticated request's claimed identity was recorded: %+v", facts)
	}
	bound := context.WithValue(context.Background(), verifiedUserScopedIdentityContextKey{}, "1001")
	bound = withAuthenticatedInspectConnector(bound, "amp")
	facts := apiAuthenticationFailureFactsFor(bound, "/api/v1/inspect/tool", "")
	if facts.Principal != "uid:1001" || facts.AuthnMethod != "user_scoped_credential" || facts.connector() != "amp" ||
		facts.Caller.ID != "1001" {
		t.Fatalf("per-user credential refusal facts = %+v", facts)
	}
	peer := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1002})
	facts = apiAuthenticationFailureFactsFor(peer, "/api/v1/foreign-hook-session/{connector}", "claudecode")
	if facts.Principal != "uid:1002" || facts.AuthnMethod != "hook_socket_peer" || facts.connector() != "claudecode" {
		t.Fatalf("hook-socket refusal facts = %+v", facts)
	}
	if ref, ok := facts.targetRef().Get(); !ok || ref != "route:/api/v1/foreign-hook-session/_connector_" ||
		!authFailureRefPattern.MatchString(ref) {
		t.Fatalf("target ref = %q %v", ref, ok)
	}
	if got := apiAuthenticationFailureLogReason(managedHookReasonUIDUnregistered); got != managedHookReasonUIDUnregistered {
		t.Fatalf("managed refusal reason dropped: %q", got)
	}
	if got := apiAuthenticationFailureLogReason("free text from a caller"); got != "" {
		t.Fatalf("a non-constant reason was accepted: %q", got)
	}
}
