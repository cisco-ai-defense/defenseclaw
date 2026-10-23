// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"net/http"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func setListenerProofTestCaller(t *testing.T, lookup func(*http.Request) string) {
	t.Helper()
	previous := userScopedProofCallerIdentity
	userScopedProofCallerIdentity = func(r *http.Request) (string, error) { return lookup(r), nil }
	t.Cleanup(func() { userScopedProofCallerIdentity = previous })
}

// A second account can relay a plugin's nonce and key ID to the real
// gateway. The gateway must not return that user's credential-derived proof
// to the second account, even when the request stays on loopback.
func TestUnixListenerProofRefusesAnotherAccountRelay(t *testing.T) {
	ledger := &userScopedTestLedger{}
	ledger.set(managedHookLedgerTarget{User: "alice", SID: listenerProofTestAlice, Connector: "opencode", OK: true})
	_, handler, observed := newUserScopedTestServer(t, true, ledger, nil)
	credential := userScopedTestToken(t, connector.UserScopedHookCredential, "opencode", listenerProofTestAlice)
	keyID := connector.UserScopedCredentialKeyID(credential)
	caller := listenerProofTestBob
	setListenerProofTestCaller(t, func(*http.Request) string { return caller })
	got := requestUserScopedListenerProof(handler, observed, http.MethodGet, "127.0.0.1:50000", "opencode", keyID, listenerProofTestNonce)
	if got.status != http.StatusUnauthorized || got.proof != "" {
		t.Fatalf("second account got proof: status=%d proof=%q", got.status, got.proof)
	}
	caller = listenerProofTestAlice
	got = requestUserScopedListenerProof(handler, observed, http.MethodGet, "127.0.0.1:50000", "opencode", keyID, listenerProofTestNonce)
	if got.status != http.StatusNoContent || got.proof == "" {
		t.Fatalf("same account was refused: status=%d proof=%q", got.status, got.proof)
	}
}
