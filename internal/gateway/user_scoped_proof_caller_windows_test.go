// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"errors"
	"net/http"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func setListenerProofTestCaller(t *testing.T, lookup func(*http.Request) string) {
	t.Helper()
	previous := userScopedProofCallerSID
	userScopedProofCallerSID = func(r *http.Request) (string, error) { return lookup(r), nil }
	t.Cleanup(func() { userScopedProofCallerSID = previous })
}

// The HMAC proof is an oracle unless the protected gateway binds its answer
// to the OS account that opened the request. A second account can otherwise
// relay a victim's challenge to a real gateway on another port.
func TestWindowsListenerProofRefusesAnotherAccountRelay(t *testing.T) {
	ledger := &userScopedTestLedger{}
	ledger.set(managedHookLedgerTarget{User: "alice", SID: listenerProofTestAlice, Connector: "opencode", OK: true})
	_, handler, observed := newUserScopedTestServer(t, true, ledger, nil)
	credential := userScopedTestToken(t, connector.UserScopedHookCredential, "opencode", listenerProofTestAlice)
	keyID := connector.UserScopedCredentialKeyID(credential)
	previous := userScopedProofCallerSID
	t.Cleanup(func() { userScopedProofCallerSID = previous })
	userScopedProofCallerSID = func(*http.Request) (string, error) { return listenerProofTestBob, nil }
	got := requestUserScopedListenerProof(handler, observed, http.MethodGet, "127.0.0.1:50000", "opencode", keyID, listenerProofTestNonce)
	if got.status != http.StatusUnauthorized || got.proof != "" {
		t.Fatalf("second account got proof: status=%d proof=%q", got.status, got.proof)
	}
	userScopedProofCallerSID = func(*http.Request) (string, error) { return "", errors.New("owner unavailable") }
	got = requestUserScopedListenerProof(handler, observed, http.MethodGet, "127.0.0.1:50000", "opencode", keyID, listenerProofTestNonce)
	if got.status != http.StatusUnauthorized || got.proof != "" {
		t.Fatalf("unknown caller got proof: status=%d proof=%q", got.status, got.proof)
	}
	userScopedProofCallerSID = func(*http.Request) (string, error) { return listenerProofTestAlice, nil }
	got = requestUserScopedListenerProof(handler, observed, http.MethodGet, "127.0.0.1:50000", "opencode", keyID, listenerProofTestNonce)
	if got.status != http.StatusNoContent || got.proof == "" {
		t.Fatalf("same account was refused: status=%d proof=%q", got.status, got.proof)
	}
}
