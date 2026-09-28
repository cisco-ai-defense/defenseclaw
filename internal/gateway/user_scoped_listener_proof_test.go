// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

const (
	listenerProofTestAlice = "S-1-5-21-1111-2222-3333-1001"
	listenerProofTestBob   = "S-1-5-21-1111-2222-3333-1002"
)

var listenerProofTestNonce = strings.Repeat("5a", 32)

type listenerProofResult struct {
	status int
	proof  string
	body   string
}

func requestUserScopedListenerProof(handler http.Handler, observed *userScopedObservation, method, remote, scope, keyID, nonce string) listenerProofResult {
	*observed = userScopedObservation{}
	req := httptest.NewRequest(method, connector.UserScopedListenerProofPath, nil)
	req.RemoteAddr = remote
	if scope != "" {
		req.Header.Set("X-DefenseClaw-Connector", scope)
	}
	if keyID != "" {
		req.Header.Set(connector.UserScopedListenerKeyIDHeader, keyID)
	}
	if nonce != "" {
		req.Header.Set(connector.UserScopedListenerNonceHeader, nonce)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	return listenerProofResult{
		status: response.Code,
		proof:  response.Header().Get(connector.UserScopedListenerProofHeader),
		body:   response.Body.String(),
	}
}

// The gateway answers a listener proof only for the hook credential of a
// user its ledger protects, for the connector that credential belongs to,
// and only with the HMAC the plugin expects. The route never reaches the
// API handlers and never returns the credential itself.
func TestUserScopedListenerProofAnswersOnlyAProtectedUsersHookCredential(t *testing.T) {
	ledger := &userScopedTestLedger{}
	ledger.set(
		managedHookLedgerTarget{User: "alice", SID: listenerProofTestAlice, Connector: "opencode", OK: true},
		managedHookLedgerTarget{User: "bob", SID: listenerProofTestBob, Connector: "opencode", OK: true},
		managedHookLedgerTarget{User: "alice", SID: listenerProofTestAlice, Connector: "codex", OK: true},
	)
	api, handler, observed := newUserScopedTestServer(t, true, ledger, nil)
	alice := userScopedTestToken(t, connector.UserScopedHookCredential, "opencode", listenerProofTestAlice)
	bob := userScopedTestToken(t, connector.UserScopedHookCredential, "opencode", listenerProofTestBob)
	aliceKeyID := connector.UserScopedCredentialKeyID(alice)

	got := requestUserScopedListenerProof(handler, observed, http.MethodGet, "127.0.0.1:50000", "opencode", aliceKeyID, listenerProofTestNonce)
	want, err := connector.UserScopedListenerProof(alice, "opencode", listenerProofTestNonce)
	if err != nil {
		t.Fatal(err)
	}
	if got.status != http.StatusNoContent || got.proof != want || observed.called {
		t.Fatalf("protected user's proof: status %d proof %q (want %q) called=%v", got.status, got.proof, want, observed.called)
	}
	if strings.Contains(got.proof+got.body, alice) {
		t.Fatal("the listener proof disclosed the credential")
	}
	bobProof := requestUserScopedListenerProof(handler, observed, http.MethodGet, "127.0.0.1:50000", "OpenCode", connector.UserScopedCredentialKeyID(bob), listenerProofTestNonce)
	if bobProof.status != http.StatusNoContent || bobProof.proof == "" || bobProof.proof == got.proof {
		t.Fatalf("each user's proof is its own: status %d proof %q", bobProof.status, bobProof.proof)
	}

	wide, err := connector.EnsureHookAPIToken(api.configDataDir(), "opencode")
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		method, remote, scope, keyID, nonce string
	}{
		"another connector":      {http.MethodGet, "127.0.0.1:50000", "amp", aliceKeyID, listenerProofTestNonce},
		"the connector-wide one": {http.MethodGet, "127.0.0.1:50000", "opencode", connector.UserScopedCredentialKeyID(wide), listenerProofTestNonce},
		"the credential itself":  {http.MethodGet, "127.0.0.1:50000", "opencode", alice, listenerProofTestNonce},
		"a short nonce":          {http.MethodGet, "127.0.0.1:50000", "opencode", aliceKeyID, "5a5a"},
		"a remote caller":        {http.MethodGet, "192.0.2.10:50000", "opencode", aliceKeyID, listenerProofTestNonce},
	} {
		result := requestUserScopedListenerProof(handler, observed, tc.method, tc.remote, tc.scope, tc.keyID, tc.nonce)
		if result.status != http.StatusUnauthorized || result.proof != "" || observed.called {
			t.Errorf("%s: status %d proof %q called=%v; want a 401 without a proof", name, result.status, result.proof, observed.called)
		}
	}

	// A user the ledger stops protecting gets no proof, like no credential.
	ledger.set(managedHookLedgerTarget{User: "bob", SID: listenerProofTestBob, Connector: "opencode", OK: true})
	if result := requestUserScopedListenerProof(handler, observed, http.MethodGet, "127.0.0.1:50000", "opencode", aliceKeyID, listenerProofTestNonce); result.status != http.StatusUnauthorized || result.proof != "" {
		t.Fatalf("revoked user: status %d proof %q", result.status, result.proof)
	}
}

// Outside the standalone profile (Secure Client included) the route does not
// exist: the request takes the ordinary authentication path and is refused
// without a proof, exactly as before.
func TestUserScopedListenerProofOnlyInStandaloneProfile(t *testing.T) {
	ledger := &userScopedTestLedger{}
	ledger.set(managedHookLedgerTarget{User: "alice", SID: listenerProofTestAlice, Connector: "opencode", OK: true})
	_, handler, observed := newUserScopedTestServer(t, false, ledger, nil)
	alice := userScopedTestToken(t, connector.UserScopedHookCredential, "opencode", listenerProofTestAlice)
	result := requestUserScopedListenerProof(handler, observed, http.MethodGet, "127.0.0.1:50000", "opencode", connector.UserScopedCredentialKeyID(alice), listenerProofTestNonce)
	if result.status != http.StatusUnauthorized || result.proof != "" || observed.called {
		t.Fatalf("outside standalone: status %d proof %q called=%v", result.status, result.proof, observed.called)
	}
}
