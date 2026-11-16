// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func TestRotationProofOnHookSocketRequiresRootAndProtectedCredential(t *testing.T) {
	ledger := &userScopedTestLedger{}
	ledger.set(managedHookLedgerTarget{UID: uidPtr(1001), Connector: "opencode", OK: true})
	api, _, _ := newUserScopedTestServer(t, true, ledger, nil)
	api.hookCallerLimits = hookCallerLimiter{rate: 1, burst: 1}
	handler := api.managedHookSocketHandler(
		newManagedHookAuthorizer(config.EnterpriseEnrollmentConfig{}, nil, nil),
		func(next http.Handler) http.Handler { return next },
	)
	credential := userScopedTestToken(t, connector.UserScopedHookCredential, "opencode", "1001")
	keyID := connector.UserScopedCredentialKeyID(credential)
	want, err := connector.UserScopedListenerProof(credential, "opencode", listenerProofTestNonce)
	if err != nil {
		t.Fatal(err)
	}
	call := func(uid int, key string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(http.MethodGet, connector.UserScopedRotationProofPath, nil)
		request.Header.Set("X-DefenseClaw-Connector", "opencode")
		request.Header.Set(connector.UserScopedListenerKeyIDHeader, key)
		request.Header.Set(connector.UserScopedListenerNonceHeader, listenerProofTestNonce)
		request = request.WithContext(withManagedHookPeer(request.Context(), managedHookPeer{UID: uid}))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	if got := call(1002, keyID); got.Code != http.StatusForbidden || got.Header().Get(connector.UserScopedListenerProofHeader) != "" {
		t.Fatalf("another account received rotation proof: status=%d proof=%q", got.Code, got.Header().Get(connector.UserScopedListenerProofHeader))
	}
	if got := call(0, "missing"); got.Code != http.StatusUnauthorized || got.Header().Get(connector.UserScopedListenerProofHeader) != "" {
		t.Fatalf("unprotected credential received rotation proof: status=%d proof=%q", got.Code, got.Header().Get(connector.UserScopedListenerProofHeader))
	}
	if got := call(0, keyID); got.Code != http.StatusNoContent || got.Header().Get(connector.UserScopedListenerProofHeader) != want {
		t.Fatalf("root rotation proof: status=%d proof=%q, want %q", got.Code, got.Header().Get(connector.UserScopedListenerProofHeader), want)
	}
	if got := call(0, keyID); got.Code != http.StatusNoContent || got.Header().Get(connector.UserScopedListenerProofHeader) != want {
		t.Fatalf("second root rotation proof was blocked by a hook-call budget: status=%d proof=%q", got.Code, got.Header().Get(connector.UserScopedListenerProofHeader))
	}
}
