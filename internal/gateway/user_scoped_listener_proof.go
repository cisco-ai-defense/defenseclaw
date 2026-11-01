// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net/http"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
)

// userScopedListenerProofRefusedReason labels a listener proof the gateway
// did not answer.
const userScopedListenerProofRefusedReason = "user_scoped_listener_proof_refused"

// serveUserScopedListenerProof answers a standalone in-agent plugin that
// asks the loopback listener to prove it is the gateway before the plugin
// sends its per-user credential (connector.UserScopedListenerProof). The
// request names a credential only by its key ID, so it is served before
// bearer authentication: proving the listener is what lets the plugin send
// its bearer. The gateway verifies that the accepted TCP caller's SID on
// Windows, or UID on Unix, belongs to the credential's account. This prevents
// a second account from relaying a challenge to the real gateway on another
// port. The answer is an HMAC under
// the credential for a nonce the caller chose; it is never accepted as a
// credential anywhere. An unbound key ID or caller gets a 401 with the same
// JSON body and Content-Type as every other authentication refusal.
func (a *APIServer) serveUserScopedListenerProof(w http.ResponseWriter, r *http.Request) {
	refuse := func() {
		a.emitHTTPAuthFailure(r.Context(), r, connector.UserScopedListenerProofPath,
			gatewaylog.ErrCodeAuthInvalidToken, userScopedListenerProofRefusedReason)
		writeJSONRefusal(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
	}
	if r.Method != http.MethodGet || !connector.IsLoopback(r) {
		refuse()
		return
	}
	scope := strings.ToLower(strings.TrimSpace(r.Header.Get("X-DefenseClaw-Connector")))
	keyID := r.Header.Get(connector.UserScopedListenerKeyIDHeader)
	nonce := strings.TrimSpace(r.Header.Get(connector.UserScopedListenerNonceHeader))
	credential, identity, ok := a.userScopedCredentialStore().hookCredentialForKeyID(scope, keyID)
	if !ok || !userScopedProofCallerMatches(r, identity) {
		refuse()
		return
	}
	proof, err := connector.UserScopedListenerProof(credential, scope, nonce)
	if err != nil {
		refuse()
		return
	}
	w.Header().Set(connector.UserScopedListenerProofHeader, proof)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

// serveRotationListenerProof is reachable only on the managed hook socket.
// The socket's kernel credentials, checked here and in managedHookPeerAuth,
// restrict it to the root lifecycle process that already holds the machine
// key. It does not relax the TCP proof route's same-account caller binding.
func (a *APIServer) serveRotationListenerProof(w http.ResponseWriter, r *http.Request) {
	peer, ok := managedHookPeerFromContext(r.Context())
	if !ok || peer.UID != 0 {
		writeManagedHookRefusal(w, http.StatusForbidden, managedHookReasonGuardianOnly)
		return
	}
	if r.Method != http.MethodGet {
		writeJSONRefusal(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	scope := strings.ToLower(strings.TrimSpace(r.Header.Get("X-DefenseClaw-Connector")))
	keyID := r.Header.Get(connector.UserScopedListenerKeyIDHeader)
	nonce := strings.TrimSpace(r.Header.Get(connector.UserScopedListenerNonceHeader))
	credential, _, ok := a.userScopedCredentialStore().hookCredentialForKeyID(scope, keyID)
	if !ok {
		writeJSONRefusal(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	proof, err := connector.UserScopedListenerProof(credential, scope, nonce)
	if err != nil {
		writeJSONRefusal(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	w.Header().Set(connector.UserScopedListenerProofHeader, proof)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}
