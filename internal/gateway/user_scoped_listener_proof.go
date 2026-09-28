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
// its bearer. The answer is an HMAC under a credential the caller already
// identified by its SHA-256, for a nonce the caller chose; it is never
// accepted as a credential anywhere. A key ID that does not name a
// protected user's hook credential for the named connector gets the same
// 401 as any other authentication failure.
func (a *APIServer) serveUserScopedListenerProof(w http.ResponseWriter, r *http.Request) {
	refuse := func() {
		a.emitHTTPAuthFailure(r.Context(), r, connector.UserScopedListenerProofPath,
			gatewaylog.ErrCodeAuthInvalidToken, userScopedListenerProofRefusedReason)
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
	}
	if r.Method != http.MethodGet || !connector.IsLoopback(r) {
		refuse()
		return
	}
	scope := strings.ToLower(strings.TrimSpace(r.Header.Get("X-DefenseClaw-Connector")))
	keyID := r.Header.Get(connector.UserScopedListenerKeyIDHeader)
	nonce := strings.TrimSpace(r.Header.Get(connector.UserScopedListenerNonceHeader))
	credential, ok := a.userScopedCredentialStore().hookCredentialForKeyID(scope, keyID)
	if !ok {
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
