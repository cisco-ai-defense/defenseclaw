// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"regexp"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// gatewayTokenListenerProofConnector is the in-agent plugin that proves a
// listener with a token in any format: the OpenClaw plugin, with its
// connector-scoped credential (GAP-0594, DESIGN-REVIEW-1 P1-2).
const gatewayTokenListenerProofConnector = "openclaw"

// gatewayTokenListenerProofDomain is the proof domain of
// connector.UserScopedListenerProof, shared by every plugin.
const gatewayTokenListenerProofDomain = "defenseclaw.listener-proof.v1"

var gatewayTokenListenerNonceRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// gatewayTokenListenerProof is connector.UserScopedListenerProof for the
// gateway token, which may be OpenClaw's own token in any format.
func gatewayTokenListenerProof(token, nonce string) string {
	mac := hmac.New(sha256.New, []byte(strings.TrimSpace(token)))
	_, _ = mac.Write([]byte(gatewayTokenListenerProofDomain + "\x00" + gatewayTokenListenerProofConnector + "\x00" + nonce))
	return hex.EncodeToString(mac.Sum(nil))
}

// isGatewayTokenListenerProofRequest reports a listener proof request of
// the OpenClaw plugin.
func isGatewayTokenListenerProofRequest(r *http.Request) bool {
	return r.URL.Path == connector.UserScopedListenerProofPath &&
		strings.EqualFold(strings.TrimSpace(r.Header.Get("X-DefenseClaw-Connector")), gatewayTokenListenerProofConnector)
}

// writeGatewayTokenListenerProof answers the OpenClaw plugin's
// GET /api/v1/hook-listener-proof on a per-user gateway, before bearer
// authentication: the plugin sends the gateway token and provider keys only
// to a listener that proves it holds that token. The request carries the
// token's SHA-256 (X-DefenseClaw-Listener-Key-Id) and a fresh nonce; the
// answer is 204 with the HMAC-SHA256 under the token over
// "defenseclaw.listener-proof.v1" NUL "openclaw" NUL nonce, the format of
// the Amp and OpenCode proofs (connector.UserScopedListenerProof), for a
// gateway token of any format. It is
// served only on loopback, to a caller of this gateway's own account (the
// kernel's connection table names it), so another account cannot relay a
// challenge to this gateway from a port it squats (on Windows the caller
// SID must be the SID of this gateway). tokens are the credentials this
// listener proves: the OpenClaw scoped plugin token and the gateway tokens. It reports whether it answered with a
// proof; on false the caller refuses the request.
func writeGatewayTokenListenerProof(w http.ResponseWriter, r *http.Request, tokens ...string) bool {
	if r.Method != http.MethodGet || !connector.IsLoopback(r) || !isGatewayTokenListenerProofRequest(r) ||
		!gatewayTokenProofCallerIsSelf(r) {
		return false
	}
	keyID := strings.ToLower(strings.TrimSpace(r.Header.Get(connector.UserScopedListenerKeyIDHeader)))
	nonce := strings.TrimSpace(r.Header.Get(connector.UserScopedListenerNonceHeader))
	if !gatewayTokenListenerNonceRE.MatchString(nonce) {
		return false
	}
	for _, token := range tokens {
		token = strings.TrimSpace(token)
		if token == "" || !constantTimeStringMatch(keyID, connector.UserScopedCredentialKeyID(token)) {
			continue
		}
		w.Header().Set(connector.UserScopedListenerProofHeader, gatewayTokenListenerProof(token, nonce))
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusNoContent)
		return true
	}
	return false
}

// writeOpenClawPluginAccountProof answers the listener proof in the
// separate-user layout, where the OpenClaw plugin runs as
// connectors.openclaw.plugin_account and not as this gateway account. It
// proves only the plugin credential (never the gateway token), and only to a
// caller of that account. It reports whether it answered.
func writeOpenClawPluginAccountProof(w http.ResponseWriter, r *http.Request, pluginToken, pluginAccount string) bool {
	pluginToken, pluginAccount = strings.TrimSpace(pluginToken), strings.TrimSpace(pluginAccount)
	if pluginToken == "" || pluginAccount == "" || r.Method != http.MethodGet || !connector.IsLoopback(r) ||
		!isGatewayTokenListenerProofRequest(r) || !gatewayTokenProofCallerIsAccount(r, pluginAccount) {
		return false
	}
	keyID := strings.ToLower(strings.TrimSpace(r.Header.Get(connector.UserScopedListenerKeyIDHeader)))
	nonce := strings.TrimSpace(r.Header.Get(connector.UserScopedListenerNonceHeader))
	if !gatewayTokenListenerNonceRE.MatchString(nonce) || !constantTimeStringMatch(keyID, connector.UserScopedCredentialKeyID(pluginToken)) {
		return false
	}
	w.Header().Set(connector.UserScopedListenerProofHeader, gatewayTokenListenerProof(pluginToken, nonce))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
	return true
}
