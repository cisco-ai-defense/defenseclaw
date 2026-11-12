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

//go:build !windows

package gateway

import (
	"net/http"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

const gatewayTokenProofTestToken = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
const gatewayTokenProofTestNonce = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

func gatewayTokenProofRequest(t *testing.T, url, connectorName, keyID string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url+connector.UserScopedListenerProofPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-DefenseClaw-Connector", connectorName)
	req.Header.Set(connector.UserScopedListenerKeyIDHeader, keyID)
	req.Header.Set(connector.UserScopedListenerNonceHeader, gatewayTokenProofTestNonce)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp
}

// GAP-0594: the per-user gateway proves itself to the OpenClaw plugin with
// the gateway token, to a caller of its own account only.
func TestGatewayTokenListenerProof(t *testing.T) {
	srv := newLocalTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !writeGatewayTokenListenerProof(w, r, "", gatewayTokenProofTestToken) {
			writeJSONRefusal(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		}
	}))
	keyID := connector.UserScopedCredentialKeyID(gatewayTokenProofTestToken)

	resp := gatewayTokenProofRequest(t, srv.URL, "openclaw", keyID)
	// The format of the Amp and OpenCode proofs.
	want, err := connector.UserScopedListenerProof(gatewayTokenProofTestToken, "openclaw", gatewayTokenProofTestNonce)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusNoContent || resp.Header.Get(connector.UserScopedListenerProofHeader) != want {
		t.Fatalf("own account: status %d proof %q, want 204 with the token HMAC", resp.StatusCode, resp.Header.Get(connector.UserScopedListenerProofHeader))
	}
	if strings.Contains(resp.Header.Get(connector.UserScopedListenerProofHeader), gatewayTokenProofTestToken) {
		t.Fatal("the proof carries the token")
	}

	for name, tc := range map[string]struct{ connector, keyID string }{
		"another key":       {"openclaw", connector.UserScopedCredentialKeyID(strings.Repeat("1", 64))},
		"another connector": {"opencode", keyID},
		"no key":            {"openclaw", ""},
	} {
		if resp := gatewayTokenProofRequest(t, srv.URL, tc.connector, tc.keyID); resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s: status %d, want 401", name, resp.StatusCode)
		}
	}

	// OpenClaw's own gateway token, which DefenseClaw may adopt, need not be
	// 64 hex characters.
	short := "oc-token-not-hex"
	shortSrv := newLocalTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !writeGatewayTokenListenerProof(w, r, short) {
			writeJSONRefusal(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		}
	}))
	if resp := gatewayTokenProofRequest(t, shortSrv.URL, "openclaw", connector.UserScopedCredentialKeyID(short)); resp.StatusCode != http.StatusNoContent ||
		resp.Header.Get(connector.UserScopedListenerProofHeader) != gatewayTokenListenerProof(short, gatewayTokenProofTestNonce) {
		t.Fatalf("non-hex token: status %d, want 204 with its HMAC", resp.StatusCode)
	}

	previous := userScopedProofCallerIdentity
	userScopedProofCallerIdentity = func(*http.Request) (string, error) { return "4242", nil }
	t.Cleanup(func() { userScopedProofCallerIdentity = previous })
	if resp := gatewayTokenProofRequest(t, srv.URL, "openclaw", keyID); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("another account: status %d, want 401", resp.StatusCode)
	}
}
