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

const windowsOpenClawProofToken = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
const windowsOpenClawProofNonce = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

func windowsOpenClawProof(t *testing.T, url string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url+connector.UserScopedListenerProofPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-DefenseClaw-Connector", "openclaw")
	req.Header.Set(connector.UserScopedListenerKeyIDHeader, connector.UserScopedCredentialKeyID(windowsOpenClawProofToken))
	req.Header.Set(connector.UserScopedListenerNonceHeader, windowsOpenClawProofNonce)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp
}

// Native Windows OpenClaw (DESIGN-REVIEW-1 P1-2): the gateway answers the
// plugin listener proof only to a caller whose SID is the SID of the gateway
// account; another account, an unknown caller or a gateway account it cannot
// read gets no proof.
func TestWindowsOpenClawListenerProofAnswersOnlyTheGatewayAccount(t *testing.T) {
	srv := newLocalTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !writeGatewayTokenListenerProof(w, r, windowsOpenClawProofToken) {
			writeJSONRefusal(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		}
	}))
	prevSelf, prevCaller := gatewayProcessSID, userScopedProofCallerSID
	t.Cleanup(func() { gatewayProcessSID, userScopedProofCallerSID = prevSelf, prevCaller })
	gatewayProcessSID = func() (string, error) { return listenerProofTestAlice, nil }

	userScopedProofCallerSID = func(*http.Request) (string, error) { return listenerProofTestAlice, nil }
	resp := windowsOpenClawProof(t, srv.URL)
	want := gatewayTokenListenerProof(windowsOpenClawProofToken, windowsOpenClawProofNonce)
	if resp.StatusCode != http.StatusNoContent || resp.Header.Get(connector.UserScopedListenerProofHeader) != want {
		t.Fatalf("same account: status %d proof %q, want 204 with the HMAC", resp.StatusCode, resp.Header.Get(connector.UserScopedListenerProofHeader))
	}

	for name, setup := range map[string]func(){
		"another account": func() {
			userScopedProofCallerSID = func(*http.Request) (string, error) { return listenerProofTestBob, nil }
		},
		"unknown caller": func() {
			userScopedProofCallerSID = func(*http.Request) (string, error) { return "", errors.New("owner unavailable") }
		},
		"unreadable gateway account": func() {
			userScopedProofCallerSID = func(*http.Request) (string, error) { return listenerProofTestAlice, nil }
			gatewayProcessSID = func() (string, error) { return "", errors.New("token unavailable") }
		},
	} {
		setup()
		if resp := windowsOpenClawProof(t, srv.URL); resp.StatusCode != http.StatusUnauthorized ||
			resp.Header.Get(connector.UserScopedListenerProofHeader) != "" {
			t.Errorf("%s: status %d, want 401 with no proof", name, resp.StatusCode)
		}
		gatewayProcessSID = func() (string, error) { return listenerProofTestAlice, nil }
	}
}

// The real process SID is the token user of this test process: a normal
// account SID, never empty.
func TestWindowsGatewayProcessSIDIsTheTokenUser(t *testing.T) {
	sid, err := gatewayProcessSID()
	if err != nil {
		t.Skipf("test runs as a service account: %v", err)
	}
	if len(sid) < 4 || sid[:4] != "S-1-" {
		t.Fatalf("gatewayProcessSID = %q, want an S-1- SID", sid)
	}
}
