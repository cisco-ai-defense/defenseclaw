// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

func TestSecureClientKeepsQualifiedHookNames(t *testing.T) {
	setIdentityFactsEnabled(false)
	useridentity.KeepQualifiedNames(true)
	t.Cleanup(func() { setIdentityFactsEnabled(false); useridentity.KeepQualifiedNames(false) })

	for _, name := range []string{"CORP\\alice", "alice@realm"} {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/claude-code/hook", nil)
		req.RemoteAddr = "127.0.0.1:4444"
		req.Header.Set(llmEventUserIDHeader, "501")
		req.Header.Set(llmEventUserNameHeader, name)
		CorrelationMiddleware(NewAgentRegistry("", ""))(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			if got := AgentIdentityFromContext(r.Context()).UserName; got != name {
				t.Errorf("correlated name = %q, want %q", got, name)
			}
			if got := resolveHookUser(r.Context(), nil).Name; got != name {
				t.Errorf("hook name = %q, want %q", got, name)
			}
			if got := resolveHTTPUser(r, nil).Name; got != name {
				t.Errorf("HTTP name = %q, want %q", got, name)
			}
		})).ServeHTTP(httptest.NewRecorder(), req)
	}
}
