// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package relay

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// B3 dc.scope: a stream token (port:N, mcp:NAME) never opens the terminal,
// task or file routes, and the relay reads the scope from the token.
func TestScopedTokenOpensNoTerminalRoute(t *testing.T) {
	s, _, ec := testServer(t, []string{"sh"})
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	scoped := ec.token(t, claims(time.Now(), func(c map[string]any) { c["dc.scope"] = "port:3000" }), TokenType)
	for _, route := range []string{"status", "files?path=x", "task/x"} {
		req, _ := http.NewRequest("GET", srv.URL+"/dcrelay/1/"+route, nil)
		req.Header.Set("Authorization", "Bearer "+scoped)
		resp, err := http.DefaultClient.Do(req)
		if err != nil || resp.StatusCode != http.StatusForbidden {
			t.Fatalf("%s with a port token: %v %v, want 403", route, resp, err)
		}
	}
	sess, err := s.opts.Verifier.(*KeyVerifier).VerifyToken(scoped)
	if err != nil || sess.Scope != "port:3000" {
		t.Fatalf("scope not read: %+v %v", sess, err)
	}
	req, _ := http.NewRequest("GET", srv.URL+"/dcrelay/1/status", nil)
	req.Header.Set("Authorization", "Bearer "+ec.token(t, claims(time.Now(), nil), TokenType))
	if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("unscoped status: %v %v", resp, err)
	}
}
