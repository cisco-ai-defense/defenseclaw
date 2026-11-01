// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package connector

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// The behaviour golden's gateway drops requests without the case's bearer
// (rel-1-0-6:GAP-0453). Other programs' requests stay dropped; a refused
// request of the case's own hook, which names the case's folder, fails the
// case even when it is sent beside the expected call.
func TestShellHookGoldenGatewayFailsTheCaseOnItsOwnRefusedRequest(t *testing.T) {
	root := filepath.Join(t.TempDir(), "1")
	g := &hookGoldenGateway{
		bearer: "Bearer " + hookGoldenHookToken,
		answer: func(int, string) (int, string) { return http.StatusOK, `{"action":"allow"}` },
	}
	srv := httptest.NewServer(g)
	defer srv.Close()
	send := func(method, auth, body string) int {
		t.Helper()
		req, err := http.NewRequest(method, srv.URL+"/api/v1/hook", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	own := `{"cwd":"` + root + `/work"}`
	if got := send(http.MethodPost, "Bearer "+hookGoldenHookToken, own); got != http.StatusOK {
		t.Fatalf("the case's hook got %d, want 200", got)
	}
	// Other programs: another test's hook (case 12's folder starts with
	// case 1's), one without a bearer, a health probe.
	for _, r := range []struct{ method, auth, body string }{
		{http.MethodPost, "Bearer tok-test", `{"cwd":"` + root + `2/work"}`},
		{http.MethodPost, "", `{"cwd":"/tmp/other/work"}`},
		{http.MethodGet, "", ""},
	} {
		if got := send(r.method, r.auth, r.body); got != http.StatusMisdirectedRequest {
			t.Fatalf("a foreign %s got %d, want 421", r.method, got)
		}
	}
	if err := hookGoldenOwnRejected(g.rejected, root); err != nil {
		t.Fatalf("foreign requests failed the case: %v", err)
	}
	// The case's own hook with the wrong bearer, beside its expected call.
	if got := send(http.MethodPost, "Bearer golden-gateway-token", own); got != http.StatusMisdirectedRequest {
		t.Fatalf("the case's mis-tokened call got %d, want 421", got)
	}
	if len(g.requests) != 1 || len(g.rejected) != 4 {
		t.Fatalf("recorded %d and refused %d requests, want 1 and 4", len(g.requests), len(g.rejected))
	}
	if err := hookGoldenOwnRejected(g.rejected, root); err == nil {
		t.Fatal("the case's own refused request did not fail the case")
	}
}
