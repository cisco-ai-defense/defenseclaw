// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
	"github.com/defenseclaw/defenseclaw/internal/substrate/relay"
)

// egressToActorListener stands in for Substrate egress: it swaps the relay's
// x-defenseclaw-actor placeholder for the actor JWT and hands the request to
// the gateway's real actor listener.
type egressToActorListener struct {
	h        http.Handler
	actorJWT string
}

func (e egressToActorListener) RoundTrip(r *http.Request) (*http.Response, error) {
	req := r.Clone(r.Context())
	if req.Header.Get(kit.PlaceholderHeader) != kit.PlaceholderValue {
		return nil, http.ErrNotSupported
	}
	req.Header.Set(substrateActorHeader, "Bearer "+e.actorJWT)
	req.RemoteAddr = "10.0.0.7:43210"
	req.RequestURI = ""
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec.Result(), nil
}

// GAP-0815: a gateway-made port:N token keeps its dc.scope through the real
// verify route and the relay's GatewayVerifier (the verifier of every
// relay-TLS kit), so the relay's scope check serves it only on its own
// stream and refuses the terminal, task, exec and file routes.
func TestGAP0815GatewayScopedTokenThroughRelay(t *testing.T) {
	f := newSubstrateFixture(t)
	gv := &relay.GatewayVerifier{URL: "http://gateway.invalid" + substrateRelayVerify,
		Client: &http.Client{Transport: egressToActorListener{h: f.actor, actorJWT: "tok-alice"}}}
	issue := func(scope string) string {
		t.Helper()
		tok, _, err := f.sessions.Issue(identity.SignInOf(alice), identity.SessionActor{Atespace: "eng-web", Name: "alice-1", UID: subUID1, Scope: scope}, 0)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	verify := func(tok string) relay.Session {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, "http://relay/dcrelay/1/status", nil)
		r.Header.Set("Authorization", "Bearer "+tok)
		s, err := gv.Verify(context.Background(), r)
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		return s
	}
	port := issue("port:3000")
	if s := verify(port); s.Scope != "port:3000" || s.Person != alice.ID() {
		t.Fatalf("the relay sees %+v for a port:3000 token, want scope port:3000", s)
	}
	// Each port is its own scope: a port:3000 token is never port:3001's.
	if s := verify(issue("port:3001")); s.Scope != "port:3001" {
		t.Fatalf("port:3001 token reads scope %q", s.Scope)
	}
	if s := verify(issue("mcp:files")); s.Scope != "mcp:files" {
		t.Fatalf("mcp:files token reads scope %q", s.Scope)
	}

	cfg := kit.DefaultConfig()
	cfg.Relay.Connector = "claudecode"
	cfg.Relay.Interactive = []string{"sh"}
	rs := relay.NewServer(relay.Options{Config: cfg, Verifier: gv,
		Warm:   func(context.Context, string) error { return nil },
		Report: func(context.Context, relay.TaskEnd) error { return nil },
		Tamper: func(context.Context, string, string) error { return nil },
	})
	h := rs.Handler()
	call := func(method, route, tok string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, relay.Path(route), strings.NewReader("{}"))
		r.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec
	}
	for _, rt := range []struct{ method, route string }{
		{http.MethodGet, relay.RouteWS}, {http.MethodPost, relay.RoutePoll},
		{http.MethodPost, relay.RouteTask}, {http.MethodGet, relay.RouteTask + "/x"},
		{http.MethodGet, relay.RouteStatus}, {http.MethodPost, relay.RouteExec},
		{http.MethodGet, relay.RouteFiles + "?path=x"}, {http.MethodPut, relay.RouteFiles + "?path=x"},
	} {
		rec := call(rt.method, rt.route, port)
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "not for this route") {
			t.Fatalf("%s %s with a port:3000 token: %d %q, want 403 not for this route", rt.method, rt.route, rec.Code, rec.Body.String())
		}
	}
	// The same chain still serves a terminal token on the terminal routes.
	if rec := call(http.MethodGet, relay.RouteStatus, issue("")); rec.Code != http.StatusOK {
		t.Fatalf("unscoped token on status: %d %q", rec.Code, rec.Body.String())
	}
}
