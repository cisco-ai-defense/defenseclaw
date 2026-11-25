// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package leader

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// GAP-0553: a gateway replica holds "*" on the leader, and "*" does not
// reach the controller's own method: a gateway's publish of the egress
// callout report is refused (403), the controller's is served, and the
// gateway keeps every other method.
func TestStarDoesNotGrantTheControllersCalloutPublishGAP0553(t *testing.T) {
	const (
		gw   = "spiffe://cluster.local/ns/dc/sa/defenseclaw-gateway"
		ctlr = "spiffe://cluster.local/ns/dc/sa/defenseclaw-controller"
	)
	s := &Server{IsLeader: func() bool { return true }, Permit: Permissions{
		gw:   {"*"},
		ctlr: {MethodCalloutPublish},
	}}
	var published int
	s.Handle(MethodCalloutPublish, Typed(func(context.Context, struct{}) (struct{}, error) { published++; return struct{}{}, nil }))
	s.Handle(MethodChainObserve, Typed(func(context.Context, struct{}) (struct{}, error) { return struct{}{}, nil }))
	s.HandleRead(MethodCalloutStatus, Typed(func(context.Context, struct{}) (struct{}, error) { return struct{}{}, nil }))
	n := 0
	call := func(peer, method string) int {
		n++
		req := httptest.NewRequest(http.MethodPost, PathPrefix+method, strings.NewReader(`{"request_id":"req-gap0553-`+string(rune('a'+n))+`","body":{}}`))
		u, _ := url.Parse(peer)
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{URIs: []*url.URL{u}}}}
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, req)
		return rec.Code
	}
	if c := call(gw, MethodCalloutPublish); c != http.StatusForbidden {
		t.Errorf("gateway CalloutPublish: %d, want 403", c)
	}
	if published != 0 {
		t.Fatalf("the gateway's report was kept (%d publishes)", published)
	}
	if c := call(ctlr, MethodCalloutPublish); c != http.StatusOK || published != 1 {
		t.Errorf("controller CalloutPublish: %d (%d publishes), want 200 and 1", c, published)
	}
	for _, m := range []string{MethodChainObserve, MethodCalloutStatus} {
		if c := call(gw, m); c != http.StatusOK {
			t.Errorf("gateway %s: %d, want 200", m, c)
		}
	}
}
