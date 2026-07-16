// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/netguard"
)

type privateUpstreamRoundTripper struct {
	remote net.Addr
}

func (rt privateUpstreamRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if trace := httptrace.ContextClientTrace(req.Context()); trace != nil && trace.GotConn != nil {
		trace.GotConn(httptrace.GotConnInfo{Conn: privateUpstreamTestConn{remote: rt.remote}})
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("ok")),
		Request:    req,
	}, nil
}

type privateUpstreamTestConn struct {
	remote net.Addr
}

func (c privateUpstreamTestConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c privateUpstreamTestConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c privateUpstreamTestConn) Close() error                     { return nil }
func (c privateUpstreamTestConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c privateUpstreamTestConn) RemoteAddr() net.Addr             { return c.remote }
func (c privateUpstreamTestConn) SetDeadline(time.Time) error      { return nil }
func (c privateUpstreamTestConn) SetReadDeadline(time.Time) error  { return nil }
func (c privateUpstreamTestConn) SetWriteDeadline(time.Time) error { return nil }

func TestPrivateUpstreamAuditUsesConnectedPeerNotPreflightDNS(t *testing.T) {
	t.Setenv("DEFENSECLAW_ALLOW_PRIVATE_UPSTREAMS", "")
	allowedIP := net.ParseIP("10.50.2.100")
	netguard.SetAllowedPrivateIPs([]net.IP{allowedIP})
	t.Cleanup(func() { netguard.SetAllowedPrivateIPs(nil) })
	fixture := newSidecarV8BootstrapFixture(t, 8, "")
	proxy := &GuardrailProxy{}
	fixture.sidecar.setGuardrailProxy(proxy)
	bound, err := fixture.sidecar.BootstrapObservabilityRuntime(
		t.Context(), fixture.configPath, fixture.raw,
	)
	if err != nil || !bound {
		t.Fatalf("bootstrap bound=%t err=%v", bound, err)
	}

	originalClient := providerHTTPClient
	providerHTTPClient = &http.Client{Transport: privateUpstreamRoundTripper{
		remote: &net.TCPAddr{IP: allowedIP, Port: 443},
	}}
	t.Cleanup(func() { providerHTTPClient = originalClient })

	originalCounter := incEgressCounter
	var counterCalls int
	incEgressCounter = func(context.Context, string, string, string) { counterCalls++ }
	t.Cleanup(func() {
		incEgressCounter = originalCounter
	})

	incoming := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	if blocked := proxy.guardUpstreamTargetURL(
		httptest.NewRecorder(), incoming, "https://10.50.2.100/v1/chat/completions",
	); blocked {
		t.Fatal("allowlisted private upstream was blocked during preflight")
	}
	if counterCalls != 0 {
		t.Fatalf("preflight emitted %d audit events; want none before a connection", counterCalls)
	}

	req, err := http.NewRequestWithContext(
		context.Background(), http.MethodPost, "https://llm.internal/v1/chat/completions", nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := doProviderRequest(req, proxy.emitEgress)
	if err != nil {
		t.Fatalf("doProviderRequest: %v", err)
	}
	_ = resp.Body.Close()

	if counterCalls != 0 {
		t.Fatalf("authoritative v8 audit used legacy metric path %d times", counterCalls)
	}
	rows, err := fixture.store.ListEvents(10)
	if err != nil {
		t.Fatal(err)
	}
	var auditBody map[string]any
	for _, row := range rows {
		if row.Action == "egress" {
			auditBody = row.Structured
			break
		}
	}
	if auditBody == nil {
		t.Fatalf("authoritative v8 SQLite rows omitted private-upstream audit: %+v", rows)
	}
	if auditBody["defenseclaw.network.branch"] != "private-upstream" ||
		auditBody["defenseclaw.network.decision"] != "allow" ||
		auditBody["defenseclaw.network.target_ref"] != "llm.internal" ||
		auditBody["defenseclaw.network.resolved_ip"] != "10.50.2.100" {
		t.Fatalf("private-upstream canonical audit=%#v", auditBody)
	}
}

func TestPrivateUpstreamObserverNeverAuditsHardDeniedPeer(t *testing.T) {
	netguard.SetAllowedPrivateIPs([]net.IP{net.ParseIP("127.0.0.1")})
	t.Cleanup(func() { netguard.SetAllowedPrivateIPs(nil) })

	observer := &privateUpstreamPeerObserver{allowed: make(map[string]struct{})}
	observer.recordRemoteAddr(&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443})
	if peers := observer.allowedPrivatePeers(); len(peers) != 0 {
		t.Fatalf("hard-denied peer was audited as allowlisted: %v", peers)
	}
}

func TestProviderHTTPClientBlocksRedirects(t *testing.T) {
	if providerHTTPClient.CheckRedirect == nil {
		t.Fatal("providerHTTPClient must refuse redirects so validated upstreams cannot pivot after preflight")
	}

	req := httptest.NewRequest(http.MethodGet, "https://private-upstream.example/v1", nil)
	err := providerHTTPClient.CheckRedirect(req, []*http.Request{
		httptest.NewRequest(http.MethodGet, "https://public-provider.example/v1", nil),
	})
	if err != netguard.ErrRedirectBlocked {
		t.Fatalf("CheckRedirect error = %v, want %v", err, netguard.ErrRedirectBlocked)
	}
}
