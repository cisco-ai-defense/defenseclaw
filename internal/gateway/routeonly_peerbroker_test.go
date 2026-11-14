// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed/peerbroker"
)

// TestRoutePeerBrokerProbe: /status on a managed Windows gateway with
// route-only reports whether the guardian peer broker answers for the
// status connection itself (doctor row), and nothing elsewhere.
func TestRoutePeerBrokerProbe(t *testing.T) {
	prevWindows, prevSID := routeCallerWindows, routePeerSID
	t.Cleanup(func() { routeCallerWindows, routePeerSID = prevWindows, prevSID; routePeerBrokerStatus.answer = nil })
	fresh := func() { routePeerBrokerStatus.answer = nil }
	cfg := &config.Config{DataDir: t.TempDir()}
	cfg.DeploymentMode, cfg.Enterprise.Profile = "managed_enterprise", "standalone"
	cfg.Routing.Enabled = true
	cfg.Routing.RouteOnly = config.RoutingRouteOnlyConfig{Connectors: []string{"codex"}}
	request := func() *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/status", nil)
		r.RemoteAddr = "127.0.0.1:51234"
		return r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 18970}))
	}
	var asked int
	answer := error(nil)
	routePeerSID = func(_ context.Context, ask routePeerAsk, local, remote *net.TCPAddr) (string, error) {
		asked++
		if local.Port != 18970 || remote.Port != 51234 || ask.DataDir != cfg.DataDir || ask.Identity != "" {
			t.Fatalf("probe asked about %v -> %v (%+v)", remote, local, ask)
		}
		if answer != nil {
			return "", answer
		}
		return "S-1-5-21-1-2-3-500", nil
	}
	routeCallerWindows = true
	fresh()
	if got := routePeerBrokerProbe(request(), cfg); got["state"] != "ok" {
		t.Fatalf("probe = %v; want ok", got)
	}
	// P4-6: /status is polled; the answer is reused for a few seconds.
	if got := routePeerBrokerProbe(request(), cfg); got["state"] != "ok" || asked != 1 {
		t.Fatalf("probe = %v after %d broker calls; want the kept ok", got, asked)
	}
	fresh()
	answer = errors.Join(peerbroker.ErrUnavailable, errors.New(`pipe absent C:\\ProgramData pid 4242`))
	got := routePeerBrokerProbe(request(), cfg)
	if detail, _ := got["detail"].(string); got["state"] != "unavailable" || strings.Contains(detail, "pipe absent") || strings.Contains(detail, "4242") || detail == "" {
		t.Fatalf("probe = %v; want unavailable with the category text only", got)
	}
	fresh()
	answer = &peerbroker.UnavailableError{Reason: peerbroker.UnavailableHeld, HolderPID: 77}
	if got := routePeerBrokerProbe(request(), cfg); got["state"] != "unavailable" || !strings.Contains(got["detail"].(string), "process 77") {
		t.Fatalf("probe = %v; want the pipe holder named", got)
	}
	fresh()
	answer = peerbroker.ErrRefused
	if got := routePeerBrokerProbe(request(), cfg); got["state"] != "refused" {
		t.Fatalf("probe = %v; want refused", got)
	}
	asked = 0
	for name, mut := range map[string]func(*config.Config){
		"not Windows":   func(*config.Config) { routeCallerWindows = false },
		"OSS":           func(c *config.Config) { c.DeploymentMode, c.Enterprise.Profile = "", "" },
		"routing off":   func(c *config.Config) { c.Routing.Enabled = false },
		"no route-only": func(c *config.Config) { c.Routing.RouteOnly = config.RoutingRouteOnlyConfig{} },
	} {
		routeCallerWindows = true
		fresh()
		c := *cfg
		mut(&c)
		if got := routePeerBrokerProbe(request(), &c); got != nil {
			t.Fatalf("%s: probe = %v; want none", name, got)
		}
	}
	if asked != 0 {
		t.Fatalf("the broker was asked %d times where no probe applies", asked)
	}
}

// TestManagedWindowsRouteCallerRefusedWhileBrokerDown: with no broker the
// managed Windows route-only caller is unverified with its own reason.
func TestManagedWindowsRouteCallerRefusedWhileBrokerDown(t *testing.T) {
	in := routeCallerInputs{Managed: true, Windows: true, Connector: "claudecode", RequireCredential: true, CredentialIdentity: "S-1-5-21-1-2-3-1001", PeerSIDErr: peerbroker.ErrUnavailable}
	got := decideRouteCaller(in)
	if got.Verified || got.Reason != routeCallerPeerBrokerUnavailable {
		t.Fatalf("decide = %+v; want unverified %s", got, routeCallerPeerBrokerUnavailable)
	}
	if text := routeCallerRefusalText(got.Reason); text == "" {
		t.Fatal("no refusal text")
	}
}

// TestManagedWindowsRouteCallerAsksTheBrokerOnlyWithAValidCredential: a
// route-only request without a valid route credential is refused before
// the guardian peer broker is asked, so unauthenticated local callers put
// no load on it; the guardrail proxy (no credential required) asks.
func TestManagedWindowsRouteCallerAsksTheBrokerOnlyWithAValidCredential(t *testing.T) {
	prevWindows, prevPeer := routeCallerWindows, acpLoopbackPeerSID
	t.Cleanup(func() { routeCallerWindows, acpLoopbackPeerSID = prevWindows, prevPeer })
	ledger := &userScopedTestLedger{}
	ledger.set(managedHookLedgerTarget{User: "alice", SID: "S-1-5-21-100-200-300-1001", Connector: "codex", OK: true})
	api, _, _ := newUserScopedTestServer(t, true, ledger, nil)
	routeCallerWindows = true
	asked := 0
	acpLoopbackPeerSID = func(_ *http.Request, ask routePeerAsk) (string, error) {
		asked++
		if ask.Identity != "" {
			t.Fatalf("the proxy lookup carried identity %q", ask.Identity)
		}
		return "", peerbroker.ErrUnavailable
	}
	r := httptest.NewRequest(http.MethodPost, "/r/codex/responses", nil)
	if got := api.verifiedRouteCaller(r, "codex", true, "not-a-route-credential"); got.Verified || got.Reason != routeCallerCredentialInvalid {
		t.Fatalf("caller = %+v; want %s", got, routeCallerCredentialInvalid)
	}
	if asked != 0 {
		t.Fatalf("the broker was asked %d times for a request without a valid credential", asked)
	}
	if got := api.verifiedRouteCaller(r, "codex", false, ""); got.Verified || got.Reason != routeCallerPeerBrokerUnavailable || asked != 1 {
		t.Fatalf("proxy caller = %+v after %d broker calls; want one call and %s", got, asked, routeCallerPeerBrokerUnavailable)
	}
}

// TestRoutePeerLookupLimiterBoundsOneIdentity: one identity gets at most
// routePeerLookupInFlight lookups at once and routePeerLookupBurst in a
// burst; another identity is not affected (REVIEW-code-winroute P3-2).
func TestRoutePeerLookupLimiterBoundsOneIdentity(t *testing.T) {
	l := &routePeerLimiter{}
	short := func() context.Context {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		t.Cleanup(cancel)
		return ctx
	}
	var releases []func()
	for i := 0; i < routePeerLookupInFlight; i++ {
		release, err := l.acquire(context.Background(), "S-1-5-21-1-2-3-1001")
		if err != nil {
			t.Fatalf("lookup %d refused: %v", i, err)
		}
		releases = append(releases, release)
	}
	if _, err := l.acquire(short(), "S-1-5-21-1-2-3-1001"); !errors.Is(err, errRoutePeerLookupLimited) {
		t.Fatalf("lookup over the in-flight cap = %v; want limited", err)
	}
	other, err := l.acquire(short(), "S-1-5-21-1-2-3-1002")
	if err != nil {
		t.Fatalf("another account was limited: %v", err)
	}
	other()
	for _, release := range releases {
		release()
	}
	// The burst: 40 lookups in a row pass (one agent opening many
	// connections), the next waits for the rate and a short wait fails.
	for i := routePeerLookupInFlight + 1; i < routePeerLookupBurst; i++ {
		release, err := l.acquire(context.Background(), "S-1-5-21-1-2-3-1001")
		if err != nil {
			t.Fatalf("burst lookup %d refused: %v", i, err)
		}
		release()
	}
	// The bucket refills at routePeerLookupRate a second, so a slow run may
	// pass a few more; lookups in a row without a wait are refused soon.
	limited := false
	for i := 0; i < 100 && !limited; i++ {
		release, err := l.acquire(short(), "S-1-5-21-1-2-3-1001")
		if errors.Is(err, errRoutePeerLookupLimited) {
			limited = true
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		release()
	}
	if !limited {
		t.Fatal("lookups over the burst were never limited")
	}
	release, err := l.acquire(context.Background(), "S-1-5-21-1-2-3-1001")
	if err != nil {
		t.Fatalf("a lookup within the wait was refused: %v", err)
	}
	release()
}

// TestManagedWindowsRouteCallerLimitedIsItsOwnReason: a lookup over the
// account bound is unverified with its own reason (429 on /r/), not a
// broker outage.
func TestManagedWindowsRouteCallerLimitedIsItsOwnReason(t *testing.T) {
	in := routeCallerInputs{Managed: true, Windows: true, Connector: "codex", RequireCredential: true, CredentialIdentity: "S-1-5-21-1-2-3-1001", PeerSIDErr: errRoutePeerLookupLimited}
	if got := decideRouteCaller(in); got.Verified || got.Reason != routeCallerPeerLookupLimited {
		t.Fatalf("decide = %+v; want %s", got, routeCallerPeerLookupLimited)
	}
	if text := routeCallerRefusalText(routeCallerPeerLookupLimited); !strings.Contains(text, "retry") {
		t.Fatalf("refusal text %q", text)
	}
}
