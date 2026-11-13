// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed/peerbroker"
)

// TestRoutePeerBrokerProbe: /status on a managed Windows gateway with
// route-only reports whether the guardian peer broker answers for the
// status connection itself (doctor row), and nothing elsewhere.
func TestRoutePeerBrokerProbe(t *testing.T) {
	prevWindows, prevSID := routeCallerWindows, routePeerSID
	t.Cleanup(func() { routeCallerWindows, routePeerSID = prevWindows, prevSID })
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
	routePeerSID = func(local, remote *net.TCPAddr) (string, error) {
		asked++
		if local.Port != 18970 || remote.Port != 51234 {
			t.Fatalf("probe asked about %v -> %v", remote, local)
		}
		if answer != nil {
			return "", answer
		}
		return "S-1-5-21-1-2-3-500", nil
	}
	routeCallerWindows = true
	if got := routePeerBrokerProbe(request(), cfg); got["state"] != "ok" {
		t.Fatalf("probe = %v; want ok", got)
	}
	answer = errors.Join(peerbroker.ErrUnavailable, errors.New("pipe absent"))
	if got := routePeerBrokerProbe(request(), cfg); got["state"] != "unavailable" {
		t.Fatalf("probe = %v; want unavailable", got)
	}
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
	acpLoopbackPeerSID = func(*http.Request) (string, error) {
		asked++
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
