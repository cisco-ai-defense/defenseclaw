// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"errors"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func withOSSRouteOnlyGate(t *testing.T) *connector.RouteOnlyGate {
	t.Helper()
	prev := ossRouteOnlyGate
	ossRouteOnlyGate = &connector.RouteOnlyGate{}
	t.Cleanup(func() { ossRouteOnlyGate = prev })
	return ossRouteOnlyGate
}

// rel-1-0-10:GAP-1133: an OSS gateway renders the real route-only config
// once it owns its API port and parks it again before it releases the port;
// the render is redone only on a change. Managed gateways never touch it.
func TestRouteOnlyPortOwnedRerendersOnChange(t *testing.T) {
	gate := withOSSRouteOnlyGate(t)
	cfg := &config.Config{DataDir: t.TempDir()}
	cfg.Routing.Enabled = true
	cfg.Routing.RouteOnly.Connectors = []string{"claudecode"}
	var renders int32
	a := &APIServer{scannerCfg: cfg, addr: "127.0.0.1:18970"}
	a.onRouteKeyRotated = func() { atomic.AddInt32(&renders, 1) }

	a.routeOnlyPortOwned(true)
	if !gate.Owned() || atomic.LoadInt32(&renders) != 1 {
		t.Fatalf("owning the port: owned=%v renders=%d", gate.Owned(), renders)
	}
	a.routeOnlyPortOwned(true)
	if atomic.LoadInt32(&renders) != 1 {
		t.Fatal("no change, no render")
	}
	a.routeOnlyPortOwned(false)
	if gate.Owned() || atomic.LoadInt32(&renders) != 2 {
		t.Fatalf("releasing the port: owned=%v renders=%d", gate.Owned(), renders)
	}

	managed := &config.Config{DataDir: t.TempDir(), DeploymentMode: "managed_enterprise"}
	managed.Enterprise.Profile = "standalone"
	managed.Routing = cfg.Routing
	a.scannerCfg = managed
	a.routeOnlyPortOwned(true)
	if gate.Owned() || atomic.LoadInt32(&renders) != 2 {
		t.Fatal("a managed gateway renders through the guardian, not the OSS gate")
	}
}

// Every OSS render the gateway writes goes through the gate (connector Setup
// options and the reload/rerender path); a restore stays nil.
func TestGatedRouteOnlyCarriesTheGate(t *testing.T) {
	gate := withOSSRouteOnlyGate(t)
	oss := &config.Config{DataDir: t.TempDir()}
	if gatedRouteOnly(oss, nil) != nil {
		t.Fatal("a restore stays nil")
	}
	route := &connector.RouteOnlySetup{BaseURL: "http://127.0.0.1:18970/r/claudecode", Token: "t"}
	got := gatedRouteOnly(oss, route)
	if got.Gate != gate || route.Gate != nil || got.BaseURL != route.BaseURL || got.Token != route.Token {
		t.Fatalf("gated = %+v (input %+v)", got, route)
	}
	// A gateway that never moves the gate must not park its route for good.
	managed := &config.Config{DataDir: t.TempDir(), DeploymentMode: "managed_enterprise"}
	if got := gatedRouteOnly(managed, route); got != route || got.Gate != nil {
		t.Fatalf("managed gated = %+v", got)
	}
}

// rel-1-0-10:GAP-1133: an OSS Windows gateway accepts the route credential
// only from a process of its own account. The credential is sent on the
// wire, so a process of another account that held the port while the
// gateway was down has it; a replay from that account is refused and never
// reaches the upstream, and a peer that cannot be read is refused too.
func TestOSSWindowsRouteOnlyRefusesACapturedCredentialFromAnotherAccount(t *testing.T) {
	f := newRouteOnlyFixture(t)
	f.srv.goos = "windows"
	owner := f.srv.tokens.owner
	peerSID, peerErr := owner, error(nil)
	prev := routeOSSPeerSID
	routeOSSPeerSID = func(*http.Request) (string, error) { return peerSID, peerErr }
	t.Cleanup(func() { routeOSSPeerSID = prev })

	if rec := f.post(t, "/r/claudecode/v1/messages", messagesBody("hello"), nil); rec.Code != http.StatusOK {
		t.Fatalf("this account = %d %s", rec.Code, rec.Body.String())
	}
	hits := atomic.LoadInt32(&f.origHits)
	peerSID = "S-1-5-21-9-9-9-1234"
	if rec := f.post(t, "/r/claudecode/v1/messages", messagesBody("hello"), nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("another account replaying the captured credential = %d", rec.Code)
	}
	peerSID, peerErr = "", errors.New("open the client process: access is denied")
	if rec := f.post(t, "/r/claudecode/v1/messages", messagesBody("hello"), nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("an unreadable peer = %d", rec.Code)
	}
	if atomic.LoadInt32(&f.origHits) != hits {
		t.Fatal("a refused route-only request reached the upstream")
	}
}
