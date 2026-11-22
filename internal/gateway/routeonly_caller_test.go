// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed/peerbroker"
)

func routeCallerTestAuthz(enrollment config.EnterpriseEnrollmentConfig, ledger *managedHookLedger, ledgerErr error) *managedHookAuthorizer {
	return newManagedHookAuthorizer(enrollment, nil, func() (managedHookLedger, error) {
		if ledgerErr != nil {
			return managedHookLedger{}, ledgerErr
		}
		return *ledger, nil
	})
}

func TestVerifiedRouteCallerUnixRules(t *testing.T) {
	ledger := &managedHookLedger{Targets: []managedHookLedgerTarget{
		{User: "alice", UID: userScopedTestUID(1001), Connector: "claudecode", OK: true},
		{User: "carol", UID: userScopedTestUID(1003), Connector: "codex", OK: true},
	}}
	base := func() routeCallerInputs {
		return routeCallerInputs{
			Managed: true, Connector: "claudecode", RequireCredential: true, CredentialIdentity: "1001",
			Authz:   routeCallerTestAuthz(config.EnterpriseEnrollmentConfig{}, ledger, nil),
			PeerUID: 1001,
			Peer: func(uid int) managedHookPeer {
				return managedHookPeer{UID: uid, Name: map[int]string{1001: "alice", 1002: "bob", 1003: "carol"}[uid]}
			},
		}
	}
	cases := []struct {
		name   string
		mut    func(*routeCallerInputs)
		want   bool
		reason string
	}{
		{"enrolled caller with its own credential", nil, true, ""},
		{"no authorizer: every caller unverified", func(in *routeCallerInputs) { in.Authz = nil }, false, routeCallerAuthorizerUnavailable},
		{"kernel peer unknown", func(in *routeCallerInputs) { in.PeerUIDErr = errors.New("gone") }, false, routeCallerPeerUnverified},
		{"root even when enrollment.root allows it", func(in *routeCallerInputs) { in.PeerUID = 0; in.CredentialIdentity = "0" }, false, routeCallerRoot},
		{"exempt user", func(in *routeCallerInputs) {
			in.Authz = routeCallerTestAuthz(config.EnterpriseEnrollmentConfig{ExemptUsers: []string{"1001"}}, ledger, nil)
		}, false, routeCallerExempt},
		{"connector disabled", func(in *routeCallerInputs) { in.Disabled = true }, false, routeCallerConnectorDisabled},
		{"not enrolled for this connector", func(in *routeCallerInputs) { in.PeerUID = 1003; in.CredentialIdentity = "1003" }, false, managedHookReasonUIDUnregistered},
		{"machine policy admits but the ledger does not enroll", func(in *routeCallerInputs) {
			in.Authz.setMachinePolicy([]string{"claudecode"})
			in.PeerUID, in.CredentialIdentity = 1002, "1002"
		}, false, routeCallerNotEnrolled},
		{"ledger unreadable", func(in *routeCallerInputs) {
			in.Authz = routeCallerTestAuthz(config.EnterpriseEnrollmentConfig{}, ledger, errors.New("busy"))
		}, false, managedHookReasonLedgerUnavailable},
		{"no route credential", func(in *routeCallerInputs) { in.CredentialIdentity = "" }, false, routeCallerCredentialInvalid},
		{"another user route credential", func(in *routeCallerInputs) { in.CredentialIdentity = "1003" }, false, routeCallerCredentialMismatch},
		{"guardrail proxy asks without a credential", func(in *routeCallerInputs) { in.RequireCredential, in.CredentialIdentity = false, "" }, true, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := base()
			if tc.mut != nil {
				tc.mut(&in)
			}
			got := decideRouteCaller(in)
			if got.Verified != tc.want || (!tc.want && got.Reason != tc.reason) || (tc.want && got.Subject != "1001") {
				t.Fatalf("decideRouteCaller = %+v, want verified=%v reason=%q", got, tc.want, tc.reason)
			}
		})
	}
}

func TestVerifiedRouteCallerWindowsRules(t *testing.T) {
	const alice, bob = "S-1-5-21-100-200-300-1001", "S-1-5-21-100-200-300-1002"
	base := func() routeCallerInputs {
		return routeCallerInputs{
			Managed: true, Windows: true, Connector: "codex", RequireCredential: true,
			CredentialIdentity: alice, PeerSID: alice,
			Enrolled: func(id string) bool { return id == alice },
			Exempt:   func(string) bool { return false },
		}
	}
	cases := []struct {
		name   string
		mut    func(*routeCallerInputs)
		want   bool
		reason string
	}{
		{"kernel SID equals the credential SID", nil, true, ""},
		{"SID case does not matter", func(in *routeCallerInputs) { in.PeerSID = "s-1-5-21-100-200-300-1001" }, true, ""},
		{"no route credential", func(in *routeCallerInputs) { in.CredentialIdentity = "" }, false, routeCallerCredentialInvalid},
		{"peer SID unreadable (no fallback to the credential)", func(in *routeCallerInputs) { in.PeerSID, in.PeerSIDErr = "", errors.New("access denied") }, false, routeCallerPeerUnverified},
		{"guardian peer broker unavailable (no in-process fallback)", func(in *routeCallerInputs) { in.PeerSID, in.PeerSIDErr = "", peerbroker.ErrUnavailable }, false, routeCallerPeerBrokerUnavailable},
		{"guardian peer broker refused", func(in *routeCallerInputs) { in.PeerSID, in.PeerSIDErr = "", peerbroker.ErrRefused }, false, routeCallerPeerUnverified},
		{"replayed credential from another account", func(in *routeCallerInputs) { in.PeerSID = bob }, false, routeCallerPeerMismatch},
		{"SYSTEM", func(in *routeCallerInputs) { in.PeerSID = "S-1-5-18" }, false, routeCallerServiceAccount},
		{"NetworkService", func(in *routeCallerInputs) { in.PeerSID = "S-1-5-20" }, false, routeCallerServiceAccount},
		{"service SID", func(in *routeCallerInputs) { in.PeerSID = "S-1-5-80-1-2-3-4-5" }, false, routeCallerServiceAccount},
		{"not a SID", func(in *routeCallerInputs) { in.PeerSID = "1001" }, false, routeCallerPeerUnverified},
		{"exempt user", func(in *routeCallerInputs) { in.Exempt = func(string) bool { return true } }, false, routeCallerExempt},
		{"connector disabled", func(in *routeCallerInputs) { in.Disabled = true }, false, routeCallerConnectorDisabled},
		{"proxy: enrolled SID", func(in *routeCallerInputs) { in.RequireCredential, in.CredentialIdentity = false, "" }, true, ""},
		{"proxy: unenrolled SID", func(in *routeCallerInputs) { in.RequireCredential, in.CredentialIdentity, in.PeerSID = false, "", bob }, false, routeCallerNotEnrolled},
		{"gMSA or computer account SID", func(in *routeCallerInputs) {
			in.PersonAccount = func(string) (bool, bool) { return false, true }
		}, false, routeCallerServiceAccount},
		{"account type unknown (lookup failed)", func(in *routeCallerInputs) {
			in.PersonAccount = func(string) (bool, bool) { return false, false }
		}, true, ""},
		{"user account", func(in *routeCallerInputs) {
			in.PersonAccount = func(string) (bool, bool) { return true, true }
		}, true, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := base()
			if tc.mut != nil {
				tc.mut(&in)
			}
			got := decideRouteCaller(in)
			if got.Verified != tc.want || (!tc.want && got.Reason != tc.reason) || (tc.want && got.Subject != alice) {
				t.Fatalf("decideRouteCaller = %+v, want verified=%v reason=%q", got, tc.want, tc.reason)
			}
		})
	}
}

func TestVerifiedRouteCallerOSSRules(t *testing.T) {
	cases := []struct {
		name string
		in   routeCallerInputs
		want bool
	}{
		{"owner with the route token", routeCallerInputs{CredentialIdentity: "501", PeerUID: 501, OwnerUID: 501}, true},
		{"no route token", routeCallerInputs{PeerUID: 501, OwnerUID: 501}, false},
		{"another account with the copied token", routeCallerInputs{CredentialIdentity: "501", PeerUID: 502, OwnerUID: 501}, false},
		{"peer unknown", routeCallerInputs{CredentialIdentity: "501", PeerUIDErr: errors.New("x"), OwnerUID: 501}, false},
		// rel-1-0-10:GAP-1133: the credential travels on the wire, so a
		// process of another account that held the port has it; the token
		// alone no longer proves the caller on Windows.
		{"Windows: owner with the route token", routeCallerInputs{Windows: true, CredentialIdentity: "S-1-5-21-1-2-3-500", PeerSID: "S-1-5-21-1-2-3-500"}, true},
		{"Windows: SID compares without case", routeCallerInputs{Windows: true, CredentialIdentity: "S-1-5-21-1-2-3-500", PeerSID: "s-1-5-21-1-2-3-500"}, true},
		{"Windows: the token alone", routeCallerInputs{Windows: true, CredentialIdentity: "S-1-5-21-1-2-3-500"}, false},
		{"Windows: another account with the captured token", routeCallerInputs{Windows: true, CredentialIdentity: "S-1-5-21-1-2-3-500", PeerSID: "S-1-5-21-1-2-3-501"}, false},
		{"Windows: peer unknown", routeCallerInputs{Windows: true, CredentialIdentity: "S-1-5-21-1-2-3-500", PeerSIDErr: errors.New("x")}, false},
	}
	for _, tc := range cases {
		if got := decideRouteCaller(tc.in); got.Verified != tc.want {
			t.Fatalf("%s: %+v", tc.name, got)
		}
	}
}

// Managed route-only end to end on Linux rules: the kernel uid, the
// authorizer, the ledger and the per-user route credential decide; the
// agent credential passes through (socket-activated port); macOS forwards
// no agent credential.
func TestManagedRouteOnlyVerifiedCaller(t *testing.T) {
	f := newRouteOnlyFixture(t)
	ledger := &userScopedTestLedger{}
	ledger.set(managedHookLedgerTarget{User: "alice", UID: userScopedTestUID(1001), Connector: "claudecode", OK: true})
	api, _, _ := newUserScopedTestServer(t, true, ledger, map[string]string{"1001": "alice", "1002": "bob"})
	api.managedHookAuthz.Store(routeCallerTestAuthz(config.EnterpriseEnrollmentConfig{}, &ledger.ledger, nil))
	f.cfg.DeploymentMode, f.cfg.Enterprise.Profile = "managed_enterprise", "standalone"
	api.SetRouteOnly(f.srv)
	f.srv.goos = "linux"
	prevWin, prevPeer, prevUID := routeCallerWindows, routeCallerPeer, acpLoopbackPeerUID
	routeCallerWindows = false
	routeCallerPeer = func(uid int) managedHookPeer {
		return managedHookPeer{UID: uid, Name: map[int]string{1001: "alice", 1002: "bob"}[uid]}
	}
	peerUID := 1001
	acpLoopbackPeerUID = func(*http.Request) (int, error) { return peerUID, nil }
	t.Cleanup(func() { routeCallerWindows, routeCallerPeer, acpLoopbackPeerUID = prevWin, prevPeer, prevUID })
	alice, _ := connector.UserScopedRouteToken(userScopedTestKey, "claudecode", "1001")
	f.token = alice

	if rec := f.post(t, "/r/claudecode/v1/messages", messagesBody("hello"), nil); rec.Code != 200 || f.origHdr.Get("X-Api-Key") != "sk-ant-agent" {
		t.Fatalf("enrolled caller = %d %s", rec.Code, rec.Body.String())
	}
	hits := atomic.LoadInt32(&f.origHits)
	for name, mut := range map[string]func(*http.Request){
		"OSS route token is not a managed credential": func(r *http.Request) {
			tok, _ := f.srv.tokens.Token("claudecode")
			r.Header.Set(routeTokenHeader, tok)
		},
		"no credential": func(r *http.Request) { r.Header.Del(routeTokenHeader) },
	} {
		if rec := f.post(t, "/r/claudecode/v1/messages", messagesBody("hello"), mut); rec.Code != 401 {
			t.Fatalf("%s = %d", name, rec.Code)
		}
	}
	peerUID = 1002
	if rec := f.post(t, "/r/claudecode/v1/messages", messagesBody("hello"), nil); rec.Code != 401 {
		t.Fatalf("another account replaying alice credential = %d", rec.Code)
	}
	peerUID = 1001
	f.srv.goos = "darwin"
	if rec := f.post(t, "/r/claudecode/v1/messages", messagesBody("hello"), nil); rec.Code != 503 {
		t.Fatalf("managed macOS without a gateway-held credential = %d", rec.Code)
	}
	placeholder := func(r *http.Request) {
		r.Header.Del("X-Api-Key")
		r.Header.Set("Authorization", "Bearer "+connector.RouteOnlyPlaceholderCredential)
	}
	if rec := f.post(t, "/r/claudecode/v1/messages", messagesBody("quick question"), placeholder); rec.Code != 503 {
		t.Fatalf("managed macOS custody render without a gateway-held credential = %d", rec.Code)
	}
	if atomic.LoadInt32(&f.origHits) != hits {
		t.Fatal("a refused request or the agent key on managed macOS reached the upstream")
	}
	api.managedHookAuthz.Store(nil)
	f.srv.goos = "linux"
	if rec := f.post(t, "/r/claudecode/v1/messages", messagesBody("hello"), nil); rec.Code != 401 {
		t.Fatalf("no hook socket authorizer = %d, want 401", rec.Code)
	}
}

// The managed Windows route epoch: a rotation (the gateway owns its port
// again) refuses every earlier route credential at once, and an enrollment
// that ended and came back gets a new credential for that account only.
func TestRouteEpochRotationRefusesOldCredentialsAtOnce(t *testing.T) {
	const alice, bob = "S-1-5-21-100-200-300-1001", "S-1-5-21-100-200-300-1002"
	ledger := &userScopedTestLedger{}
	aliceRow := managedHookLedgerTarget{User: "alice", SID: alice, Connector: "codex", OK: true}
	bobRow := managedHookLedgerTarget{User: "bob", SID: bob, Connector: "codex", OK: true}
	ledger.set(aliceRow, bobRow)
	api, _, _ := newUserScopedTestServer(t, true, ledger, nil)
	// The published epoch, in memory: on the managed Windows gateway it is a
	// service runtime file (connector.WriteRouteEpoch), which a test temp
	// folder cannot be.
	published := &testPublishedRouteEpoch{}
	store := api.userScopedCredentialStore()
	store.routeEpoch = published.state(api.configDataDir)
	token := func(identity string) string {
		epoch, err := published.load(api.scannerCfg.DataDir)
		if err != nil || epoch == nil {
			t.Fatalf("published epoch = %v, %v", epoch, err)
		}
		tok, err := connector.ManagedRouteToken(userScopedTestKey, epoch, "codex", identity)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	valid := func(tok string) bool {
		_, ok := api.lookupUserScopedCredential(connector.UserScopedRouteCredential, "codex", tok)
		return ok
	}
	plain, _ := connector.UserScopedRouteToken(userScopedTestKey, "codex", alice)
	if valid(plain) {
		t.Fatal("before the gateway owns its port no route credential may authenticate")
	}
	api.startRouteEpoch(false)
	first, bobFirst := token(alice), token(bob)
	if !valid(first) || !valid(bobFirst) || valid(plain) {
		t.Fatal("after the first start the published epoch credentials authenticate, and only they")
	}
	// A normal restart (a new gateway process, nothing held the port)
	// keeps the published epoch: running agents keep working (P2-3).
	store.routeEpoch = published.state(api.configDataDir)
	store.invalidate()
	if valid(first) {
		t.Fatal("before the restarted gateway owns its port no route credential may authenticate")
	}
	api.startRouteEpoch(false)
	if !valid(first) || token(alice) != first {
		t.Fatal("a normal restart must keep the route epoch and the rendered credential")
	}
	// The bind found the port held during the restart: a new epoch.
	api.startRouteEpoch(true)
	second := token(alice)
	if valid(first) || !valid(second) {
		t.Fatal("a restart after another process held the port must refuse the old credential at once")
	}
	// An unusable published epoch is never adopted.
	saved := published.raw
	published.raw = []byte("not json")
	other := published.state(api.configDataDir)
	if rotated, err := other.start(false); !rotated || err != nil {
		t.Fatalf("start over a corrupt published epoch = %v, %v; want a new epoch", rotated, err)
	}
	published.raw = saved
	bobSecond := token(bob)
	ledger.set(bobRow)
	if valid(second) {
		t.Fatal("an ended enrollment must be refused")
	}
	ledger.set(aliceRow, bobRow)
	if valid(second) {
		t.Fatal("a credential from before the enrollment gap must stay refused")
	}
	third := token(alice)
	if third == second || !valid(third) {
		t.Fatal("the account that came back authenticates with its new credential")
	}
	if !valid(bobSecond) {
		t.Fatal("another account credential must not change with that bump")
	}
	// A failed apply (the row stays, OK false) and its recovery are not an
	// enrollment gap: the rendered credential stays (REVIEW-code-slice4 P3-2).
	failed := aliceRow
	failed.OK = false
	ledger.set(failed, bobRow)
	if valid(third) {
		t.Fatal("a target whose apply failed must not authenticate")
	}
	ledger.set(aliceRow, bobRow)
	if !valid(third) || token(alice) != third {
		t.Fatal("a failed apply and its recovery must keep the route credential")
	}
}

// testPublishedRouteEpoch is the published route epoch of a test gateway,
// held in memory with the decoding and validation of the real file.
type testPublishedRouteEpoch struct{ raw []byte }

func (p *testPublishedRouteEpoch) state(dataDir func() string) *routeEpochState {
	st := newRouteEpochState(dataDir)
	st.write, st.load = p.write, p.load
	return st
}

func (p *testPublishedRouteEpoch) write(_ string, epoch connector.RouteEpoch) error {
	if err := epoch.Validate(); err != nil {
		return err
	}
	raw, err := json.Marshal(epoch)
	if err != nil {
		return err
	}
	p.raw = raw
	return nil
}

func (p *testPublishedRouteEpoch) load(string) (*connector.RouteEpoch, error) {
	if p.raw == nil {
		return nil, nil
	}
	var epoch connector.RouteEpoch
	if err := json.Unmarshal(p.raw, &epoch); err != nil {
		return nil, err
	}
	if err := epoch.Validate(); err != nil {
		return nil, err
	}
	return &epoch, nil
}

func TestRouteOnlySetupManagedVsOSS(t *testing.T) {
	cfg := &config.Config{DataDir: t.TempDir()}
	cfg.Guardrail.Connector = "codex"
	cfg.Routing.Enabled = true
	cfg.Routing.RouteOnly = config.RoutingRouteOnlyConfig{Connectors: []string{"codex"}, Upstreams: map[string]config.RoutingUpstreamConfig{"codex": {BaseURL: "https://api.openai.com/v1", API: "responses"}}}
	if ManagedRouteOnlySetup(cfg, "codex", "127.0.0.1:18970", "tok") != nil {
		t.Fatal("an OSS host never gets the managed per-user rendering")
	}
	if routeOnlySetupFor(cfg, "codex", "127.0.0.1:18970") == nil {
		t.Fatal("OSS rendering missing")
	}
	cfg.DeploymentMode, cfg.Enterprise.Profile = "managed_enterprise", "standalone"
	if routeOnlySetupFor(cfg, "codex", "127.0.0.1:18970") != nil {
		t.Fatal("a managed gateway never renders route-only itself (no machine-wide file)")
	}
	prevGOOS := managedRouteOnlyGOOS
	t.Cleanup(func() { managedRouteOnlyGOOS = prevGOOS })
	managedRouteOnlyGOOS = "linux"
	route := ManagedRouteOnlySetup(cfg, "codex", "127.0.0.1:18970", "tok")
	if route == nil || route.Token != "tok" || route.BaseURL != "http://127.0.0.1:18970/r/codex" || route.Custody {
		t.Fatalf("managed Linux rendering = %+v (socket activation: passthrough)", route)
	}
	// Managed macOS and Windows: the agent gets a placeholder credential,
	// never its own key or login (REVIEW-code-slice4 P1-2).
	for _, goos := range []string{"darwin", "windows"} {
		managedRouteOnlyGOOS = goos
		if route := ManagedRouteOnlySetup(cfg, "codex", "0.0.0.0:18970", "tok"); route == nil || !route.Custody || route.BaseURL != "http://127.0.0.1:18970/r/codex" {
			t.Fatalf("managed %s rendering = %+v", goos, route)
		}
	}
	managedRouteOnlyGOOS = "linux"
	if ManagedRouteOnlySetup(cfg, "codex", "127.0.0.1:18970", "") != nil || ManagedRouteOnlySetup(cfg, "claudecode", "127.0.0.1:18970", "tok") != nil {
		t.Fatal("no credential or an unrouted connector renders nothing")
	}
}

func TestGuardrailProxyKernelPeerAttachesTheVerifiedSubject(t *testing.T) {
	restore := identityFactsEnabled.Load()
	identityFactsEnabled.Store(true)
	t.Cleanup(func() { identityFactsEnabled.Store(restore) })
	p := &GuardrailProxy{skipAuthForTest: true}
	r, _ := http.NewRequest(http.MethodPost, "http://127.0.0.1:4000/v1/chat/completions", nil)
	verified := false
	p.kernelPeer = func(*http.Request, string) (string, bool) { return "1001", verified }
	out, ok := p.authenticateRequest(r)
	if _, has := verifiedSubjectFromContext(out.Context()); !ok || has {
		t.Fatal("an unverified peer must leave the request base-only")
	}
	verified = true
	out, ok = p.authenticateRequest(r)
	subject, has := verifiedSubjectFromContext(out.Context())
	if !ok || !has || subject.UserID != "1001" || subject.Source != subjectSourceKernelPeer {
		t.Fatalf("verified peer subject = %+v %v", subject, has)
	}
}

// The guardrail proxy asks for the kernel peer on managed Linux and macOS
// with routing on, never on Windows until the live probe (P1-1).
func TestProxyKernelPeerAllowedOffOnWindows(t *testing.T) {
	cfg := &config.Config{}
	cfg.DeploymentMode, cfg.Enterprise.Profile = "managed_enterprise", "standalone"
	cfg.Routing.Enabled = true
	if !proxyKernelPeerAllowed(cfg, "claudecode", false) {
		t.Fatal("managed Unix with routing on asks for the kernel peer")
	}
	if proxyKernelPeerAllowed(cfg, "claudecode", true) {
		t.Fatal("managed Windows must keep the base-only proxy answer")
	}
	if proxyKernelPeerAllowed(cfg, "", false) || proxyKernelPeerAllowed(nil, "claudecode", false) {
		t.Fatal("no connector or no config asks nothing")
	}
	cfg.Routing.Enabled = false
	if proxyKernelPeerAllowed(cfg, "claudecode", false) {
		t.Fatal("routing off keeps the 1.0.9 behaviour")
	}
	oss := &config.Config{}
	oss.Routing.Enabled = true
	if proxyKernelPeerAllowed(oss, "claudecode", false) {
		t.Fatal("OSS never asks for the kernel peer")
	}
}

// A refresh that fails (key or ledger unreadable) drops the enrollment
// answers with the index, never serving the last good ledger (P3-1).
func TestUserScopedStoreFailClearsEnrolled(t *testing.T) {
	const alice = "S-1-5-21-100-200-300-1001"
	ledger := &userScopedTestLedger{}
	ledger.set(managedHookLedgerTarget{User: "alice", SID: alice, Connector: "codex", OK: true})
	api, _, _ := newUserScopedTestServer(t, true, ledger, nil)
	store := api.userScopedCredentialStore()
	if !store.enrolledFor(alice, "codex") {
		t.Fatal("an enrolled account must be reported")
	}
	store.loadKey = func(string) (string, error) { return "", errors.New("key unreadable") }
	if store.enrolledFor(alice, "codex") {
		t.Fatal("a failed refresh must not answer from the last good ledger")
	}
}
