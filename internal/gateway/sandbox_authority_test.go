// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"github.com/defenseclaw/defenseclaw/internal/sandboxreg"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

var (
	sbxAlice = managedHookPeer{UID: 94404076, Name: "ent-alice"}
	sbxBob   = managedHookPeer{UID: 94404077, Name: "ent-bob"}
)

type sandboxFixture struct {
	t       testing.TB
	api     *APIServer
	cfg     *config.Config
	handler http.Handler

	mu    sync.Mutex
	facts map[int]useridentity.DirectoryFacts

	rematched []string
}

// newSandboxFixture serves the hook socket's handler chain in-process: the
// peer identity middleware, peer auth with authorizer, the hook-socket mux,
// and a stand-in relayed hook route that runs sandboxRelayAdmit the way the
// relay does and answers the subject profileRequestSubject gives it.
func newSandboxFixture(t testing.TB, enrollment config.EnterpriseEnrollmentConfig, ledger *managedHookLedger) *sandboxFixture {
	t.Helper()
	f := &sandboxFixture{t: t, facts: map[int]useridentity.DirectoryFacts{}}
	cfg := &config.Config{DataDir: t.TempDir()}
	cfg.OpenShell.Enabled = true
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{
		"contractors":   {Description: "Contractors"},
		"engineering":   {Description: "Engineering"},
		"offline-floor": {Description: "Offline floor"},
	}
	cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{
		{Profile: "contractors", Match: config.ProfileMatch{Groups: []string{"dc-sbx-contractors"}}},
		{Profile: "engineering", Match: config.ProfileMatch{Groups: []string{"dc-sbx-devs"}}},
	}
	cfg.Guardrail.DefaultProfile = "offline-floor"
	cfg.Enterprise.Enrollment = enrollment
	f.cfg = cfg
	f.api = NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, nil, nil, cfg)

	restoreFacts, restoreBlocking := identityFactsEnabled.Load(), identityLookupBlocking.Load()
	identityFactsEnabled.Store(true)
	identityLookupBlocking.Store(true)
	prevDirectory, prevKey, prevAvail, prevWait := managedHookPeerDirectory, sandboxAuthorityKey, sandboxHostAvailability, sandboxResolveWait
	prevRematched := sandboxRecordRematched
	managedHookPeerDirectory = func(uid int, block bool) (useridentity.DirectoryFacts, bool) {
		f.mu.Lock()
		defer f.mu.Unlock()
		facts, ok := f.facts[uid]
		return facts, ok
	}
	sandboxAuthorityKey = func(string) ([]byte, error) { return bytes.Repeat([]byte{7}, 32), nil }
	sandboxHostAvailability = func(*config.Config, managedHookPeer, config.OpenShellAdminConfig) sandboxAvailability {
		return sandboxAvailability{Available: true, Driver: sandboxTestDriver, DriverReason: "configured"}
	}
	sandboxResolveWait = 300 * time.Millisecond
	sandboxRecordRematched = func(_ *APIServer, before, after sandboxreg.Registration, changed []string, action string) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.rematched = append(f.rematched, after.ID+":"+action+":"+strings.Join(changed, ","))
	}
	t.Cleanup(func() {
		identityFactsEnabled.Store(restoreFacts)
		identityLookupBlocking.Store(restoreBlocking)
		managedHookPeerDirectory, sandboxAuthorityKey, sandboxHostAvailability, sandboxResolveWait = prevDirectory, prevKey, prevAvail, prevWait
		sandboxRecordRematched = prevRematched
	})
	load := func() (managedHookLedger, error) {
		if ledger == nil {
			return managedHookLedger{}, nil
		}
		return *ledger, nil
	}
	authorizer := newManagedHookAuthorizer(enrollment, []string{"claudecode", "codex"}, load)
	relay := http.NewServeMux()
	relay.HandleFunc("POST "+sandboxrelay.PathHookPrefix+"{connector}", func(w http.ResponseWriter, r *http.Request) {
		ctx, reg, ok := f.api.sandboxRelayAdmit(w, r, r.PathValue("connector"))
		if !ok {
			return
		}
		binding := sandboxauth.Binding{ID: reg.BindingID, SandboxName: reg.SandboxName, Connector: reg.Connector}
		subject, source := profileRequestSubject(sandboxauth.WithRequest(ctx, binding, sandboxauth.NewFSView(binding, nil)))
		uid := ""
		if subject != nil {
			uid = subject.UserID
		}
		f.api.writeJSON(w, http.StatusOK, map[string]string{"uid": uid, "source": source, "profile": reg.Profile})
	})
	socketMux := f.api.managedHookSocketMux()
	outer := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, sandboxrelay.PathHookPrefix) {
			f.api.apiCSRFProtect(relay).ServeHTTP(w, r)
			return
		}
		socketMux.ServeHTTP(w, r)
	})
	f.handler = managedHookPeerIdentityMiddleware(f.api.managedHookPeerAuth(authorizer, outer))
	return f
}

func (f *sandboxFixture) setGroups(peer managedHookPeer, groups ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.facts[peer.UID] = useridentity.DirectoryFacts{
		Principal: peer.Name + "@DCLAB.TEST", Domain: "dclab.test", Directory: useridentity.DirectoryActiveDirectory,
		Groups: groups, Source: "sssd", ResolvedAt: time.Now(),
	}
}

func (f *sandboxFixture) coldCache(peer managedHookPeer) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.facts, peer.UID)
}

func (f *sandboxFixture) do(peer managedHookPeer, method, path string, body any, header map[string]string) *httptest.ResponseRecorder {
	f.t.Helper()
	var raw []byte
	switch b := body.(type) {
	case nil:
	case []byte:
		raw = b
	default:
		var err error
		if raw, err = json.Marshal(b); err != nil {
			f.t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(sandboxrelay.ClientHeader, sandboxrelay.ClientHeaderValue)
	req.Header.Set(sandboxrelay.DaemonContractHeader, strconv.Itoa(sandboxrelay.DaemonContract))
	for k, v := range header {
		if v == "" {
			req.Header.Del(k)
			continue
		}
		req.Header.Set(k, v)
	}
	req = req.WithContext(withManagedHookPeer(req.Context(), peer))
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	return rec
}

// sandboxTestDriver is the compute driver the gateway accepts on this
// platform by default: the MicroVM driver on macOS, docker on Linux
// (sandboxDriverClaim). The fixture claims it, so a resolve runs the same
// host path the platform runs.
var sandboxTestDriver = config.EnterpriseOpenShellConfig{}.SandboxDriver(runtime.GOOS)

func claudeResolve() sandboxrelay.ResolveRequest {
	spec, _ := harness.Get("claudecode")
	return sandboxrelay.ResolveRequest{
		V: 1, Harness: "claudecode", Connector: "claudecode", HarnessVersion: spec.DefaultVersion,
		ProjectReal: "/home/ent-alice/project", Driver: sandboxTestDriver,
	}
}

func (f *sandboxFixture) resolve(peer managedHookPeer, req sandboxrelay.ResolveRequest) sandboxrelay.ResolveResponse {
	f.t.Helper()
	rec := f.do(peer, http.MethodPost, sandboxrelay.PathPolicyResolve, req, map[string]string{sandboxrelay.ConnectorHeader: req.Connector})
	if rec.Code != http.StatusOK {
		f.t.Fatalf("resolve for uid %d: %d %s", peer.UID, rec.Code, rec.Body.String())
	}
	var resp sandboxrelay.ResolveResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		f.t.Fatal(err)
	}
	return resp
}

func (f *sandboxFixture) bind(peer managedHookPeer, id string, n int) *httptest.ResponseRecorder {
	return f.do(peer, http.MethodPost, sandboxrelay.PathRegistrations+id+sandboxrelay.RegistrationBindSub, sandboxrelay.BindRequest{
		V: 1, SandboxName: "dc-claude-" + strconv.Itoa(n), SandboxID: "sbx-" + strconv.Itoa(n),
		BindingID: "sb_" + strings.Repeat(strconv.Itoa(n%10), 32),
	}, nil)
}

func (f *sandboxFixture) hook(peer managedHookPeer, id, connectorName string, header map[string]string) *httptest.ResponseRecorder {
	h := map[string]string{sandboxrelay.RegistrationHeader: id}
	for k, v := range header {
		h[k] = v
	}
	return f.do(peer, http.MethodPost, sandboxrelay.PathHookPrefix+connectorName, []byte(`{"hook_event_name":"PreToolUse"}`), h)
}

func (f *sandboxFixture) current(peer managedHookPeer, id string) (int, sandboxrelay.CurrentPolicy) {
	rec := f.do(peer, http.MethodGet, sandboxrelay.PathPolicyCurrent+"?registration="+id, nil, nil)
	var cur sandboxrelay.CurrentPolicy
	_ = json.Unmarshal(rec.Body.Bytes(), &cur)
	return rec.Code, cur
}

func errorReason(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Error  string `json:"error"`
		Reason string `json:"reason"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body.Reason != "" {
		return body.Reason
	}
	return body.Error
}

func (f *sandboxFixture) live(peer managedHookPeer, n int) sandboxrelay.ResolveResponse {
	f.t.Helper()
	resp := f.resolve(peer, claudeResolve())
	if rec := f.bind(peer, resp.Registration.ID, n); rec.Code != http.StatusOK {
		f.t.Fatalf("bind: %d %s", rec.Code, rec.Body.String())
	}
	return resp
}

// Two accounts on one gateway: each gets its own profile, and neither can
// use the other's registration through any route.
func TestSandboxAuthorityTwoAccounts(t *testing.T) {
	f := newSandboxFixture(t, config.EnterpriseEnrollmentConfig{}, nil)
	f.setGroups(sbxAlice, "dc-sbx-contractors")
	f.setGroups(sbxBob, "dc-sbx-devs")
	alice := f.live(sbxAlice, 1)
	bob := f.live(sbxBob, 2)
	if alice.Banner.Profile != "contractors" || bob.Banner.Profile != "engineering" || alice.Banner.Provisional {
		t.Fatalf("banners: alice %+v bob %+v", alice.Banner, bob.Banner)
	}
	if alice.Registration.ID == bob.Registration.ID || !sandboxreg.ValidID(alice.Registration.ID) || len(alice.Effective) == 0 {
		t.Fatalf("registrations: %+v %+v", alice.Registration, bob.Registration)
	}
	rec := f.hook(sbxAlice, alice.Registration.ID, "claudecode", nil)
	var seen map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &seen)
	if rec.Code != http.StatusOK || seen["uid"] != strconv.Itoa(sbxAlice.UID) || seen["source"] != profileSubjectVerified ||
		rec.Header().Get(sandboxrelay.ProfileHeader) != "contractors" || rec.Header().Get(sandboxrelay.GenerationHeader) == "" {
		t.Fatalf("alice's relayed hook: %d %s %v", rec.Code, rec.Body.String(), rec.Header())
	}
	// Bob presenting Alice's id, a forged id or a malformed one: unknown.
	forged, _ := sandboxreg.NewID()
	for _, id := range []string{alice.Registration.ID, forged, "reg-../../1001", ""} {
		if rec := f.hook(sbxBob, id, "claudecode", nil); rec.Code != http.StatusNotFound || errorReason(t, rec) != sandboxrelay.ReasonRegistrationUnknown {
			t.Errorf("bob hook with %q: %d %s", id, rec.Code, rec.Body.String())
		}
	}
	if code, _ := f.current(sbxBob, alice.Registration.ID); code != http.StatusNotFound {
		t.Errorf("bob reads alice's policy: %d", code)
	}
	if rec := f.bind(sbxBob, alice.Registration.ID, 3); rec.Code != http.StatusNotFound {
		t.Errorf("bob binds alice's registration: %d", rec.Code)
	}
	if rec := f.do(sbxBob, http.MethodPost, sandboxrelay.PathRegistrations+alice.Registration.ID+sandboxrelay.RegistrationDelSub, []byte(`{}`), nil); rec.Code != http.StatusNotFound {
		t.Errorf("bob deletes alice's registration: %d", rec.Code)
	}
	// Alice's own id on another connector's route.
	if rec := f.hook(sbxAlice, alice.Registration.ID, "codex", nil); rec.Code != http.StatusForbidden || errorReason(t, rec) != sandboxrelay.ReasonConnectorMismatch {
		t.Errorf("connector mismatch: %d %s", rec.Code, rec.Body.String())
	}
	// The reserved files header is refused (copy-only).
	if rec := f.hook(sbxAlice, alice.Registration.ID, "claudecode", map[string]string{sandboxrelay.FilesHeader: "x"}); rec.Code != http.StatusBadRequest ||
		errorReason(t, rec) != sandboxrelay.ReasonRelayFilesUnsupported {
		t.Errorf("files header: %d %s", rec.Code, rec.Body.String())
	}
	// A sandbox request that was not relay-verified never gets a subject.
	ctx := withManagedHookPeer(context.Background(), sbxAlice)
	ctx = withVerifiedSubject(ctx, VerifiedSubject{UserID: strconv.Itoa(sbxAlice.UID), IDKind: useridentity.KindPOSIXUID, Source: subjectSourcePeerCredentials})
	binding := sandboxauth.Binding{ID: "sb_" + strings.Repeat("a", 32), Connector: "claudecode"}
	if subject, source := profileRequestSubject(sandboxauth.WithRequest(ctx, binding, sandboxauth.NewFSView(binding, nil))); subject != nil || source != "" {
		t.Fatalf("an unrelayed sandbox request got subject %+v %q", subject, source)
	}
}

// Revocation and a restarted gateway: the store persists, a tombstone
// stays revoked, and policy/current reports it.
func TestSandboxAuthorityRevokedAndRestart(t *testing.T) {
	f := newSandboxFixture(t, config.EnterpriseEnrollmentConfig{}, nil)
	f.setGroups(sbxAlice, "dc-sbx-contractors")
	kept := f.live(sbxAlice, 1)
	revoked := f.live(sbxAlice, 2)
	auth, err := f.api.sandboxAuth()
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.store.Revoke(sbxAlice.UID, revoked.Registration.ID, "regrouped"); err != nil {
		t.Fatal(err)
	}
	// A restarted gateway: a new API server on the same data directory.
	restarted := newSandboxFixtureOn(t, f)
	if rec := restarted.hook(sbxAlice, kept.Registration.ID, "claudecode", nil); rec.Code != http.StatusOK {
		t.Fatalf("hook after restart: %d %s", rec.Code, rec.Body.String())
	}
	if rec := restarted.hook(sbxAlice, revoked.Registration.ID, "claudecode", nil); rec.Code != http.StatusGone ||
		errorReason(t, rec) != sandboxrelay.ReasonRegistrationRevoked {
		t.Fatalf("revoked hook after restart: %d %s", rec.Code, rec.Body.String())
	}
	if code, cur := restarted.current(sbxAlice, revoked.Registration.ID); code != http.StatusOK || !cur.Revoked || cur.RevokedReason == "" {
		t.Fatalf("current of a tombstone: %d %+v", code, cur)
	}
	// The tombstoned sandbox never registers again.
	again := restarted.resolve(sbxAlice, claudeResolve())
	if rec := restarted.bind(sbxAlice, again.Registration.ID, 2); rec.Code != http.StatusGone {
		t.Fatalf("re-register a tombstoned sandbox: %d %s", rec.Code, rec.Body.String())
	}
}

// newSandboxFixtureOn is another gateway process on f's data directory.
func newSandboxFixtureOn(t testing.TB, f *sandboxFixture) *sandboxFixture {
	t.Helper()
	g := newSandboxFixture(t, f.cfg.Enterprise.Enrollment, nil)
	g.cfg.DataDir = f.cfg.DataDir
	g.api.scannerCfg.DataDir = f.cfg.DataDir
	f.mu.Lock()
	for uid, facts := range f.facts {
		g.facts[uid] = facts
	}
	f.mu.Unlock()
	return g
}

func (f *sandboxFixture) report(peer managedHookPeer, id string, running bool) (int, sandboxrelay.CurrentPolicy) {
	rec := f.do(peer, http.MethodPost, sandboxrelay.PathRegistrations+id+sandboxrelay.RegistrationStateSub,
		sandboxrelay.StateReport{V: 1, Running: running}, nil)
	var cur sandboxrelay.CurrentPolicy
	_ = json.Unmarshal(rec.Body.Bytes(), &cur)
	return rec.Code, cur
}

// A registration authorizes relayed calls only while its daemon reports the
// sandbox running (GAP-0505, GAP-0446): a stopped report or a lapsed lease
// refuses hooks with sandbox_registration_stopped while policy/current stays
// readable, a running report admits them again, and a bind must name the
// sandbox id.
func TestSandboxAuthorityRegistrationFollowsTheSandbox(t *testing.T) {
	f := newSandboxFixture(t, config.EnterpriseEnrollmentConfig{}, nil)
	f.setGroups(sbxBob, "dc-sbx-devs")
	resp := f.resolve(sbxBob, claudeResolve())
	noID := f.do(sbxBob, http.MethodPost, sandboxrelay.PathRegistrations+resp.Registration.ID+sandboxrelay.RegistrationBindSub,
		sandboxrelay.BindRequest{V: 1, SandboxName: "cxr2fake", BindingID: "sb_" + strings.Repeat("c", 32)}, nil)
	if noID.Code != http.StatusBadRequest {
		t.Fatalf("bind without a sandbox id: %d %s", noID.Code, noID.Body.String())
	}
	if code, _ := f.report(sbxBob, resp.Registration.ID, true); code != http.StatusForbidden {
		t.Fatalf("state report of a pending registration: %d", code)
	}
	if rec := f.bind(sbxBob, resp.Registration.ID, 1); rec.Code != http.StatusOK {
		t.Fatalf("bind: %d %s", rec.Code, rec.Body.String())
	}
	id := resp.Registration.ID
	if code, cur := f.report(sbxBob, id, false); code != http.StatusOK || cur.Revoked {
		t.Fatalf("stopped report: %d %+v", code, cur)
	}
	if rec := f.hook(sbxBob, id, "claudecode", nil); rec.Code != http.StatusForbidden || errorReason(t, rec) != sandboxrelay.ReasonRegistrationStopped {
		t.Fatalf("hook of a stopped sandbox: %d %s", rec.Code, rec.Body.String())
	}
	if code, cur := f.current(sbxBob, id); code != http.StatusOK || cur.Revoked {
		t.Fatalf("current of a stopped sandbox: %d %+v", code, cur)
	}
	// GAP-0574: a session-only answer has no running sandbox to apply to;
	// a saved decision is kept for the next start.
	decide := func(kind, scope string) *httptest.ResponseRecorder {
		return f.do(sbxBob, http.MethodPost, sandboxrelay.PathDecisions, sandboxrelay.DecisionRequest{
			V: 1, Registration: id, Kind: kind, Host: "example.org", Scope: scope}, nil)
	}
	if rec := decide(sandboxrelay.DecisionEgressAllow, sandboxrelay.DecisionScopeSession); rec.Code != http.StatusForbidden ||
		errorReason(t, rec) != sandboxrelay.ReasonRegistrationStopped {
		t.Fatalf("session decision of a stopped sandbox: %d %s", rec.Code, rec.Body.String())
	}
	if rec := decide(sandboxrelay.DecisionEgressBlock, sandboxrelay.DecisionScopeAlways); rec.Code != http.StatusOK {
		t.Fatalf("saved decision of a stopped sandbox: %d %s", rec.Code, rec.Body.String())
	}
	if code, _ := f.report(sbxBob, id, true); code != http.StatusOK {
		t.Fatalf("running report: %d", code)
	}
	if rec := decide(sandboxrelay.DecisionEgressAllow, sandboxrelay.DecisionScopeSession); rec.Code != http.StatusOK {
		t.Fatalf("session decision of a running sandbox: %d %s", rec.Code, rec.Body.String())
	}
	if rec := f.hook(sbxBob, id, "claudecode", nil); rec.Code != http.StatusOK {
		t.Fatalf("hook after the sandbox started again: %d %s", rec.Code, rec.Body.String())
	}
	// The daemon stops reporting (it, or the sandbox, is gone): the lease
	// lapses and the hook is refused.
	auth, _ := f.api.sandboxAuth()
	later := time.Now().Add(sandboxreg.LiveLease + time.Second)
	auth.store.(*sandboxreg.FileStore).Now = func() time.Time { return later }
	auth.now = func() time.Time { return later }
	if rec := f.hook(sbxBob, id, "claudecode", nil); rec.Code != http.StatusForbidden || errorReason(t, rec) != sandboxrelay.ReasonRegistrationStopped {
		t.Fatalf("hook past the lease: %d %s", rec.Code, rec.Body.String())
	}
}

// A registration bound to a sandbox its account's daemon reports foreign is
// revoked: the foreign sandbox's stop or delete leaves no live registration
// to stamp a later hook with (GAP-0529).
func TestSandboxAuthorityForeignReportRevokesItsRegistration(t *testing.T) {
	f := newSandboxFixture(t, config.EnterpriseEnrollmentConfig{}, nil)
	f.setGroups(sbxAlice, "dc-sbx-contractors")
	forged := f.live(sbxAlice, 1)
	own := f.live(sbxAlice, 2)
	payload, _ := json.Marshal(map[string]string{"sandbox": "dc-claude-1", "sandbox_id": "sbx-1", "action": "stop"})
	batch := sandboxrelay.EventBatch{V: 1, Events: []sandboxrelay.Event{{Kind: sandboxrelay.EventForeignSandbox, Time: time.Now(), Payload: payload}}}
	if rec := f.do(sbxBob, http.MethodPost, sandboxrelay.PathEvents, batch, nil); rec.Code != http.StatusAccepted {
		t.Fatalf("another account's foreign record: %d %s", rec.Code, rec.Body.String())
	}
	if rec := f.hook(sbxAlice, forged.Registration.ID, "claudecode", nil); rec.Code != http.StatusOK {
		t.Fatalf("another account's record revoked alice's registration: %d", rec.Code)
	}
	if rec := f.do(sbxAlice, http.MethodPost, sandboxrelay.PathEvents, batch, nil); rec.Code != http.StatusAccepted {
		t.Fatalf("foreign record: %d %s", rec.Code, rec.Body.String())
	}
	if rec := f.hook(sbxAlice, forged.Registration.ID, "claudecode", nil); rec.Code != http.StatusGone ||
		errorReason(t, rec) != sandboxrelay.ReasonRegistrationRevoked {
		t.Fatalf("hook of the foreign sandbox's registration: %d %s", rec.Code, rec.Body.String())
	}
	if rec := f.hook(sbxAlice, own.Registration.ID, "claudecode", nil); rec.Code != http.StatusOK {
		t.Fatalf("hook of alice's own sandbox: %d %s", rec.Code, rec.Body.String())
	}
}

func TestSandboxAuthorityPendingExpires(t *testing.T) {
	f := newSandboxFixture(t, config.EnterpriseEnrollmentConfig{}, nil)
	f.setGroups(sbxAlice, "dc-sbx-contractors")
	resp := f.resolve(sbxAlice, claudeResolve())
	if resp.Registration.State != sandboxreg.StatePending || resp.Registration.ExpiresAt.IsZero() {
		t.Fatalf("pending view: %+v", resp.Registration)
	}
	if rec := f.hook(sbxAlice, resp.Registration.ID, "claudecode", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("hook before bind: %d %s", rec.Code, rec.Body.String())
	}
	auth, _ := f.api.sandboxAuth()
	later := time.Now().Add(sandboxreg.PendingTTL + time.Second)
	auth.store.(*sandboxreg.FileStore).Now = func() time.Time { return later }
	auth.now = func() time.Time { return later }
	if rec := f.bind(sbxAlice, resp.Registration.ID, 1); rec.Code != http.StatusGone || errorReason(t, rec) != sandboxrelay.ReasonRegistrationExpired {
		t.Fatalf("bind after expiry: %d %s", rec.Code, rec.Body.String())
	}
}

// A create on a cold identity cache waits, then refuses, naming the group
// fact its assignments need. Once the cache warms, a new registration uses the
// proven group's profile (GAP-0022).
func TestSandboxAuthorityColdCacheRefusesUntilIdentityConfirmed(t *testing.T) {
	f := newSandboxFixture(t, config.EnterpriseEnrollmentConfig{}, nil)
	// contractors blocks under strict: a create that may get it is refused
	// until the groups are proven.
	f.cfg.Guardrail.Profiles["contractors"] = strictTier(t, f.cfg, config.GuardrailProfile{Description: "Contractors"}, "strict")
	f.publishFirstGeneration()
	f.coldCache(sbxAlice)
	start := time.Now()
	rec := f.do(sbxAlice, http.MethodPost, sandboxrelay.PathPolicyResolve, claudeResolve(),
		map[string]string{sandboxrelay.ConnectorHeader: "claudecode"})
	if waited := time.Since(start); waited < sandboxResolveWait {
		t.Fatalf("resolve answered after %v without waiting for the lookup", waited)
	}
	if rec.Code != http.StatusServiceUnavailable || errorReason(t, rec) != sandboxrelay.ReasonUnavailable ||
		!strings.Contains(rec.Body.String(), "group membership is unconfirmed") {
		t.Fatalf("cold create: %d %s; want a refusal naming the group fact its assignments need", rec.Code, rec.Body.String())
	}
	f.setGroups(sbxAlice, "dc-sbx-contractors")
	resp := f.live(sbxAlice, 1)
	if resp.Registration.Provisional || resp.Banner.Profile != "contractors" {
		t.Fatalf("create after identity confirmation: %+v %+v", resp.Registration, resp.Banner)
	}
	rec = f.hook(sbxAlice, resp.Registration.ID, "claudecode", nil)
	if rec.Code != http.StatusOK || rec.Header().Get(sandboxrelay.ProfileHeader) != "contractors" {
		t.Fatalf("hook after identity confirmation: %d %s %v", rec.Code, rec.Body.String(), rec.Header())
	}
	auth, _ := f.api.sandboxAuth()
	reg, _, _ := auth.store.Get(sbxAlice.UID, resp.Registration.ID)
	if reg.Provisional || reg.Profile != "contractors" || reg.ProfileMatch != sandboxreg.MatchGroup || reg.State != sandboxreg.StateLive {
		t.Fatalf("registration after identity confirmation: %+v", reg)
	}
	if code, cur := f.current(sbxAlice, resp.Registration.ID); code != http.StatusOK || cur.Provisional == nil || *cur.Provisional ||
		cur.Profile != "contractors" {
		t.Fatalf("current after identity confirmation: %d profile %q provisional %v", code, cur.Profile, cur.Provisional)
	}
}

// Review of r104 Q-identity (continuation 3, loop round 3): where every
// profile a cold create may get only observes with the same sandbox
// section, no answer of the groups could change what the sandbox enforces,
// and the create is not refused: it gets a provisional registration under
// default_profile, and its stamp records no candidate profile. With a
// profile whose own sandbox section is among them, the provisional create
// gets their strictest combination, that section included (continuation 4:
// only strict refuses).
func TestSandboxAuthorityColdCacheAmongObserveProfilesIsProvisional(t *testing.T) {
	for _, sandboxed := range []bool{false, true} {
		t.Run(map[bool]string{false: "observe only", true: "a sandbox section"}[sandboxed], func(t *testing.T) {
			f := newSandboxFixture(t, config.EnterpriseEnrollmentConfig{}, nil)
			if sandboxed {
				f.cfg.Guardrail.Profiles["contractors"] = config.GuardrailProfile{Description: "Contractors",
					Sandbox: &config.OpenShellAdminConfig{RequiredFor: []string{"claudecode"}}}
				f.publishFirstGeneration()
			}
			f.coldCache(sbxAlice)
			rec := f.do(sbxAlice, http.MethodPost, sandboxrelay.PathPolicyResolve, claudeResolve(),
				map[string]string{sandboxrelay.ConnectorHeader: "claudecode"})
			var resp sandboxrelay.ResolveResponse
			if sandboxed {
				if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &resp) != nil || !resp.Registration.Provisional ||
					resp.Banner.Profile == "offline-floor" {
					t.Fatalf("cold create with a sandboxed candidate: %d %s; want provisional under the strictest combination", rec.Code, rec.Body.String())
				}
				name := f.api.sandboxMatchPeer(context.Background(), sbxAlice, "claudecode", 0).decision.Name
				if floor, _, err := sandboxFloorFor(f.cfg, name); err != nil || !slices.Contains(floor.RequiredFor, "claudecode") {
					t.Fatalf("the strictest combination %q dropped the candidate's sandbox section: %+v (%v)", name, floor, err)
				}
				return
			}
			if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &resp) != nil {
				t.Fatalf("cold create among observe profiles: %d %s; want a provisional registration", rec.Code, rec.Body.String())
			}
			if !resp.Registration.Provisional || resp.Banner.Profile != "offline-floor" {
				t.Fatalf("cold create among observe profiles: %+v %+v; want provisional under default_profile", resp.Registration, resp.Banner)
			}
			reg := sandboxreg.Registration{UID: sbxAlice.UID, UserName: sbxAlice.Name, SubjectKey: "hmac-sha256:" + strings.Repeat("b", 64)}
			if m := f.api.sandboxForeignIdentity(context.Background(), reg, "c1", "plain", "claudecode", "").Managed; m.GuardrailProfile != "" || m.ProfileDigest != "" {
				t.Fatalf("stamp of an observed uncertain decision: %+v; want no candidate profile", m)
			}
		})
	}
}

// A new run during a hard directory outage (GAP-0507): the account database
// names no account for the uid. A remembered name is not proof of the
// account holder, so both a named and a nameless request refuse. Once the
// directory answers, the run can bind to the proven account.
//
// The named run is refused only under strict (contractors in action mode
// with the strict rule pack). Otherwise it gets a provisional registration
// under the strictest profile it may get, as 1.0.3 gave (review of r104
// Q-identity, continuation 3, loop round 3, and continuation 4).
func TestSandboxAuthorityResolveDuringDirectoryOutage(t *testing.T) {
	for _, contractorsMode := range []string{"strict", "action", "observe"} {
		t.Run(contractorsMode, func(t *testing.T) { sandboxResolveDuringDirectoryOutage(t, contractorsMode) })
	}
}

func sandboxResolveDuringDirectoryOutage(t *testing.T, contractorsMode string) {
	f := newSandboxFixture(t, config.EnterpriseEnrollmentConfig{}, nil)
	f.cfg.Guardrail.Profiles["contractors"] = strictTier(t, f.cfg, config.GuardrailProfile{Description: "Contractors"}, contractorsMode)
	f.publishFirstGeneration()
	f.coldCache(sbxAlice)
	nameless := managedHookPeer{UID: sbxAlice.UID}
	prev := managedHookPeerLastName
	t.Cleanup(func() { managedHookPeerLastName = prev })
	managedHookPeerLastName = func(int) string { return "" }
	rec := f.do(nameless, http.MethodPost, sandboxrelay.PathPolicyResolve, claudeResolve(), map[string]string{sandboxrelay.ConnectorHeader: "claudecode"})
	if rec.Code != http.StatusServiceUnavailable || errorReason(t, rec) != sandboxrelay.ReasonUnavailable {
		t.Fatalf("no name at all: %d %s, want the account-unknown refusal", rec.Code, rec.Body.String())
	}
	managedHookPeerLastName = func(uid int) string {
		if uid == sbxAlice.UID {
			return sbxAlice.Name
		}
		return ""
	}
	rec = f.do(nameless, http.MethodPost, sandboxrelay.PathPolicyResolve, claudeResolve(),
		map[string]string{sandboxrelay.ConnectorHeader: "claudecode"})
	if contractorsMode != "strict" {
		var resp sandboxrelay.ResolveResponse
		want := map[string]string{"observe": "offline-floor", "action": "strictest combination"}[contractorsMode]
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &resp) != nil ||
			!resp.Registration.Provisional || resp.Banner.Profile != want {
			t.Fatalf("run during an outage, contractors %s: %d banner %+v registration %+v; want provisional %s", contractorsMode, rec.Code, resp.Banner, resp.Registration, want)
		}
	} else if rec.Code != http.StatusServiceUnavailable || errorReason(t, rec) != sandboxrelay.ReasonUnavailable ||
		!strings.Contains(rec.Body.String(), "group membership is unconfirmed") {
		t.Fatalf("run during an outage: %d %s; want a refusal naming the group fact its assignments need", rec.Code, rec.Body.String())
	}
	f.setGroups(sbxAlice, "dc-sbx-contractors")
	resp := f.resolve(nameless, claudeResolve())
	if resp.Registration.Provisional || resp.Banner.Profile != "contractors" {
		t.Fatalf("run after the directory recovers: %+v %+v", resp.Registration, resp.Banner)
	}
	auth, _ := f.api.sandboxAuth()
	reg, ok, _ := auth.store.Get(sbxAlice.UID, resp.Registration.ID)
	if !ok || reg.UserName != sbxAlice.Name || !sandboxSubjectMatches(auth.key, reg, sbxAlice) {
		t.Fatalf("registration %+v does not bind to the account's own name", reg)
	}
	if rec := f.bind(sbxAlice, resp.Registration.ID, 1); rec.Code != http.StatusOK {
		t.Fatalf("bind by the named account: %d %s", rec.Code, rec.Body.String())
	}
}

// A recycled uid now belonging to another account: 409 and revoked.
func TestSandboxAuthorityRecycledUID(t *testing.T) {
	f := newSandboxFixture(t, config.EnterpriseEnrollmentConfig{}, nil)
	f.setGroups(sbxAlice, "dc-sbx-contractors")
	resp := f.live(sbxAlice, 1)
	mallory := managedHookPeer{UID: sbxAlice.UID, Name: "mallory"}
	if rec := f.hook(mallory, resp.Registration.ID, "claudecode", nil); rec.Code != http.StatusConflict ||
		errorReason(t, rec) != sandboxrelay.ReasonSubjectChanged {
		t.Fatalf("recycled uid: %d %s", rec.Code, rec.Body.String())
	}
	if rec := f.hook(sbxAlice, resp.Registration.ID, "claudecode", nil); rec.Code != http.StatusGone {
		t.Fatalf("the registration must be revoked: %d", rec.Code)
	}
}

// A config change re-matches on the next poll: the live fields switch and
// the re-match is recorded.
func TestSandboxAuthorityConfigChangeSwitchesLiveFields(t *testing.T) {
	f := newSandboxFixture(t, config.EnterpriseEnrollmentConfig{}, nil)
	f.setGroups(sbxAlice, "dc-sbx-contractors")
	gen := &Generation{N: 1, Config: f.cfg, Profiles: f.api.guardrailProfileSet()}
	var genMu sync.Mutex
	f.api.SetGenerationSource(func() *Generation { genMu.Lock(); defer genMu.Unlock(); return gen })
	resp := f.live(sbxAlice, 1)
	_, before := f.current(sbxAlice, resp.Registration.ID)
	next := *f.cfg
	next.OpenShell.Admin.EgressBlock = []string{"blocked.example"}
	genMu.Lock()
	gen = &Generation{N: 2, Config: &next, Profiles: f.api.guardrailProfileSet()}
	genMu.Unlock()
	code, after := f.current(sbxAlice, resp.Registration.ID)
	if code != http.StatusOK || after.Floor == nil || len(after.Floor.EgressBlock) != 1 || after.Generation == before.Generation || after.Revoked {
		t.Fatalf("current after the change: %d %+v (before %+v)", code, after, before)
	}
	f.mu.Lock()
	rematched := strings.Join(f.rematched, ";")
	f.mu.Unlock()
	if !strings.Contains(rematched, "floor") {
		t.Fatalf("re-match record: %q", rematched)
	}
}

// GAP-0224: once the organization raises the profile to strict, the
// saved allow of a sandbox registered under the looser one is left out of
// its decisions list (the store keeps the record), a user block stays, and
// policy/current names the strict min_profile a restart takes.
func TestSandboxAuthorityStrictFloorCapsSavedDecisions(t *testing.T) {
	f := newSandboxFixture(t, config.EnterpriseEnrollmentConfig{}, nil)
	f.setGroups(sbxAlice, "dc-sbx-contractors")
	gen := &Generation{N: 1, Config: f.cfg, Profiles: f.api.guardrailProfileSet()}
	var genMu sync.Mutex
	f.api.SetGenerationSource(func() *Generation { genMu.Lock(); defer genMu.Unlock(); return gen })
	resp := f.live(sbxAlice, 1)
	for _, kind := range []string{sandboxrelay.DecisionEgressAllow, sandboxrelay.DecisionEgressBlock} {
		rec := f.do(sbxAlice, http.MethodPost, sandboxrelay.PathDecisions, sandboxrelay.DecisionRequest{
			V: 1, Registration: resp.Registration.ID, Kind: kind, Host: kind + ".example.com", Scope: sandboxrelay.DecisionScopeAlways,
		}, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("save %s: %d %s", kind, rec.Code, rec.Body.String())
		}
	}
	list := func() []sandboxrelay.Decision {
		rec := f.do(sbxAlice, http.MethodGet, sandboxrelay.PathDecisions+"?registration="+resp.Registration.ID, nil, nil)
		var listed []sandboxrelay.Decision
		if err := json.Unmarshal(rec.Body.Bytes(), &listed); err != nil || rec.Code != http.StatusOK {
			t.Fatalf("decisions: %d %s", rec.Code, rec.Body.String())
		}
		return listed
	}
	if got := list(); len(got) != 2 {
		t.Fatalf("decisions under the loose floor = %+v", got)
	}
	if _, cur := f.current(sbxAlice, resp.Registration.ID); cur.MinProfile == nil || *cur.MinProfile == config.OpenShellProfileStrict {
		t.Fatalf("min_profile before the change = %v", cur.MinProfile)
	}
	next := *f.cfg
	next.OpenShell.Admin.MinProfile = config.OpenShellProfileStrict
	genMu.Lock()
	gen = &Generation{N: 2, Config: &next, Profiles: f.api.guardrailProfileSet()}
	genMu.Unlock()
	code, cur := f.current(sbxAlice, resp.Registration.ID)
	if code != http.StatusOK || cur.MinProfile == nil || *cur.MinProfile != config.OpenShellProfileStrict {
		t.Fatalf("current after the strict change: %d min_profile %v", code, cur.MinProfile)
	}
	if got := list(); len(got) != 1 || got[0].Kind != sandboxrelay.DecisionEgressBlock {
		t.Fatalf("decisions under the strict floor = %+v, want the user block only", got)
	}
}

// A decision past the floor is refused even sent directly; a user block is
// always stored; a session allow is not.
func TestSandboxAuthorityDecisions(t *testing.T) {
	f := newSandboxFixture(t, config.EnterpriseEnrollmentConfig{}, nil)
	f.setGroups(sbxAlice, "dc-sbx-contractors")
	prev := sandboxDecisionCheck
	sandboxDecisionCheck = func(_ config.OpenShellAdminConfig, d sandboxrelay.DecisionRequest) error {
		if d.Scope == sandboxrelay.DecisionScopeAlways {
			return &sandboxreg.DecisionRefusedError{Rule: "user_approvals", Message: "Your organization allows this only for the session."}
		}
		return nil
	}
	t.Cleanup(func() { sandboxDecisionCheck = prev })
	resp := f.live(sbxAlice, 1)
	decide := func(kind, scope string) (int, sandboxrelay.DecisionResult, string) {
		rec := f.do(sbxAlice, http.MethodPost, sandboxrelay.PathDecisions, sandboxrelay.DecisionRequest{
			V: 1, Registration: resp.Registration.ID, Kind: kind, Host: "api.example.com", Scope: scope,
		}, nil)
		var result sandboxrelay.DecisionResult
		_ = json.Unmarshal(rec.Body.Bytes(), &result)
		return rec.Code, result, errorReason(t, rec)
	}
	if code, _, reason := decide(sandboxrelay.DecisionEgressAllow, sandboxrelay.DecisionScopeAlways); code != http.StatusForbidden || reason != sandboxrelay.ReasonDecisionRefused {
		t.Fatalf("always past the floor: %d %s", code, reason)
	}
	// GAP-0504: the refusal is the managed shape, the check's reason a
	// sentence of its own before the contact and the Quote line.
	refusedRec := f.do(sbxAlice, http.MethodPost, sandboxrelay.PathDecisions, sandboxrelay.DecisionRequest{
		V: 1, Registration: resp.Registration.ID, Kind: sandboxrelay.DecisionEgressAllow, Host: "api.example.com", Scope: sandboxrelay.DecisionScopeAlways,
	}, nil)
	var refusal struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(refusedRec.Body.Bytes(), &refusal); err != nil || !sandboxapi.IsPolicyRefusal(refusal.Message) ||
		!strings.Contains(refusal.Message, "Your organization allows this only for the session (") ||
		!strings.Contains(refusal.Message, "rule user_approvals). You can't approve this.\nRequest access: ") ||
		!strings.Contains(refusal.Message, "host api.example.com") || strings.Contains(refusal.Message, "To ask for access") {
		t.Fatalf("refusal = %s", refusedRec.Body.String())
	}
	if code, result, _ := decide(sandboxrelay.DecisionEgressAllow, sandboxrelay.DecisionScopeSession); code != http.StatusOK || result.Stored {
		t.Fatalf("session allow: %d %+v", code, result)
	}
	if code, result, _ := decide(sandboxrelay.DecisionEgressBlock, sandboxrelay.DecisionScopeAlways); code != http.StatusOK || !result.Stored || result.Decision.ID == "" {
		t.Fatalf("user block: %d %+v", code, result)
	}
	rec := f.do(sbxAlice, http.MethodGet, sandboxrelay.PathDecisions+"?registration="+resp.Registration.ID, nil, nil)
	var listed []sandboxrelay.Decision
	if err := json.Unmarshal(rec.Body.Bytes(), &listed); err != nil || rec.Code != http.StatusOK || len(listed) != 1 || listed[0].Kind != sandboxrelay.DecisionEgressBlock {
		t.Fatalf("decisions: %d %s", rec.Code, rec.Body.String())
	}
	if rec := f.do(sbxBob, http.MethodGet, sandboxrelay.PathDecisions+"?registration="+resp.Registration.ID, nil, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("bob lists alice's decisions: %d", rec.Code)
	}
}

// GAP-0559, GAP-0563: a mistake in the user's own repository file, or a
// --pack they may not use, is told to them with the file and the key, in
// explain and in resolve, rather than as the organization's policy failing
// to load.
func TestSandboxAuthorityNamesAMistakeInTheUsersOwnInput(t *testing.T) {
	f := newSandboxFixture(t, config.EnterpriseEnrollmentConfig{}, nil)
	f.setGroups(sbxAlice, "dc-sbx-contractors")
	explain := func(req sandboxrelay.ExplainRequest) (int, string, string) {
		req.V, req.Connector = 1, "claudecode"
		rec := f.do(sbxAlice, http.MethodPost, sandboxrelay.PathPolicyExplain, req, nil)
		var body struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		return rec.Code, errorReason(t, rec), body.Message
	}
	code, reason, msg := explain(sandboxrelay.ExplainRequest{ProjectReal: "/home/ent-alice/project",
		RepoOverlay: []byte("version: 1\nworkdir: {mode: mount}\n")})
	if code != http.StatusForbidden || reason != sandboxrelay.ReasonNotAllowed ||
		!strings.Contains(msg, ".defenseclaw/sandbox.yaml is not valid") || !strings.Contains(msg, "workdir") || strings.Contains(msg, "organization") {
		t.Fatalf("explain with a bad repository file: %d %s %q", code, reason, msg)
	}
	code, reason, msg = explain(sandboxrelay.ExplainRequest{Flags: &sandboxrelay.RunFlags{Pack: "contractors"}})
	if code != http.StatusForbidden || reason != sandboxrelay.ReasonNotAllowed || !strings.Contains(msg, `--pack "contractors" is not a pack this computer can load for you`) {
		t.Fatalf("explain with a pack the user may not use: %d %s %q", code, reason, msg)
	}
	if code, _, _ := explain(sandboxrelay.ExplainRequest{Flags: &sandboxrelay.RunFlags{Pack: "strict"}}); code != http.StatusOK {
		t.Fatalf("explain with --pack strict: %d", code)
	}

	req := claudeResolve()
	req.RepoOverlay = []byte("version: 1\nworkdir: {mode: mount}\n")
	rec := f.do(sbxAlice, http.MethodPost, sandboxrelay.PathPolicyResolve, req, map[string]string{sandboxrelay.ConnectorHeader: req.Connector})
	if rec.Code != http.StatusForbidden || errorReason(t, rec) != sandboxrelay.ReasonNotAllowed || !strings.Contains(rec.Body.String(), "workdir") {
		t.Fatalf("resolve with a bad repository file: %d %s", rec.Code, rec.Body.String())
	}
	req = claudeResolve()
	req.Flags = sandboxrelay.RunFlags{Pack: "contractors"}
	rec = f.do(sbxAlice, http.MethodPost, sandboxrelay.PathPolicyResolve, req, map[string]string{sandboxrelay.ConnectorHeader: req.Connector})
	if rec.Code != http.StatusForbidden || errorReason(t, rec) != sandboxrelay.ReasonNotAllowed {
		t.Fatalf("resolve with a pack the user may not use: %d %s", rec.Code, rec.Body.String())
	}
}

// GAP-0554: the registration keeps which MCP servers its resolve brought
// along and which it left out, so the administrator's view can list them.
func TestSandboxAuthorityResolveKeepsTheMCPJudgment(t *testing.T) {
	prev := sandboxFilterMCP
	sandboxFilterMCP = func(_ context.Context, _ *APIServer, _ managedHookPeer, _ string, claims []sandboxrelay.MCPServerClaim) ([]string, []sandboxrelay.MCPSkip) {
		if len(claims) == 1 && claims[0].Name == "fresh-srv" {
			return []string{"fresh-srv"}, nil
		}
		return []string{"ok-srv"}, []sandboxrelay.MCPSkip{{Name: "blocked-srv", Reason: sandboxrelay.MCPSkipOrganizationBlock}}
	}
	t.Cleanup(func() { sandboxFilterMCP = prev })
	f := newSandboxFixture(t, config.EnterpriseEnrollmentConfig{}, nil)
	f.setGroups(sbxBob, "dc-sbx-devs")
	resp := f.resolve(sbxBob, claudeResolve())
	auth, _ := f.api.sandboxAuth()
	reg, ok, _ := auth.store.Get(sbxBob.UID, resp.Registration.ID)
	if !ok || len(reg.MCPKept) != 1 || reg.MCPKept[0] != "ok-srv" ||
		len(reg.MCPSkipped) != 1 || reg.MCPSkipped[0].Name != "blocked-srv" || reg.MCPSkipped[0].Reason != sandboxrelay.MCPSkipOrganizationBlock {
		t.Fatalf("registration MCP = kept %v skipped %v", reg.MCPKept, reg.MCPSkipped)
	}
	explain := postureExplain(t, f, sbxBob, sandboxrelay.ExplainRequest{Registration: resp.Registration.ID})
	if !slices.Equal(explain.MCPIncluded, reg.MCPKept) || len(explain.MCPBlocked) != 1 ||
		explain.MCPBlocked[0].Name != "blocked-srv" {
		t.Fatalf("registered explain MCP = kept %v blocked %v", explain.MCPIncluded, explain.MCPBlocked)
	}
	explain = postureExplain(t, f, sbxBob, sandboxrelay.ExplainRequest{Registration: resp.Registration.ID,
		MCP: []sandboxrelay.MCPServerClaim{{Name: "fresh-srv", Command: "npx"}}})
	if !slices.Equal(explain.MCPIncluded, []string{"fresh-srv"}) || len(explain.MCPBlocked) != 0 {
		t.Fatalf("registered MCP recheck = kept %v blocked %v", explain.MCPIncluded, explain.MCPBlocked)
	}
}

// uid 0 is refused on every sandbox route even when root is inspected; an
// unenrolled user under unenrolled_users: deny gets no registration; an
// unverified harness version is refused under unverified_versions: refuse;
// a POST without the CSRF header gets the CSRF 403.
func TestSandboxAuthorityRefusals(t *testing.T) {
	f := newSandboxFixture(t, config.EnterpriseEnrollmentConfig{Root: config.EnterpriseRootInspect}, nil)
	f.setGroups(sbxAlice, "dc-sbx-contractors")
	root := managedHookPeer{UID: 0, Name: "root"}
	for _, path := range []string{sandboxrelay.PathSettings, sandboxrelay.PathPolicyResolve, sandboxrelay.PathHookPrefix + "claudecode"} {
		method := http.MethodPost
		if path == sandboxrelay.PathSettings {
			method = http.MethodGet
		}
		if rec := f.do(root, method, path, claudeResolve(), nil); rec.Code != http.StatusForbidden || errorReason(t, rec) != managedHookReasonRootDenied {
			t.Errorf("root on %s: %d %s", path, rec.Code, rec.Body.String())
		}
	}
	rec := f.do(sbxAlice, http.MethodPost, sandboxrelay.PathPolicyResolve, claudeResolve(), map[string]string{sandboxrelay.ClientHeader: ""})
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "X-DefenseClaw-Client") {
		t.Errorf("no CSRF header: %d %s", rec.Code, rec.Body.String())
	}

	strict := newSandboxFixture(t, config.EnterpriseEnrollmentConfig{UnenrolledUsers: config.EnterpriseUnenrolledDeny}, &managedHookLedger{})
	strict.setGroups(sbxAlice, "dc-sbx-contractors")
	if rec := strict.do(sbxAlice, http.MethodPost, sandboxrelay.PathPolicyResolve, claudeResolve(), nil); rec.Code != http.StatusForbidden ||
		errorReason(t, rec) != managedHookReasonUIDUnregistered {
		t.Errorf("unenrolled create: %d %s", rec.Code, rec.Body.String())
	}
	auth, _ := strict.api.sandboxAuth()
	if regs, _ := auth.store.List(sbxAlice.UID); len(regs) != 0 {
		t.Errorf("an unenrolled create registered %d", len(regs))
	}

	refuse := newSandboxFixture(t, config.EnterpriseEnrollmentConfig{UnverifiedVersions: config.EnterpriseUnverifiedRefuse}, nil)
	refuse.setGroups(sbxAlice, "dc-sbx-contractors")
	old := claudeResolve()
	old.HarnessVersion = "0.0.1"
	if rec := refuse.do(sbxAlice, http.MethodPost, sandboxrelay.PathPolicyResolve, old, nil); rec.Code != http.StatusForbidden ||
		errorReason(t, rec) != sandboxrelay.ReasonNotAllowed || !strings.Contains(rec.Body.String(), `"refusal"`) {
		t.Errorf("unverified version: %d %s", rec.Code, rec.Body.String())
	}
	if rec := refuse.do(sbxAlice, http.MethodPost, sandboxrelay.PathPolicyResolve, claudeResolve(), nil); rec.Code != http.StatusOK {
		t.Errorf("verified version: %d %s", rec.Code, rec.Body.String())
	}
	// A sandbox created before refuse was set is held to it on its hooks.
	report := newSandboxFixture(t, config.EnterpriseEnrollmentConfig{}, nil)
	report.setGroups(sbxAlice, "dc-sbx-contractors")
	resp := report.resolve(sbxAlice, old)
	if rec := report.bind(sbxAlice, resp.Registration.ID, 1); rec.Code != http.StatusOK {
		t.Fatalf("bind: %d %s", rec.Code, rec.Body.String())
	}
	report.cfg.Enterprise.Enrollment.UnverifiedVersions = config.EnterpriseUnverifiedRefuse
	report.api.scannerCfg.Enterprise.Enrollment.UnverifiedVersions = config.EnterpriseUnverifiedRefuse
	if rec := report.hook(sbxAlice, resp.Registration.ID, "claudecode", nil); rec.Code != http.StatusForbidden ||
		errorReason(t, rec) != sandboxrelay.ReasonNotAllowed {
		t.Errorf("unverified version on a relayed hook: %d %s", rec.Code, rec.Body.String())
	}
}

// GAP-0175: the settings route sends the bare unavailable reason, so the
// launcher's off message frames it once and ends with one period; the
// resolve refusal is that same sentence.
func TestSandboxUnavailableReasonFramedOnce(t *testing.T) {
	f := newSandboxFixture(t, config.EnterpriseEnrollmentConfig{}, nil)
	f.setGroups(sbxAlice, "dc-sbx-contractors")
	sandboxHostAvailability = func(*config.Config, managedHookPeer, config.OpenShellAdminConfig) sandboxAvailability {
		return sandboxUnavailable(sandboxUnavailableNoOpenShell)
	}
	rec := f.do(sbxAlice, http.MethodGet, sandboxrelay.PathSettings, nil, nil)
	var settings sandboxrelay.DaemonSettings
	if err := json.Unmarshal(rec.Body.Bytes(), &settings); rec.Code != http.StatusOK || err != nil {
		t.Fatalf("settings: %d %s", rec.Code, rec.Body.String())
	}
	if settings.Available || settings.Unavailable != sandboxUnavailableNoOpenShell {
		t.Fatalf("settings unavailable = %q, want the bare reason", settings.Unavailable)
	}
	off := (&sandboxapi.Status{Managed: &sandboxapi.ManagedStatus{Unavailable: settings.Unavailable}}).OffMessage()
	if strings.Count(off, "aren't available on this computer") != 1 || strings.Contains(off, "..") ||
		!strings.HasPrefix(off, "Sandboxes aren't available on this computer: OpenShell is not installed. ") {
		t.Fatalf("off message = %q", off)
	}
	rec = f.do(sbxAlice, http.MethodPost, sandboxrelay.PathPolicyResolve, claudeResolve(), nil)
	var refused sandboxrelay.ResolveResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &refused); err != nil || refused.Refusal == nil ||
		refused.Refusal.Message != sandboxapi.UnavailableSentence(sandboxUnavailableNoOpenShell) {
		t.Fatalf("resolve refusal: %d %s", rec.Code, rec.Body.String())
	}
	if got := sandboxapi.UnavailableSentence("this computer has no KVM."); got != "Sandboxes aren't available on this computer: this computer has no KVM." {
		t.Fatalf("a reason with its own period: %q", got)
	}
}

// Budgets (GAP-0023): a flood of relayed hooks exhausts only the
// sandbox-hook class; the same uid's create and host hooks still pass.
// Events are bounded at 1/s burst 5.
func TestSandboxAuthorityBudgets(t *testing.T) {
	f := newSandboxFixture(t, config.EnterpriseEnrollmentConfig{}, nil)
	f.setGroups(sbxAlice, "dc-sbx-contractors")
	frozen := time.Now()
	f.api.hookCallerLimits.now = func() time.Time { return frozen }
	resp := f.live(sbxAlice, 1)
	limited := 0
	var refusal *httptest.ResponseRecorder
	for range 210 {
		if rec := f.hook(sbxAlice, resp.Registration.ID, "claudecode", nil); rec.Code == http.StatusTooManyRequests {
			limited++
			refusal = rec
		}
	}
	if limited == 0 || refusal.Header().Get("Retry-After") == "" || !strings.Contains(refusal.Body.String(), managedHookReasonRateLimited) {
		t.Fatalf("sandbox-hook flood: %d refused", limited)
	}
	if again := f.resolve(sbxAlice, claudeResolve()); again.Registration.ID == "" {
		t.Fatal("create during a hook flood")
	}
	_, release := f.api.admitHookCaller(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook", nil), strconv.Itoa(sbxAlice.UID), "hook")
	if release == nil {
		t.Fatal("a host hook was refused during a sandbox hook flood")
	}
	release()
	events := 0
	for range sandboxBudgetLimits[sandboxBudgetEvents].Burst + 1 {
		rec := f.do(sbxAlice, http.MethodPost, sandboxrelay.PathEvents, sandboxrelay.EventBatch{
			V: 1, Registration: resp.Registration.ID, Events: []sandboxrelay.Event{{Kind: sandboxrelay.EventSettingsDrift}},
		}, nil)
		if rec.Code == http.StatusTooManyRequests {
			events++
		} else if rec.Code != http.StatusAccepted {
			t.Fatalf("events: %d %s", rec.Code, rec.Body.String())
		}
	}
	if events != 1 {
		t.Fatalf("events past the burst: %d refused, want 1", events)
	}
}

func TestSandboxBudgetKeys(t *testing.T) {
	for path, want := range map[string]string{
		"/api/v1/claudecode/hook":                           "1001",
		sandboxrelay.PathHookPrefix + "claudecode":          "1001|" + sandboxBudgetHook,
		sandboxrelay.PathNotifyPrefix + "codex":             "1001|" + sandboxBudgetHook,
		sandboxrelay.PathInspectPrefix + "tool":             "1001|" + sandboxBudgetHook,
		sandboxrelay.PathPolicyResolve:                      "1001|" + sandboxBudgetPolicy,
		sandboxrelay.PathSettings:                           "1001|" + sandboxBudgetPolicy,
		sandboxrelay.PathRegistrations + "reg-x/bind":       "1001|" + sandboxBudgetPolicy,
		sandboxrelay.PathDecisions:                          "1001|" + sandboxBudgetPolicy,
		sandboxrelay.PathEvents:                             "1001|" + sandboxBudgetEvents,
		sandboxrelay.PathOTLPPrefix + sandboxrelay.OTLPLogs: "1001" + hookCallerTelemetryBudget,
		"/v1/logs": "1001" + hookCallerTelemetryBudget,
	} {
		if got := hookCallerBudgetKey("1001", path); got != want {
			t.Errorf("%s: key %q, want %q", path, got, want)
		}
	}
	var l hookCallerLimiter
	if rps, burst, inFlight, _ := l.limits("1001|" + sandboxBudgetEvents); rps != 2 || burst != 8 || inFlight != 2 {
		t.Fatalf("events limits %d/%d/%d", rps, burst, inFlight)
	}
	if rps, burst, _, _ := l.limits("1001"); rps != hookCallerRate || burst != hookCallerBurst {
		t.Fatalf("host limits %d/%d", rps, burst)
	}
	if sandboxRouteBodyLimit(sandboxrelay.PathOTLPPrefix+"logs") != sandboxrelay.MaxOTLPBodyBytes ||
		sandboxRouteBodyLimit(sandboxrelay.PathEvents) != sandboxrelay.MaxEventBatchBytes ||
		sandboxRouteBodyLimit(sandboxrelay.PathPolicyResolve) != sandboxrelay.MaxResolveBytes ||
		sandboxRouteBodyLimit("/api/v1/claudecode/hook") != 0 {
		t.Fatal("sandbox route body limits")
	}
}

func TestSandboxSubjectKeyIgnoresDirectoryFacts(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	a := sandboxSubjectKey(key, 1001, "Alice", "")
	if a != sandboxSubjectKey(key, 1001, "alice", "") || !strings.HasPrefix(a, sandboxreg.DigestPrefix) {
		t.Fatalf("subject key %q", a)
	}
	if a == sandboxSubjectKey(key, 1002, "alice", "") || a == sandboxSubjectKey(key, 1001, "bob", "") ||
		a == sandboxSubjectKey(bytes.Repeat([]byte{2}, 32), 1001, "alice", "") {
		t.Fatal("subject key collides")
	}
	cold := sandboxFactsDigest(key, useridentity.DirectoryFacts{}, false)
	warm := sandboxFactsDigest(key, useridentity.DirectoryFacts{Principal: "alice@X", Groups: []string{"b", "a"}}, true)
	if cold == warm || warm != sandboxFactsDigest(key, useridentity.DirectoryFacts{Principal: "alice@X", Groups: []string{"A", "B"}}, true) {
		t.Fatal("facts digest is not order- and case-stable or misses a change")
	}
}

// The resolve decoder and validator take any bytes without panicking, and
// what they accept is bounded.
func FuzzSandboxResolveDecoder(f *testing.F) {
	seed, _ := json.Marshal(claudeResolve())
	f.Add(seed)
	f.Add([]byte(`{"v":1,"harness":"claudecode","connector":"claudecode","project_real":"/a/../b"}`))
	f.Add([]byte(`{"v":1,"mcp":[{"name":""}],"flags":{"host_ports":[0]}}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		var req sandboxrelay.ResolveRequest
		if dec.Decode(&req) != nil {
			return
		}
		if validateSandboxResolve(&req) != "" {
			return
		}
		if !sandboxCleanAbsPath(req.ProjectReal) || len(req.MCP) > sandboxMCPClaimsMax || sandboxConnectorClaim(req.Connector) == "" {
			t.Fatalf("accepted %+v", req)
		}
	})
}

// No registration or files header value admits a relayed call except the
// caller's own live registration id: not another uid's live one, not the
// caller's revoked one, not a forged or malformed one.
func FuzzSandboxRelayHeaders(f *testing.F) {
	fx := newSandboxFixture(f, config.EnterpriseEnrollmentConfig{}, nil)
	fx.setGroups(sbxAlice, "dc-sbx-contractors")
	fx.setGroups(sbxBob, "dc-sbx-devs")
	own := fx.live(sbxAlice, 1).Registration.ID
	revoked := fx.live(sbxAlice, 2).Registration.ID
	bobs := fx.live(sbxBob, 3).Registration.ID
	auth, err := fx.api.sandboxAuth()
	if err != nil {
		f.Fatal(err)
	}
	if err := auth.store.Revoke(sbxAlice.UID, revoked, "regrouped"); err != nil {
		f.Fatal(err)
	}
	if rec := fx.hook(sbxAlice, own, "claudecode", nil); rec.Code != http.StatusOK {
		f.Fatalf("own live registration: %d %s", rec.Code, rec.Body.String())
	}
	for _, seed := range []string{own, revoked, bobs, "reg-aaaaaaaaaaaaaaaaaaaaaaaaaa", "../../x", "", " " + own, strings.ToUpper(own)} {
		f.Add(seed, "")
		f.Add(seed, "1")
	}
	f.Fuzz(func(t *testing.T, registration, files string) {
		// The fixture's helpers report through f, which a fuzz target must
		// not call: build the relayed call here.
		req := httptest.NewRequest(http.MethodPost, sandboxrelay.PathHookPrefix+"claudecode", strings.NewReader(`{"hook_event_name":"PreToolUse"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(sandboxrelay.ClientHeader, sandboxrelay.ClientHeaderValue)
		req.Header.Set(sandboxrelay.DaemonContractHeader, strconv.Itoa(sandboxrelay.DaemonContract))
		req.Header.Set(sandboxrelay.RegistrationHeader, registration)
		if files != "" {
			req.Header.Set(sandboxrelay.FilesHeader, files)
		}
		rec := httptest.NewRecorder()
		fx.handler.ServeHTTP(rec, req.WithContext(withManagedHookPeer(req.Context(), sbxAlice)))
		if rec.Code == http.StatusOK && (strings.TrimSpace(registration) != own || files != "") {
			t.Fatalf("registration %q files %q admitted a relayed call", registration, files)
		}
	})
}
