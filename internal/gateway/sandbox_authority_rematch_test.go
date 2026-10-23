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
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/sandboxreg"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// publishFirstGeneration gives f's API server a generation source that
// answers N=1 for f.cfg, as every freshly started gateway process does
// before its first hot swap.
func (f *sandboxFixture) publishFirstGeneration() {
	f.t.Helper()
	set, err := newGuardrailProfileSet(f.cfg, nil, false)
	if err != nil {
		f.t.Fatal(err)
	}
	gen := &Generation{N: 1, Config: f.cfg, Profiles: set}
	f.api.SetGenerationSource(func() *Generation { return gen })
}

func (f *sandboxFixture) rematches() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.Join(f.rematched, ";")
}

// GAP-1288: two gateway processes on one data directory, both at
// generation N=1 but with different profile assignments. The registration
// the first one made is re-matched by the second; a third with the same
// policy as the second re-matches nothing.
func TestSandboxAuthorityRematchAcrossRestart(t *testing.T) {
	f := newSandboxFixture(t, config.EnterpriseEnrollmentConfig{}, nil)
	f.setGroups(sbxAlice, "dc-sbx-contractors")
	f.publishFirstGeneration()
	resp := f.live(sbxAlice, 1)
	if resp.Banner.Profile != "contractors" {
		t.Fatalf("first process: %+v", resp.Banner)
	}

	moved := newSandboxFixtureOn(t, f)
	moved.cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{
		{Profile: "engineering", Match: config.ProfileMatch{Groups: []string{"dc-sbx-contractors"}}},
	}
	moved.publishFirstGeneration()
	rec := moved.hook(sbxAlice, resp.Registration.ID, "claudecode", nil)
	if rec.Code != http.StatusOK || rec.Header().Get(sandboxrelay.ProfileHeader) != "engineering" {
		t.Fatalf("hook after a restart with new assignments: %d %s %v", rec.Code, rec.Body.String(), rec.Header())
	}
	auth, _ := moved.api.sandboxAuth()
	if reg, _, _ := auth.store.Get(sbxAlice.UID, resp.Registration.ID); reg.Profile != "engineering" || reg.Generation != 1 {
		t.Fatalf("re-matched registration: %+v", reg)
	}
	if !strings.Contains(moved.rematches(), resp.Registration.ID+":live:profile") {
		t.Fatalf("re-match record: %q", moved.rematches())
	}

	same := newSandboxFixtureOn(t, moved)
	same.cfg.Guardrail.ProfileAssignments = moved.cfg.Guardrail.ProfileAssignments
	same.publishFirstGeneration()
	if rec := same.hook(sbxAlice, resp.Registration.ID, "claudecode", nil); rec.Code != http.StatusOK ||
		rec.Header().Get(sandboxrelay.ProfileHeader) != "engineering" {
		t.Fatalf("hook after a restart with the same policy: %d %v", rec.Code, rec.Header())
	}
	if got := same.rematches(); got != "" {
		t.Fatalf("an unchanged policy re-matched across a restart: %q", got)
	}
}

// A stop a re-match asked for revokes the registration at once (GAP-0623,
// GAP-0644): it admits no hook, the daemon is told the stop, and a policy
// relaxed again does not bring it back, in this process or after a restart.
func TestSandboxAuthorityStopRevokesAtOnce(t *testing.T) {
	f := newSandboxFixture(t, config.EnterpriseEnrollmentConfig{}, nil)
	f.setGroups(sbxAlice, "dc-sbx-contractors")
	f.publishFirstGeneration()
	resp := f.live(sbxAlice, 1)

	no := false
	refused := newSandboxFixtureOn(t, f)
	refused.cfg.OpenShell.Admin.Allowed = &no
	refused.cfg.OpenShell.Admin.RequestAccess = "sandbox-access@example.invalid"
	refused.publishFirstGeneration()
	// The first hook after the policy changed is refused: the registration is
	// revoked, not left live for a grace period.
	if rec := refused.hook(sbxAlice, resp.Registration.ID, "claudecode", nil); rec.Code != http.StatusGone ||
		errorReason(t, rec) != sandboxrelay.ReasonRegistrationRevoked {
		t.Fatalf("hook after sandboxes were disallowed: %d %s", rec.Code, rec.Body.String())
	}
	auth, _ := refused.api.sandboxAuth()
	if reg, _, _ := auth.store.Get(sbxAlice.UID, resp.Registration.ID); reg.State != sandboxreg.StateRevoked || reg.RevokedReason != sandboxreg.ReasonPolicyChanged {
		t.Fatalf("revoked registration: %+v", reg)
	}
	code, cur := refused.current(sbxAlice, resp.Registration.ID)
	if code != http.StatusOK || !cur.Revoked || !strings.Contains(cur.RevokedReason, "Request access: sandbox-access@example.invalid.") ||
		!strings.Contains(cur.RevokedReason, "sandboxes") || strings.Contains(cur.RevokedReason, "Start it again") {
		t.Fatalf("current after sandboxes were disallowed: %d %+v", code, cur)
	}

	// The policy is relaxed again, in a new process: still revoked, with the
	// same text.
	later := newSandboxFixtureOn(t, refused)
	later.publishFirstGeneration()
	if rec := later.hook(sbxAlice, resp.Registration.ID, "claudecode", nil); rec.Code != http.StatusGone {
		t.Fatalf("a revoked registration came back after the policy was relaxed: %d %s", rec.Code, rec.Body.String())
	}
	if code, again := later.current(sbxAlice, resp.Registration.ID); code != http.StatusOK || !again.Revoked || again.RevokedReason != cur.RevokedReason {
		t.Fatalf("the stop was lost across a restart: %d %+v", code, again)
	}
}

// GAP-0467: a sandbox created with --host-port under engineering kept its
// host port after a regroup to a profile with allow_host_ports false. The
// re-match revokes it with the stop that names host ports, and a regroup
// back does not take that back.
func TestSandboxAuthorityRegroupStopsAnOpenedHostPort(t *testing.T) {
	f := newSandboxFixture(t, config.EnterpriseEnrollmentConfig{}, nil)
	no := false
	f.cfg.Guardrail.Profiles["contractors"] = config.GuardrailProfile{Description: "Contractors",
		Sandbox: &config.OpenShellAdminConfig{AllowHostPorts: &no}}
	f.setGroups(sbxBob, "dc-sbx-devs")
	req := claudeResolve()
	req.Flags = sandboxrelay.RunFlags{Pack: "open", HostPorts: []int{5432}}
	resp := f.resolve(sbxBob, req)
	if rec := f.bind(sbxBob, resp.Registration.ID, 1); rec.Code != http.StatusOK {
		t.Fatalf("bind: %d %s", rec.Code, rec.Body.String())
	}
	auth, _ := f.api.sandboxAuth()
	if run, _, _ := auth.store.Run(sbxBob.UID, resp.Registration.ID); !slices.Equal(run.HostPorts, []int{5432}) {
		t.Fatalf("host ports the create opened = %v", run.HostPorts)
	}

	f.setGroups(sbxBob, "dc-sbx-contractors")
	code, cur := f.current(sbxBob, resp.Registration.ID)
	const want = "This sandbox was stopped: your profile no longer allows host ports. Start it again without --host-port: "
	if code != http.StatusOK || !cur.Revoked || !strings.HasPrefix(cur.RevokedReason, want) {
		t.Fatalf("current after the regroup: %d %+v", code, cur)
	}
	if !strings.Contains(f.rematches(), resp.Registration.ID+":stop:") {
		t.Fatalf("re-match record: %q", f.rematches())
	}

	f.setGroups(sbxBob, "dc-sbx-devs")
	if code, cur := f.current(sbxBob, resp.Registration.ID); code != http.StatusOK || !cur.Revoked || !strings.HasPrefix(cur.RevokedReason, want) {
		t.Fatalf("current after the regroup back: %d %+v", code, cur)
	}

	// A port the floor refused at create was never opened: no stop is owed.
	f.setGroups(sbxAlice, "dc-sbx-contractors")
	refused := f.resolve(sbxAlice, req)
	if run, _, _ := auth.store.Run(sbxAlice.UID, refused.Registration.ID); len(run.HostPorts) != 0 {
		t.Fatalf("host ports opened under allow_host_ports false = %v", run.HostPorts)
	}
}

// GAP-0078: on a managed computer a --host-port the policy does not open is
// a fatal violation (GAP-0558), so the re-match of a sandbox created with
// one under a profile that allows host ports stopped it after a regroup to
// a profile that does not with "no longer allows the settings this sandbox
// was started with". The stop now names host ports and says to start again
// without --host-port.
func TestSandboxAuthorityManagedRegroupNamesTheHostPortStop(t *testing.T) {
	f := newSandboxFixture(t, config.EnterpriseEnrollmentConfig{}, nil)
	f.cfg.DeploymentMode = string(config.DeploymentModeManagedEnterprise)
	no := false
	f.cfg.Guardrail.Profiles["contractors"] = config.GuardrailProfile{Description: "Contractors",
		Sandbox: &config.OpenShellAdminConfig{AllowHostPorts: &no}}
	f.setGroups(sbxBob, "dc-sbx-devs")
	req := claudeResolve()
	req.Flags = sandboxrelay.RunFlags{Pack: "open", HostPorts: []int{5432}}
	resp := f.resolve(sbxBob, req)
	if rec := f.bind(sbxBob, resp.Registration.ID, 1); rec.Code != http.StatusOK {
		t.Fatalf("bind: %d %s", rec.Code, rec.Body.String())
	}
	f.setGroups(sbxBob, "dc-sbx-contractors")
	code, cur := f.current(sbxBob, resp.Registration.ID)
	const want = "This sandbox was stopped: your profile no longer allows host ports. Start it again without --host-port: "
	if code != http.StatusOK || !cur.Revoked || !strings.HasPrefix(cur.RevokedReason, want) {
		t.Fatalf("current after the regroup: %d %+v", code, cur)
	}
}

// sandboxRematchStopField names host ports only when they are all a run
// violates (GAP-0078).
func TestSandboxRematchStopField(t *testing.T) {
	hostPort := packs.Violation{Key: sandboxHostPortsKey, Attempted: "5432", Fatal: true}
	yolo := packs.Violation{Key: "yolo", Attempted: "on", Fatal: true}
	for _, tc := range []struct {
		name         string
		violations   []packs.Violation
		opened, open []int
		want         string
	}{
		{"nothing", nil, []int{5432}, []int{5432}, ""},
		{"a warning only", []packs.Violation{{Key: "yolo"}}, nil, nil, ""},
		{"an opened port closed", nil, []int{5432}, nil, sandboxStopFieldHostPorts},
		{"a refused --host-port", []packs.Violation{hostPort}, []int{5432}, nil, sandboxStopFieldHostPorts},
		{"a refused --host-port and another fatal one", []packs.Violation{hostPort, yolo}, []int{5432}, nil, sandboxStopFieldSettings},
		{"another fatal one first", []packs.Violation{yolo, hostPort}, nil, nil, sandboxStopFieldSettings},
	} {
		if got := sandboxRematchStopField(tc.violations, tc.opened, tc.open); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
}

func (f *sandboxFixture) deleted(peer managedHookPeer, id string) int {
	return f.do(peer, http.MethodPost, sandboxrelay.PathRegistrations+id+sandboxrelay.RegistrationDelSub, []byte(`{}`), nil).Code
}

// rebind registers a fresh run and binds it to sandbox n again.
func (f *sandboxFixture) rebind(peer managedHookPeer, n int) int {
	f.t.Helper()
	return f.bind(peer, f.resolve(peer, claudeResolve()).Registration.ID, n).Code
}

// GAP-1290: deleted never lets a sandbox the gateway revoked register
// again, and only the registering account may report it.
func TestSandboxAuthorityDeleted(t *testing.T) {
	prev := sandboxBudgetLimits[sandboxBudgetPolicy]
	sandboxBudgetLimits[sandboxBudgetPolicy] = sandboxBudgetLimit{Rate: 1000, Burst: 1000, InFlight: 8}
	t.Cleanup(func() { sandboxBudgetLimits[sandboxBudgetPolicy] = prev })
	f := newSandboxFixture(t, config.EnterpriseEnrollmentConfig{}, nil)
	f.setGroups(sbxAlice, "dc-sbx-contractors")
	auth, err := f.api.sandboxAuth()
	if err != nil {
		t.Fatal(err)
	}

	// A pending registration is dropped.
	pending := f.resolve(sbxAlice, claudeResolve())
	if code := f.deleted(sbxAlice, pending.Registration.ID); code != http.StatusNoContent {
		t.Fatalf("deleted pending: %d", code)
	}
	if _, ok, _ := auth.store.Get(sbxAlice.UID, pending.Registration.ID); ok {
		t.Fatal("a deleted pending registration is kept")
	}

	// A live one becomes a tombstone: its hooks stop and its sandbox
	// can't register again until the tombstone is dropped too.
	own := f.live(sbxAlice, 1)
	if code := f.deleted(sbxAlice, own.Registration.ID); code != http.StatusNoContent {
		t.Fatalf("deleted live: %d", code)
	}
	if rec := f.hook(sbxAlice, own.Registration.ID, "claudecode", nil); rec.Code != http.StatusGone {
		t.Fatalf("hook of a deleted sandbox: %d", rec.Code)
	}
	if code := f.rebind(sbxAlice, 1); code != http.StatusGone {
		t.Fatalf("re-bind of a deleted live sandbox: %d", code)
	}
	if code := f.deleted(sbxAlice, own.Registration.ID); code != http.StatusNoContent {
		t.Fatalf("deleted tombstone: %d", code)
	}
	if code := f.rebind(sbxAlice, 1); code != http.StatusOK {
		t.Fatalf("the user's own deleted sandbox ids after its tombstone went: %d", code)
	}

	// A gateway revocation: dropping the tombstone retires its ids.
	revoked := f.live(sbxAlice, 2)
	if err := auth.store.Revoke(sbxAlice.UID, revoked.Registration.ID, "regrouped"); err != nil {
		t.Fatal(err)
	}
	if code := f.deleted(sbxAlice, revoked.Registration.ID); code != http.StatusNoContent {
		t.Fatalf("deleted a revoked tombstone: %d", code)
	}
	if code := f.rebind(sbxAlice, 2); code != http.StatusGone {
		t.Fatalf("re-bind of a revoked sandbox after deleted: %d", code)
	}

	// Another account behind the uid: 409, the registration is revoked
	// and kept, and its ids stay refused.
	theirs := f.live(sbxAlice, 4)
	mallory := managedHookPeer{UID: sbxAlice.UID, Name: "mallory"}
	if rec := f.do(mallory, http.MethodPost, sandboxrelay.PathRegistrations+theirs.Registration.ID+sandboxrelay.RegistrationDelSub, []byte(`{}`), nil); rec.Code != http.StatusConflict ||
		errorReason(t, rec) != sandboxrelay.ReasonSubjectChanged {
		t.Fatalf("deleted by another account: %d %s", rec.Code, rec.Body.String())
	}
	if code := f.deleted(mallory, theirs.Registration.ID); code != http.StatusConflict {
		t.Fatalf("another account drops the tombstone: %d", code)
	}
	if reg, ok, _ := auth.store.Get(sbxAlice.UID, theirs.Registration.ID); !ok || reg.RevokedReason != sandboxrelay.ReasonSubjectChanged {
		t.Fatalf("subject_changed tombstone: %+v %v", reg, ok)
	}
	_ = f.deleted(sbxAlice, theirs.Registration.ID)
	if code := f.rebind(sbxAlice, 4); code != http.StatusGone {
		t.Fatalf("re-bind after a subject change: %d", code)
	}
}

// Explain, test and packs answer only the caller's own registration and
// pack chain.
func TestSandboxAuthorityPolicyPrivacy(t *testing.T) {
	f := newSandboxFixture(t, config.EnterpriseEnrollmentConfig{}, nil)
	f.setGroups(sbxAlice, "dc-sbx-contractors")
	f.setGroups(sbxBob, "dc-sbx-devs")
	alice := f.live(sbxAlice, 1).Registration.ID
	bob := f.live(sbxBob, 2).Registration.ID

	explain := func(peer managedHookPeer, id string) (int, map[string]any) {
		rec := f.do(peer, http.MethodPost, sandboxrelay.PathPolicyExplain, sandboxrelay.ExplainRequest{V: 1, Registration: id}, nil)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}
	if code, out := explain(sbxAlice, alice); code != http.StatusOK || out["profile"] != "contractors" {
		t.Fatalf("alice's explain: %d %v", code, out)
	}
	if code, out := explain(sbxAlice, bob); code != http.StatusNotFound || out["profile"] != nil {
		t.Fatalf("alice explains bob's registration: %d %v", code, out)
	}
	test := f.do(sbxAlice, http.MethodPost, sandboxrelay.PathPolicyTest, map[string]any{"v": 1, "checks": []map[string]any{{"host": "example.com", "port": 443}}},
		map[string]string{sandboxrelay.RegistrationHeader: bob})
	if test.Code != http.StatusNotFound {
		t.Fatalf("alice tests bob's policy: %d %s", test.Code, test.Body.String())
	}
	if rec := f.do(sbxAlice, http.MethodGet, sandboxrelay.PathPolicyPacks, nil, map[string]string{sandboxrelay.RegistrationHeader: bob}); rec.Code != http.StatusNotFound {
		t.Fatalf("alice lists bob's packs: %d %s", rec.Code, rec.Body.String())
	}
	rec := f.do(sbxAlice, http.MethodGet, sandboxrelay.PathPolicyPacks, nil, map[string]string{sandboxrelay.RegistrationHeader: alice})
	var views []sandboxrelay.PackView
	if err := json.Unmarshal(rec.Body.Bytes(), &views); rec.Code != http.StatusOK || err != nil || len(views) == 0 {
		t.Fatalf("alice's packs: %d %s", rec.Code, rec.Body.String())
	}
	inChain := func(name string) bool {
		return slices.ContainsFunc(views, func(v sandboxrelay.PackView) bool { return v.Name == name })
	}
	for _, name := range append(packs.BuiltinNames(), "no-such-pack") {
		if inChain(name) {
			continue
		}
		rec := f.do(sbxAlice, http.MethodGet, sandboxrelay.PathPolicyPacks+"/"+name, nil, map[string]string{sandboxrelay.RegistrationHeader: alice})
		if rec.Code != http.StatusNotFound || strings.Contains(rec.Body.String(), `"content"`) {
			t.Errorf("pack %q outside alice's chain: %d %s", name, rec.Code, rec.Body.String())
		}
	}
}

// unenrolled_users: deny refuses every sandbox route of an account that
// is no longer enrolled, settings without a claim included; an enrolled
// account reads its settings without naming a connector.
func TestSandboxAuthorityUnenrolledDenyEveryRoute(t *testing.T) {
	uid := sbxAlice.UID
	ledger := &managedHookLedger{Targets: []managedHookLedgerTarget{{UID: &uid, Connector: "claudecode", OK: true}}}
	f := newSandboxFixture(t, config.EnterpriseEnrollmentConfig{UnenrolledUsers: config.EnterpriseUnenrolledDeny}, ledger)
	f.setGroups(sbxAlice, "dc-sbx-contractors")
	if rec := f.do(sbxAlice, http.MethodGet, sandboxrelay.PathSettings, nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("enrolled settings: %d %s", rec.Code, rec.Body.String())
	}
	live := f.live(sbxAlice, 1).Registration.ID
	pending := f.resolve(sbxAlice, claudeResolve()).Registration.ID
	ledger.Targets = nil

	for name, rec := range map[string]func() int{
		"settings": func() int { return f.do(sbxAlice, http.MethodGet, sandboxrelay.PathSettings, nil, nil).Code },
		"bind":     func() int { return f.bind(sbxAlice, pending, 2).Code },
		"current":  func() int { code, _ := f.current(sbxAlice, live); return code },
		"decisions": func() int {
			return f.do(sbxAlice, http.MethodGet, sandboxrelay.PathDecisions+"?registration="+live, nil, nil).Code
		},
		"decide": func() int {
			return f.do(sbxAlice, http.MethodPost, sandboxrelay.PathDecisions, sandboxrelay.DecisionRequest{
				V: 1, Registration: live, Kind: sandboxrelay.DecisionEgressBlock, Host: "x.example", Scope: sandboxrelay.DecisionScopeAlways,
			}, nil).Code
		},
		"events": func() int {
			return f.do(sbxAlice, http.MethodPost, sandboxrelay.PathEvents, sandboxrelay.EventBatch{
				V: 1, Registration: live, Events: []sandboxrelay.Event{{Kind: sandboxrelay.EventSettingsDrift}},
			}, nil).Code
		},
		"deleted": func() int { return f.deleted(sbxAlice, live) },
		"hook":    func() int { return f.hook(sbxAlice, live, "claudecode", nil).Code },
	} {
		if code := rec(); code != http.StatusForbidden {
			t.Errorf("%s for an unenrolled account: %d", name, code)
		}
	}
}

// GAP-0109: no registration without an account name, and a later call
// whose account name can't be looked up is refused without revoking.
func TestSandboxAuthorityNeedsAnAccountName(t *testing.T) {
	f := newSandboxFixture(t, config.EnterpriseEnrollmentConfig{}, nil)
	f.setGroups(sbxAlice, "dc-sbx-contractors")
	nameless := managedHookPeer{UID: sbxAlice.UID}
	req := claudeResolve()
	rec := f.do(nameless, http.MethodPost, sandboxrelay.PathPolicyResolve, req, nil)
	if rec.Code != http.StatusServiceUnavailable || errorReason(t, rec) != sandboxrelay.ReasonUnavailable {
		t.Fatalf("resolve without an account name: %d %s", rec.Code, rec.Body.String())
	}
	live := f.live(sbxAlice, 1).Registration.ID
	if rec := f.hook(nameless, live, "claudecode", nil); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("hook without an account name: %d %s", rec.Code, rec.Body.String())
	}
	if rec := f.hook(sbxAlice, live, "claudecode", nil); rec.Code != http.StatusOK {
		t.Fatalf("the registration must be kept: %d %s", rec.Code, rec.Body.String())
	}
	if sandboxSubjectMatches([]byte("k"), sandboxreg.Registration{UID: sbxAlice.UID}, sbxAlice) {
		t.Fatal("a registration without an account name matched")
	}
}

// Every sandbox route needs the CSRF client header, GET included.
func TestSandboxAuthorityGetNeedsClientHeader(t *testing.T) {
	f := newSandboxFixture(t, config.EnterpriseEnrollmentConfig{}, nil)
	f.setGroups(sbxAlice, "dc-sbx-contractors")
	live := f.live(sbxAlice, 1).Registration.ID
	for _, path := range []string{sandboxrelay.PathSettings, sandboxrelay.PathPolicyCurrent + "?registration=" + live,
		sandboxrelay.PathDecisions + "?registration=" + live, sandboxrelay.PathPolicyPacks} {
		rec := f.do(sbxAlice, http.MethodGet, path, nil, map[string]string{sandboxrelay.ClientHeader: ""})
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "X-DefenseClaw-Client") {
			t.Errorf("GET %s without the client header: %d %s", path, rec.Code, rec.Body.String())
		}
	}
}

// A first call that can't load the authority's key fails closed, and the
// next call tries again instead of answering 503 until a restart.
func TestSandboxAuthorityInitRetries(t *testing.T) {
	f := newSandboxFixture(t, config.EnterpriseEnrollmentConfig{}, nil)
	f.setGroups(sbxAlice, "dc-sbx-contractors")
	working := sandboxAuthorityKey
	sandboxAuthorityKey = func(string) ([]byte, error) { return nil, errors.New("key not readable yet") }
	rec := f.do(sbxAlice, http.MethodPost, sandboxrelay.PathPolicyResolve, claudeResolve(), nil)
	sandboxAuthorityKey = working
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("resolve without a key: %d %s", rec.Code, rec.Body.String())
	}
	if resp := f.resolve(sbxAlice, claudeResolve()); resp.Registration.ID == "" {
		t.Fatal("no registration once the key loads")
	}
}

// GAP-1289: the run inputs live in the uid's own store file, bounded per
// uid; another account's registrations never evict them.
func TestSandboxAuthorityRunInputsArePerUID(t *testing.T) {
	f := newSandboxFixture(t, config.EnterpriseEnrollmentConfig{}, nil)
	f.setGroups(sbxAlice, "dc-sbx-contractors")
	f.setGroups(sbxBob, "dc-sbx-devs")
	req := claudeResolve()
	req.Flags.Safe = true
	alice := f.resolve(sbxAlice, req).Registration.ID
	for range 15 {
		f.resolve(sbxBob, claudeResolve())
	}
	auth, _ := f.api.sandboxAuth()
	run, ok, err := auth.store.Run(sbxAlice.UID, alice)
	if err != nil || !ok || !run.Flags.Safe || run.PolicyKey == "" || run.FloorDigest == "" {
		t.Fatalf("alice's run record: %+v %v %v", run, ok, err)
	}
	restarted := newSandboxFixtureOn(t, f)
	again, _ := restarted.api.sandboxAuth()
	if run, ok, _ := again.store.Run(sbxAlice.UID, alice); !ok || !run.Flags.Safe {
		t.Fatalf("run record after a restart: %+v %v", run, ok)
	}
}

// sandboxStoreWriteFails is a registration store whose Revoke, or
// UpdateRun too, fails with an I/O error, as an unwritable registration
// directory does.
type sandboxStoreWriteFails struct {
	sandboxRegistrationStore
	updateRun bool
}

func (s sandboxStoreWriteFails) Revoke(int, string, string) error {
	return errors.New("input/output error")
}

func (s sandboxStoreWriteFails) UpdateRun(uid int, r sandboxreg.Registration, run *sandboxreg.Run) error {
	if s.updateRun {
		return errors.New("input/output error")
	}
	return s.sandboxRegistrationStore.UpdateRun(uid, r, run)
}

// GAP-0657: a verified re-match that finds sandboxes no longer allowed
// refuses the relayed call even when the revoke (or the stop before it)
// can't be written, and the next call, with the store writable again,
// stores the revoke.
func TestSandboxAuthorityStopFailsClosedWhenTheRevokeIsNotStored(t *testing.T) {
	for _, tc := range []struct {
		name      string
		updateRun bool
	}{{"revoke fails", false}, {"stop and revoke fail", true}} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSandboxFixture(t, config.EnterpriseEnrollmentConfig{}, nil)
			f.setGroups(sbxAlice, "dc-sbx-contractors")
			f.publishFirstGeneration()
			resp := f.live(sbxAlice, 1)

			no := false
			refused := newSandboxFixtureOn(t, f)
			refused.cfg.OpenShell.Admin.Allowed = &no
			refused.publishFirstGeneration()
			auth, err := refused.api.sandboxAuth()
			if err != nil {
				t.Fatal(err)
			}
			writable := auth.store
			auth.store = sandboxStoreWriteFails{sandboxRegistrationStore: writable, updateRun: tc.updateRun}
			for i := 0; i < 2; i++ {
				if rec := refused.hook(sbxAlice, resp.Registration.ID, "claudecode", nil); rec.Code != http.StatusGone ||
					errorReason(t, rec) != sandboxrelay.ReasonRegistrationRevoked {
					t.Fatalf("hook %d while the revoke can't be stored: %d %s", i, rec.Code, rec.Body.String())
				}
			}
			if code, cur := refused.current(sbxAlice, resp.Registration.ID); code != http.StatusOK || !cur.Revoked {
				t.Fatalf("current while the revoke can't be stored: %d %+v", code, cur)
			}
			if reg, _, _ := writable.Get(sbxAlice.UID, resp.Registration.ID); reg.State == sandboxreg.StateRevoked {
				t.Fatalf("the failing store revoked: %+v", reg)
			}

			auth.store = writable
			if rec := refused.hook(sbxAlice, resp.Registration.ID, "claudecode", nil); rec.Code != http.StatusGone {
				t.Fatalf("hook once the store is writable: %d %s", rec.Code, rec.Body.String())
			}
			if reg, _, _ := writable.Get(sbxAlice.UID, resp.Registration.ID); reg.State != sandboxreg.StateRevoked || reg.RevokedReason != sandboxreg.ReasonPolicyChanged {
				t.Fatalf("the revoke was not stored once the store is writable: %+v", reg)
			}
		})
	}
}

// GAP-0367: a managed Mac's burst of 200 relayed PreToolUse calls from one
// sandbox, 32 at a time, had half its calls answered after more than 5 s
// while the gateway's own evaluation took about 50 ms: every relayed call
// took the registration's re-match lock, so the sandbox's calls waited in
// one line, and behind whatever a call holding it waited for. A call with
// nothing due now never takes the lock: 32 concurrent calls are answered
// while a re-match holds it, and their latency stays far inside the budget.
func TestSandboxRelayedHookBurstDoesNotQueueOnTheRematchLock(t *testing.T) {
	f := newSandboxFixture(t, config.EnterpriseEnrollmentConfig{}, nil)
	f.publishFirstGeneration()
	resp := f.live(sbxAlice, 1)
	if rec := f.hook(sbxAlice, resp.Registration.ID, "claudecode", nil); rec.Code != http.StatusOK {
		t.Fatalf("first hook: %d %s", rec.Code, rec.Body.String())
	}
	auth, _ := f.api.sandboxAuth()
	const held, budget = 3 * time.Second, time.Second
	// 32 as in the cell, within what one caller may hold at once here (a
	// quarter of the gateway's bound, which follows GOMAXPROCS).
	workers := min(32, max(1, f.api.hookCallerLimits.globalLimit()/4))
	unlock := auth.rematch.lock(resp.Registration.ID)
	release := time.AfterFunc(held, unlock)
	defer func() {
		if release.Stop() {
			unlock()
		}
	}()
	latencies := make([]time.Duration, workers)
	codes := make([]int, workers)
	var wg sync.WaitGroup
	for i := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			began := time.Now()
			codes[i] = f.hook(sbxAlice, resp.Registration.ID, "claudecode", nil).Code
			latencies[i] = time.Since(began)
		}()
	}
	wg.Wait()
	slices.Sort(latencies)
	t.Logf("%d concurrent relayed hooks while a re-match holds the lock: p50=%v max=%v", workers, latencies[workers/2], latencies[workers-1])
	for i, code := range codes {
		if code != http.StatusOK {
			t.Fatalf("call %d: status %d", i, code)
		}
	}
	if latencies[workers-1] >= budget {
		t.Fatalf("slowest relayed hook took %v; a call with no re-match due waited for the lock (budget %v)", latencies[workers-1], budget)
	}
}

// sandboxStoreWriteBetweenReads is a registration store on which a
// concurrent re-match stores its result right after a relayed call's first
// read: write runs once, after the first Get, Run or GetWithRun returns.
type sandboxStoreWriteBetweenReads struct {
	sandboxRegistrationStore
	once  sync.Once
	write func()
}

func (s *sandboxStoreWriteBetweenReads) Get(uid int, id string) (sandboxreg.Registration, bool, error) {
	defer s.once.Do(s.write)
	return s.sandboxRegistrationStore.Get(uid, id)
}

func (s *sandboxStoreWriteBetweenReads) Run(uid int, id string) (sandboxreg.Run, bool, error) {
	defer s.once.Do(s.write)
	return s.sandboxRegistrationStore.Run(uid, id)
}

func (s *sandboxStoreWriteBetweenReads) GetWithRun(uid int, id string) (sandboxreg.Registration, bool, sandboxreg.Run, bool, error) {
	defer s.once.Do(s.write)
	return s.sandboxRegistrationStore.GetWithRun(uid, id)
}

// GAP-0367 follow-up: the lock-free due check read the registration and
// its run record in two store calls. A re-match that stored a new
// registration and run between them paired the old registration with the
// new policy key, so the call found nothing due and was answered under the
// registration as it was before the re-match. Read together, the call sees
// either the stale pair (due: it re-reads under the lock) or the new one.
func TestSandboxRematchDueReadsTheRegistrationAndItsRunTogether(t *testing.T) {
	f := newSandboxFixture(t, config.EnterpriseEnrollmentConfig{}, nil)
	f.publishFirstGeneration()
	resp := f.live(sbxAlice, 1)
	if rec := f.hook(sbxAlice, resp.Registration.ID, "claudecode", nil); rec.Code != http.StatusOK {
		t.Fatalf("first hook: %d %s", rec.Code, rec.Body.String())
	}
	auth, _ := f.api.sandboxAuth()
	ctx := context.Background()
	id := resp.Registration.ID
	stored, ok, run, hasRun, err := auth.store.GetWithRun(sbxAlice.UID, id)
	if err != nil || !ok || !hasRun {
		t.Fatalf("stored registration: %+v %v %v %v", stored, ok, hasRun, err)
	}
	key := f.api.sandboxPolicyKey(ctx, f.api.liveBaseConfig(ctx))
	if key == "" {
		t.Fatal("no policy key")
	}
	// The registration was last matched under an older policy: a re-match
	// is due.
	stale := run
	stale.PolicyKey = "policy-before-the-change"
	if err := auth.store.UpdateRun(sbxAlice.UID, stored, &stale); err != nil {
		t.Fatal(err)
	}
	// The concurrent re-match stores the registration it matched and the
	// current policy key in one write.
	const rematched = "matched-by-the-concurrent-rematch"
	next := stored
	next.MatchedGroup = rematched
	current := run
	current.PolicyKey = key
	writable := auth.store
	auth.store = &sandboxStoreWriteBetweenReads{sandboxRegistrationStore: writable, write: func() {
		if err := writable.UpdateRun(sbxAlice.UID, next, &current); err != nil {
			t.Errorf("concurrent re-match write: %v", err)
		}
	}}
	t.Cleanup(func() { auth.store = writable })

	got := f.api.sandboxRematchIfDue(ctx, auth, sbxAlice, stored)
	if got.MatchedGroup != rematched {
		t.Fatalf("relayed call answered under the registration before the re-match (matched group %q), want %q",
			got.MatchedGroup, rematched)
	}
}
