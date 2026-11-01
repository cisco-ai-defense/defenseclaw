// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/sandboxreg"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// countSubject counts uid's registrations and saved decisions of subject.
func countSubject(t *testing.T, f *sandboxFixture, uid int, subject string) (regs, decisions int) {
	t.Helper()
	auth, err := f.api.sandboxAuth()
	if err != nil {
		t.Fatal(err)
	}
	all, err := auth.store.List(uid)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range all {
		if r.SubjectKey == subject {
			regs++
		}
	}
	saved, err := auth.decisions.List(uid, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range saved {
		if d.SubjectKey == subject || d.SubjectKey == "" {
			decisions++
		}
	}
	return regs, decisions
}

// servedDecisions resolves and binds a sandbox for peer (sandbox n) and
// returns the hosts of the decisions GET decisions serves its registration.
func servedDecisions(t *testing.T, f *sandboxFixture, peer managedHookPeer, n int) []string {
	t.Helper()
	resp := f.resolve(peer, claudeResolve())
	if rec := f.bind(peer, resp.Registration.ID, n); rec.Code != http.StatusOK {
		t.Fatalf("bind: %d %s", rec.Code, rec.Body.String())
	}
	rec := f.do(peer, http.MethodGet, sandboxrelay.PathDecisions+"?registration="+resp.Registration.ID, nil, nil)
	var listed []sandboxrelay.Decision
	if err := json.Unmarshal(rec.Body.Bytes(), &listed); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("decisions: %d %s", rec.Code, rec.Body.String())
	}
	hosts := []string{}
	for _, d := range listed {
		hosts = append(hosts, d.Host)
	}
	return hosts
}

func resolveCode(f *sandboxFixture, peer managedHookPeer) int {
	return f.do(peer, http.MethodPost, sandboxrelay.PathPolicyResolve, claudeResolve(), map[string]string{sandboxrelay.ConnectorHeader: "claudecode"}).Code
}

// Review of rel-1-0-6:GAP-0262, item 1: the earlier account's records are
// removed only on a fresh answer of the account database. Not while the
// peer's own lookup failed (the last name stands in), not while a lookup
// with no cache fails, and not while it names another account; once it
// names the caller's account they go.
func TestSandboxEarlierAccountsRecordsStayWithoutAFreshAccountLookup(t *testing.T) {
	f := newSandboxFixture(t, config.EnterpriseEnrollmentConfig{}, nil)
	const uid = 1012
	oldKey := seedEarlierAccount(t, f, uid, 3)
	newcomer := managedHookPeer{UID: uid, Name: "r106vs7a1"}
	f.setGroups(newcomer, "dc-sbx-contractors")
	prevLast := managedHookPeerLastName
	managedHookPeerLastName = func(int) string { return newcomer.Name }
	t.Cleanup(func() { managedHookPeerLastName = prevLast })
	lookups := 0
	answer := func(int) (string, error) { lookups++; return newcomer.Name, nil }
	stubSandboxAccountNow(t, func(uid int) (string, error) { return answer(uid) })

	outage := managedHookPeer{UID: uid}
	if code := resolveCode(f, outage); code != http.StatusOK {
		t.Fatalf("resolve under the stand-in name: %d", code)
	}
	if regs, decisions := countSubject(t, f, uid, oldKey); regs != 3 || decisions != 2 || lookups != 0 {
		t.Fatalf("a failed peer lookup removed records: %d registrations, %d decisions left, %d lookups", regs, decisions, lookups)
	}
	if served := servedDecisions(t, f, outage, 1); len(served) != 0 {
		t.Fatalf("during the peer lookup outage the new account is served the earlier account's decisions: %v", served)
	}
	answer = func(int) (string, error) { lookups++; return "", errors.New("sssd is not answering") }
	if code := resolveCode(f, newcomer); code != http.StatusOK {
		t.Fatalf("resolve while the fresh lookup fails: %d", code)
	}
	if regs, decisions := countSubject(t, f, uid, oldKey); regs != 3 || decisions != 2 || lookups != 1 {
		t.Fatalf("a failed fresh lookup removed records: %d registrations, %d decisions left, %d lookups", regs, decisions, lookups)
	}
	if served := servedDecisions(t, f, newcomer, 2); len(served) != 0 {
		t.Fatalf("while the fresh lookup fails the new account is served the earlier account's decisions: %v", served)
	}
	answer = func(int) (string, error) { lookups++; return "r106fs7a", nil }
	if code := resolveCode(f, newcomer); code != http.StatusOK {
		t.Fatalf("resolve while the directory names the earlier account: %d", code)
	}
	if regs, decisions := countSubject(t, f, uid, oldKey); regs != 3 || decisions != 2 {
		t.Fatalf("a stale peer name removed records: %d registrations, %d decisions left", regs, decisions)
	}
	if served := servedDecisions(t, f, newcomer, 3); len(served) != 0 {
		t.Fatalf("while the directory names the earlier account the new account is served its decisions: %v", served)
	}
	answer = func(int) (string, error) { lookups++; return newcomer.Name, nil }
	if code := resolveCode(f, newcomer); code != http.StatusOK {
		t.Fatalf("resolve once the directory confirms the account: %d", code)
	}
	if regs, decisions := countSubject(t, f, uid, oldKey); regs != 0 || decisions != 0 {
		t.Fatalf("after the confirmed lookup: %d registrations, %d decisions of the earlier account left", regs, decisions)
	}
}

// failingSettleDecisions is a decision store whose settle write fails.
type failingSettleDecisions struct{ sandboxreg.DecisionStore }

func (failingSettleDecisions) SettleAccount(int, string, func(sandboxreg.Decision) (string, bool)) (int, error) {
	return 0, errors.New("injected decisions write failure")
}

// Review of rel-1-0-6:GAP-0262, item 2: the decisions go before the
// registrations. A failed decisions write keeps the earlier account's
// registrations, so the next start finds the uid reused and drops its
// legacy decisions then; they never outlive the registrations that prove
// they are another account's.
func TestSandboxEarlierAccountsRegistrationsStayWhenTheDecisionsWriteFails(t *testing.T) {
	f := newSandboxFixture(t, config.EnterpriseEnrollmentConfig{}, nil)
	const uid = 1012
	oldKey := seedEarlierAccount(t, f, uid, 3)
	newcomer := managedHookPeer{UID: uid, Name: "r106vs7a1"}
	f.setGroups(newcomer, "dc-sbx-contractors")
	stubSandboxAccountNow(t, func(int) (string, error) { return newcomer.Name, nil })
	auth, err := f.api.sandboxAuth()
	if err != nil {
		t.Fatal(err)
	}
	real := auth.decisions
	auth.decisions = failingSettleDecisions{real}
	if code := resolveCode(f, newcomer); code != http.StatusOK {
		t.Fatalf("resolve with the failing decisions write: %d", code)
	}
	if regs, decisions := countSubject(t, f, uid, oldKey); regs != 3 || decisions != 2 {
		t.Fatalf("after the failed decisions write: %d registrations, %d decisions of the earlier account left", regs, decisions)
	}
	if served := servedDecisions(t, f, newcomer, 1); len(served) != 0 {
		t.Fatalf("after the failed decisions write the new account is served the earlier account's decisions: %v", served)
	}
	auth.decisions = real
	if code := resolveCode(f, newcomer); code != http.StatusOK {
		t.Fatalf("resolve after the store recovered: %d", code)
	}
	if regs, decisions := countSubject(t, f, uid, oldKey); regs != 0 || decisions != 0 {
		t.Fatalf("the next start did not finish the cleanup: %d registrations, %d decisions left", regs, decisions)
	}
}

// Review of rel-1-0-6:GAP-0262, item 3 and review 2: on the first start
// after the upgrade, a legacy decision takes its registration's key; one
// whose registration is gone takes the caller's key only when its actor's
// directory principal is the caller's, and is dropped otherwise (another
// principal, or none). A stamped decision applies to its account only.
func TestSandboxFirstStartAfterTheUpgradeStampsLegacyDecisions(t *testing.T) {
	f := newSandboxFixture(t, config.EnterpriseEnrollmentConfig{}, nil)
	f.setGroups(sbxAlice, "dc-sbx-contractors")
	stubSandboxAccountNow(t, func(int) (string, error) { return sbxAlice.Name, nil })
	resp := f.live(sbxAlice, 1)
	auth, _ := f.api.sandboxAuth()
	for i, legacy := range []struct {
		registration, principal string
	}{
		{resp.Registration.ID, ""},
		{"", "ent-alice@DCLAB.TEST"},
		{"", "ent-mallory@DCLAB.TEST"},
		{"", ""},
	} {
		if legacy.registration == "" {
			id, err := sandboxreg.NewID()
			if err != nil {
				t.Fatal(err)
			}
			legacy.registration = id
		}
		d := sandboxreg.Decision{Registration: legacy.registration, Kind: sandboxrelay.DecisionEgressAllow, Host: "h" + string(rune('a'+i)) + ".example.com",
			Scope: sandboxrelay.DecisionScopeAlways, Actor: sandboxreg.DecisionActor{PrincipalHash: sandboxPrincipalHash(auth.key, legacy.principal)}}
		if err := auth.decisions.Add(sbxAlice.UID, d); err != nil {
			t.Fatal(err)
		}
	}
	f.resolve(sbxAlice, claudeResolve())
	reg, _, _ := auth.store.Get(sbxAlice.UID, resp.Registration.ID)
	saved, _ := auth.decisions.List(sbxAlice.UID, "")
	hosts := ""
	for _, d := range saved {
		if d.SubjectKey != reg.SubjectKey {
			t.Fatalf("legacy decision %s not stamped with the account's key", d.Host)
		}
		hosts += d.Host[:2]
	}
	if hosts != "hahb" {
		t.Fatalf("kept %q, want the own registration's and the own principal's (ha hb)", hosts)
	}
	mallory := managedHookPeer{UID: sbxAlice.UID, Name: "mallory"}
	if !saved[1].AppliesTo(reg) || saved[1].AppliesTo(sandboxreg.Registration{SubjectKey: sandboxSubjectKey(auth.key, mallory.UID, mallory.Name, "")}) {
		t.Fatal("a stamped decision must apply to its account only")
	}
}

// Review 2 of rel-1-0-6:GAP-0262, note 2: the caller's principal is the one
// the resolve just resolved (match.facts), not the cached one the request
// came in with. Without one (a local account, facts with no principal) a
// legacy decision whose registration is gone is dropped, never stamped to
// the caller, whatever principal its actor had.
func TestSandboxLegacyDecisionIsDroppedWithoutTheCallersPrincipal(t *testing.T) {
	for _, tc := range []struct {
		name            string
		callerPrincipal bool
		decisionPrinc   string
		wantKept        bool
	}{
		{"local caller, directory actor", false, "ent-alice@DCLAB.TEST", false},
		{"local caller, local actor", false, "", false},
		{"directory caller, same principal", true, "ent-alice@DCLAB.TEST", true},
		{"directory caller, actor without principal", true, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSandboxFixture(t, config.EnterpriseEnrollmentConfig{}, nil)
			stubSandboxAccountNow(t, func(int) (string, error) { return sbxAlice.Name, nil })
			f.setGroups(sbxAlice, "dc-sbx-contractors")
			if !tc.callerPrincipal {
				f.mu.Lock()
				facts := f.facts[sbxAlice.UID]
				facts.Principal, facts.UPN, facts.Domain, facts.Directory, facts.Source = "", "", "", "", "files"
				f.facts[sbxAlice.UID] = facts
				f.mu.Unlock()
			}
			auth, err := f.api.sandboxAuth()
			if err != nil {
				t.Fatal(err)
			}
			gone, err := sandboxreg.NewID()
			if err != nil {
				t.Fatal(err)
			}
			if err := auth.decisions.Add(sbxAlice.UID, sandboxreg.Decision{Registration: gone, Kind: sandboxrelay.DecisionEgressAllow,
				Host: "legacy.example.com", Scope: sandboxrelay.DecisionScopeAlways,
				Actor: sandboxreg.DecisionActor{PrincipalHash: sandboxPrincipalHash(auth.key, tc.decisionPrinc)}}); err != nil {
				t.Fatal(err)
			}
			if rec := f.do(sbxAlice, http.MethodPost, sandboxrelay.PathPolicyResolve, claudeResolve(), map[string]string{sandboxrelay.ConnectorHeader: "claudecode"}); rec.Code != http.StatusOK {
				t.Fatalf("resolve: %d %s", rec.Code, rec.Body.String())
			}
			saved, _ := auth.decisions.List(sbxAlice.UID, "")
			if tc.wantKept != (len(saved) == 1) {
				t.Fatalf("kept %d legacy decisions, want kept %v", len(saved), tc.wantKept)
			}
			for _, d := range saved {
				if d.SubjectKey == "" {
					t.Fatalf("a kept legacy decision is not stamped: %+v", d)
				}
			}
		})
	}
}

// Review 2 of rel-1-0-6:GAP-0262 (the reviewer's probe): while the fresh
// account lookup fails, the earlier account's records are kept, and its
// legacy "always" decision is not served to the new account's sandbox.
func TestSandboxOutageKeepsTheEarlierAccountsLegacyDecisionUnserved(t *testing.T) {
	f := newSandboxFixture(t, config.EnterpriseEnrollmentConfig{}, nil)
	const uid = 1012
	oldKey := seedEarlierAccount(t, f, uid, 3)
	newcomer := managedHookPeer{UID: uid, Name: "r106vs7a1"}
	f.setGroups(newcomer, "dc-sbx-contractors")
	stubSandboxAccountNow(t, func(int) (string, error) { return "", errors.New("sssd is not answering") })
	if served := servedDecisions(t, f, newcomer, 1); len(served) != 0 {
		t.Fatalf("the new account is served %v of the earlier account during the lookup outage", served)
	}
	if regs, decisions := countSubject(t, f, uid, oldKey); regs != 3 || decisions != 2 {
		t.Fatalf("records of the earlier account must be kept during the outage: %d registrations, %d decisions", regs, decisions)
	}
}
