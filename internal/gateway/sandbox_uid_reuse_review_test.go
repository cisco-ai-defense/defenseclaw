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
	answer = func(int) (string, error) { lookups++; return "", errors.New("sssd is not answering") }
	if code := resolveCode(f, newcomer); code != http.StatusOK {
		t.Fatalf("resolve while the fresh lookup fails: %d", code)
	}
	if regs, decisions := countSubject(t, f, uid, oldKey); regs != 3 || decisions != 2 || lookups != 1 {
		t.Fatalf("a failed fresh lookup removed records: %d registrations, %d decisions left, %d lookups", regs, decisions, lookups)
	}
	answer = func(int) (string, error) { lookups++; return "r106fs7a", nil }
	if code := resolveCode(f, newcomer); code != http.StatusOK {
		t.Fatalf("resolve while the directory names the earlier account: %d", code)
	}
	if regs, decisions := countSubject(t, f, uid, oldKey); regs != 3 || decisions != 2 {
		t.Fatalf("a stale peer name removed records: %d registrations, %d decisions left", regs, decisions)
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

func (failingSettleDecisions) SettleAccount(int, string, func(string) (string, bool), bool) (int, error) {
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
	auth.decisions = real
	if code := resolveCode(f, newcomer); code != http.StatusOK {
		t.Fatalf("resolve after the store recovered: %d", code)
	}
	if regs, decisions := countSubject(t, f, uid, oldKey); regs != 0 || decisions != 0 {
		t.Fatalf("the next start did not finish the cleanup: %d registrations, %d decisions left", regs, decisions)
	}
}

// Review of rel-1-0-6:GAP-0262, item 3: on the first start after the
// upgrade, a legacy decision of a uid that held one account only takes that
// account's key and keeps applying to it; a later account on the uid then
// never inherits it.
func TestSandboxFirstStartAfterTheUpgradeStampsLegacyDecisions(t *testing.T) {
	f := newSandboxFixture(t, config.EnterpriseEnrollmentConfig{}, nil)
	f.setGroups(sbxAlice, "dc-sbx-contractors")
	stubSandboxAccountNow(t, func(int) (string, error) { return sbxAlice.Name, nil })
	resp := f.live(sbxAlice, 1)
	auth, _ := f.api.sandboxAuth()
	gone, err := sandboxreg.NewID()
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []sandboxreg.Decision{
		{Registration: resp.Registration.ID, Kind: sandboxrelay.DecisionEgressAllow, Host: "own-reg.example.com", Scope: sandboxrelay.DecisionScopeAlways},
		{Registration: gone, Kind: sandboxrelay.DecisionEgressAllow, Host: "evicted-reg.example.com", Scope: sandboxrelay.DecisionScopeAlways},
	} {
		if err := auth.decisions.Add(sbxAlice.UID, d); err != nil {
			t.Fatal(err)
		}
	}
	f.resolve(sbxAlice, claudeResolve())
	reg, _, _ := auth.store.Get(sbxAlice.UID, resp.Registration.ID)
	saved, _ := auth.decisions.List(sbxAlice.UID, "")
	if len(saved) != 2 {
		t.Fatalf("the account's own legacy decisions must stay: %+v", saved)
	}
	for _, d := range saved {
		if d.SubjectKey != reg.SubjectKey {
			t.Fatalf("legacy decision %s not stamped with the account's key", d.Host)
		}
	}
	mallory := managedHookPeer{UID: sbxAlice.UID, Name: "mallory"}
	if !saved[1].AppliesTo(reg) || saved[1].AppliesTo(sandboxreg.Registration{SubjectKey: sandboxSubjectKey(auth.key, mallory.UID, mallory.Name, "")}) {
		t.Fatal("a stamped decision must apply to its account only")
	}
}

// Review of rel-1-0-6:GAP-0262, item 3: a legacy decision whose
// registration is gone is another account's when its actor's directory
// principal is known and is not the caller's: it is dropped, not stamped.
// One with no principal is stamped to the caller (the documented residual,
// rel-1-0-6:GAP-0282).
func TestSandboxLegacyDecisionOfAnotherPrincipalIsDropped(t *testing.T) {
	f := newSandboxFixture(t, config.EnterpriseEnrollmentConfig{}, nil)
	f.setGroups(sbxAlice, "dc-sbx-contractors")
	stubSandboxAccountNow(t, func(int) (string, error) { return sbxAlice.Name, nil })
	auth, err := f.api.sandboxAuth()
	if err != nil {
		t.Fatal(err)
	}
	for i, principal := range []string{"ent-mallory@DCLAB.TEST", "ent-alice@DCLAB.TEST", ""} {
		gone, err := sandboxreg.NewID()
		if err != nil {
			t.Fatal(err)
		}
		d := sandboxreg.Decision{Registration: gone, Kind: sandboxrelay.DecisionEgressAllow, Host: "h" + string(rune('a'+i)) + ".example.com",
			Scope: sandboxrelay.DecisionScopeAlways, Actor: sandboxreg.DecisionActor{PrincipalHash: sandboxPrincipalHash(auth.key, principal)}}
		if err := auth.decisions.Add(sbxAlice.UID, d); err != nil {
			t.Fatal(err)
		}
	}
	f.resolve(sbxAlice, claudeResolve())
	saved, _ := auth.decisions.List(sbxAlice.UID, "")
	hosts := ""
	for _, d := range saved {
		hosts += d.Host[:2]
	}
	if hosts != "hbhc" {
		t.Fatalf("kept %q: the decision of another principal must go, the own and unknown ones stay", hosts)
	}
}
