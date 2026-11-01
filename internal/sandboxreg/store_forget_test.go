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

package sandboxreg

import (
	"errors"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// rel-1-0-6:GAP-0262: a uid the account database gave to a new account
// starts without the earlier account's registrations. Before the forget,
// the earlier account's stopped registrations fill the uid (ErrFull for the
// new account); after it only the new account's own remain, the removed
// sandboxes never register again, and a second forget writes nothing.
func TestForgetOtherAccountsRemovesOnlyTheEarlierAccountsRegistrations(t *testing.T) {
	s, _, _ := newTestStore(t)
	s.limit = 4
	const uid = 1012
	oldKey, newKey := DigestPrefix+"old-account", DigestPrefix+"new-account"
	for n := range 4 {
		r := pending(t)
		r.SubjectKey = oldKey
		if err := s.Create(uid, r); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Bind(uid, r.ID, bind(n)); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Report(uid, r.ID, false); err != nil {
			t.Fatal(err)
		}
	}
	fresh := pending(t)
	fresh.SubjectKey = newKey
	if err := s.Create(uid, fresh); !errors.Is(err, ErrFull) {
		t.Fatalf("the earlier account's stopped registrations must fill the uid before the forget: %v", err)
	}
	var gone []string
	s.OnGone = func(r Registration) { gone = append(gone, r.ID) }
	removed, err := s.ForgetOtherAccounts(uid, newKey)
	if err != nil || len(removed) != 4 || len(gone) != 4 {
		t.Fatalf("forget: %d removed, %d gone, %v", len(removed), len(gone), err)
	}
	if regs, _ := s.List(uid); len(regs) != 0 {
		t.Fatalf("%d registrations of the earlier account remain", len(regs))
	}
	if err := s.Create(uid, fresh); err != nil {
		t.Fatalf("the new account registers after the forget: %v", err)
	}
	if _, err := s.Bind(uid, fresh.ID, bind(1)); !errors.Is(err, ErrTombstoned) {
		t.Fatalf("the earlier account's sandbox must never register again: %v", err)
	}
	writes := 0
	saved := storeFileWrite
	t.Cleanup(func() { storeFileWrite = saved })
	storeFileWrite = func(dir, path string, v any) error { writes++; return saved(dir, path, v) }
	if removed, err := s.ForgetOtherAccounts(uid, newKey); err != nil || len(removed) != 0 || writes != 0 {
		t.Fatalf("a forget with nothing to forget: %d removed, %d writes, %v", len(removed), writes, err)
	}
	if regs, _ := s.List(uid); len(regs) != 1 || regs[0].ID != fresh.ID {
		t.Fatalf("the new account's own registration must stay: %+v", regs)
	}
	if _, err := s.ForgetOtherAccounts(uid, ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("an empty subject key must be refused: %v", err)
	}
}

// rel-1-0-6:GAP-0262: saved decisions follow their account. A keyed
// decision of another account goes. A decision saved before decisions
// carried the key takes the key keyOf gives it and goes when keyOf proves no
// account. A settled store is not written again.
func TestSettleAccountStampsLegacyDecisionsAndDropsTheEarlierAccounts(t *testing.T) {
	const uid = 1012
	oldKey, newKey := DigestPrefix+"old-account", DigestPrefix+"new-account"
	s := NewFileDecisionStore(t.TempDir())
	ids := make([]string, 5)
	// 0 keyed old, 1 keyed new, 2 legacy keyOf new, 3 legacy keyOf old,
	// 4 legacy keyOf none.
	for i, key := range []string{oldKey, newKey, "", "", ""} {
		id, err := NewID()
		if err != nil {
			t.Fatal(err)
		}
		ids[i] = id
		d := Decision{Registration: id, Kind: sandboxrelay.DecisionEgressAllow, Host: "h" + string(rune('a'+i)) + ".example.com",
			Scope: sandboxrelay.DecisionScopeAlways, SubjectKey: key}
		if err := s.Add(uid, d); err != nil {
			t.Fatal(err)
		}
	}
	keyOf := func(d Decision) (string, bool) {
		switch d.Registration {
		case ids[2]:
			return newKey, true
		case ids[3]:
			return oldKey, true
		}
		return "", false
	}
	if n, err := s.SettleAccount(uid, newKey, keyOf); err != nil || n != 3 {
		t.Fatalf("dropped %d: %v", n, err)
	}
	left, _ := s.List(uid, "")
	hosts := ""
	for _, d := range left {
		if d.SubjectKey != newKey {
			t.Fatalf("a kept decision is not the account's: %+v", d)
		}
		hosts += d.Host[:2]
	}
	if hosts != "hbhc" {
		t.Fatalf("kept %q, want hb hc", hosts)
	}
	if n, err := s.SettleAccount(uid, newKey, keyOf); err != nil || n != 0 {
		t.Fatalf("a settled store: dropped %d: %v", n, err)
	}
	if _, err := s.SettleAccount(uid, "", keyOf); !errors.Is(err, ErrInvalid) {
		t.Fatalf("an empty subject key must be refused: %v", err)
	}
}

// Review 2 of rel-1-0-6:GAP-0262: a decision without the key applies only
// inside its own registration; a keyed one to every registration of its
// account and to no other.
func TestDecisionAppliesToItsOwnRegistrationOrAccountOnly(t *testing.T) {
	newKey, oldKey := DigestPrefix+"new-account", DigestPrefix+"old-account"
	mine := Registration{ID: "reg-a", SubjectKey: newKey}
	sibling := Registration{ID: "reg-b", SubjectKey: newKey}
	theirs := Registration{ID: "reg-c", SubjectKey: oldKey}
	legacy := Decision{Registration: "reg-c"}
	keyed := Decision{Registration: "reg-a", SubjectKey: newKey}
	if legacy.AppliesTo(mine) || legacy.AppliesTo(sibling) || !legacy.AppliesTo(theirs) {
		t.Fatal("a legacy decision must apply only inside its own registration")
	}
	if !keyed.AppliesTo(mine) || !keyed.AppliesTo(sibling) || keyed.AppliesTo(theirs) {
		t.Fatal("a keyed decision must apply to its account's registrations only")
	}
}
