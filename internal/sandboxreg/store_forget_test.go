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
// decision of another account goes; a decision saved before decisions
// carried the key goes only once the uid is known to have changed accounts
// and its registration is not one the account now holding the uid keeps.
func TestForgetOtherAccountsDropsTheEarlierAccountsDecisions(t *testing.T) {
	s := NewFileDecisionStore(t.TempDir())
	const uid = 1012
	oldKey, newKey := DigestPrefix+"old-account", DigestPrefix+"new-account"
	ids := make([]string, 4)
	for i := range ids {
		id, err := NewID()
		if err != nil {
			t.Fatal(err)
		}
		ids[i] = id
	}
	for i, key := range []string{oldKey, newKey, "", ""} {
		d := Decision{Registration: ids[i], Kind: sandboxrelay.DecisionEgressAllow, Host: "h" + string(rune('a'+i)) + ".example.com",
			Scope: sandboxrelay.DecisionScopeAlways, SubjectKey: key}
		if err := s.Add(uid, d); err != nil {
			t.Fatal(err)
		}
	}
	if n, err := s.ForgetOtherAccounts(uid, newKey, nil); err != nil || n != 1 {
		t.Fatalf("keyed forget dropped %d: %v", n, err)
	}
	if n, err := s.ForgetOtherAccounts(uid, newKey, func(id string) bool { return id == ids[2] }); err != nil || n != 1 {
		t.Fatalf("legacy forget dropped %d: %v", n, err)
	}
	left, _ := s.List(uid, "")
	if len(left) != 2 || left[0].Registration != ids[1] || left[1].Registration != ids[2] {
		t.Fatalf("decisions left: %+v", left)
	}
	mine := Registration{SubjectKey: newKey}
	theirs := Registration{SubjectKey: oldKey}
	if !left[0].AppliesTo(mine) || left[0].AppliesTo(theirs) || !left[1].AppliesTo(theirs) {
		t.Fatal("AppliesTo must keep a keyed decision to its own account and a legacy one to any")
	}
}
