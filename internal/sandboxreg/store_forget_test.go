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
// carried the key takes the key of its registration when that is known; one
// whose registration is gone goes when the uid is known to have held another
// account and is stamped with the current account's key otherwise (the first
// start after the upgrade). A settled store is not written again.
func TestSettleAccountStampsLegacyDecisionsAndDropsTheEarlierAccounts(t *testing.T) {
	const uid = 1012
	oldKey, newKey := DigestPrefix+"old-account", DigestPrefix+"new-account"
	ids := make([]string, 5)
	for i := range ids {
		id, err := NewID()
		if err != nil {
			t.Fatal(err)
		}
		ids[i] = id
	}
	seed := func(t *testing.T) *FileDecisionStore {
		s := NewFileDecisionStore(t.TempDir())
		// 0 keyed old, 1 keyed new, 2 legacy of a new registration, 3 legacy
		// of an old registration, 4 legacy whose registration is gone.
		for i, key := range []string{oldKey, newKey, "", "", ""} {
			d := Decision{Registration: ids[i], Kind: sandboxrelay.DecisionEgressAllow, Host: "h" + string(rune('a'+i)) + ".example.com",
				Scope: sandboxrelay.DecisionScopeAlways, SubjectKey: key}
			if err := s.Add(uid, d); err != nil {
				t.Fatal(err)
			}
		}
		return s
	}
	owner := func(id string) (string, bool) {
		switch id {
		case ids[2]:
			return newKey, true
		case ids[3]:
			return oldKey, true
		}
		return "", false
	}
	hosts := func(ds []Decision) string {
		out := ""
		for _, d := range ds {
			if d.SubjectKey != newKey {
				t.Fatalf("a kept decision is not stamped with the account's key: %+v", d)
			}
			out += d.Host[:2]
		}
		return out
	}
	t.Run("reused uid", func(t *testing.T) {
		s := seed(t)
		if n, err := s.SettleAccount(uid, newKey, owner, true); err != nil || n != 3 {
			t.Fatalf("dropped %d: %v", n, err)
		}
		left, _ := s.List(uid, "")
		if got := hosts(left); got != "hbhc" {
			t.Fatalf("kept %q, want hb hc", got)
		}
		if n, err := s.SettleAccount(uid, newKey, owner, true); err != nil || n != 0 {
			t.Fatalf("a settled store: dropped %d: %v", n, err)
		}
	})
	t.Run("first start after the upgrade", func(t *testing.T) {
		s := seed(t)
		if n, err := s.SettleAccount(uid, newKey, owner, false); err != nil || n != 2 {
			t.Fatalf("dropped %d: %v", n, err)
		}
		left, _ := s.List(uid, "")
		if got := hosts(left); got != "hbhche" {
			t.Fatalf("kept %q, want hb hc he", got)
		}
	})
	if _, err := NewFileDecisionStore(t.TempDir()).SettleAccount(uid, "", nil, false); !errors.Is(err, ErrInvalid) {
		t.Fatalf("an empty subject key must be refused: %v", err)
	}
	mine, theirs := Registration{SubjectKey: newKey}, Registration{SubjectKey: oldKey}
	keyed, legacy := Decision{SubjectKey: newKey}, Decision{}
	if !keyed.AppliesTo(mine) || keyed.AppliesTo(theirs) || !legacy.AppliesTo(theirs) {
		t.Fatal("AppliesTo must keep a keyed decision to its own account and a legacy one to any")
	}
}
