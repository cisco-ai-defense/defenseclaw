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
	"slices"
	"testing"
	"time"
)

// OnGone sees every registration a stored write revoked, removed or
// evicted, after the store is unlocked (the callback may read the store),
// and nothing for a write that changed nothing.
func TestFileStoreOnGoneSeesEveryWayARegistrationGoes(t *testing.T) {
	s, clock, _ := newTestStore(t)
	s.limit = 3
	var gone []string
	s.OnGone = func(r Registration) {
		if _, _, err := s.Get(1001, r.ID); err != nil {
			t.Errorf("the store is not readable from OnGone: %v", err)
		}
		gone = append(gone, r.ID)
	}
	expect := func(what string, ids ...string) {
		t.Helper()
		if !slices.Equal(gone, ids) {
			t.Fatalf("%s: OnGone saw %v, want %v", what, gone, ids)
		}
		gone = nil
	}
	var ids []string
	for i := range 3 {
		r := pending(t)
		ids = append(ids, r.ID)
		if err := s.Create(1001, r); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Bind(1001, r.ID, bind(i+1)); err != nil {
			t.Fatal(err)
		}
		clock.t = clock.t.Add(time.Second)
	}
	expect("create and bind")

	if err := s.Revoke(1001, ids[0], ReasonPolicyChanged); err != nil {
		t.Fatal(err)
	}
	expect("revoke", ids[0])
	clock.t = clock.t.Add(time.Second)
	if err := s.Revoke(1001, ids[0], ReasonPolicyChanged); err != nil {
		t.Fatal(err)
	}
	expect("revoking a tombstone again")

	if err := s.Deleted(1001, ids[1]); err != nil {
		t.Fatal(err)
	}
	expect("deleted (live to tombstone)", ids[1])
	if err := s.Deleted(1001, ids[1]); err != nil {
		t.Fatal(err)
	}
	expect("deleted (tombstone removed)", ids[1])

	if _, err := s.RevokeSandbox(1001, bind(3).SandboxID, "", ReasonForeign); err != nil {
		t.Fatal(err)
	}
	expect("revoke a foreign sandbox", ids[2])

	// Two tombstones (ids[0], ids[2]) and one more pending entry: a fourth
	// entry evicts the oldest tombstone.
	if err := s.Create(1001, pending(t)); err != nil {
		t.Fatal(err)
	}
	expect("create under the limit")
	if err := s.Create(1001, pending(t)); err != nil {
		t.Fatal(err)
	}
	expect("create evicting a tombstone", ids[0])
}
