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

package telemetryrelay

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// S6b: the leader keeps the newest allowed request of each registered
// actor to each host (never a refusal, an injection record or an
// unregistered actor), clamps a future time and stays within its bound.
func TestS6bHostUses(t *testing.T) {
	ctx := context.Background()
	s := &Store{MaxHostUses: 16}
	now := time.Now().UTC()
	rec := func(uid, host, decision string, at time.Time) Record {
		return Record{Kind: KindEgress, Atespace: "eng", Actor: "a-" + uid, UID: uid, Host: host, Decision: decision, At: at}
	}
	if _, err := s.PostEgress(ctx, PostRequest{Records: []Record{
		rec("u1", "gitlab.com", "allow", now.Add(-time.Minute)),
		rec("u1", "gitlab.com", "allow", now.Add(-time.Hour)), // older: ignored
		rec("u1", "blocked.example", "block", now),
		rec("u1", "inject.example", "inject", now),
		rec("u1", "future.example", "allow", now.Add(time.Hour)),
		rec("", "nouid.example", "allow", now),
		rec("u2", "github.com", "allow", now),
	}}); err != nil {
		t.Fatal(err)
	}
	got, err := s.HostUses(ctx, HostUsesRequest{Actors: []ActorRef{{Atespace: "eng", UID: "u1"}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Uses) != 2 || got.Uses[0].Host != "future.example" || got.Uses[1].Host != "gitlab.com" ||
		!got.Uses[1].At.Equal(now.Add(-time.Minute)) || got.Uses[0].At.After(time.Now()) {
		t.Fatalf("uses of u1 = %+v", got.Uses)
	}
	var many []Record
	for i := range 40 {
		many = append(many, rec("u3", fmt.Sprintf("h%02d.example", i), "allow", now.Add(time.Duration(i-100)*time.Second)))
	}
	if _, err := s.PostEgress(ctx, PostRequest{Records: many}); err != nil {
		t.Fatal(err)
	}
	if s.useCount > 16 {
		t.Errorf("%d entries, bound 16", s.useCount)
	}
	got, _ = s.HostUses(ctx, HostUsesRequest{Actors: []ActorRef{{Atespace: "eng", UID: "u3"}}})
	if len(got.Uses) == 0 || got.Uses[0].Host != "h39.example" {
		t.Errorf("the newest use of u3 is gone: %+v", got.Uses)
	}
}
