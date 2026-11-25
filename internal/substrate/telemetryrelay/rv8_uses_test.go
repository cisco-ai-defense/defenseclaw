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
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

func rv8Rec(uid, host string, at time.Time) Record {
	return Record{Kind: KindEgress, Atespace: "eng", Actor: "a-" + uid, UID: uid, Host: host, Decision: "allow", At: at}
}

// RV8-2 (GAP-0835): 80 actors that flood 256 hosts each no longer push out
// another actor's last use: the trim takes from the actors with the most.
func TestRV8MultiActorFloodKeepsVictim(t *testing.T) {
	ctx := context.Background()
	s := &Store{}
	now := time.Now().UTC()
	s.PostEgress(ctx, PostRequest{Records: []Record{rv8Rec("victim", "github.com", now.Add(-time.Minute))}})
	for a := 0; a < 80; a++ {
		var flood []Record
		for i := 0; i < 256; i++ {
			flood = append(flood, rv8Rec(fmt.Sprintf("att%02d", a), fmt.Sprintf("h%d.example.com", i), now.Add(-time.Duration(a*256+i)*time.Microsecond)))
		}
		s.PostEgress(ctx, PostRequest{Records: flood})
	}
	v, _ := s.HostUses(ctx, HostUsesRequest{Actors: []ActorRef{{Atespace: "eng", UID: "victim"}}})
	if len(v.Uses) != 1 || v.Uses[0].Host != "github.com" {
		t.Errorf("victim uses = %+v, want github.com (useCount %d)", v.Uses, s.useCount)
	}
	if s.useCount > DefaultMaxHostUses {
		t.Errorf("useCount = %d, over %d", s.useCount, DefaultMaxHostUses)
	}
	a, _ := s.HostUses(ctx, HostUsesRequest{Actors: []ActorRef{{Atespace: "eng", UID: "att00"}}})
	if len(a.Uses) == 0 || a.Uses[0].Host != "h0.example.com" {
		t.Errorf("a flooding actor lost its newest use: %+v", a.Uses[:min(1, len(a.Uses))])
	}
}

// RV8-2: one person's many agents, one host each, do not push out another
// person's use either: the trim takes from the person with the most first.
func TestRV8PersonFloodKeepsOtherPerson(t *testing.T) {
	ctx := context.Background()
	regs := fakeRegs{}
	reg := func(uid, subject string) {
		regs["eng/"+uid] = registry.Registration{Atespace: "eng", UID: uid, Name: "a-" + uid, Person: registry.Person{Kind: "oidc", Issuer: "https://idp", Subject: subject}}
	}
	reg("victim", "bob")
	n := DefaultMaxHostUses + 1
	for i := range n {
		reg(fmt.Sprintf("m%05d", i), "mallory")
	}
	s := &Store{Registrations: regs}
	now := time.Now().UTC()
	s.PostEgress(ctx, PostRequest{Records: []Record{rv8Rec("victim", "github.com", now.Add(-time.Hour))}})
	var flood []Record
	for i := range n {
		flood = append(flood, rv8Rec(fmt.Sprintf("m%05d", i), "x.example.com", now.Add(-time.Duration(n-i)*time.Microsecond)))
		if len(flood) == 500 {
			s.PostEgress(ctx, PostRequest{Records: flood})
			flood = nil
		}
	}
	s.PostEgress(ctx, PostRequest{Records: flood})
	v, _ := s.HostUses(ctx, HostUsesRequest{Actors: []ActorRef{{Atespace: "eng", UID: "victim"}}})
	if len(v.Uses) != 1 {
		t.Errorf("bob's use pushed out by mallory's %d agents (useCount %d)", n, s.useCount)
	}
	if s.useCount > DefaultMaxHostUses {
		t.Errorf("useCount = %d, over %d", s.useCount, DefaultMaxHostUses)
	}
}

// fairShares keeps groups under the level whole and splits the rest.
func TestRV8FairShares(t *testing.T) {
	t0 := time.Now()
	got := fairShares([]int{1, 10, 10}, []time.Time{t0, t0.Add(time.Second), t0}, 12)
	if got[0] != 1 || got[1]+got[2] != 11 || got[1] != 6 || got[2] != 5 {
		t.Errorf("fairShares = %v, want [1 6 5]", got)
	}
	got = fairShares([]int{1, 1, 1}, []time.Time{t0, t0.Add(2 * time.Second), t0.Add(time.Second)}, 2)
	if got[0] != 0 || got[1] != 1 || got[2] != 1 {
		t.Errorf("fairShares one each = %v, want the two newest [0 1 1]", got)
	}
}

// RV8-3 (GAP-0836): the reader merges its batches newest first.
func TestRV8ReaderMergesNewestFirst(t *testing.T) {
	s := &Store{}
	now := time.Now().UTC()
	var recs []Record
	var actors []ActorRef
	for i := range 300 {
		uid := fmt.Sprintf("u%03d", i)
		at := now.Add(-time.Hour)
		if i == 299 {
			at = now
		}
		recs = append(recs, rv8Rec(uid, "github.com", at))
		actors = append(actors, ActorRef{Atespace: "eng", UID: uid})
	}
	s.PostEgress(context.Background(), PostRequest{Records: recs})
	got, err := (&UseReader{Leader: relayLeader(t, s)}).HostUses(context.Background(), actors)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 300 || got[0].UID != "u299" {
		t.Fatalf("got %d uses, first %+v, want 300 with u299 first", len(got), got[:min(1, len(got))])
	}
	for i := 1; i < len(got); i++ {
		if got[i].At.After(got[i-1].At) {
			t.Fatalf("use %d is newer than use %d", i, i-1)
		}
	}
}

// RV8-6: a full map of long host names no longer overflows the leader's
// body limit (the read failed and last used was left out): the answer is
// cut to fit, newest first, and the reader drops what a cut could skew.
func TestRV8LongHostsAnswerFits(t *testing.T) {
	ctx := context.Background()
	s := &Store{}
	now := time.Now().UTC()
	long := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 50)
	var actors []ActorRef
	for a := range 80 {
		uid := fmt.Sprintf("u%02d", a)
		actors = append(actors, ActorRef{Atespace: "eng", UID: uid})
		var recs []Record
		for i := range 250 {
			recs = append(recs, rv8Rec(uid, fmt.Sprintf("h%03d", i)+long, now.Add(-time.Duration(a*250+i)*time.Millisecond)))
		}
		s.PostEgress(ctx, PostRequest{Records: recs})
	}
	got, err := (&UseReader{Leader: relayLeader(t, s)}).HostUses(ctx, actors)
	if err != nil {
		t.Fatalf("read of 20000 long uses failed: %v", err)
	}
	if len(got) == 0 || got[0].UID != "u00" || !strings.HasPrefix(got[0].Host, "h000") {
		t.Fatalf("got %d uses, first %+v, want the newest", len(got), got[:min(1, len(got))])
	}
	for i := 1; i < len(got); i++ {
		if got[i].At.After(got[i-1].At) {
			t.Fatalf("use %d is newer than use %d", i, i-1)
		}
	}
}
