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

	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

func rv9Reg(atespace, uid, person string) registry.Registration {
	r := registry.Registration{Atespace: atespace, UID: uid, Name: "a-" + uid}
	if person == "" {
		r.Attributed = true
	} else {
		r.Person = registry.Person{Kind: "oidc", Issuer: "https://idp", Subject: person}
	}
	return r
}

func rv9RecIn(atespace, uid, host string, at time.Time) Record {
	r := rv8Rec(uid, host, at)
	r.Atespace = atespace
	return r
}

// rv9Flood: a victim in victimSpace (person victimPerson, "" = attributed)
// with 256 uses, the oldest its secret host, against 100 attributed actors
// in eng with 256 hosts each. It returns the victim's uses and whether the
// secret host is still there.
func rv9Flood(t *testing.T, victimSpace, victimPerson string) (int, bool) {
	t.Helper()
	ctx := context.Background()
	regs := fakeRegs{victimSpace + "/v1": rv9Reg(victimSpace, "v1", victimPerson)}
	for a := range 100 {
		uid := fmt.Sprintf("f%03d", a)
		regs["eng/"+uid] = rv9Reg("eng", uid, "")
	}
	s := &Store{Registrations: regs}
	now := time.Now().UTC()
	vs := []Record{rv9RecIn(victimSpace, "v1", "secret.example.com", now.Add(-2*time.Hour))}
	for i := 1; i < 256; i++ {
		vs = append(vs, rv9RecIn(victimSpace, "v1", fmt.Sprintf("b%d.example.com", i), now.Add(-time.Hour+time.Duration(i)*time.Microsecond)))
	}
	s.PostEgress(ctx, PostRequest{Records: vs})
	for a := range 100 {
		var fl []Record
		for i := range 256 {
			fl = append(fl, rv8Rec(fmt.Sprintf("f%03d", a), fmt.Sprintf("h%d.example.com", i), now.Add(-time.Duration(a*256+i)*time.Microsecond)))
		}
		s.PostEgress(ctx, PostRequest{Records: fl})
	}
	if s.useCount > DefaultMaxHostUses {
		t.Errorf("useCount = %d, over %d", s.useCount, DefaultMaxHostUses)
	}
	v, _ := s.HostUses(ctx, HostUsesRequest{Actors: []ActorRef{{Atespace: victimSpace, UID: "v1"}}})
	has := false
	for _, u := range v.Uses {
		has = has || u.Host == "secret.example.com"
	}
	return len(v.Uses), has
}

// RV9-1 (GAP-0867): 100 attributed actors (forks, or actors made outside
// DefenseClaw: no person) count as one group, their atespace, so they no
// longer push out another person's oldest use.
func TestRV9AttributedFloodKeepsPerson(t *testing.T) {
	if n, has := rv9Flood(t, "eng", "bob"); n != 256 || !has {
		t.Errorf("bob uses = %d, secret kept = %v; want 256 and true", n, has)
	}
}

// RV9-1: an attributed actor of another atespace keeps its uses too.
func TestRV9AttributedFloodKeepsOtherAtespace(t *testing.T) {
	if n, has := rv9Flood(t, "ops", ""); n != 256 || !has {
		t.Errorf("ops actor uses = %d, secret kept = %v; want 256 and true", n, has)
	}
}

// RV9-1: inside one atespace's group the trim is still fair per actor:
// an attributed actor under the level (100 uses against 100 neighbours of
// its atespace with 256 each) keeps all it has, as it did when every
// attributed actor was a group of its own.
func TestRV9AtespaceGroupFairPerActor(t *testing.T) {
	ctx := context.Background()
	regs := fakeRegs{"eng/v1": rv9Reg("eng", "v1", "")}
	for a := range 100 {
		uid := fmt.Sprintf("f%03d", a)
		regs["eng/"+uid] = rv9Reg("eng", uid, "")
	}
	s := &Store{Registrations: regs}
	now := time.Now().UTC()
	var vs []Record
	for i := range 100 {
		vs = append(vs, rv8Rec("v1", fmt.Sprintf("b%d.example.com", i), now.Add(-2*time.Hour+time.Duration(i)*time.Microsecond)))
	}
	s.PostEgress(ctx, PostRequest{Records: vs})
	for a := range 100 {
		var fl []Record
		for i := range 256 {
			fl = append(fl, rv8Rec(fmt.Sprintf("f%03d", a), fmt.Sprintf("h%d.example.com", i), now.Add(-time.Duration(a*256+i)*time.Microsecond)))
		}
		s.PostEgress(ctx, PostRequest{Records: fl})
	}
	v, _ := s.HostUses(ctx, HostUsesRequest{Actors: []ActorRef{{Atespace: "eng", UID: "v1"}}})
	if len(v.Uses) != 100 {
		t.Errorf("attributed eng actor uses = %d, want 100 (useCount %d)", len(v.Uses), s.useCount)
	}
}

// RV9-1: 20001 attributed one-host actors no longer empty a person's
// actor with one use.
func TestRV9AttributedActorsDoNotEmptyVictim(t *testing.T) {
	ctx := context.Background()
	regs := fakeRegs{"eng/victim": rv9Reg("eng", "victim", "bob")}
	n := DefaultMaxHostUses + 1
	for i := range n {
		uid := fmt.Sprintf("m%05d", i)
		regs["eng/"+uid] = rv9Reg("eng", uid, "")
	}
	s := &Store{Registrations: regs}
	now := time.Now().UTC()
	s.PostEgress(ctx, PostRequest{Records: []Record{rv8Rec("victim", "github.com", now.Add(-time.Hour))}})
	var fl []Record
	for i := range n {
		fl = append(fl, rv8Rec(fmt.Sprintf("m%05d", i), "x.example.com", now.Add(-time.Duration(n-i)*time.Microsecond)))
		if len(fl) == 500 {
			s.PostEgress(ctx, PostRequest{Records: fl})
			fl = nil
		}
	}
	s.PostEgress(ctx, PostRequest{Records: fl})
	v, _ := s.HostUses(ctx, HostUsesRequest{Actors: []ActorRef{{Atespace: "eng", UID: "victim"}}})
	if len(v.Uses) != 1 || v.Uses[0].Host != "github.com" {
		t.Errorf("victim uses = %+v, want github.com (useCount %d)", v.Uses, s.useCount)
	}
}
