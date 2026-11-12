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

package controller_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

// leaderStore is the leader's registration store as the controller sees it
// over the RPC (registry.Store), with a switch for an unreachable leader.
type leaderStore struct {
	mu   sync.Mutex
	m    map[string]registry.Registration
	down bool
}

func (s *leaderStore) Get(_ context.Context, atespace, uid string) (registry.Registration, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.down {
		return registry.Registration{}, false, errors.New("leader unreachable")
	}
	r, ok := s.m[atespace+"/"+uid]
	return r, ok, nil
}

func (s *leaderStore) Put(_ context.Context, r registry.Registration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.down {
		return errors.New("leader unreachable")
	}
	if err := r.Validate(); err != nil {
		return err
	}
	s.m[r.Atespace+"/"+r.UID] = r
	return nil
}

func (s *leaderStore) List(context.Context, registry.Filter) ([]registry.Registration, error) {
	return nil, nil
}

// GAP-0125: the controller reads the registrations the launcher writes to
// the leader; a launcher-created actor gets its profile policy, and while
// the leader is unreachable nothing changes.
func TestLeaderRegistrations(t *testing.T) {
	store := &leaderStore{m: map[string]registry.Registration{}}
	r := newRig(t, func(_ *config.Config, o *controller.Options) { o.Registry = &controller.LeaderRegistry{Store: store} })
	// What the gateway's launcher route writes (registry.Registration).
	a := r.actor("eng-web", "alice-1", ateapi.ActorStateSuspended, "")
	uid := a.GetMetadata().GetUid()
	if err := store.Put(context.Background(), registry.Registration{Atespace: "eng-web", Name: "alice-1", UID: uid,
		Person: registry.Person{Kind: "person", Issuer: "https://idp.example", Subject: "sub-alice"}, Profile: "eng",
		Connector: "claudecode", Template: "eng-web/claude", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	ref := ateapi.RefOf(a.GetMetadata())
	r.pass()
	if r.api.Policy(ref) == nil {
		t.Fatal("a launcher-created actor registered on the leader got no policy")
	}
	if n := len(r.sink.Events(controller.EventForeignActor)); n != 0 {
		t.Fatalf("a launcher-created actor was called foreign (%d)", n)
	}

	// Leader down: an unknown actor in a launcher atespace is held, not
	// refused as foreign, and existing policies stay.
	store.down = true
	b := r.actor("eng-web", "bob-1", ateapi.ActorStateSuspended, "")
	writes := len(r.api.PolicyWrites())
	r.clk.Add(time.Minute) // past the registration TTL: alice is re-read too
	_ = r.ctl.Reconcile(context.Background())
	if len(r.sink.Events(controller.EventForeignActor)) != 0 {
		t.Fatal("an actor was called foreign while the leader was unreachable")
	}
	if len(r.api.PolicyWrites()) != writes || r.api.Policy(ref) == nil {
		t.Fatal("a policy changed while the leader was unreachable")
	}
	// Leader back, bob never registered: now he is foreign.
	store.down = false
	r.pass()
	if r.api.Policy(ateapi.RefOf(b.GetMetadata())) != nil || len(r.sink.Events(controller.EventForeignActor)) != 1 {
		t.Fatal("an unregistered launcher-atespace actor was not refused once the leader answered")
	}

	// An actor in a managed atespace is written to the leader as attributed
	// (D3), with no person; a lifecycle change re-reads its registration.
	c := r.actor("ci-runs", "job-1", ateapi.ActorStateSuspended, "")
	r.pass()
	got, ok, _ := store.Get(context.Background(), "ci-runs", c.GetMetadata().GetUid())
	if !ok || !got.Attributed || got.Person.Subject != "" || got.Connector != controller.ConnectorUnknown {
		t.Fatalf("attributed registration = %+v", got)
	}
	// The launcher revokes alice (tombstone): on her next resume she is foreign.
	tomb, _, _ := store.Get(context.Background(), "eng-web", uid)
	tomb.Deleted = true
	_ = store.Put(context.Background(), tomb)
	if err := r.api.SetState(ref, ateapi.ActorStateResuming); err != nil {
		t.Fatal(err)
	}
	r.pass()
	if r.api.Policy(ref) != nil {
		t.Fatal("a revoked registration kept its policy after a lifecycle change")
	}
}

// A fork DefenseClaw makes in a launcher atespace is written back with the
// parent's full person; the person's issuer survives the round trip.
func TestLeaderRegistrationForkKeepsOwner(t *testing.T) {
	store := &leaderStore{m: map[string]registry.Registration{}}
	r := newRig(t, func(_ *config.Config, o *controller.Options) { o.Registry = &controller.LeaderRegistry{Store: store} })
	p := r.actor("eng-web", "alice-1", ateapi.ActorStateSuspended, "")
	_ = store.Put(context.Background(), registry.Registration{Atespace: "eng-web", Name: "alice-1", UID: p.GetMetadata().GetUid(),
		Person: registry.Person{Kind: "person", Issuer: "https://idp.example", Subject: "sub-alice"}, Profile: "eng",
		Connector: "claudecode", CreatedAt: time.Now()})
	r.pass()
	child, err := r.api.Fork(ateapi.RefOf(p.GetMetadata()), "t1", "alice-1-fork")
	if err != nil {
		t.Fatal(err)
	}
	r.pass()
	got, ok, _ := store.Get(context.Background(), "eng-web", child.GetMetadata().GetUid())
	if !ok || got.Attributed || got.Person.Issuer != "https://idp.example" || got.ParentUID != p.GetMetadata().GetUid() || got.Connector != "claudecode" {
		t.Fatalf("fork registration = %+v", got)
	}
	if r.api.Policy(ateapi.RefOf(child.GetMetadata())) == nil {
		t.Fatal("the fork got no policy")
	}
}
