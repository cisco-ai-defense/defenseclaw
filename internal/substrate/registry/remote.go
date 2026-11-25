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

package registry

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/leader"
)

type getIn struct {
	Atespace string `json:"atespace"`
	UID      string `json:"uid"`
}

type getOut struct {
	Found        bool          `json:"found"`
	Registration *Registration `json:"registration,omitempty"`
}

type listOut struct {
	Registrations []Registration `json:"registrations"`
}

type lookupIn struct {
	Atespace string `json:"atespace"`
	Name     string `json:"name"`
}

type putOut struct {
	Key string `json:"key"`
}

// Serve registers the registration methods of s on the leader server.
func Serve(srv *leader.Server, s Store) {
	srv.Handle(leader.MethodRegistrationWrite, leader.Typed(func(ctx context.Context, r Registration) (putOut, error) {
		if err := r.Validate(); err != nil {
			return putOut{}, &leader.WireError{Code: leader.CodeBadRequest, Message: err.Error()}
		}
		if err := s.Put(ctx, r); err != nil {
			return putOut{}, &leader.WireError{Code: leader.CodeBadRequest, Message: err.Error()}
		}
		return putOut{Key: r.Key}, nil
	}))
	srv.HandleRead(leader.MethodRegistrationGet, leader.Typed(func(ctx context.Context, in getIn) (getOut, error) {
		r, ok, err := s.Get(ctx, in.Atespace, in.UID)
		if err != nil {
			return getOut{}, err
		}
		if !ok {
			return getOut{}, nil
		}
		return getOut{Found: true, Registration: &r}, nil
	}))
	srv.HandleRead(leader.MethodRegistrationList, leader.Typed(func(ctx context.Context, f Filter) (listOut, error) {
		rs, err := s.List(ctx, f)
		return listOut{Registrations: rs}, err
	}))
	srv.HandleRead(leader.MethodRegistrationLookup, leader.Typed(func(ctx context.Context, in lookupIn) (Lookup, error) {
		return LookupName(ctx, s, in.Atespace, in.Name)
	}))
	if rc, ok := s.(RelayCerts); ok {
		serveRelayCerts(srv, rc)
	}
}

// remoteTTL is how long a follower reuses a registration it read. A
// registration does not change identity fields after it is written; a
// tombstone or profile re-match reaches followers within this time.
const remoteTTL = 15 * time.Second

// remoteMissTTL is how long a follower reuses "not registered".
const remoteMissTTL = time.Second

// Remote is Store over the leader transport, with a short read cache.
type Remote struct {
	Client *leader.Client

	mu    sync.Mutex
	cache map[string]cached
}

type cached struct {
	r     Registration
	found bool
	at    time.Time
}

// Get implements Store.
func (s *Remote) Get(ctx context.Context, atespace, uid string) (Registration, bool, error) {
	k := atespace + "/" + uid
	s.mu.Lock()
	c, ok := s.cache[k]
	s.mu.Unlock()
	if ok && c.found && time.Since(c.at) < remoteTTL {
		return c.r, true, nil
	}
	if ok && !c.found && time.Since(c.at) < remoteMissTTL {
		return Registration{}, false, nil
	}
	var out getOut
	if err := s.Client.Call(ctx, leader.MethodRegistrationGet, leader.NewRequestID(), getIn{Atespace: atespace, UID: uid}, &out); err != nil {
		return Registration{}, false, err
	}
	found := out.Found && out.Registration != nil
	s.mu.Lock()
	if s.cache == nil || len(s.cache) > 65536 {
		s.cache = map[string]cached{}
	}
	if found {
		s.cache[k] = cached{r: *out.Registration, found: true, at: time.Now()}
	} else {
		// A miss is cached only briefly: an unregistered actor's flood
		// costs one leader call a second, and the launcher resumes an actor
		// only after its registration is written (GAP-0057).
		s.cache[k] = cached{at: time.Now()}
	}
	s.mu.Unlock()
	if found {
		return *out.Registration, true, nil
	}
	return Registration{}, false, nil
}

// GetFresh reads the leader past the miss cache (a found record still comes
// from the cache). The controller calls it before it calls a launcher actor
// foreign, because the launcher writes the registration one leader call
// after CreateActor and a cached miss from that gap is stale (GAP-0145).
func (s *Remote) GetFresh(ctx context.Context, atespace, uid string) (Registration, bool, error) {
	s.mu.Lock()
	if c, ok := s.cache[atespace+"/"+uid]; ok && !c.found {
		delete(s.cache, atespace+"/"+uid)
	}
	s.mu.Unlock()
	return s.Get(ctx, atespace, uid)
}

// GetLatest reads the leader past the cache, found or not. A caller that
// writes a record back (the controller's policy_conflict mark) reads it this
// way, so a cached copy does not undo a newer write such as an approval.
func (s *Remote) GetLatest(ctx context.Context, atespace, uid string) (Registration, bool, error) {
	s.mu.Lock()
	delete(s.cache, atespace+"/"+uid)
	s.mu.Unlock()
	return s.Get(ctx, atespace, uid)
}

// Invalidate forgets the cached registration atespace/uid, so the next Get
// reads the leader: a revoked approval stops at once on this replica
// (GAP-0492).
func (s *Remote) Invalidate(atespace, uid string) {
	s.mu.Lock()
	delete(s.cache, atespace+"/"+uid)
	s.mu.Unlock()
}

// Put implements Store.
func (s *Remote) Put(ctx context.Context, r Registration) error {
	if err := r.Validate(); err != nil {
		return err
	}
	err := s.Client.Call(ctx, leader.MethodRegistrationWrite, leader.NewRequestID(), r, nil)
	if old, ok := r.olderLeaderForm(); ok && leader.IsUndecodable(err) {
		// GAP-0943: a leader older than this follower (a rolling upgrade)
		// refuses a field it does not know. Write the record in the form it
		// knows, under a new request ID (the refused call changed nothing).
		fmt.Fprintf(os.Stderr, "[substrate] the leader predates the sign-in assurance mark; %s/%s is registered without it\n", r.Atespace, r.Name)
		err = s.Client.Call(ctx, leader.MethodRegistrationWrite, leader.NewRequestID(), old, nil)
	}
	if err != nil {
		return err
	}
	s.mu.Lock()
	delete(s.cache, r.Atespace+"/"+r.UID)
	s.mu.Unlock()
	return nil
}

// List implements Store.
func (s *Remote) List(ctx context.Context, f Filter) ([]Registration, error) {
	var out listOut
	err := s.Client.Call(ctx, leader.MethodRegistrationList, leader.NewRequestID(), f, &out)
	return out.Registrations, err
}

// Lookup asks the leader for atespace/name's newest incarnation. It is not
// cached here: the callout's UID cache holds the answer.
func (s *Remote) Lookup(ctx context.Context, atespace, name string) (Lookup, error) {
	var out Lookup
	err := s.Client.Call(ctx, leader.MethodRegistrationLookup, leader.NewRequestID(), lookupIn{Atespace: atespace, Name: name}, &out)
	return out, err
}
