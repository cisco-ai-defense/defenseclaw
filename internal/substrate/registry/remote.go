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
	srv.Handle(leader.MethodRegistrationGet, leader.Typed(func(ctx context.Context, in getIn) (getOut, error) {
		r, ok, err := s.Get(ctx, in.Atespace, in.UID)
		if err != nil {
			return getOut{}, err
		}
		if !ok {
			return getOut{}, nil
		}
		return getOut{Found: true, Registration: &r}, nil
	}))
	srv.Handle(leader.MethodRegistrationList, leader.Typed(func(ctx context.Context, f Filter) (listOut, error) {
		rs, err := s.List(ctx, f)
		return listOut{Registrations: rs}, err
	}))
}

// remoteTTL is how long a follower reuses a registration it read. A
// registration does not change identity fields after it is written; a
// tombstone or profile re-match reaches followers within this time.
const remoteTTL = 15 * time.Second

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
	if ok && time.Since(c.at) < remoteTTL && c.found {
		return c.r, true, nil
	}
	var out getOut
	if err := s.Client.Call(ctx, leader.MethodRegistrationGet, leader.NewRequestID(), getIn{Atespace: atespace, UID: uid}, &out); err != nil {
		return Registration{}, false, err
	}
	// A miss is not cached: the launcher writes a registration before it
	// answers, and the actor's first call may follow at once.
	if out.Found && out.Registration != nil {
		s.mu.Lock()
		if s.cache == nil || len(s.cache) > 65536 {
			s.cache = map[string]cached{}
		}
		s.cache[k] = cached{r: *out.Registration, found: true, at: time.Now()}
		s.mu.Unlock()
		return *out.Registration, true, nil
	}
	return Registration{}, false, nil
}

// Put implements Store.
func (s *Remote) Put(ctx context.Context, r Registration) error {
	if err := r.Validate(); err != nil {
		return err
	}
	if err := s.Client.Call(ctx, leader.MethodRegistrationWrite, leader.NewRequestID(), r, nil); err != nil {
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
