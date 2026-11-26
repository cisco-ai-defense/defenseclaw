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

//go:build !windows

package gateway

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi/ateapifake"
	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

// leaderDownStore is a registry whose leader does not answer: a read blocks
// until its context ends, as the leader client does while it retries, or
// fails after leaderDownGiveUp (the CLI's timeout, shortened for the test).
const leaderDownGiveUp = 1500 * time.Millisecond

type leaderDownStore struct {
	registry.Store
	down atomic.Bool
}

func (s *leaderDownStore) wait(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(leaderDownGiveUp):
		return errors.New("the leader did not answer")
	}
}

func (s *leaderDownStore) List(ctx context.Context, f registry.Filter) ([]registry.Registration, error) {
	if s.down.Load() {
		return nil, s.wait(ctx)
	}
	return s.Store.List(ctx, f)
}

func (s *leaderDownStore) Get(ctx context.Context, atespace, uid string) (registry.Registration, bool, error) {
	if s.down.Load() {
		return registry.Registration{}, false, s.wait(ctx)
	}
	return s.Store.Get(ctx, atespace, uid)
}

// substrate-1:GAP-1089: with the leader down, list and status retried until
// the CLI's 30 s timeout ended. They now retry inside a short window and then
// answer 503 registrations_unavailable (the plain "try again in a minute"
// message) at once.
func TestGAP1089ListAndStatusAnswerFastWhenTheLeaderIsDown(t *testing.T) {
	fake := ateapifake.New()
	fake.PutTemplate(&ateapi.ActorTemplate{Metadata: &ateapi.ResourceMetadata{Atespace: "eng-web", Name: "cc"}})
	f := newSubstrateFixture(t, func(c *SubstrateConfig) {
		c.Profiles = func(identity.Person, string, string, bool) (string, string, error) { return "eng", "eng-web", nil }
	})
	st := f.api.substrateState()
	st.cfg.Actions = &SubstrateATEActions{Client: fake, Ensure: func(context.Context, string, string) error { return nil }}
	st.cfg.Lookup = identity.ActorLookupFunc(func(ctx context.Context, atespace, name string) (identity.LiveActor, error) {
		a, err := fake.GetActor(ctx, ateapi.Ref(atespace, name))
		if err != nil {
			return identity.LiveActor{}, identity.ErrActorNotFound
		}
		return identity.LiveActor{UID: a.GetMetadata().GetUid()}, nil
	})
	if rec := f.do(t, f.admin, http.MethodPost, "/api/v1/substrate/actors", "p-alice", `{"template":"cc","connector":"claudecode","name":"alice-89"}`); rec.Code != http.StatusCreated {
		t.Fatalf("create %d %s", rec.Code, rec.Body)
	}
	down := &leaderDownStore{Store: st.cfg.Registrations}
	st.cfg.Registrations = down
	down.down.Store(true)
	old := substrateRegistryReadWindow
	substrateRegistryReadWindow = 200 * time.Millisecond
	t.Cleanup(func() { substrateRegistryReadWindow = old })

	for _, path := range []string{"/api/v1/substrate/actors", "/api/v1/substrate/actors/eng-web/alice-89"} {
		began := time.Now()
		rec := f.do(t, f.admin, http.MethodGet, path, "p-alice", "")
		if took := time.Since(began); took >= leaderDownGiveUp {
			t.Errorf("GET %s took %v with the leader down, want the bounded window", path, took)
		}
		if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "registrations_unavailable") {
			t.Errorf("GET %s = %d %s, want 503 registrations_unavailable", path, rec.Code, rec.Body)
		}
	}
}
