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

package chainstate

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/leader"
)

// GAP-0601: the start grace runs from the first call of each leader term.
// The boundary is exact, a new term (Leading) starts it again, and a call
// answered not_leader starts nothing.
func TestStartGraceRunsFromTheTermsFirstCallGAP0601(t *testing.T) {
	ctx := context.Background()
	h := coldLeader(t)
	post := EgressRequest{Actor: actorB, Name: "b", Host: "github.com", Method: "POST"}
	h.otherCall()
	h.advance(15*time.Second - time.Millisecond)
	if _, err := h.svc.Egress(ctx, post); !errors.Is(err, errStarting) {
		t.Fatalf("just inside the grace of the first call: want errStarting, got %v", err)
	}
	h.advance(time.Millisecond)
	if v, err := h.svc.Egress(ctx, post); err != nil || v.Deny {
		t.Fatalf("at the end of the grace: %+v %v", v, err)
	}
	// A new term (the lease lost and taken again): the next call starts
	// the grace again, and a check that comes first starts it too.
	h.advance(time.Minute)
	h.svc.Leading()
	h.otherCall()
	h.advance(6 * time.Second)
	if _, err := h.svc.Egress(ctx, post); !errors.Is(err, errStarting) {
		t.Fatalf("6 s into a new term: want errStarting, got %v", err)
	}
	h.advance(9 * time.Second)
	if v, err := h.svc.Egress(ctx, post); err != nil || v.Deny {
		t.Fatalf("15 s into a new term: %+v %v", v, err)
	}
	h.svc.Leading()
	h.advance(10 * time.Second)
	if _, err := h.svc.Egress(ctx, post); !errors.Is(err, errStarting) {
		t.Fatalf("a term whose first call is the check: want errStarting, got %v", err)
	}
	// Leading and LeaderCall on no service are no-ops.
	var none *Service
	none.Leading()
	none.LeaderCall()
}

// A replica that is not the leader serves no call, so a call it answers
// not_leader does not start its grace.
func TestNotLeaderCallStartsNoGraceGAP0601(t *testing.T) {
	h := &harness{t: t, dir: t.TempDir(), now: time.Date(2026, 11, 18, 11, 0, 0, 0, time.UTC)}
	svc, err := New(Options{Dir: h.dir, Now: h.clock, StartGrace: 15 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	var leading atomic.Bool
	ls := &leader.Server{IsLeader: leading.Load}
	svc.Register(ls)
	ls.HandleRead(leader.MethodRegistrationGet, func(context.Context, json.RawMessage) (json.RawMessage, error) {
		return json.RawMessage(`{}`), nil
	})
	srv := httptest.NewServer(ls)
	t.Cleanup(func() { srv.Close(); _ = svc.Close() })
	lc := &leader.Client{BaseURL: srv.URL, HTTP: srv.Client(), Retry: time.Millisecond}
	if err := lc.Call(context.Background(), leader.MethodRegistrationGet, "", struct{}{}, nil); !leader.IsNotLeader(err) {
		t.Fatalf("standby: want not_leader, got %v", err)
	}
	h.advance(time.Minute)
	leading.Store(true)
	svc.Leading()
	if err := lc.Call(context.Background(), leader.MethodRegistrationGet, "", struct{}{}, nil); err != nil {
		t.Fatal(err)
	}
	h.advance(6 * time.Second)
	if _, err := svc.Egress(context.Background(), EgressRequest{Actor: actorB, Name: "b", Host: "github.com", Method: "POST"}); !errors.Is(err, errStarting) {
		t.Fatalf("6 s after the first call as the leader: want errStarting, got %v", err)
	}
}

// LeaderCall, Leading and the check race on the term (go test -race).
func TestStartGraceTermConcurrentGAP0601(t *testing.T) {
	h := coldLeader(t)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				switch j % 3 {
				case 0:
					h.svc.LeaderCall()
				case 1:
					h.svc.Leading()
				default:
					_ = h.svc.starting()
				}
			}
		}()
	}
	wg.Wait()
}
