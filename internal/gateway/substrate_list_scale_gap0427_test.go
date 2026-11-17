// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// The substrate fixture (substrate_listener_test.go) is not built on Windows.

//go:build !windows

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

// countingLookup counts control API calls and their peak concurrency; with
// list set it can also list an atespace (identity.ActorLister).
type countingLookup struct {
	mu             sync.Mutex
	gets, lists    int
	inFlight, peak int
	live           map[string]identity.LiveActor // atespace/name
	delay          time.Duration
}

func (c *countingLookup) LookupActor(_ context.Context, atespace, name string) (identity.LiveActor, error) {
	c.mu.Lock()
	c.gets++
	c.inFlight++
	c.peak = max(c.peak, c.inFlight)
	c.mu.Unlock()
	time.Sleep(c.delay)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.inFlight--
	if l, ok := c.live[atespace+"/"+name]; ok {
		return l, nil
	}
	return identity.LiveActor{}, identity.ErrActorNotFound
}

type listingLookup struct{ *countingLookup }

func (c listingLookup) ListLiveActors(_ context.Context, atespace string) (map[string]identity.LiveActor, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lists++
	out := map[string]identity.LiveActor{}
	for k, v := range c.live {
		if len(k) > len(atespace) && k[:len(atespace)+1] == atespace+"/" {
			out[k[len(atespace)+1:]] = v
		}
	}
	return out, nil
}

func scaleUID(i int) string { return fmt.Sprintf("7f9c3a1e-8d2b-4c77-9e0a-%012d", i) }

// GAP-0427: a person with many agents (2,100 on E2) got "the cluster did
// not answer in time" from list, because the gateway asked the control API
// for every agent's state one after another. With a lookup that can list,
// an atespace is one call; any other lookup runs in parallel.
func TestSubstrateListManyAgentsGAP0427(t *testing.T) {
	const n = 300
	base := &countingLookup{live: map[string]identity.LiveActor{}, delay: 2 * time.Millisecond}
	for _, listing := range []bool{true, false} {
		base.gets, base.lists, base.peak = 0, 0, 0
		var lookup identity.ActorLookup = base
		if listing {
			lookup = listingLookup{base}
		}
		f := newSubstrateFixture(t, func(c *SubstrateConfig) { c.Lookup = lookup })
		ctx := context.Background()
		for i := range n {
			name := fmt.Sprintf("scale-%d", i)
			if err := f.regs.Put(ctx, registry.Registration{Atespace: "eng-scale", Name: name, UID: scaleUID(i),
				Connector: "claudecode", Profile: "eng", Person: ownerOf(alice), Unattended: true}); err != nil {
				t.Fatal(err)
			}
			if i%3 == 0 {
				base.live["eng-scale/"+name] = identity.LiveActor{UID: scaleUID(i), State: identity.ActorRunning}
			} else if i%3 == 1 {
				base.live["eng-scale/"+name] = identity.LiveActor{UID: "recreated", State: identity.ActorRunning}
			}
		}
		rec := f.do(t, f.admin, http.MethodGet, "/api/v1/substrate/actors", "p-alice", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("list: %d %s", rec.Code, rec.Body)
		}
		var body struct {
			Actors []map[string]any `json:"actors"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		running := 0
		for _, a := range body.Actors {
			if a["state"] == "running" {
				running++
			}
		}
		// alice-1 from the fixture is not in the fake's live set.
		if len(body.Actors) != n+1 || running != n/3 {
			t.Fatalf("listing=%t: %d agents (%d running), want %d (%d running)", listing, len(body.Actors), running, n+1, n/3)
		}
		base.mu.Lock()
		gets, lists, peak := base.gets, base.lists, base.peak
		base.mu.Unlock()
		if listing && (lists != 1 || gets > 1) {
			t.Errorf("a listing lookup: %d list calls and %d single lookups for %d agents, want 1 list", lists, gets, n)
		}
		if !listing && (gets != n+1 || peak < 2) {
			t.Errorf("a plain lookup: %d lookups, peak concurrency %d; want %d lookups run in parallel", gets, peak, n+1)
		}
	}
}
