// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/activity"
	"github.com/defenseclaw/defenseclaw/internal/substrate/asks"
	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

// BenchmarkSubstrateListActivity is the cost of `substrate list` with the
// agent activity state (B3.6) against the same list without it, for one
// person's agents up to a fleet (2,100 agents, the GAP-0427 scale). "off" is
// the list as it was before the activity state (no feed, so no snapshot read
// and no activity object); "on" adds the leader snapshot, the pending asks
// (one in twenty agents) and the per-agent activity object. Read the ratio of
// the two lines of one size. The bar (GAP-1019) is "on" at 2,100 agents within
// 1.10x of the rel list, measured interleaved on the timing box.
func BenchmarkSubstrateListActivity(b *testing.B) {
	for _, n := range []int{210, 2100} {
		for _, on := range []bool{false, true} {
			state := map[bool]string{false: "off", true: "on"}[on]
			b.Run(fmt.Sprintf("agents=%d/activity=%s", n, state), func(b *testing.B) {
				now := time.Now()
				snap := activity.Snapshot{
					Last:  map[string]time.Time{},
					Kinds: map[string]map[string]time.Time{activity.KindModel: {}, activity.KindHook: {}},
				}
				store := asks.NewMemory()
				f := newSubstrateFixture(b, func(c *SubstrateConfig) {
					c.Asks = asksDirect{store}
					if on {
						c.ActivityFeed = &fakeActivityFeed{snap: snap}
					}
				})
				ctx := context.Background()
				for i := 0; i < n; i++ {
					uid := fmt.Sprintf("%08x-8d2b-4c77-9e0a-6b5f1d2c3e4a", 0x70000000+i)
					name := fmt.Sprintf("bench-%04d", i)
					reg := registry.Registration{Atespace: "eng-web", Name: name, UID: uid, Connector: "claudecode", Profile: "eng", Person: ownerOf(alice)}
					if err := f.regs.Put(ctx, reg); err != nil {
						b.Fatal(err)
					}
					f.live["eng-web/"+name] = identity.LiveActor{UID: uid, State: identity.ActorRunning}
					at := now.Add(-time.Duration(i%600) * time.Second)
					snap.Last[uid] = at
					snap.Kinds[activity.KindModel][uid] = at
					snap.Kinds[activity.KindHook][uid] = at
					if i%20 == 0 {
						if _, err := store.OpenAsk(ctx, asks.Ask{Atespace: "eng-web", Actor: name, UID: uid, OwnerID: alice.ID(), Kind: "egress", Host: "files.example.org", Created: now}); err != nil {
							b.Fatal(err)
						}
					}
				}
				if rec := f.do(b, f.admin, http.MethodGet, "/api/v1/substrate/actors", "p-alice", ""); rec.Code != http.StatusOK {
					b.Fatalf("list %d %s", rec.Code, rec.Body)
				}
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					f.do(b, f.admin, http.MethodGet, "/api/v1/substrate/actors", "p-alice", "")
				}
			})
		}
	}
}
