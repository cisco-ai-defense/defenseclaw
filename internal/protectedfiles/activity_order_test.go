// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package protectedfiles

import (
	"fmt"
	"math/rand"
	"sort"
	"testing"
	"time"
)

// sortedActivity is the Activity of 1.0.7 rc3: every Begin walked the open
// calls to expire them and, at maxOpen, sorted them all to drop the oldest.
// TestActivityMatchesTheSortingTracker holds the begin-order tracker to it.
type sortedActivity struct {
	open  map[callKey]openCall
	ended []endedCall
}

func (a *sortedActivity) expire(now time.Time) {
	for key, call := range a.open {
		if now.Sub(call.begin) > maxOpenCall {
			delete(a.open, key)
		}
	}
	cut := 0
	for cut < len(a.ended) && now.Sub(a.ended[cut].end) > maxOpenCall {
		cut++
	}
	a.ended = a.ended[cut:]
}

func (a *sortedActivity) begin(now time.Time, home string, s Session) {
	a.expire(now)
	key := callKey{cleanHome(home), s.Connector, s.SessionID, s.ToolInvocationID}
	if _, ok := a.open[key]; !ok && len(a.open) >= maxOpen {
		keys := make([]callKey, 0, len(a.open))
		for key := range a.open {
			keys = append(keys, key)
		}
		sort.Slice(keys, func(i, j int) bool { return a.open[keys[i]].begin.Before(a.open[keys[j]].begin) })
		delete(a.open, keys[0])
	}
	a.open[key] = openCall{begin: now, session: s}
}

func (a *sortedActivity) end(now time.Time, home string, s Session) {
	home = cleanHome(home)
	for key, call := range a.open {
		if key.home != home || key.connector != s.Connector || key.session != s.SessionID {
			continue
		}
		if s.ToolInvocationID != "" && key.tool != s.ToolInvocationID && key.tool != "" {
			continue
		}
		delete(a.open, key)
		a.ended = append(a.ended, endedCall{home: home, begin: call.begin, end: now, session: call.session})
	}
	if len(a.ended) > maxEnded {
		a.ended = a.ended[len(a.ended)-maxEnded:]
	}
}

// TestActivityMatchesTheSortingTracker pins rel-1-0-6 GAP-0381: keeping the
// open calls in begin order changes no answer. Random begins (past maxOpen,
// re-begun calls included), results, stops, clock steps past maxOpenCall and
// attributions run against both trackers; the open calls and every
// attribution must agree.
func TestActivityMatchesTheSortingTracker(t *testing.T) {
	for seed := int64(1); seed <= 4; seed++ {
		t.Run(fmt.Sprintf("seed %d", seed), func(t *testing.T) {
			r := rand.New(rand.NewSource(seed))
			c := &clock{t: time.Unix(1_800_000_000, 0)}
			got := NewActivity(c.now)
			want := &sortedActivity{open: map[callKey]openCall{}}
			homes := []string{"/home/a", "/home/b/"}
			atCapacity := 0
			for op := 0; op < 6000; op++ {
				// Distinct begin times: the sorting tracker broke ties in no
				// defined order.
				c.tick(time.Duration(1+r.Intn(3)) * time.Millisecond)
				if op%2500 == 2499 {
					c.tick(maxOpenCall - time.Duration(r.Intn(2000))*time.Millisecond)
				}
				home := homes[r.Intn(len(homes))]
				s := Session{Connector: []string{"claudecode", "codex"}[r.Intn(2)], SessionID: fmt.Sprintf("s%d", r.Intn(6)),
					ToolInvocationID: fmt.Sprintf("t%d", r.Intn(1600))}
				switch k := r.Intn(200); {
				case k < 160:
					got.Begin(home, s)
					want.begin(c.now(), home, s)
				case k < 190:
					got.End(home, s)
					want.end(c.now(), home, s)
				case k < 191:
					s.ToolInvocationID = ""
					got.End(home, s)
					want.end(c.now(), home, s)
				default:
					from := c.now().Add(-time.Duration(r.Intn(4000)) * time.Millisecond)
					gs, gok := got.Attribute(home, from, c.now())
					want.expire(c.now())
					ws, wok := attributeSorted(want, home, from, c.now())
					if gs != ws || gok != wok {
						t.Fatalf("op %d: attribute = %+v %v, want %+v %v", op, gs, gok, ws, wok)
					}
				}
				if len(want.open) == maxOpen {
					atCapacity++
				}
				if len(got.open) != len(want.open) {
					t.Fatalf("op %d: %d open calls, want %d", op, len(got.open), len(want.open))
				}
				for key, call := range want.open {
					if g, ok := got.open[key]; !ok || !g.begin.Equal(call.begin) || g.session != call.session {
						t.Fatalf("op %d: open call %+v = %+v %v, want %+v", op, key, g, ok, call)
					}
				}
				if len(got.order) > 2*maxOpen+65 {
					t.Fatalf("op %d: %d order entries for %d open calls", op, len(got.order), len(got.open))
				}
			}
			if atCapacity < 100 {
				t.Fatalf("the run was at maxOpen open calls after %d operations, want at least 100", atCapacity)
			}
		})
	}
}

func attributeSorted(a *sortedActivity, home string, from, to time.Time) (Session, bool) {
	home = cleanHome(home)
	var best Session
	var bestAt time.Time
	found := false
	for key, call := range a.open {
		if key.home == home && !call.begin.After(to) && (!found || call.begin.After(bestAt)) {
			best, bestAt, found = call.session, call.begin, true
		}
	}
	if found {
		return best, true
	}
	for i := len(a.ended) - 1; i >= 0; i-- {
		call := a.ended[i]
		if call.home == home && !call.begin.After(to) && !call.end.Before(from.Add(-endedGrace)) {
			return call.session, true
		}
	}
	return Session{}, false
}

// TestBeginAtCapacityDoesNotWalkTheOpenCalls: with maxOpen calls that got no
// result, a Begin drops the oldest without copying or sorting the open calls
// (the sort allocated a key slice and a swapper on every call).
func TestBeginAtCapacityDoesNotWalkTheOpenCalls(t *testing.T) {
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	a := NewActivity(c.now)
	for i := 0; i < maxOpen; i++ {
		c.tick(time.Millisecond)
		a.Begin("/home/u", Session{Connector: "claudecode", SessionID: "s", ToolInvocationID: fmt.Sprintf("warm%d", i)})
	}
	tools := make([]string, 400)
	for i := range tools {
		tools[i] = fmt.Sprintf("t%d", i)
	}
	next := 0
	allocs := testing.AllocsPerRun(300, func() {
		c.tick(time.Millisecond)
		a.Begin("/home/u", Session{Connector: "claudecode", SessionID: "s", ToolInvocationID: tools[next%len(tools)]})
		next++
	})
	if allocs > 1 {
		t.Fatalf("Begin at capacity made %.1f allocations, want at most 1", allocs)
	}
	if len(a.open) != maxOpen {
		t.Fatalf("%d open calls, want %d", len(a.open), maxOpen)
	}
	first := Session{Connector: "claudecode", SessionID: "s", ToolInvocationID: "warm0"}
	if _, ok := a.open[callKey{"/home/u", first.Connector, first.SessionID, first.ToolInvocationID}]; ok {
		t.Fatal("the oldest open call was not dropped")
	}
}

func BenchmarkActivityBeginAtCapacity(b *testing.B) {
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	a := NewActivity(c.now)
	tools := make([]string, 4*maxOpen)
	for i := range tools {
		tools[i] = fmt.Sprintf("t%d", i)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.tick(time.Millisecond)
		a.Begin("/home/u", Session{Connector: "claudecode", SessionID: "s", ToolInvocationID: tools[i%len(tools)]})
	}
}
