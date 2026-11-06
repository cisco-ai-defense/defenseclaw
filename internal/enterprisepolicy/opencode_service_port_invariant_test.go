// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"math/rand"
	"testing"
)

// openCodeHost simulates the guardian's world: homes with service.json
// ports, accounts bound to homes, the eligible set and the record.
type openCodeHost struct {
	homePort map[int]int // home id -> port its service.json names (0: none)
	homeOf   map[int]int // uid -> home id
	eligible map[int]bool
	record   map[int]int
}

// pass is one guardian pass: plan, then each eligible account's worker
// writes its port (or replaces the conflicting one), and the record follows.
func (h *openCodeHost) pass(t *testing.T, allowNew bool) OpenCodePortPlan {
	t.Helper()
	var uids []int
	files := map[int]int{}
	for uid := range h.eligible {
		uids = append(uids, uid)
		if port := h.homePort[h.homeOf[uid]]; port > 0 {
			files[uid] = port
		}
	}
	plan := PlanOpenCodeServicePorts(uids, files, h.record, allowNew)
	for _, uid := range uids {
		want := plan.Ports[uid]
		if want == 0 {
			continue
		}
		home := h.homeOf[uid]
		switch current := h.homePort[home]; {
		case current == 0:
			h.homePort[home] = want
		case plan.Replace[uid] == current:
			h.homePort[home] = want
		}
	}
	if allowNew {
		h.record = plan.Record
	}
	return plan
}

// The class invariant of REVIEW-gx053-4: over any sequence of adds, deletes,
// returns, exclusions, home reuse and copied files, after a pass no two
// eligible accounts' service.json files name the same port, every eligible
// account holds the port the plan gave it, and no entry is dropped.
func TestOpenCodePortInvariantOverRandomSequences(t *testing.T) {
	for seed := int64(1); seed <= 400; seed++ {
		rng := rand.New(rand.NewSource(seed))
		h := &openCodeHost{homePort: map[int]int{}, homeOf: map[int]int{}, eligible: map[int]bool{}, record: map[int]int{}}
		nextUID, nextHome := 1001, 1
		newAccount := func(home int) int {
			uid := nextUID
			// uids that share a first port, now and then
			if rng.Intn(4) == 0 {
				uid += OpenCodeAccountPortSpan * (1 + rng.Intn(3))
			}
			nextUID++
			if _, used := h.homeOf[uid]; used {
				uid = nextUID + 100000
				nextUID++
			}
			if home == 0 {
				home = nextHome
				nextHome++
			}
			h.homeOf[uid] = home
			h.eligible[uid] = true
			return uid
		}
		pick := func(eligibleWanted bool) int {
			var out []int
			for uid := range h.homeOf {
				if h.eligible[uid] == eligibleWanted {
					out = append(out, uid)
				}
			}
			if len(out) == 0 {
				return 0
			}
			return out[rng.Intn(len(out))]
		}
		for step := 0; step < 40; step++ {
			switch op := rng.Intn(7); op {
			case 0, 1: // add
				newAccount(0)
			case 2: // delete or exclude (the home stays)
				if uid := pick(true); uid != 0 {
					delete(h.eligible, uid)
				}
			case 3: // return (same uid, same home)
				if uid := pick(false); uid != 0 {
					h.eligible[uid] = true
				}
			case 4: // a new uid takes a departed account's home
				if uid := pick(false); uid != 0 {
					newAccount(h.homeOf[uid])
					delete(h.homeOf, uid)
					if _, ok := h.record[uid]; !ok {
						continue
					}
					// the old uid comes back with a fresh home
					h.homeOf[uid] = nextHome
					nextHome++
					h.eligible[uid] = rng.Intn(2) == 0
				}
			case 5: // a copied service.json (skel, dotfiles): another account's port
				a, b := pick(true), pick(true)
				if a != 0 && b != 0 && a != b {
					h.homePort[h.homeOf[b]] = h.homePort[h.homeOf[a]]
				}
			case 6: // a user sets a port by hand
				if uid := pick(true); uid != 0 {
					h.homePort[h.homeOf[uid]] = OpenCodeAccountPortBase + rng.Intn(64)
				}
			}
			before := map[int]int{}
			for uid, port := range h.record {
				before[uid] = port
			}
			plan := h.pass(t, true)
			seen := map[int]int{}
			for uid := range h.eligible {
				port := h.homePort[h.homeOf[uid]]
				if port != plan.Ports[uid] {
					t.Fatalf("seed %d step %d: uid %d file %d, plan %d (%+v)", seed, step, uid, port, plan.Ports[uid], plan)
				}
				if other, dup := seen[port]; dup && port != 0 {
					t.Fatalf("seed %d step %d: uids %d and %d share port %d", seed, step, other, uid, port)
				}
				seen[port] = uid
			}
			for uid := range before {
				if _, kept := h.record[uid]; !kept {
					t.Fatalf("seed %d step %d: entry %d dropped", seed, step, uid)
				}
			}
			holders := map[int]int{}
			for uid, port := range h.record {
				if other, dup := holders[port]; dup {
					t.Fatalf("seed %d step %d: record pairs uids %d and %d with port %d", seed, step, other, uid, port)
				}
				holders[port] = uid
			}
		}
	}
}

// With the record unreadable (allowNew false) nobody gets a new port and no
// file is changed; a later readable pass resolves what waited.
func TestOpenCodePortPlanWithoutRecordGivesNothingNew(t *testing.T) {
	plan := PlanOpenCodeServicePorts([]int{1001, 1002, 1003}, map[int]int{1001: 25001, 1002: 25001}, map[int]int{}, false)
	if plan.Ports[1001] != 25001 || plan.Ports[1002] != 0 || plan.Ports[1003] != 0 || len(plan.Replace) != 0 {
		t.Fatalf("plan %+v", plan)
	}
	if len(plan.Conflicts) != 1 || plan.Conflicts[0] != (OpenCodePortConflict{UID: 1002, Holder: 1001, Port: 25001}) {
		t.Fatalf("conflicts %+v", plan.Conflicts)
	}
	if len(plan.NoPort) != 2 {
		t.Fatalf("no-port %v", plan.NoPort)
	}
}
