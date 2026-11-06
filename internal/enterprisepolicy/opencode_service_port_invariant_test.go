// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"math/rand"
	"sort"
	"testing"
)

// openCodeWorld simulates the guardian's world under the record model
// (REVIEW-gx053-9): accounts with files the users control (port, linked or
// read-only so the guardian cannot write, unreadable, corrupt), the eligible
// set, and the root-owned record.
type openCodeWorld struct {
	file       map[int]int  // uid -> port its service.json names (0: none or corrupt)
	unwritable map[int]bool // linked or chmod 500 folder: the worker cannot write
	unreadable map[int]bool // the read worker fails or times out
	eligible   map[int]bool
	record     map[int]int
}

func (w *openCodeWorld) pass(t *testing.T) OpenCodePortPlan {
	t.Helper()
	var uids []int
	imports, unknown := map[int]int{}, map[int]bool{}
	for uid := range w.eligible {
		uids = append(uids, uid)
		if _, recorded := w.record[uid]; recorded {
			continue // a recorded uid's file is never input
		}
		if w.unreadable[uid] {
			unknown[uid] = true
		} else if w.file[uid] > 0 {
			imports[uid] = w.file[uid]
		}
	}
	sort.Ints(uids)
	plan := PlanOpenCodeServicePorts(uids, imports, w.record, true, unknown)
	for _, uid := range uids {
		port := plan.Ports[uid]
		if port == 0 {
			continue
		}
		if w.unwritable[uid] || w.unreadable[uid] {
			if _, recorded := w.record[uid]; !recorded {
				delete(plan.Record, uid) // a new binding that could not be written
			}
			continue
		}
		w.file[uid] = port
	}
	w.record = plan.Record
	return plan
}

// The class property of REVIEW-gx053-9 over random user actions on their own
// files (link, chmod, edit, delete, corrupt, unreadable) and admin changes
// (enrol, exclude, return): once a uid is bound in the record, nothing any
// user does changes that binding; no entry is dropped; the record never pairs
// two uids; every writable eligible account's file names its recorded port.
func TestOpenCodeRecordIsTheOnlyAuthority(t *testing.T) {
	for seed := int64(1); seed <= 500; seed++ {
		rng := rand.New(rand.NewSource(seed))
		w := &openCodeWorld{file: map[int]int{}, unwritable: map[int]bool{}, unreadable: map[int]bool{}, eligible: map[int]bool{}, record: map[int]int{}}
		var all []int
		pick := func() int {
			if len(all) == 0 {
				return 0
			}
			return all[rng.Intn(len(all))]
		}
		for step := 0; step < 50; step++ {
			switch rng.Intn(9) {
			case 0, 1: // enrol a new account (uids that share a first port now and then)
				uid := 1000 + rng.Intn(3)*OpenCodeAccountPortSpan + rng.Intn(400)
				if !w.eligible[uid] {
					all = append(all, uid)
					w.eligible[uid] = true
				}
			case 2: // exclude or return (admin)
				if uid := pick(); uid != 0 {
					w.eligible[uid] = !w.eligible[uid]
				}
			case 3: // the user edits the port, maybe to another uid's port
				if uid := pick(); uid != 0 {
					if other := pick(); other != 0 && rng.Intn(2) == 0 {
						w.file[uid] = w.record[other]
					} else {
						w.file[uid] = OpenCodeAccountPortBase + rng.Intn(500)
					}
				}
			case 4: // link or chmod 500 the folder, or undo it
				if uid := pick(); uid != 0 {
					w.unwritable[uid] = !w.unwritable[uid]
				}
			case 5: // delete or corrupt the file
				if uid := pick(); uid != 0 {
					w.file[uid] = 0
				}
			case 6: // the read fails or recovers
				if uid := pick(); uid != 0 {
					w.unreadable[uid] = !w.unreadable[uid]
				}
			default: // nothing
			}
			before := map[int]int{}
			for uid, port := range w.record {
				before[uid] = port
			}
			w.pass(t)
			for uid, port := range before {
				if w.record[uid] != port {
					t.Fatalf("seed %d step %d: uid %d's binding changed %d -> %d", seed, step, uid, port, w.record[uid])
				}
			}
			holders := map[int]int{}
			for uid, port := range w.record {
				if other, dup := holders[port]; dup {
					t.Fatalf("seed %d step %d: the record pairs uids %d and %d with %d", seed, step, other, uid, port)
				}
				holders[port] = uid
			}
			for uid := range w.eligible {
				if port, ok := w.record[uid]; ok && !w.unwritable[uid] && !w.unreadable[uid] && w.file[uid] != port {
					t.Fatalf("seed %d step %d: uid %d's writable file names %d, its record %d", seed, step, uid, w.file[uid], port)
				}
			}
		}
	}
}

// With the record unreadable (allowNew false) nothing new is bound.
func TestOpenCodePortPlanWithoutRecordGivesNothingNew(t *testing.T) {
	plan := PlanOpenCodeServicePorts([]int{1001, 1002}, map[int]int{1001: 25001}, map[int]int{}, false, nil)
	if len(plan.Ports) != 0 || len(plan.Record) != 0 || len(plan.NoPort) != 2 {
		t.Fatalf("plan %+v", plan)
	}
}

// An import the record gives another uid gets a fresh port; an import nobody
// holds is bound; an excluded uid's recorded port is never given away.
func TestOpenCodePortImportRules(t *testing.T) {
	recorded := map[int]int{1001: 25001, 1009: 25009} // 1009 is excluded
	plan := PlanOpenCodeServicePorts([]int{1001, 1002, 1003, 1004}, map[int]int{1002: 25001, 1003: 26000, 1004: 25009}, recorded, true, nil)
	if plan.Ports[1001] != 25001 || plan.Ports[1003] != 26000 {
		t.Fatalf("ports %v", plan.Ports)
	}
	for _, uid := range []int{1002, 1004} {
		if port := plan.Ports[uid]; port == 0 || port == 25001 || port == 25009 {
			t.Fatalf("uid %d got %d: an import of a recorded port was allowed", uid, port)
		}
	}
	if plan.Record[1009] != 25009 || len(plan.Conflicts) != 2 {
		t.Fatalf("record %v conflicts %v", plan.Record, plan.Conflicts)
	}
}
