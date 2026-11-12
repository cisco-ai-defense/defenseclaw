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
	built      bool         // the record exists: the import window is closed
	contested  map[int]bool // contested marks in the record
}

func (w *openCodeWorld) pass(t *testing.T) OpenCodePortPlan {
	t.Helper()
	var uids []int
	imports, unknown := map[int]int{}, map[int]bool{}
	for uid := range w.eligible {
		uids = append(uids, uid)
		if _, recorded := w.record[uid]; recorded || w.built {
			continue // a recorded uid's file is never input; after the window no file is
		}
		if w.unreadable[uid] {
			unknown[uid] = true
		} else if w.file[uid] > 0 {
			imports[uid] = w.file[uid]
		}
	}
	sort.Ints(uids)
	plan := PlanOpenCodeServicePorts(uids, imports, w.record, true, unknown, !w.built, w.contested)
	for port := range plan.Contested {
		w.contested[port] = true
	}
	w.built = true
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
		w := &openCodeWorld{file: map[int]int{}, unwritable: map[int]bool{}, unreadable: map[int]bool{}, eligible: map[int]bool{}, record: map[int]int{}, contested: map[int]bool{}}
		// Enrol a few accounts with files before the record is built, some
		// naming the same port, so the import window and contests happen.
		for i := 0; i < 1+rng.Intn(6); i++ {
			uid := 1000 + rng.Intn(400)
			w.eligible[uid] = true
			w.file[uid] = OpenCodeAccountPortBase + rng.Intn(20)
			w.unreadable[uid] = rng.Intn(5) == 0
		}
		var all []int
		for uid := range w.eligible {
			all = append(all, uid)
		}
		sort.Ints(all)
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
			for uid, port := range w.record {
				if w.contested[port] {
					t.Fatalf("seed %d step %d: uid %d was given contested port %d", seed, step, uid, port)
				}
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
	plan := PlanOpenCodeServicePorts([]int{1001, 1002}, map[int]int{1001: 25001}, map[int]int{}, false, nil, true, nil)
	if len(plan.Ports) != 0 || len(plan.Record) != 0 || len(plan.NoPort) != 2 {
		t.Fatalf("plan %+v", plan)
	}
}

// An import the record gives another uid gets a fresh port; an import nobody
// holds is bound; an excluded uid's recorded port is never given away.
func TestOpenCodePortImportRules(t *testing.T) {
	recorded := map[int]int{1001: 25001, 1009: 25009} // 1009 is excluded
	plan := PlanOpenCodeServicePorts([]int{1001, 1002, 1003, 1004}, map[int]int{1002: 25001, 1003: 26000, 1004: 25009}, recorded, true, nil, true, nil)
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

// REVIEW-gx053-10: claims are collected before any is granted, so the order
// of uids decides nothing; a port two unrecorded files name is given to
// nobody, nor handed out fresh; OpenCode's defaults are not imported.
func TestOpenCodePortContestedImport(t *testing.T) {
	for _, order := range [][]int{{1001, 1002, 1003}, {1003, 1002, 1001}} {
		plan := PlanOpenCodeServicePorts(order, map[int]int{1001: 25002, 1002: 25002, 1003: OpenCodeDefaultServicePort}, nil, true, nil, true, nil)
		for _, uid := range order {
			if port := plan.Ports[uid]; port == 0 || port == 25002 || port == OpenCodeDefaultServicePort {
				t.Fatalf("order %v: uid %d got %d", order, uid, port)
			}
		}
		if got := plan.Contested[25002]; len(got) != 2 || got[0] != 1001 || got[1] != 1002 {
			t.Fatalf("contested %v", plan.Contested)
		}
	}
	// With a record, the record decides: bob keeps 25002, the copy is refused.
	plan := PlanOpenCodeServicePorts([]int{1001, 1002}, map[int]int{1001: 25002}, map[int]int{1002: 25002}, true, nil, true, nil)
	if plan.Ports[1002] != 25002 || plan.Ports[1001] == 25002 {
		t.Fatalf("ports %v", plan.Ports)
	}
}

// REVIEW-gx053-11: outside the window no file is imported; a contested mark
// keeps its port out of imports and fresh ports in every later pass.
func TestOpenCodePortImportWindowAndMarks(t *testing.T) {
	plan := PlanOpenCodeServicePorts([]int{1001}, map[int]int{1001: 26600}, map[int]int{1002: 25002}, true, nil, false, nil)
	if plan.Ports[1001] == 26600 || plan.Ports[1001] == 0 {
		t.Fatalf("an import outside the window: %v", plan.Ports)
	}
	plan = PlanOpenCodeServicePorts([]int{1001, 1003}, map[int]int{1001: 25003}, nil, true, nil, true, map[int]bool{25003: true})
	if plan.Ports[1001] == 25003 || plan.Ports[1003] == 25003 {
		t.Fatalf("a contested port was given: %v", plan.Ports)
	}
}
