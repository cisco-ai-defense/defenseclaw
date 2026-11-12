// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import "sort"

// OpenCodeAccountPortConflict names an import that could not take a port.
type OpenCodeAccountPortConflict struct {
	Account string
	Holder  string
	Port    int
}

// OpenCodeAccountPortPlan is the Windows guardian's full-SID view of the
// shared record-authoritative OpenCode port plan.
type OpenCodeAccountPortPlan struct {
	Ports     map[string]int
	Record    map[string]int
	Conflicts []OpenCodeAccountPortConflict
	Contested map[int][]string
	NoPort    []string
}

// PlanOpenCodeServicePortsByAccountWithClaims maps full SIDs to distinct
// planner IDs with the same initial port as their RID. The shared planner
// then applies the same record and import rules on every operating system.
// Per-user claims can keep a port out of the fresh pool but never displace a
// binding already in the protected record.
func PlanOpenCodeServicePortsByAccountWithClaims(ids map[string]uint64, eligible []string, imports, recorded map[string]int, claims map[int]string, allowNew bool, unknown map[string]bool, importWindow bool, contestedMarks map[int]bool) OpenCodeAccountPortPlan {
	plan := OpenCodeAccountPortPlan{
		Ports: map[string]int{}, Record: map[string]int{}, Contested: map[int][]string{},
	}
	all := map[string]bool{}
	for sid := range recorded {
		all[sid] = true
	}
	for _, sid := range eligible {
		all[sid] = true
	}
	keys := make([]string, 0, len(all))
	for sid := range all {
		keys = append(keys, sid)
	}
	sort.Strings(keys)
	uidFor := make(map[string]int, len(keys))
	sidFor := make(map[int]string, len(keys))
	for i, sid := range keys {
		uid := (i+1)*OpenCodeAccountPortSpan + int(ids[sid]%OpenCodeAccountPortSpan)
		uidFor[sid], sidFor[uid] = uid, sid
	}
	eligibleUIDs := make([]int, 0, len(eligible))
	for _, sid := range eligible {
		eligibleUIDs = append(eligibleUIDs, uidFor[sid])
	}
	importUIDs := map[int]int{}
	for sid, port := range imports {
		if uid, ok := uidFor[sid]; ok {
			importUIDs[uid] = port
		}
	}
	recordUIDs := map[int]int{}
	recordedPorts := map[int]bool{}
	for sid, port := range recorded {
		recordUIDs[uidFor[sid]] = port
		recordedPorts[port] = true
	}
	unknownUIDs := map[int]bool{}
	for sid := range unknown {
		if uid, ok := uidFor[sid]; ok {
			unknownUIDs[uid] = true
		}
	}
	// Claims reserve free ports from other SIDs but do not enter the
	// protected record. Their owner can retry a claim after a file write
	// refusal without accumulating a new claim on every guardian pass.
	reserved := map[int]int{}
	for port, owner := range claims {
		if port <= 0 || port > 65535 || recordedPorts[port] {
			continue
		}
		if uid, ok := uidFor[owner]; ok {
			reserved[port] = uid
		} else {
			reserved[port] = -1
		}
	}
	shared := planOpenCodeServicePorts(eligibleUIDs, importUIDs, recordUIDs, allowNew, unknownUIDs, importWindow, contestedMarks, reserved)
	for uid, port := range shared.Ports {
		if sid := sidFor[uid]; sid != "" {
			plan.Ports[sid] = port
		}
	}
	for uid, port := range shared.Record {
		if sid := sidFor[uid]; sid != "" {
			plan.Record[sid] = port
		}
	}
	for _, conflict := range shared.Conflicts {
		holder := sidFor[conflict.Holder]
		plan.Conflicts = append(plan.Conflicts, OpenCodeAccountPortConflict{sidFor[conflict.UID], holder, conflict.Port})
	}
	for port, uids := range shared.Contested {
		for _, uid := range uids {
			plan.Contested[port] = append(plan.Contested[port], sidFor[uid])
		}
	}
	for _, uid := range shared.NoPort {
		if sid := sidFor[uid]; sid != "" {
			plan.NoPort = append(plan.NoPort, sid)
		}
	}
	sort.Strings(plan.NoPort)
	return plan
}
