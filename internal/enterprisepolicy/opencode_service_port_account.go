// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import "sort"

// OpenCodeAccountPortConflict names a live account whose service file names
// a port held by a different account.
type OpenCodeAccountPortConflict struct {
	Account string
	Holder  string
	Port    int
}

// OpenCodeAccountPortPlan is the Windows guardian's SID keyed port plan.
type OpenCodeAccountPortPlan struct {
	Ports     map[string]int
	Replace   map[string]int
	Record    map[string]int
	Conflicts []OpenCodeAccountPortConflict
	NoPort    []string
}

// PlanOpenCodeServicePortsByAccountWithClaims keeps the full SID as the key.
// Recorded reservations win before new file ports; a live file naming its own
// recorded port wins first. Other file ports then win before any new port.
// Existing claim files reserve candidates for their owner, including accounts
// that are not currently eligible. A conflict asks the caller to replace the
// losing file's port under its account token. When allowNew is false, the
// caller must not write the returned record or replace any file.
func PlanOpenCodeServicePortsByAccountWithClaims(ids map[string]uint64, eligible []string, filePorts, recorded map[string]int, claims map[int]string, allowNew bool) OpenCodeAccountPortPlan {
	plan := OpenCodeAccountPortPlan{Ports: map[string]int{}, Replace: map[string]int{}, Record: map[string]int{}}
	eligible = append([]string(nil), eligible...)
	sort.Strings(eligible)
	isEligible := make(map[string]bool, len(eligible))
	for _, sid := range eligible {
		isEligible[sid] = true
	}
	recordKeys := make([]string, 0, len(recorded))
	for sid := range recorded {
		recordKeys = append(recordKeys, sid)
	}
	sort.Strings(recordKeys)
	holder := map[int]string{}
	hold := func(sid string, port int) bool {
		if port <= 0 || port > 65535 {
			return false
		}
		if other := holder[port]; other != "" && other != sid {
			return false
		}
		holder[port] = sid
		return true
	}
	for _, sid := range eligible {
		if port := filePorts[sid]; port > 0 && port == recorded[sid] && hold(sid, port) {
			plan.Ports[sid] = port
		}
	}
	var superseded []string
	for _, sid := range recordKeys {
		if plan.Ports[sid] != 0 || (isEligible[sid] && filePorts[sid] > 0) {
			continue
		}
		port := recorded[sid]
		if hold(sid, port) {
			if isEligible[sid] {
				plan.Ports[sid] = port
			} else {
				plan.Record[sid] = port
			}
			continue
		}
		if isEligible[sid] {
			plan.Conflicts = append(plan.Conflicts, OpenCodeAccountPortConflict{sid, holder[port], port})
		} else {
			superseded = append(superseded, sid)
		}
	}
	claimPorts := make([]int, 0, len(claims))
	for port := range claims {
		claimPorts = append(claimPorts, port)
	}
	sort.Ints(claimPorts)
	for _, port := range claimPorts {
		if port > 0 && port <= 65535 && holder[port] == "" {
			owner := claims[port]
			if owner == "" {
				owner = "!"
			}
			holder[port] = owner
		}
	}
	var fresh []string
	for _, sid := range eligible {
		if plan.Ports[sid] != 0 {
			continue
		}
		port := filePorts[sid]
		if port <= 0 {
			fresh = append(fresh, sid)
			continue
		}
		if hold(sid, port) {
			plan.Ports[sid] = port
			continue
		}
		plan.Conflicts = append(plan.Conflicts, OpenCodeAccountPortConflict{sid, holder[port], port})
		if allowNew {
			plan.Replace[sid] = port
		}
		fresh = append(fresh, sid)
	}
	next := func(sid string) int {
		if port := recorded[sid]; port > 0 && hold(sid, port) {
			return port
		}
		start := OpenCodeAccountPort(ids[sid]) - OpenCodeAccountPortBase
		for step := 0; step < OpenCodeAccountPortSpan; step++ {
			port := OpenCodeAccountPortBase + (start+step)%OpenCodeAccountPortSpan
			if hold(sid, port) {
				return port
			}
		}
		return 0
	}
	for _, sid := range fresh {
		port := 0
		if allowNew {
			port = next(sid)
		}
		if port == 0 {
			plan.NoPort = append(plan.NoPort, sid)
			delete(plan.Replace, sid)
			continue
		}
		plan.Ports[sid] = port
	}
	for _, sid := range superseded {
		port := 0
		if allowNew {
			port = next(sid)
		}
		if port == 0 {
			port = recorded[sid]
		}
		plan.Record[sid] = port
	}
	for sid, port := range plan.Ports {
		plan.Record[sid] = port
	}
	sort.Strings(plan.NoPort)
	return plan
}
