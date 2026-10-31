// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisestatus

import "sort"

// EnforcementPending summarises the running agent sessions a result names as
// not enforced until they restart: an agent reads its hooks when it starts,
// so a session that started before the deployment, a newly enabled
// connector, an enrollment or a guardian restore gave it hooks runs without
// DefenseClaw until it is restarted (agent_sessions_restart_required, and
// the bundle scan in bundle.sessions_restart_required). It carries a count
// and connector names only, never a user name or a process id, so a
// management agent can forward it as it is.
type EnforcementPending struct {
	Count      int      `json:"count"`
	Connectors []string `json:"connectors"`
}

// NotePendingSession records that this result names the session pid of
// connector as running without DefenseClaw until it restarts. Finish turns
// the noted sessions into enforcement_pending.
func (r *Result) NotePendingSession(connector string, pid int) {
	if r == nil || pid <= 0 {
		return
	}
	if connector == "" {
		connector = "unknown"
	}
	if r.pendingSessions == nil {
		r.pendingSessions = map[int]string{}
	}
	r.pendingSessions[pid] = connector
}

// PendingFromScan is the enforcement_pending summary of one live session
// scan (bundle status); nil when the scan found none or is unknown.
func PendingFromScan(status SessionRestartStatus) *EnforcementPending {
	return summarizePending(nil, &status)
}

// summarizePending merges the noted sessions with a known scan. A session
// both name counts once (by process id); scan sessions beyond its 20 listed
// entries count without a connector name.
func summarizePending(noted map[int]string, scan *SessionRestartStatus) *EnforcementPending {
	sessions := make(map[int]string, len(noted))
	for pid, connector := range noted {
		sessions[pid] = connector
	}
	unlisted := 0
	if scan != nil && scan.State == "known" && scan.Count > 0 {
		listed := 0
		for _, entry := range scan.Entries {
			if entry.PID > 0 {
				sessions[entry.PID] = entry.Agent
				listed++
			}
		}
		unlisted = max(scan.Count-listed, 0)
	}
	if len(sessions)+unlisted == 0 {
		return nil
	}
	seen := map[string]bool{}
	connectors := []string{}
	for _, connector := range sessions {
		if !seen[connector] {
			seen[connector] = true
			connectors = append(connectors, connector)
		}
	}
	sort.Strings(connectors)
	return &EnforcementPending{Count: len(sessions) + unlisted, Connectors: connectors}
}
