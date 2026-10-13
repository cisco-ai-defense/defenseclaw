// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisestatus

import (
	"sort"
	"time"
)

const CodeSessionsNeedRestart = "sessions_need_restart"

// SessionProcess is the minimal process information needed for a managed
// hook activation check. Callers obtain it from the platform process scan.
type SessionProcess struct {
	PID       int
	User      string
	Agent     string
	StartedAt time.Time
}

// SessionEntry is one running agent that predates its managed hook settings.
type SessionEntry struct {
	PID       int    `json:"pid"`
	User      string `json:"user"`
	Agent     string `json:"agent"`
	StartedAt string `json:"started_at"`
}

// SessionRestartStatus is the current scan, not the historical count on a
// receipt. Unknown means the process list could not be inspected with the
// required privilege or within the scan bound.
type SessionRestartStatus struct {
	State   string         `json:"state"` // known, unknown
	Count   int            `json:"count"`
	Entries []SessionEntry `json:"entries"`
}

// UnprotectedSessions compares process creation with the last installation
// or change of each connector's managed settings. It keeps at most 20 named
// sessions while retaining the full count. An unprivileged caller cannot
// prove absence of another account's sessions.
func UnprotectedSessions(processes []SessionProcess, changed map[string]time.Time, privileged bool) SessionRestartStatus {
	status := SessionRestartStatus{State: "known", Entries: []SessionEntry{}}
	if !privileged {
		status.State = "unknown"
		return status
	}
	sort.Slice(processes, func(i, j int) bool { return processes[i].PID < processes[j].PID })
	for _, process := range processes {
		at := changed[process.Agent]
		if process.PID <= 0 || at.IsZero() || process.StartedAt.IsZero() || !process.StartedAt.Before(at) {
			continue
		}
		status.Count++
		if len(status.Entries) < 20 {
			status.Entries = append(status.Entries, SessionEntry{PID: process.PID, User: process.User,
				Agent: process.Agent, StartedAt: process.StartedAt.UTC().Format(time.RFC3339Nano)})
		}
	}
	return status
}

// SetBundleSessions adds the live scan to the bundle block and warns while
// keeping a confirmed receipt's state independent of running agent sessions.
func (r *Result) SetBundleSessions(status SessionRestartStatus) {
	if r == nil || r.Bundle == nil {
		return
	}
	r.Bundle.SessionsRestartRequired = &status
	if status.Count > 0 {
		r.CoverageComplete, r.SecurityComplete = false, false
		for _, warning := range r.Warnings {
			if warning.Code == CodeSessionsNeedRestart {
				return
			}
		}
		r.AddWarning(CodeSessionsNeedRestart, "running agent sessions started before managed hooks changed; ask the listed users to restart them")
	}
}
