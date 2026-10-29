// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisestatus

import (
	"fmt"
	"io"
	"slices"
	"sort"
	"time"
)

const CodeSessionsNeedRestart = "sessions_need_restart"

// SessionProcess is the minimal process information needed for a managed
// hook activation check. Callers obtain it from the platform process scan.
type SessionProcess struct {
	PID int
	// PPID is the parent process, 0 when unknown. A launcher and the agent
	// process it starts (the npm node script and its native Codex) are one
	// session (GAP-2439).
	PPID      int
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
	Reason  string         `json:"reason,omitempty"`
}

// ScanSessions keeps platform process enumeration separate from the common
// comparison. An enumeration error must never be reported as zero sessions.
func ScanSessions(list func() ([]SessionProcess, error), changed map[string]time.Time, privileged bool) SessionRestartStatus {
	if !privileged {
		return SessionRestartStatus{State: "unknown", Entries: []SessionEntry{}, Reason: "administrator privileges are required to inspect every user's agent sessions"}
	}
	processes, err := list()
	if err != nil {
		return SessionRestartStatus{State: "unknown", Entries: []SessionEntry{}, Reason: err.Error()}
	}
	return UnprotectedSessions(processes, changed)
}

func SessionWarning(status SessionRestartStatus) (code, message string) {
	if status.State == "unknown" {
		return "sessions_scan_unknown", "could not inspect running agent sessions: " + status.Reason + "; restart any sessions opened before managed hooks changed"
	}
	if status.Count > 0 {
		return CodeSessionsNeedRestart, "running agent sessions started before managed hooks changed; ask the listed users to restart them"
	}
	return "", ""
}

// WriteSessionEntries prints the actionable details from the same live scan
// that the JSON result and warning use.
func WriteSessionEntries(w io.Writer, status SessionRestartStatus) {
	for _, entry := range status.Entries {
		fmt.Fprintf(w, "  %s pid %d user %s started %s: ask this user to restart the agent\n", entry.Agent, entry.PID, entry.User, entry.StartedAt)
	}
}

// UnprotectedSessions compares process creation with the last installation
// or change of each connector's managed settings. It keeps at most 20 named
// sessions while retaining the full count. The caller has already verified
// that it could inspect the process list.
func UnprotectedSessions(processes []SessionProcess, changed map[string]time.Time) SessionRestartStatus {
	status := SessionRestartStatus{State: "known", Entries: []SessionEntry{}}
	sort.Slice(processes, func(i, j int) bool { return processes[i].PID < processes[j].PID })
	leaders := SessionLeaders(processes)
	for _, process := range processes {
		if process.PID > 0 && leaders[process.PID] != process.PID {
			continue
		}
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

// SessionLeaders maps the pid of each listed process to the pid of the
// session it belongs to. A process whose parent chain reaches another listed
// process of the same agent and user belongs to the topmost such process:
// one npm Codex runs as a node launcher and the native codex it starts, and
// both match an agent CLI, but they are one session, which a restart of the
// launcher restarts (GAP-2439, GitHub #1360). Processes of another agent or
// user, and processes that only share a name, are never merged. A parent
// cycle ends the walk; the lowest pid seen leads it.
func SessionLeaders(processes []SessionProcess) map[int]int {
	byPID := make(map[int]SessionProcess, len(processes))
	for _, process := range processes {
		if process.PID > 0 {
			byPID[process.PID] = process
		}
	}
	leaders := make(map[int]int, len(byPID))
	for pid, process := range byPID {
		leader := pid
		seen := map[int]bool{pid: true}
		for {
			parent, ok := byPID[byPID[leader].PPID]
			if !ok || parent.PID == leader || parent.Agent != process.Agent || parent.User != process.User {
				break
			}
			if seen[parent.PID] {
				for member := range seen {
					leader = min(leader, member)
				}
				break
			}
			seen[parent.PID] = true
			leader = parent.PID
		}
		leaders[pid] = leader
	}
	return leaders
}

// SetBundleSessions adds the live scan to the bundle block and warns while
// keeping a confirmed receipt's state independent of running agent sessions.
func (r *Result) SetBundleSessions(status SessionRestartStatus) {
	if r == nil || r.Bundle == nil {
		return
	}
	r.Bundle.SessionsRestartRequired = &status
	if status.Count > 0 || status.State == "unknown" {
		code, message := SessionWarning(status)
		r.MarkCoverageIncomplete(code)
		for _, warning := range r.Warnings {
			if warning.Code == code {
				return
			}
		}
		r.AddWarning(code, message)
	}
}

// SetBundleReceiptWarnings exposes a receipt's digest and publish markers
// in lifecycle status text as well as in its bundle JSON block.
func (r *Result) SetBundleReceiptWarnings() {
	if r == nil || r.Bundle == nil {
		return
	}
	for _, code := range r.Bundle.WarningCodes {
		message, ok := bundleReceiptWarningMessages[code]
		if !ok || slices.ContainsFunc(r.Warnings, func(w Message) bool { return w.Code == code }) {
			continue
		}
		r.AddWarning(code, message)
	}
}

// BundleReceiptWarningMessage explains a receipt warning code that a
// lifecycle result also lists in warnings[]; false for any other code.
// bundle status uses the same words.
func BundleReceiptWarningMessage(code string) (string, bool) {
	message, ok := bundleReceiptWarningMessages[code]
	return message, ok
}

// bundleReceiptWarningMessages are the receipt warning codes a lifecycle
// result also lists in warnings[].
var bundleReceiptWarningMessages = map[string]string{
	"digest_unverifiable":        "the signer used a different product version, so its signed digest cannot be compared with this build's; bundle file hashes and the gateway-versus-installed digest were checked",
	"digest_layout_unverifiable": "the device's non-standard managed layout changed the effective digest; the signed digest matched this device's digest for the standard layout, and the gateway's enforcing digest was recorded",
	"receipt_publish_failed":     "the public copy of this receipt (receipt-events/ and receipt.json) could not be written, so the gateway does not report it; this result and bundle status are the record",
	"receipt_events_dropped":     "receipt-events/ was full of events the gateway had not reported (is the gateway running?), so the oldest were removed and are missing from the audit log; bundle status lists the newest receipts",
}
