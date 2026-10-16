// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
)

// The standalone enumerator is told which agent sessions run now, so a
// running agent of an enabled connector that no row enrolls is recorded as
// unprotected and status and verify stop saying security_complete. Without
// it a Codex the discovery could not read (GAP-0226: the install.ps1 layout)
// ran without DefenseClaw hooks while every report was green.

// enterpriseWindowsEnumerateRunningLookupTimeout bounds one account lookup,
// and enterpriseWindowsEnumerateRunningLookupBudget all of one cycle, so an
// unreachable domain controller cannot stall the cycle.
var (
	enterpriseWindowsEnumerateRunningLookupTimeout = 3 * time.Second
	enterpriseWindowsEnumerateRunningLookupBudget  = 10 * time.Second
)

// Seams for the running agents and the account lookup; tests replace them.
var (
	enterpriseWindowsEnumerateAgentProcesses = inventory.RunningWindowsAgentProcesses
	enterpriseWindowsEnumerateAccountSID     = func(account string) string {
		sid, _, _, err := windows.LookupSID("", account)
		if err != nil || sid == nil {
			return ""
		}
		return sid.String()
	}
)

// enterpriseWindowsEnumerateKnownSIDs keeps, for the life of the enumerator
// process (the interval loop), the SID each account resolved to. A lookup that
// fails or times out in a later cycle (an unreachable domain controller) uses
// it, so that account's running agent is still judged against its rows instead
// of dropping out of the unprotected record for the cycle.
var enterpriseWindowsEnumerateKnownSIDs = struct {
	sync.Mutex
	byAccount map[string]string
}{byAccount: map[string]string{}}

// enterpriseWindowsEnumerateKnownSIDsMax bounds that cache; past it the cache
// starts over.
const enterpriseWindowsEnumerateKnownSIDsMax = 4096

// enterpriseWindowsEnumerateResolveSID resolves account (key is its lowercase
// spelling) within remaining, or returns the SID an earlier cycle resolved,
// or "" when neither is known.
func enterpriseWindowsEnumerateResolveSID(account, key string, remaining time.Duration) string {
	sid := enterpriseWindowsEnumerateLookupWithin(account, remaining)
	known := &enterpriseWindowsEnumerateKnownSIDs
	known.Lock()
	defer known.Unlock()
	if sid == "" {
		return known.byAccount[key]
	}
	if len(known.byAccount) >= enterpriseWindowsEnumerateKnownSIDsMax {
		known.byAccount = map[string]string{}
	}
	known.byAccount[key] = sid
	return sid
}

// enterpriseWindowsEnumerateRunningAgents returns, by account SID and
// connector, a label of one running agent session ("codex (pid 4242)"). An
// agent of an enabled connector whose snapshot has no owner SID and whose
// account resolves to no SID this cycle or earlier is returned as an
// owner-unknown unprotected agent instead:
// no row can be matched to it, so it is not known to be protected.
func enterpriseWindowsEnumerateRunningAgents(stderr io.Writer, connectors []string) (map[string]map[string]string, []enterprisehooks.UnprotectedAgent) {
	processes, err := enterpriseWindowsEnumerateAgentProcesses()
	if err != nil {
		fmt.Fprintf(stderr, "[hook-enumerator] WARN running agent sessions are unreadable this cycle; only installs are checked for unenrolled agents: %v\n", err)
		return nil, nil
	}
	enabled := make(map[string]bool, len(connectors))
	for _, name := range connectors {
		enabled[strings.ToLower(strings.TrimSpace(name))] = true
	}
	out := map[string]map[string]string{}
	sids := map[string]string{}
	var unknown []enterprisehooks.UnprotectedAgent
	unknownSeen := map[string]bool{}
	var spent time.Duration
	for _, process := range processes {
		user := strings.TrimSpace(process.User)
		connector := strings.ToLower(strings.TrimSpace(process.Connector))
		if connector == "" {
			continue
		}
		key := strings.ToLower(user)
		sid := process.OwnerSID
		if sid == "" && user != "" {
			var resolved bool
			sid, resolved = sids[key]
			if !resolved {
				started := time.Now()
				sid = enterpriseWindowsEnumerateResolveSID(user, key, enterpriseWindowsEnumerateRunningLookupBudget-spent)
				spent += time.Since(started)
				sids[key] = sid
			}
		}
		label := fmt.Sprintf("%s (pid %d)", connector, process.PID)
		if sid == "" {
			if enabled[connector] && !unknownSeen[key+"\x00"+connector] {
				unknownSeen[key+"\x00"+connector] = true
				reason := fmt.Sprintf("%s runs for this account, but its account SID could not be resolved this cycle (the lookup failed or did not answer in time), so DefenseClaw cannot tell whether a row enrolls it; it counts as unprotected until the lookup answers", label)
				if user == "" {
					user = "(unknown account)"
					reason = fmt.Sprintf("%s runs, but the account behind the process could not be identified this cycle, so DefenseClaw cannot tell whether a row enrolls it; it counts as unprotected until the account is known", label)
				}
				unknown = append(unknown, enterprisehooks.UnprotectedAgent{
					User:      user,
					Connector: connector,
					Code:      enterprisehooks.UnprotectedCodeAgentUnprotected,
					Reason:    reason,
				})
			}
			continue
		}
		if out[sid] == nil {
			out[sid] = map[string]string{}
		}
		if _, seen := out[sid][connector]; !seen {
			out[sid][connector] = label
		}
	}
	return out, unknown
}

// enterpriseWindowsEnumerateLookupWithin resolves account to its SID, or ""
// when the lookup fails or does not answer within the remaining budget.
func enterpriseWindowsEnumerateLookupWithin(account string, remaining time.Duration) string {
	if remaining <= 0 {
		return ""
	}
	if remaining > enterpriseWindowsEnumerateRunningLookupTimeout {
		remaining = enterpriseWindowsEnumerateRunningLookupTimeout
	}
	done := make(chan string, 1)
	lookup := enterpriseWindowsEnumerateAccountSID
	go func() { done <- strings.TrimSpace(lookup(account)) }()
	timer := time.NewTimer(remaining)
	defer timer.Stop()
	select {
	case sid := <-done:
		return sid
	case <-timer.C:
		return ""
	}
}
