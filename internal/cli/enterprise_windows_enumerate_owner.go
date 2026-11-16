// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/inventory"
)

// The Windows standalone enumerator judges each running agent by its
// account SID (enterprise_windows_enumerate_running_windows.go). These
// parts of that judgement need no Windows API.

// enterpriseWindowsEnumerateKnownSIDMaxAge bounds how long the SID an account
// last resolved to stands in for a lookup that fails. Kept for the life of
// the enumerator process, an account deleted and created again while the
// domain controller did not answer kept its old SID (rel-1-0-2 GAP-0618).
// Past it the agent counts as owner unknown (unprotected) until the lookup
// answers.
const enterpriseWindowsEnumerateKnownSIDMaxAge = time.Hour

// enterpriseWindowsEnumerateKnownSIDsMax bounds the cache; past it the cache
// starts over.
const enterpriseWindowsEnumerateKnownSIDsMax = 4096

// enterpriseWindowsEnumerateNow is the clock of the cache; tests replace it.
var enterpriseWindowsEnumerateNow = time.Now

// enterpriseWindowsKnownSID is one account's last resolved SID and when.
type enterpriseWindowsKnownSID struct {
	sid      string
	resolved time.Time
}

// enterpriseWindowsKnownSIDs is the account name to SID cache.
type enterpriseWindowsKnownSIDs struct {
	sync.Mutex
	byAccount map[string]enterpriseWindowsKnownSID
}

// remember returns the SID to judge the account key by: sid when this
// cycle's lookup answered (kept as the latest answer), else the last answer
// while it is at most enterpriseWindowsEnumerateKnownSIDMaxAge old, else "".
func (k *enterpriseWindowsKnownSIDs) remember(key, sid string) string {
	now := enterpriseWindowsEnumerateNow()
	k.Lock()
	defer k.Unlock()
	if k.byAccount == nil {
		k.byAccount = map[string]enterpriseWindowsKnownSID{}
	}
	if sid == "" {
		known, ok := k.byAccount[key]
		if !ok {
			return ""
		}
		if age := now.Sub(known.resolved); age < 0 || age > enterpriseWindowsEnumerateKnownSIDMaxAge {
			delete(k.byAccount, key)
			return ""
		}
		return known.sid
	}
	if len(k.byAccount) >= enterpriseWindowsEnumerateKnownSIDsMax {
		k.byAccount = map[string]enterpriseWindowsKnownSID{}
	}
	k.byAccount[key] = enterpriseWindowsKnownSID{sid: sid, resolved: now}
	return sid
}

// enterpriseWindowsRunningAgentSnapshotSID is the owner SID the snapshot
// gives process, or "" when its account name must be resolved instead. Where
// Remote Desktop Services shows no token SID, the snapshot names the account
// signed in to the session, so an agent started there as another account
// (runas) was counted as the session account's (rel-1-0-2 GAP-0618). Its
// own token account, when known, is resolved instead.
func enterpriseWindowsRunningAgentSnapshotSID(process inventory.AgentProcess) string {
	if process.OwnerSIDFromSession && strings.TrimSpace(process.User) != "" {
		return ""
	}
	return process.OwnerSID
}
