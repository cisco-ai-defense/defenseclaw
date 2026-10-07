// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// Windows: the gateway resolves a verified SID itself (LookupAccountSid,
// the identity store, the join state, TranslateNameW) and takes
// the account's groups from the SYSTEM enumerator's identity spool record,
// which carries the token-group cache resolved to names; the gateway's
// service account cannot read that cache directly.

var (
	windowsDirectoriesOnce sync.Once
	windowsDirectories     *identityDirectoryCache
)

func windowsDirectoryFacts(sid string, block bool) (useridentity.DirectoryFacts, bool) {
	sid = strings.ToUpper(strings.TrimSpace(sid))
	if !strings.HasPrefix(sid, "S-1-") {
		return useridentity.DirectoryFacts{}, false
	}
	return peerDirectoryCache().get(sid, block)
}

// peerDirectoryCache is the cache the hook path reads directory facts from,
// created on first use.
func peerDirectoryCache() *identityDirectoryCache {
	windowsDirectoriesOnce.Do(func() {
		windowsDirectories = newIdentityDirectoryCache(func(sid string) (useridentity.DirectoryFacts, error) {
			wait := time.Duration(0)
			if identityLookupBlocking.Load() {
				wait = windowsUPNWait
			}
			return resolveWindowsDirectoryFacts(sid, wait)
		})
		windowsDirectories.incomplete = func(facts useridentity.DirectoryFacts) bool {
			return adWithoutUPN(facts) || awaitingSpool(facts)
		}
		windowsDirectories.partial = func(facts useridentity.DirectoryFacts) bool { return facts.GroupsPartial }
	})
	return windowsDirectories
}

// windowsUPNWait is how long a lookup waits for an AD account's UPN when a
// users or groups assignment needs the facts on every request. TranslateNameW
// may contact a domain controller; the wait stays under the identity lookup
// budget the first request spends, so that request still gets the account's
// UPN rather than a record without it that stays cached.
const windowsUPNWait = 1500 * time.Millisecond

// adWithoutUPN marks facts the cache must refresh soon: an AD account whose
// UPN was not available yet (a slow or unreachable domain controller).
func adWithoutUPN(facts useridentity.DirectoryFacts) bool {
	return facts.Directory == useridentity.DirectoryActiveDirectory && facts.UPN == ""
}

// resolveWindowsDirectoryFacts resolves a SID's facts, waiting at most
// upnWait for the AD UPN.
func resolveWindowsDirectoryFacts(sid string, upnWait time.Duration) (useridentity.DirectoryFacts, error) {
	now := time.Now().UTC()
	facts := useridentity.WindowsDirectoryFacts(sid, upnWait)
	if record, ok := readIdentitySpoolFacts(sid, now); ok {
		facts = mergeSpoolFacts(facts, record.Facts)
	}
	if facts.Empty() {
		return useridentity.DirectoryFacts{ResolvedAt: now}, nil
	}
	return facts, nil
}

// verifiedIdentityDirectory returns the directory facts of a verified SID.
func verifiedIdentityDirectory(identity string, block bool) (useridentity.DirectoryFacts, bool) {
	return windowsDirectoryFacts(identity, block)
}
