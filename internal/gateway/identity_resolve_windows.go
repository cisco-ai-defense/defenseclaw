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
// the identity store, the join state, a background TranslateNameW) and takes
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
	windowsDirectoriesOnce.Do(func() {
		windowsDirectories = newIdentityDirectoryCache(resolveWindowsDirectoryFacts)
	})
	return windowsDirectories.get(sid, block)
}

func resolveWindowsDirectoryFacts(sid string) (useridentity.DirectoryFacts, error) {
	now := time.Now().UTC()
	facts := useridentity.WindowsDirectoryFacts(sid)
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
