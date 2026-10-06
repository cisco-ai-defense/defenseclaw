// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	osuser "os/user"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// profileExplainAccount names an account (name or SID) through the LSA.
func profileExplainAccount(name string) (id, userName string, ok bool) {
	account, err := osuser.Lookup(name)
	if err != nil {
		if account, err = osuser.LookupId(name); err != nil {
			return "", "", false
		}
	}
	return strings.ToUpper(account.Uid), useridentity.BareAccountName(account.Username), true
}

// profileExplainUPNWait is how long explain waits for an AD account's UPN, so
// a users assignment by UPN is reported as a request would match it.
const profileExplainUPNWait = 5 * time.Second

// profileExplainDirectoryFacts resolves the facts a verified request from
// sid carries: the Windows identity store plus the guardian identity spool.
func profileExplainDirectoryFacts(id string) (useridentity.DirectoryFacts, error) {
	return resolveWindowsDirectoryFacts(id, profileExplainUPNWait)
}
