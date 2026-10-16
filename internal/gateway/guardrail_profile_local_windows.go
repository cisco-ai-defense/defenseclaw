//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os/user"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

func profileAccountLocality(account *user.User) (local, known bool) {
	facts := useridentity.WindowsDirectoryFacts(account.Uid, 0)
	if facts.Empty() {
		return false, false
	}
	if facts.Directory == useridentity.DirectoryLocal {
		if enterprisehooks.WindowsLocalAccountSID(account.Uid) {
			return true, true
		}
		return false, false
	}
	return false, true
}
