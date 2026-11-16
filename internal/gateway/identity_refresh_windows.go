// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// identityRefreshPrepare returns the cache key of the SID key (upper case,
// as the hook path keys it), after asking the domain controller for an AD
// account's UPN again and waiting for it within profileExplainUPNWait: the
// re-read then takes a renamed UPN, not the one TranslateNameW answered up
// to five minutes earlier (identity-round GAP-1238).
func identityRefreshPrepare(key string) string {
	sid := strings.ToUpper(strings.TrimSpace(key))
	useridentity.ExpireWindowsADUPN(sid)
	useridentity.WindowsDirectoryFacts(sid, profileExplainUPNWait)
	return sid
}
