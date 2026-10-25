// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import "github.com/defenseclaw/defenseclaw/internal/useridentity"

// macOSOwnDirectory is the directory the gateway's own Open Directory answer
// proves for an account: local for an account of the local node
// (darwinLocalNodeAccount) that is not linked to Platform SSO, else unknown
// until the guardian's record names it. A Platform SSO account is held by
// the local node too, but it is the identity provider's account, and only
// the guardian's record carries its UPN. Calling it local let a users entry
// naming that UPN miss it while the record was absent or aged out, so the
// account got the default profile where it was refused (GAP-0532).
func macOSOwnDirectory(localNode, platformSSOLinked bool) useridentity.Directory {
	if localNode && !platformSSOLinked {
		return useridentity.DirectoryLocal
	}
	return ""
}
