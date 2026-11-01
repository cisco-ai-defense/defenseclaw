// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import "github.com/defenseclaw/defenseclaw/internal/useridentity"

// platformSSOLink is what the local node's AltSecurityIdentities listing
// says of an account (darwinPlatformSSOLink).
type platformSSOLink uint8

const (
	ssoUnlinked platformSSOLink = iota
	ssoLinked
	// ssoLinkUnknown is a listing that failed or ran out of time.
	ssoLinkUnknown
)

// macOSOwnDirectory is the directory the gateway's own Open Directory answer
// proves for an account, and whether its UPN is still pending: local for an
// account of the local node (darwinLocalNodeAccount) that is not linked to
// Platform SSO, else unknown until the guardian's record names it. A
// Platform SSO account is held by the local node too, but it is the identity
// provider's account, and only the guardian's record carries its UPN.
// Calling it local let a users entry naming that UPN miss it while the
// record was absent or aged out, so the account got the default profile
// where it was refused (GAP-0532). A link listing that failed proves the
// account neither linked nor unlinked: it stays local, so a bare users entry
// written for a directory namesake does not select it (GAP-0305), and only
// a UPN or DOMAIN\name entry waits for the record (UPNPending, GAP-1612).
func macOSOwnDirectory(localNode bool, link platformSSOLink) (directory useridentity.Directory, upnPending bool) {
	if !localNode || link == ssoLinked {
		return "", false
	}
	return useridentity.DirectoryLocal, link == ssoLinkUnknown
}
