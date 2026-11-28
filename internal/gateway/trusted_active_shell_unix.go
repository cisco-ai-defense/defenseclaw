//go:build linux || darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import "context"

// trustedActiveShell reads the login shell from the same cached account record
// that supplied the verified hook peer's home. It never falls back to the
// gateway service account when a peer is present.
func trustedActiveShell(ctx context.Context) string {
	peer, ok := managedHookPeerFromContext(ctx)
	if !ok || peer.UID < 0 {
		return ""
	}
	account, ok := managedHookPeerHomes.account(peer.UID)
	if !ok || account.Home == "" || account.Home != peer.Home {
		return ""
	}
	return account.Shell
}
