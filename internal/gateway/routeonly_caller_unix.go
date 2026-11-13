//go:build linux || darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

// routeCallerPeer builds a TCP caller the way the hook socket builds its
// peer (managedHookPeerFor): the account name and home from the same
// account database lookups and caches. Replaceable in tests.
var routeCallerPeer = func(uid int) managedHookPeer {
	return managedHookPeer{UID: uid, Name: managedHookPeerName(uid), Home: managedHookPeerHome(uid)}
}
