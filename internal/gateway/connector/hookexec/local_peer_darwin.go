// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package hookexec

import "net"

// Docker Desktop's port proxy runs as the signed-in account on macOS.
// The account's accepted socket proves the connected tuple.
func verifyLocalPeerTuple(client, server *net.TCPAddr) error {
	return verifyPerUserConnectedTuple(client, server)
}
