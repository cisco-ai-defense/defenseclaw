// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package hookexec

import "net"

// Docker Desktop's port proxy runs as the signed-in account on macOS.
// lsof run as that account proves only its own accepted socket.
func verifyLocalPeerTuple(client, server *net.TCPAddr) error {
	return verifyPerUserConnectedTuple(client, server)
}
