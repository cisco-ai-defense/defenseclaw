//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package peercred

import "net"

// SIDs and the owner-module TCP table exist only on Windows.
func loopbackTCPClientOwner(_, _ *net.TCPAddr) (TCPConnOwner, error) {
	return TCPConnOwner{}, ErrUnsupported
}

func verifyLoopbackTCPPeer(_, _ *net.TCPAddr, _ uint32, _ TCPConnOwner) (PeerIdentity, error) {
	return PeerIdentity{}, ErrUnsupported
}
