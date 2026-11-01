// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !darwin

package hookexec

import "net"

// perUserConnectedPeerPID is unknown here: no restart is proven.
func perUserConnectedPeerPID(*net.TCPAddr, *net.TCPAddr) (int, bool) { return 0, false }

// perUserListenerOwner is unknown here.
func perUserListenerOwner(*net.TCPAddr) (perUserPeerProcess, bool) {
	return perUserPeerProcess{}, false
}
