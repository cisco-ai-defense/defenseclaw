// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !darwin

package hookexec

import (
	"context"
	"net"
)

// perUserConnectedPeerPID is unknown here: no restart is proven.
func perUserConnectedPeerPID(*net.TCPAddr, *net.TCPAddr) (int, bool) { return 0, false }

// perUserListenerOwners is unknown here.
func perUserListenerOwners(context.Context, *net.TCPAddr) ([]perUserPeerProcess, bool) {
	return nil, false
}
