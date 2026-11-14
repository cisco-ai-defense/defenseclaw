// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package hookexec

import (
	"context"
	"net"
)

// perUserGatewayPeerPID is perUserConnectedPeerPIDWithin here: macOS already
// reads the holders of the one connected tuple, and Windows reads the owner
// from its connection table (no process walk to skip).
func perUserGatewayPeerPID(ctx context.Context, _ []string, client, server *net.TCPAddr) (int, bool) {
	return perUserConnectedPeerPIDWithin(ctx, client, server)
}
