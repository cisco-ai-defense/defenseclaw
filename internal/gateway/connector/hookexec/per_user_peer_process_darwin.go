// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package hookexec

import (
	"context"
	"net"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/procidentity"
)

// perUserConnectedPeerPID is the one process of this account holding the
// accepted end of the connected tuple. It runs when the call connects, long
// before any deadline: the 2 s is a cap on the work of this one read, on the
// system clock, and not one of the post-deadline proof budgets that the proof
// clock decides (internal/proofclock).
func perUserConnectedPeerPID(client, server *net.TCPAddr) (int, bool) {
	return perUserConnectedPeerPIDWithin(context.Background(), client, server)
}

func perUserConnectedPeerPIDWithin(parent context.Context, client, server *net.TCPAddr) (int, bool) {
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	owners, err := darwinSocketOwnerPIDs(ctx, server, client, darwinTCPEstablished)
	if err != nil || len(owners) != 1 {
		return 0, false
	}
	return owners[0], true
}

// perUserListenerOwners finds processes of this account listening on the
// exact gateway address and records their process identities.
func perUserListenerOwners(ctx context.Context, server *net.TCPAddr) ([]perUserPeerProcess, bool) {
	owners, err := darwinSocketOwnerPIDs(ctx, server, nil, darwinTCPListen)
	if err != nil || len(owners) == 0 {
		return nil, false
	}
	result := make([]perUserPeerProcess, 0, len(owners))
	for _, pid := range owners {
		identity, _ := procidentity.Of(pid)
		result = append(result, perUserPeerProcess{pid: pid, identity: identity, server: server})
	}
	return result, ctx.Err() == nil
}
