// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookexec

import (
	"context"
	"net"
)

// The connected reverse tuple identifies the process that accepted this
// request, including while another process binds the configured listener.
func perUserConnectedPeerPID(client, server *net.TCPAddr) (int, bool) {
	return perUserConnectedPeerPIDWithin(context.Background(), client, server)
}

func perUserConnectedPeerPIDWithin(ctx context.Context, client, server *net.TCPAddr) (int, bool) {
	if ctx.Err() != nil {
		return 0, false
	}
	clientEndpoint, err := managedIPv4EndpointFromAddr(client)
	if err != nil {
		return 0, false
	}
	serverEndpoint, err := managedIPv4EndpointFromAddr(server)
	if err != nil {
		return 0, false
	}
	pid, err := connectedManagedGatewayPIDForEndpoints(clientEndpoint, serverEndpoint)
	return int(pid), err == nil && ctx.Err() == nil
}
