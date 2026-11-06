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
	clientEndpoint, err := managedIPv4EndpointFromAddr(client)
	if err != nil {
		return 0, false
	}
	serverEndpoint, err := managedIPv4EndpointFromAddr(server)
	if err != nil {
		return 0, false
	}
	pid, err := connectedManagedGatewayPIDForEndpoints(clientEndpoint, serverEndpoint)
	return int(pid), err == nil
}

func perUserListenerOwners(context.Context, *net.TCPAddr) ([]perUserPeerProcess, bool) {
	return nil, false
}
