// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookexec

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"
)

// newManagedGatewayHTTPClient connects only to the running SCM service
// process peer names (dialManagedGatewayService). The configured address may
// name the loopback as localhost; the connection always goes to 127.0.0.1.
func newManagedGatewayHTTPClient(timeout time.Duration, apiAddr string, peer ManagedGatewayPeer) (*http.Client, error) {
	host, rawPort, err := net.SplitHostPort(apiAddr)
	if err != nil {
		return nil, managedGatewayPeerError("invalid managed gateway address: %v", err)
	}
	if host == "localhost" {
		host = "127.0.0.1"
	}
	canonicalAddr, err := normalizeManagedGatewayAddress(net.JoinHostPort(host, rawPort))
	if err != nil {
		return nil, managedGatewayPeerError("%v", err)
	}
	if err := validateManagedGatewayServiceName(peer.ServiceName); err != nil {
		return nil, managedGatewayPeerError("%v", err)
	}
	return verifiedGatewayHTTPClient(timeout, apiAddr, "managed gateway",
		func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialManagedGatewayService(ctx, canonicalAddr, peer.ServiceName)
		},
		func(net.Conn) error { return nil },
	), nil
}

// verifyManagedConnectedTuple proves that the server end of an open
// connection is the running gateway service process, the same process before
// and after the connection is looked up.
func verifyManagedConnectedTuple(client, server *net.TCPAddr, peer ManagedGatewayPeer) error {
	if err := validateManagedGatewayServiceName(peer.ServiceName); err != nil {
		return managedGatewayPeerError("%v", err)
	}
	clientEndpoint, err := managedIPv4EndpointFromAddr(client)
	if err != nil {
		return managedGatewayPeerError("%v", err)
	}
	serverEndpoint, err := managedIPv4EndpointFromAddr(server)
	if err != nil {
		return managedGatewayPeerError("%v", err)
	}
	servicePID, err := managedEnterpriseQueryServicePID(peer.ServiceName)
	if err != nil {
		return managedGatewayPeerError("query protected gateway service: %v", err)
	}
	connectedPID, err := managedEnterpriseConnectedPIDForEndpoints(clientEndpoint, serverEndpoint)
	if err != nil {
		return managedGatewayPeerError("resolve connected listener owner: %v", err)
	}
	if connectedPID != servicePID {
		return fmt.Errorf("%w: %w: connected listener PID %d does not equal service PID %d",
			errManagedGatewayPeerUnverified, errManagedGatewayPortHeld, connectedPID, servicePID)
	}
	recheckedPID, err := managedEnterpriseQueryServicePID(peer.ServiceName)
	if err != nil || recheckedPID != servicePID {
		return managedGatewayPeerError("gateway service PID changed during verification")
	}
	return nil
}
