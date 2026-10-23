// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package hookexec

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/peercred"
)

// managedConnectedSocketOwner returns the uid that owns the server end of a
// loopback connection from client to server: the kernel copies a listening
// socket's owner to each socket it accepts. Replaceable in tests.
var managedConnectedSocketOwner = func(client, server *net.TCPAddr) (int, error) {
	return peercred.LoopbackTCPPeerUID(client, server)
}

func newManagedGatewayHTTPClient(timeout time.Duration, apiAddr string, peer ManagedGatewayPeer) (*http.Client, error) {
	host, rawPort, err := net.SplitHostPort(apiAddr)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid managed gateway address: %v", errManagedGatewayPeerUnverified, err)
	}
	if host != "localhost" {
		if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
			return nil, fmt.Errorf("%w: managed gateway target must be loopback", errManagedGatewayPeerUnverified)
		}
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("%w: managed gateway port is invalid", errManagedGatewayPeerUnverified)
	}
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	return verifiedGatewayHTTPClient(timeout, apiAddr, "managed gateway",
		func(ctx context.Context, _, address string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp", address)
		},
		func(conn net.Conn) error {
			client, clientOK := conn.LocalAddr().(*net.TCPAddr)
			server, serverOK := conn.RemoteAddr().(*net.TCPAddr)
			if !clientOK || !serverOK || !server.IP.IsLoopback() || server.Port != port {
				return fmt.Errorf("%w: connected gateway endpoint is not the configured loopback port", errManagedGatewayPeerUnverified)
			}
			return verifyManagedConnectedTuple(client, server, peer)
		},
	), nil
}

func verifyManagedConnectedTuple(client, server *net.TCPAddr, peer ManagedGatewayPeer) error {
	uid, err := managedConnectedSocketOwner(client, server)
	if err != nil {
		return fmt.Errorf("%w: read the connected gateway socket owner: %v", errManagedGatewayPeerUnverified, err)
	}
	if !standaloneTrustedGatewayUID(uid, peer.ServiceUID) {
		return fmt.Errorf("%w: %w: the connected listener belongs to uid %d, neither root nor the gateway service account",
			errManagedGatewayPeerUnverified, errManagedGatewayPortHeld, uid)
	}
	return nil
}
