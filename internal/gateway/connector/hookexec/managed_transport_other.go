// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookexec

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"
)

// managedEnterpriseHTTPClient checks an accepted TCP socket against the
// protected gateway LaunchDaemon on macOS or systemd service on Linux before
// net/http writes a credential or event. The Unix lifecycle also uses it for
// an older gateway whose hook socket cannot answer /health.
func managedEnterpriseHTTPClient(timeout time.Duration, apiAddr, serviceName string) (*http.Client, error) {
	host, rawPort, err := net.SplitHostPort(apiAddr)
	if err != nil || host != "127.0.0.1" {
		return nil, fmt.Errorf("%w: managed gateway address must be canonical IPv4 loopback", errManagedGatewayPeerUnverified)
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil || port < 1 || port > 65535 || strconv.Itoa(port) != rawPort {
		return nil, fmt.Errorf("%w: managed gateway port is invalid", errManagedGatewayPeerUnverified)
	}
	if timeout <= 0 {
		timeout = defaultHookRequestTimeout
	}
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:             nil,
			DisableKeepAlives: true,
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				if address != apiAddr || (network != "tcp" && network != "tcp4") {
					return nil, fmt.Errorf("%w: managed gateway dial target changed", errManagedGatewayPeerUnverified)
				}
				conn, err := dialer.DialContext(ctx, "tcp4", apiAddr)
				if err != nil {
					return nil, err
				}
				client, clientOK := conn.LocalAddr().(*net.TCPAddr)
				server, serverOK := conn.RemoteAddr().(*net.TCPAddr)
				if !clientOK || !serverOK {
					_ = conn.Close()
					return nil, fmt.Errorf("%w: managed gateway connected endpoints are invalid", errManagedGatewayPeerUnverified)
				}
				if err := verifyManagedConnectedPeer(ctx, client, server, serviceName); err != nil {
					_ = conn.Close()
					return nil, fmt.Errorf("%w: %v", errManagedGatewayPeerUnverified, err)
				}
				return conn, nil
			},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

func verifyManagedConnectedTuple(client, server *net.TCPAddr, serviceName string) error {
	return verifyManagedConnectedPeer(context.Background(), client, server, serviceName)
}
