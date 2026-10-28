// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookexec

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"time"

	"golang.org/x/sys/windows"
)

func newPerUserHookHTTPClient(timeout time.Duration, apiAddr string) (*http.Client, error) {
	targets, err := perUserLoopbackTargets(apiAddr)
	if err != nil {
		return nil, err
	}
	// The Windows tuple check reads the IPv4 table: dial the first
	// normalised IPv4 endpoint (localhost is 127.0.0.1).
	var endpoint netip.AddrPort
	for _, target := range targets {
		if target.Addr().Is4() {
			endpoint = target
			break
		}
	}
	if !endpoint.IsValid() {
		return nil, errors.New("per-user gateway target must be an IPv4 loopback endpoint")
	}
	if timeout < 0 {
		timeout = defaultHookRequestTimeout
	}
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	return verifiedPerUserHTTPClient(timeout, apiAddr,
		func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp4", endpoint.String())
		},
		func(conn net.Conn) error {
			client, clientOK := conn.LocalAddr().(*net.TCPAddr)
			server, serverOK := conn.RemoteAddr().(*net.TCPAddr)
			if !clientOK || !serverOK || !perUserTargetMatches([]netip.AddrPort{endpoint}, server) {
				return errors.New("connected gateway endpoint is not the configured loopback port")
			}
			return verifyPerUserConnectedTuple(client, server)
		},
	), nil
}

func connectedPerUserProcessOwned(pid uint32) error {
	if pid == 0 {
		return errors.New("connected listener has no owner PID")
	}
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return fmt.Errorf("open connected listener process: %w", err)
	}
	defer windows.CloseHandle(process)
	var token windows.Token
	if err := windows.OpenProcessToken(process, windows.TOKEN_QUERY, &token); err != nil {
		return fmt.Errorf("read connected listener account: %w", err)
	}
	defer token.Close()
	peer, err := token.GetTokenUser()
	if err != nil {
		return fmt.Errorf("read connected listener account SID: %w", err)
	}
	self, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fmt.Errorf("read current account SID: %w", err)
	}
	if !peer.User.Sid.Equals(self.User.Sid) {
		return errors.New("connected listener belongs to another account")
	}
	return nil
}

func verifyPerUserConnectedTuple(client, server *net.TCPAddr) error {
	clientEndpoint, err := managedIPv4EndpointFromAddr(client)
	if err != nil {
		return err
	}
	serverEndpoint, err := managedIPv4EndpointFromAddr(server)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return awaitPerUserWindowsSocket(ctx, func() (uint32, error) {
		return connectedManagedGatewayPIDForEndpoints(clientEndpoint, serverEndpoint)
	}, connectedPerUserProcessOwned)
}

// Connect can complete before GetExtendedTcpTable exposes the accepted row.
// Keep the connection held and retry only an absent exact reverse tuple.
func awaitPerUserWindowsSocket(ctx context.Context, inspect func() (uint32, error), owned func(uint32) error) error {
	for {
		if ctx.Err() != nil {
			return errConnectedSocketNotFound
		}
		pid, err := inspect()
		if err == nil {
			return owned(pid)
		}
		if !errors.Is(err, errConnectedSocketNotFound) {
			return err
		}
		select {
		case <-ctx.Done():
			return errConnectedSocketNotFound
		case <-time.After(20 * time.Millisecond):
		}
	}
}
