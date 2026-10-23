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
	"strconv"
	"time"

	"golang.org/x/sys/windows"
)

func newPerUserHookHTTPClient(timeout time.Duration, apiAddr string) (*http.Client, error) {
	host, rawPort, err := net.SplitHostPort(apiAddr)
	if err != nil || (host != "127.0.0.1" && host != "localhost") {
		return nil, errors.New("per-user gateway target must be an IPv4 loopback endpoint")
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil || port < 1 || port > 65535 {
		return nil, errors.New("per-user gateway port is invalid")
	}
	if timeout < 0 {
		timeout = defaultHookRequestTimeout
	}
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	endpoint := net.JoinHostPort("127.0.0.1", rawPort)
	return verifiedPerUserHTTPClient(timeout, apiAddr,
		func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp4", endpoint)
		},
		func(conn net.Conn) error {
			pid, err := managedEnterpriseConnectedPID(conn)
			if err != nil {
				return err
			}
			return connectedPerUserProcessOwned(pid)
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
	pid, err := connectedManagedGatewayPIDForEndpoints(clientEndpoint, serverEndpoint)
	if err != nil {
		return err
	}
	return connectedPerUserProcessOwned(pid)
}
