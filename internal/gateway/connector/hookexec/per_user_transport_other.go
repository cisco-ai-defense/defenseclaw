// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookexec

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"
)

// The OS implementation proves the accepted reverse TCP tuple, rather than
// looking up a listening port that could change hands after the dial.
var perUserConnectedPeer = verifyPerUserConnectedTuple

func newPerUserHookHTTPClient(timeout time.Duration, apiAddr string) (*http.Client, error) {
	host, rawPort, err := net.SplitHostPort(apiAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid per-user gateway address: %w", err)
	}
	if host != "localhost" {
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return nil, errors.New("per-user gateway target must be loopback")
		}
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil || port < 1 || port > 65535 {
		return nil, errors.New("per-user gateway port is invalid")
	}
	if timeout < 0 {
		timeout = defaultHookRequestTimeout
	}
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	return verifiedPerUserHTTPClient(timeout, apiAddr,
		func(ctx context.Context, _, address string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp", address)
		},
		func(conn net.Conn) error {
			client, clientOK := conn.LocalAddr().(*net.TCPAddr)
			peer, peerOK := conn.RemoteAddr().(*net.TCPAddr)
			if !clientOK || !peerOK || !peer.IP.IsLoopback() || peer.Port != port {
				return errors.New("connected gateway endpoint is not the configured loopback port")
			}
			return perUserConnectedPeer(client, peer)
		},
	), nil
}
