// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookexec

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"
)

// The OS implementation proves the accepted reverse TCP tuple, rather than
// looking up a listening port that could change hands after the dial.
var perUserConnectedPeer = verifyPerUserConnectedTuple

func newPerUserHookHTTPClient(timeout time.Duration, apiAddr string) (*http.Client, error) {
	targets, err := perUserLoopbackTargets(apiAddr)
	if err != nil {
		return nil, err
	}
	if timeout < 0 {
		timeout = defaultHookRequestTimeout
	}
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	return verifiedPerUserHTTPClient(timeout, apiAddr,
		func(ctx context.Context, _, _ string) (net.Conn, error) {
			// Dial the normalised endpoints in order, as the shell preflight
			// checks them: only a refused endpoint moves on to the next.
			var lastErr error
			for _, target := range targets {
				conn, err := dialer.DialContext(ctx, "tcp", target.String())
				if err == nil || !connectionRefused(err) {
					return conn, err
				}
				lastErr = err
			}
			return nil, lastErr
		},
		func(conn net.Conn) error {
			client, clientOK := conn.LocalAddr().(*net.TCPAddr)
			peer, peerOK := conn.RemoteAddr().(*net.TCPAddr)
			if !clientOK || !peerOK || !perUserTargetMatches(targets, peer) {
				return errors.New("connected gateway endpoint is not the configured loopback port")
			}
			return perUserConnectedPeer(client, peer)
		},
	), nil
}
