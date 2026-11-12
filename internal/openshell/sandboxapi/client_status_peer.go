// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package sandboxapi

import (
	"context"
	"net"
	"net/http"
)

// statusPeerEvidence records the kernel identity of every part of one status
// response. A mixed or unverified response cannot prove a daemon port.
type statusPeerEvidence struct {
	pid, uid int
	seen     bool
	invalid  bool
}

// StatusWithPeer returns a status and the kernel-verified PID of the process
// that supplied it. A zero PID means the response cannot prove a busy port's
// owner; the status itself remains available for the other doctor rows.
func (c *Client) StatusWithPeer(ctx context.Context) (*Status, int, error) {
	if c.unixSocketPath == "" {
		st, err := c.Status(ctx)
		return st, 0, err
	}
	var evidence *statusPeerEvidence
	transport := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			conn, err := dialDaemonSocket(ctx, c.unixSocketPath)
			if err != nil {
				return nil, err
			}
			e := &statusPeerEvidence{}
			wrapped := statusPeerConn(conn, e)
			evidence = e
			return wrapped, nil
		},
	}
	defer transport.CloseIdleConnections()
	clone := *c
	clone.HTTP = &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	st, err := clone.Status(ctx)
	if err != nil {
		return nil, 0, err
	}
	if evidence == nil || !evidence.seen || evidence.invalid || st.DaemonPID != evidence.pid ||
		st.DaemonUID != nil && *st.DaemonUID != evidence.uid {
		return st, 0, nil
	}
	return st, evidence.pid, nil
}
