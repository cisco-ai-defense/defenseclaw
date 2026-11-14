// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hookexec

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"
)

func verifyLocalPeerTuple(client, server *net.TCPAddr) error {
	return verifyLocalPeerIn(procSelfNet, client, server)
}

// verifyLocalPeerIn accepts this account or the system account as the owner
// of the accepted server socket. A row the service has not accept()ed yet
// reports a provisional UID 0, so it waits for accept like the per-user
// gateway check instead of reading that 0 as the system account.
func verifyLocalPeerIn(procNet string, client, server *net.TCPAddr) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	self := os.Geteuid()
	return awaitPerUserLinuxSocket(ctx, self, func() (int, error) {
		uid, err := findConnectedTCPUID(procNet, client, server)
		if err == nil && uid == 0 {
			return self, nil
		}
		return uid, err
	})
}

// VerifyLocalPeerOwnedBy accepts a loopback connection whose accepted
// server socket belongs to uid: the OpenClaw account of the separate-user
// layout (connectors.openclaw.plugin_account), which is not this account.
func VerifyLocalPeerOwnedBy(conn net.Conn, uid int) error {
	local, localOK := conn.LocalAddr().(*net.TCPAddr)
	remote, remoteOK := conn.RemoteAddr().(*net.TCPAddr)
	if !localOK || !remoteOK || uid <= 0 {
		return fmt.Errorf("local peer is not a TCP connection of a named account")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return awaitPerUserLinuxSocket(ctx, uid, func() (int, error) {
		return findConnectedTCPUID(procSelfNet, local, remote)
	})
}
