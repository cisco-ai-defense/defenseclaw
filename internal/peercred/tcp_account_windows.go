//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package peercred

import (
	"errors"
	"net"
)

// LoopbackTCPPeerAccount returns the SID of the account whose process owns
// the client end of a loopback TCP connection this process accepted (the
// Secure Client caller account). It is the same owner lookup the guardian
// peer broker answers with (ownerSIDLookup, tcp_owner_table.go): the owner
// PID and connection creation time come from the kernel owner-module table,
// the account from that process's token, a process that started after the
// connection was created is refused (its PID was reused), and the table is
// read again with the process open and must name the same PID and creation
// time. The answer is what Windows recorded, not what the client sent.
func LoopbackTCPPeerAccount(local, remote *net.TCPAddr) (string, error) {
	if local == nil || remote == nil || !local.IP.IsLoopback() || !remote.IP.IsLoopback() {
		return "", errors.New("peercred: the connection is not on a loopback address")
	}
	identity, err := ownerSIDLookup{rows: tcpOwnerRows, open: openProcess}.account(local, remote)
	if err != nil {
		return "", err
	}
	return identity.SID, nil
}
