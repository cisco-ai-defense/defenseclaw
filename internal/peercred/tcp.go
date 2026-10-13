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

// ErrPeerNotFound reports a loopback TCP connection the kernel's connection
// table does not list, for example one the client already closed.
var ErrPeerNotFound = errors.New("peercred: the loopback TCP connection is not in the kernel connection table")

// LoopbackTCPPeerUID returns the uid of the account that owns the client end
// of a loopback TCP connection this process accepted. local is the address
// the connection was accepted on and remote the client's address. The kernel
// records the account that opened every socket, so, unlike a bearer, the
// answer cannot be borrowed by copying a file to another account.
func LoopbackTCPPeerUID(local, remote *net.TCPAddr) (int, error) {
	if local == nil || remote == nil || !local.IP.IsLoopback() || !remote.IP.IsLoopback() {
		return -1, errors.New("peercred: the connection is not on a loopback address")
	}
	return loopbackTCPOwner(local, remote)
}
