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

// LoopbackTCPClientOwner returns the PID and connection creation time the
// kernel TCP table names for the client end of a loopback TCP connection
// this process accepted (Windows; no process is opened). The managed
// Windows gateway sends it to the guardian peer broker, which proves the
// account (VerifyLoopbackTCPPeer). Other platforms return ErrUnsupported.
func LoopbackTCPClientOwner(local, remote *net.TCPAddr) (TCPConnOwner, error) {
	if local == nil || remote == nil || !local.IP.IsLoopback() || !remote.IP.IsLoopback() {
		return TCPConnOwner{}, errors.New("peercred: the connection is not on a loopback address")
	}
	return loopbackTCPClientOwner(local, remote)
}

// VerifyLoopbackTCPPeer is the peer broker lookup (Windows, LocalSystem):
// the server end of the connection must be owned by serverPID, the client
// end by want, and the process with that PID must have started no later
// than the connection was created; it returns the token user SID and the
// session of that process. Other platforms return ErrUnsupported.
func VerifyLoopbackTCPPeer(local, remote *net.TCPAddr, serverPID uint32, want TCPConnOwner) (PeerIdentity, error) {
	if local == nil || remote == nil || !local.IP.IsLoopback() || !remote.IP.IsLoopback() {
		return PeerIdentity{}, errors.New("peercred: the connection is not on a loopback address")
	}
	return verifyLoopbackTCPPeer(local, remote, serverPID, want)
}
