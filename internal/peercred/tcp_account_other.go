//go:build !windows

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
	"net"
	"strconv"
)

// LoopbackTCPPeerAccount returns the account that owns the client end of a
// loopback TCP connection this process accepted, as the decimal uid
// (LoopbackTCPPeerUID).
func LoopbackTCPPeerAccount(local, remote *net.TCPAddr) (string, error) {
	uid, err := LoopbackTCPPeerUID(local, remote)
	if err != nil {
		return "", err
	}
	return strconv.Itoa(uid), nil
}
