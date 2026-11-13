// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package peerbroker

import (
	"net"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/peercred"
)

func clientOwnerForTest(conn net.Conn) (peercred.TCPConnOwner, error) {
	return peercred.LoopbackTCPClientOwner(conn.LocalAddr().(*net.TCPAddr), conn.RemoteAddr().(*net.TCPAddr))
}

func containsPID(text string, pid uint32) bool {
	return strings.Contains(text, " "+strconv.FormatUint(uint64(pid), 10)+",")
}
