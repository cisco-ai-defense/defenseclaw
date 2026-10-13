//go:build linux

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
	"strings"
	"testing"
)

// The client's row, not the gateway's own end of the same connection, names
// the caller (GAP-0348).
func TestTCPTableOwnerReadsTheClientRow(t *testing.T) {
	table := strings.Join([]string{
		"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode",
		"   0: 0100007F:4A1A 0100007F:D431 01 00000000:00000000 00:00000000 00000000   991        0 101 1",
		"   1: 0100007F:D431 0100007F:4A1A 06 00000000:00000000 03:00000000 00000000     0        0 0 3",
		"   2: 0100007F:D431 0100007F:4A1A 01 00000000:00000000 00:00000000 00000000  1008        0 102 1",
	}, "\n")
	server := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0x4A1A}
	client := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0xD431}
	uid, found, err := tcpTableOwner(strings.NewReader(table), server, client)
	if err != nil || !found || uid != 1008 {
		t.Fatalf("tcpTableOwner = %d, %v, %v; want 1008", uid, found, err)
	}
}
