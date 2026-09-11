// Copyright 2026 Cisco Systems, Inc. and its affiliates
// Copyright (c) 2026 Mike Storm. All rights reserved.
//
// Derived from ShadowClaw -- Universal Shadow AI Detector, by Mike Storm,
// Distinguished Engineer, CCIE Security 13847. Reimplemented in Go and
// absorbed into the DefenseClaw gateway; see NOTICE for the modifications.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package netprobe

import (
	"encoding/binary"
	"net"
	"testing"
	"unsafe"
)

// encodeIPv4Table builds a MIB_TCPTABLE_OWNER_PID body the way the kernel
// lays it out, so decodeTable is exercised against the real packed form
// rather than a Go struct slice that would hide any layout mistake.
func encodeIPv4Table(t *testing.T, rows []mibTCPRowOwnerPID) []byte {
	t.Helper()
	rowSize := int(unsafe.Sizeof(mibTCPRowOwnerPID{}))
	buffer := make([]byte, 4+rowSize*len(rows))
	binary.LittleEndian.PutUint32(buffer[:4], uint32(len(rows)))
	for index := range rows {
		offset := 4 + index*rowSize
		*(*mibTCPRowOwnerPID)(unsafe.Pointer(&buffer[offset])) = rows[index]
	}
	return buffer
}

// hostPort renders a port the way Windows stores it: network byte order in
// the low two bytes of a host-order uint32.
func hostPort(port uint16) uint32 {
	var raw [4]byte
	binary.BigEndian.PutUint16(raw[:2], port)
	return binary.LittleEndian.Uint32(raw[:])
}

func TestDecodeTableReadsOwnerAndEndianness(t *testing.T) {
	t.Parallel()
	buffer := encodeIPv4Table(t, []mibTCPRowOwnerPID{
		{
			State:      mibTCPStateListen,
			LocalAddr:  0,
			LocalPort:  hostPort(8080),
			RemoteAddr: 0,
			RemotePort: 0,
			OwningPID:  4242,
		},
		{
			State: mibTCPStateEstablished,
			// 0x0101A8C0 little-endian is 192.168.1.1.
			LocalAddr: 0x0101A8C0,
			LocalPort: hostPort(51234),
			// Bytes 7F 00 00 01 read back as a host-order uint32.
			RemoteAddr: 0x0100007F,
			RemotePort: hostPort(443),
			OwningPID:  99,
		},
	})

	connections, err := decodeTable(buffer, afINET)
	if err != nil {
		t.Fatalf("decodeTable: %v", err)
	}
	if len(connections) != 2 {
		t.Fatalf("decoded %d connections, want 2", len(connections))
	}

	listener := connections[0]
	if listener.State != StateListen {
		t.Errorf("listener state = %v, want StateListen", listener.State)
	}
	if listener.LocalPort != 8080 {
		t.Errorf("listener local port = %d, want 8080", listener.LocalPort)
	}
	if listener.PID != 4242 {
		t.Errorf("listener pid = %d, want 4242", listener.PID)
	}
	if listener.RemotePort != 0 {
		t.Errorf("listener has a peer port %d; a listener has no peer", listener.RemotePort)
	}

	client := connections[1]
	if client.State != StateEstablished {
		t.Errorf("client state = %v, want StateEstablished", client.State)
	}
	if client.LocalPort != 51234 {
		t.Errorf("client local port = %d, want 51234", client.LocalPort)
	}
	if client.RemotePort != 443 {
		t.Errorf("client remote port = %d, want 443", client.RemotePort)
	}
	if client.PID != 99 {
		t.Errorf("client pid = %d, want 99", client.PID)
	}
	if !client.RemoteIP.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Errorf("client remote ip = %s, want 127.0.0.1", client.RemoteIP)
	}
}

// TestDecodeTableIsBoundedByTheBuffer pins the guard that matters most: the
// declared entry count is attacker-adjacent kernel data, and trusting it over
// the allocation length is a read past the end.
func TestDecodeTableIsBoundedByTheBuffer(t *testing.T) {
	t.Parallel()
	rowSize := int(unsafe.Sizeof(mibTCPRowOwnerPID{}))
	buffer := make([]byte, 4+rowSize) // room for exactly one row
	binary.LittleEndian.PutUint32(buffer[:4], 4096)

	connections, err := decodeTable(buffer, afINET)
	if err != nil {
		t.Fatalf("decodeTable: %v", err)
	}
	if len(connections) != 1 {
		t.Fatalf("decoded %d connections from a one-row buffer that claimed 4096", len(connections))
	}
}

func TestDecodeTableHandlesShortAndEmptyBuffers(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		name   string
		buffer []byte
	}{
		{name: "empty", buffer: nil},
		{name: "shorter than the count", buffer: []byte{0, 0}},
		{name: "count only, no rows", buffer: []byte{0, 0, 0, 0}},
		{name: "claims a row it does not carry", buffer: []byte{1, 0, 0, 0}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			connections, err := decodeTable(testCase.buffer, afINET)
			if err != nil {
				t.Fatalf("decodeTable: %v", err)
			}
			if len(connections) != 0 {
				t.Fatalf("decoded %d connections from %q", len(connections), testCase.name)
			}
		})
	}
}

func TestNetworkPortAndAddressDecoding(t *testing.T) {
	t.Parallel()
	for _, port := range []uint16{0, 53, 443, 8080, 51234, 65535} {
		if got := networkPort(hostPort(port)); got != int(port) {
			t.Errorf("networkPort round trip for %d = %d", port, got)
		}
	}
	// 0x0101A8C0 in host order is the little-endian encoding of 192.168.1.1.
	if got := decodeIPv4(0x0101A8C0); !got.Equal(net.IPv4(192, 168, 1, 1)) {
		t.Errorf("decodeIPv4 = %s, want 192.168.1.1", got)
	}
}
