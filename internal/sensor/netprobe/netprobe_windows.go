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
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Address families and the table class that includes the owning pid.
const (
	afINET  = 2
	afINET6 = 23
	// tcpTableOwnerPIDAll is TCP_TABLE_OWNER_PID_ALL. It is what makes Windows
	// the one platform where socket-to-pid attribution needs no privilege: the
	// kernel hands back the owning pid in every row.
	tcpTableOwnerPIDAll = 5
)

// Windows MIB_TCP_STATE values.
const (
	mibTCPStateListen      = 2
	mibTCPStateEstablished = 5
)

var (
	modIPHlpAPI             = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTCPTable = modIPHlpAPI.NewProc("GetExtendedTcpTable")
)

type mibTCPRowOwnerPID struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPID  uint32
}

type mibTCP6RowOwnerPID struct {
	LocalAddr     [16]byte
	LocalScopeID  uint32
	LocalPort     uint32
	RemoteAddr    [16]byte
	RemoteScopeID uint32
	RemotePort    uint32
	State         uint32
	OwningPID     uint32
}

// snapshot reads both address families from GetExtendedTcpTable.
//
// Unlike macOS and Linux there is no privilege asymmetry to report here: every
// row carries its owning pid, so unattributed is only ever non-zero for a row
// the kernel returned with pid 0, which is a system socket rather than a
// coverage gap.
func snapshot() ([]Connection, int, error) {
	connections := make([]Connection, 0, 256)
	unattributed := 0

	v4, err := readTable(afINET)
	if err != nil {
		return nil, 0, err
	}
	connections = append(connections, v4...)

	// A host with IPv6 disabled returns an error for the v6 table. That is not
	// a failure of the probe, so the v4 result stands.
	if v6, err := readTable(afINET6); err == nil {
		connections = append(connections, v6...)
	}

	for _, connection := range connections {
		if !connection.Attributed() {
			unattributed++
		}
	}
	return connections, unattributed, nil
}

func readTable(family uint32) ([]Connection, error) {
	var size uint32
	ret, _, _ := procGetExtendedTCPTable.Call(
		0, uintptr(unsafe.Pointer(&size)), 0, uintptr(family), tcpTableOwnerPIDAll, 0,
	)
	if ret != uintptr(windows.ERROR_INSUFFICIENT_BUFFER) && ret != 0 {
		return nil, fmt.Errorf("GetExtendedTcpTable(size, family=%d): %w", family, windows.Errno(ret))
	}
	if size == 0 {
		return nil, nil
	}
	// Retry when the table outgrows the size the first call reported. Sizing
	// and reading are two calls with a gap between them, and connections open
	// constantly, so ERROR_INSUFFICIENT_BUFFER on the second call is an
	// ordinary race rather than a fault. Treating it as fatal drops the whole
	// connection table for that poll -- reported as a host with no egress,
	// which is the reading this subsystem must never produce by accident.
	for attempt := 0; attempt < tableGrowthRetries; attempt++ {
		buffer := make([]byte, size)
		ret, _, _ = procGetExtendedTCPTable.Call(
			uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&size)),
			0, uintptr(family), tcpTableOwnerPIDAll, 0,
		)
		switch ret {
		case 0:
			return decodeTable(buffer, family)
		case uintptr(windows.ERROR_INSUFFICIENT_BUFFER):
			// size now holds what the kernel says it needs; go round again.
			continue
		default:
			return nil, fmt.Errorf("GetExtendedTcpTable(family=%d): %w", family, windows.Errno(ret))
		}
	}
	return nil, fmt.Errorf(
		"GetExtendedTcpTable(family=%d): the connection table grew on every one of %d attempts",
		family, tableGrowthRetries)
}

// tableGrowthRetries bounds the size-then-read retry. A host busy enough to
// outgrow its own table three times running is reported as an error rather
// than retried forever.
const tableGrowthRetries = 3

// decodeTable walks the MIB_TCPTABLE_OWNER_PID layout: a uint32 entry count
// followed by that many packed rows.
func decodeTable(buffer []byte, family uint32) ([]Connection, error) {
	if len(buffer) < 4 {
		return nil, nil
	}
	entries := binary.LittleEndian.Uint32(buffer[:4])
	rows := buffer[4:]

	rowSize := int(unsafe.Sizeof(mibTCPRowOwnerPID{}))
	if family == afINET6 {
		rowSize = int(unsafe.Sizeof(mibTCP6RowOwnerPID{}))
	}
	// Bound the loop by the buffer the kernel actually returned rather than by
	// the declared count: a mismatch would otherwise read past the allocation.
	available := len(rows) / rowSize
	if int(entries) < available {
		available = int(entries)
	}

	connections := make([]Connection, 0, available)
	for index := 0; index < available; index++ {
		offset := index * rowSize
		if family == afINET6 {
			row := (*mibTCP6RowOwnerPID)(unsafe.Pointer(&rows[offset]))
			connections = append(connections, Connection{
				PID:        int(row.OwningPID),
				LocalPort:  networkPort(row.LocalPort),
				RemoteIP:   net.IP(append([]byte(nil), row.RemoteAddr[:]...)),
				RemotePort: networkPort(row.RemotePort),
				State:      decodeState(row.State),
			})
			continue
		}
		row := (*mibTCPRowOwnerPID)(unsafe.Pointer(&rows[offset]))
		connections = append(connections, Connection{
			PID:        int(row.OwningPID),
			LocalPort:  networkPort(row.LocalPort),
			RemoteIP:   decodeIPv4(row.RemoteAddr),
			RemotePort: networkPort(row.RemotePort),
			State:      decodeState(row.State),
		})
	}
	return connections, nil
}

// networkPort extracts the port, which Windows stores in network byte order in
// the low two bytes of a host-order uint32.
func networkPort(value uint32) int {
	var raw [4]byte
	binary.LittleEndian.PutUint32(raw[:], value)
	return int(binary.BigEndian.Uint16(raw[:2]))
}

// decodeIPv4 converts the host-order uint32 address to a net.IP.
func decodeIPv4(value uint32) net.IP {
	var raw [4]byte
	binary.LittleEndian.PutUint32(raw[:], value)
	return net.IPv4(raw[0], raw[1], raw[2], raw[3])
}

func decodeState(value uint32) State {
	switch value {
	case mibTCPStateEstablished:
		return StateEstablished
	case mibTCPStateListen:
		return StateListen
	default:
		return StateOther
	}
}
