// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package peercred

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

// The Windows owner-PID TCP tables (GetExtendedTcpTable with
// TCP_TABLE_OWNER_PID_CONNECTIONS) as raw bytes. The parsing and the row
// match are plain Go so every platform tests them; tcp_windows.go reads the
// tables and the process token.

const (
	// mibTCPStateEstab is MIB_TCP_STATE_ESTAB.
	mibTCPStateEstab = 5
	// sizes of MIB_TCPROW_OWNER_PID and MIB_TCP6ROW_OWNER_PID.
	tcp4OwnerRowSize = 24
	tcp6OwnerRowSize = 56
)

// tcpOwnerRow is one connection of an owner-PID TCP table.
type tcpOwnerRow struct {
	LocalIP    net.IP
	LocalPort  int
	RemoteIP   net.IP
	RemotePort int
	State      uint32
	PID        uint32
}

var errTCPTableShort = errors.New("peercred: the TCP table is truncated")

// tableRowCount reads dwNumEntries and checks that rows of rowSize fit.
// MIB_TCPTABLE_OWNER_PID aligns its rows on 4 bytes after the count, and
// MIB_TCP6TABLE_OWNER_PID likewise (its row has no 8-byte member).
func tableRowCount(buf []byte, rowSize int) (int, error) {
	if len(buf) < 4 {
		return 0, errTCPTableShort
	}
	n := int(binary.LittleEndian.Uint32(buf))
	if n < 0 || n > (len(buf)-4)/rowSize {
		return 0, errTCPTableShort
	}
	return n, nil
}

// windowsPort decodes a port the tables keep in network byte order in the
// low 16 bits of a DWORD.
func windowsPort(v uint32) int {
	return int(uint16(v&0xff)<<8 | uint16((v>>8)&0xff))
}

// parseTCP4OwnerTable decodes MIB_TCPTABLE_OWNER_PID.
func parseTCP4OwnerTable(buf []byte) ([]tcpOwnerRow, error) {
	n, err := tableRowCount(buf, tcp4OwnerRowSize)
	if err != nil {
		return nil, err
	}
	rows := make([]tcpOwnerRow, 0, n)
	for i := 0; i < n; i++ {
		r := buf[4+i*tcp4OwnerRowSize : 4+(i+1)*tcp4OwnerRowSize]
		u := func(o int) uint32 { return binary.LittleEndian.Uint32(r[o:]) }
		rows = append(rows, tcpOwnerRow{
			State:      u(0),
			LocalIP:    net.IPv4(r[4], r[5], r[6], r[7]).To4(),
			LocalPort:  windowsPort(u(8)),
			RemoteIP:   net.IPv4(r[12], r[13], r[14], r[15]).To4(),
			RemotePort: windowsPort(u(16)),
			PID:        u(20),
		})
	}
	return rows, nil
}

// parseTCP6OwnerTable decodes MIB_TCP6TABLE_OWNER_PID: local address [16],
// local scope, local port, remote address [16], remote scope, remote port,
// state, owning PID.
func parseTCP6OwnerTable(buf []byte) ([]tcpOwnerRow, error) {
	n, err := tableRowCount(buf, tcp6OwnerRowSize)
	if err != nil {
		return nil, err
	}
	rows := make([]tcpOwnerRow, 0, n)
	for i := 0; i < n; i++ {
		r := buf[4+i*tcp6OwnerRowSize : 4+(i+1)*tcp6OwnerRowSize]
		u := func(o int) uint32 { return binary.LittleEndian.Uint32(r[o:]) }
		rows = append(rows, tcpOwnerRow{
			LocalIP:    append(net.IP(nil), r[0:16]...),
			LocalPort:  windowsPort(u(20)),
			RemoteIP:   append(net.IP(nil), r[24:40]...),
			RemotePort: windowsPort(u(44)),
			State:      u(48),
			PID:        u(52),
		})
	}
	return rows, nil
}

// clientRowPID finds the client end of a connection this process accepted:
// the ESTABLISHED row whose local end is the client address (remote) and
// whose remote end is the address the connection was accepted on (local).
// The server end of the same connection (local and remote swapped) is
// owned by this process and is never taken. More than one matching row is
// refused: the answer must name exactly one process.
func clientRowPID(rows []tcpOwnerRow, local, remote *net.TCPAddr) (uint32, error) {
	var found []uint32
	for _, row := range rows {
		if row.State != mibTCPStateEstab {
			continue
		}
		if row.LocalPort != remote.Port || !row.LocalIP.Equal(remote.IP) {
			continue
		}
		if row.RemotePort != local.Port || !row.RemoteIP.Equal(local.IP) {
			continue
		}
		found = append(found, row.PID)
	}
	switch len(found) {
	case 0:
		return 0, ErrPeerNotFound
	case 1:
		if found[0] == 0 || found[0] == 4 {
			return 0, fmt.Errorf("peercred: the loopback connection is owned by system process %d", found[0])
		}
		return found[0], nil
	default:
		return 0, errors.New("peercred: more than one process owns the loopback connection")
	}
}
