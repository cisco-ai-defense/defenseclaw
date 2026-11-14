// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package peercred

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

// The Windows owner-module TCP tables (GetExtendedTcpTable with
// TCP_TABLE_OWNER_MODULE_CONNECTIONS) as raw bytes, and the lookup that
// turns a row into a user SID. The parsing, the row match and the PID reuse
// check are plain Go so every platform tests them; tcp_windows.go reads the
// tables and opens the process.

const (
	// mibTCPStateEstab is MIB_TCP_STATE_ESTAB.
	mibTCPStateEstab = 5
	// Sizes of MIB_TCPROW_OWNER_MODULE and MIB_TCP6ROW_OWNER_MODULE: the
	// owner-PID row, then liCreateTimestamp (LARGE_INTEGER) and
	// OwningModuleInfo (16 ULONGLONG).
	tcp4OwnerRowSize = 160
	tcp6OwnerRowSize = 192
	// The rows hold 8-byte members, so the first row starts 8 bytes into
	// the table: dwNumEntries, then 4 bytes of padding.
	tcpOwnerTableHeader = 8
)

// tcpOwnerRow is one connection of an owner-module TCP table.
type tcpOwnerRow struct {
	LocalIP    net.IP
	LocalPort  int
	RemoteIP   net.IP
	RemotePort int
	State      uint32
	PID        uint32
	// CreateTime is liCreateTimestamp: the FILETIME (100 ns units since
	// 1601) of the bind that created the connection; 0 when unknown.
	CreateTime uint64
}

var errTCPTableShort = errors.New("peercred: the TCP table is truncated")

// tableRowCount reads dwNumEntries and checks that rows of rowSize fit.
func tableRowCount(buf []byte, rowSize int) (int, error) {
	if len(buf) < tcpOwnerTableHeader {
		return 0, errTCPTableShort
	}
	n := int(binary.LittleEndian.Uint32(buf))
	if n < 0 || n > (len(buf)-tcpOwnerTableHeader)/rowSize {
		return 0, errTCPTableShort
	}
	return n, nil
}

// windowsPort decodes a port the tables keep in network byte order in the
// low 16 bits of a DWORD.
func windowsPort(v uint32) int {
	return int(uint16(v&0xff)<<8 | uint16((v>>8)&0xff))
}

func tableRow(buf []byte, i, rowSize int) []byte {
	start := tcpOwnerTableHeader + i*rowSize
	return buf[start : start+rowSize]
}

// parseTCP4OwnerTable decodes MIB_TCPTABLE_OWNER_MODULE.
func parseTCP4OwnerTable(buf []byte) ([]tcpOwnerRow, error) {
	n, err := tableRowCount(buf, tcp4OwnerRowSize)
	if err != nil {
		return nil, err
	}
	rows := make([]tcpOwnerRow, 0, n)
	for i := 0; i < n; i++ {
		r := tableRow(buf, i, tcp4OwnerRowSize)
		u := func(o int) uint32 { return binary.LittleEndian.Uint32(r[o:]) }
		rows = append(rows, tcpOwnerRow{
			State:      u(0),
			LocalIP:    net.IPv4(r[4], r[5], r[6], r[7]).To4(),
			LocalPort:  windowsPort(u(8)),
			RemoteIP:   net.IPv4(r[12], r[13], r[14], r[15]).To4(),
			RemotePort: windowsPort(u(16)),
			PID:        u(20),
			CreateTime: binary.LittleEndian.Uint64(r[24:]),
		})
	}
	return rows, nil
}

// parseTCP6OwnerTable decodes MIB_TCP6TABLE_OWNER_MODULE: local address
// [16], local scope, local port, remote address [16], remote scope, remote
// port, state, owning PID, creation timestamp, module info.
func parseTCP6OwnerTable(buf []byte) ([]tcpOwnerRow, error) {
	n, err := tableRowCount(buf, tcp6OwnerRowSize)
	if err != nil {
		return nil, err
	}
	rows := make([]tcpOwnerRow, 0, n)
	for i := 0; i < n; i++ {
		r := tableRow(buf, i, tcp6OwnerRowSize)
		u := func(o int) uint32 { return binary.LittleEndian.Uint32(r[o:]) }
		rows = append(rows, tcpOwnerRow{
			LocalIP:    append(net.IP(nil), r[0:16]...),
			LocalPort:  windowsPort(u(20)),
			RemoteIP:   append(net.IP(nil), r[24:40]...),
			RemotePort: windowsPort(u(44)),
			State:      u(48),
			PID:        u(52),
			CreateTime: binary.LittleEndian.Uint64(r[56:]),
		})
	}
	return rows, nil
}

// clientRow finds the client end of a connection this process accepted:
// the ESTABLISHED row whose local end is the client address (remote) and
// whose remote end is the address the connection was accepted on (local).
// The server end of the same connection (local and remote swapped) is
// owned by this process and is never taken. More than one matching row is
// refused: the answer must name exactly one process.
func clientRow(rows []tcpOwnerRow, local, remote *net.TCPAddr) (tcpOwnerRow, error) {
	var found []tcpOwnerRow
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
		found = append(found, row)
	}
	switch len(found) {
	case 0:
		return tcpOwnerRow{}, ErrPeerNotFound
	case 1:
		if found[0].PID == 0 || found[0].PID == 4 {
			return tcpOwnerRow{}, fmt.Errorf("peercred: the loopback connection is owned by system process %d", found[0].PID)
		}
		return found[0], nil
	default:
		return tcpOwnerRow{}, errors.New("peercred: more than one process owns the loopback connection")
	}
}

// TCPConnOwner is the process the owner-module table names for the client
// end of a loopback connection: its PID and the connection creation time.
type TCPConnOwner struct {
	PID        uint32
	CreateTime uint64
}

// PeerIdentity is the account of a verified loopback client process.
type PeerIdentity struct {
	SID string
}

// peerProcess is the opened client process (tcp_windows.go; fakes in the
// tests). While it is open its PID cannot be reused.
type peerProcess interface {
	// CreationTime is the FILETIME the process started (GetProcessTimes).
	CreationTime() (uint64, error)
	// Identity is the token user SID of the process.
	Identity() (PeerIdentity, error)
	Close()
}

// ownerSIDLookup maps the client end of a loopback connection to the
// account of the process that owns it.
type ownerSIDLookup struct {
	rows func() ([]tcpOwnerRow, error)
	open func(pid uint32) (peerProcess, error)
}

// clientOwner reads the client row of the connection (no process is
// opened): the gateway side of the peer broker request.
func (l ownerSIDLookup) clientOwner(local, remote *net.TCPAddr) (TCPConnOwner, error) {
	rows, err := l.rows()
	if err != nil {
		return TCPConnOwner{}, err
	}
	row, err := clientRow(rows, local, remote)
	if err != nil {
		return TCPConnOwner{}, err
	}
	if row.CreateTime == 0 {
		return TCPConnOwner{}, errors.New("peercred: the TCP table has no creation time for the loopback connection")
	}
	return TCPConnOwner{PID: row.PID, CreateTime: row.CreateTime}, nil
}

// serverRowOwnedBy checks that the server end of the connection (local is
// the address it was accepted on) is one ESTABLISHED row owned by pid: the
// peer broker answers only for connections its caller accepted.
func serverRowOwnedBy(rows []tcpOwnerRow, local, remote *net.TCPAddr, pid uint32) error {
	var found []tcpOwnerRow
	for _, row := range rows {
		if row.State != mibTCPStateEstab {
			continue
		}
		if row.LocalPort != local.Port || !row.LocalIP.Equal(local.IP) {
			continue
		}
		if row.RemotePort != remote.Port || !row.RemoteIP.Equal(remote.IP) {
			continue
		}
		found = append(found, row)
	}
	switch {
	case len(found) == 0:
		return ErrPeerNotFound
	case len(found) > 1:
		return errors.New("peercred: more than one process owns the server end of the loopback connection")
	case found[0].PID != pid || pid == 0:
		return ErrNotAccepted
	}
	return nil
}

// ErrNotAccepted reports a connection whose server end the asking process
// does not own.
var ErrNotAccepted = errors.New("peercred: the asking process did not accept this loopback connection")

// ErrOwnerChanged reports a client end that is no longer owned by the
// process (PID and connection creation time) the request named.
var ErrOwnerChanged = errors.New("peercred: the loopback connection is not owned by the process the request names")

// verify is the peer broker answer (S1 Q7). The server end must be owned by
// serverPID (the authenticated gateway) and the client end by want (the
// PID and creation time the gateway read). It opens that PID and refuses
// the answer unless the process started no later than the connection was
// created: the table keeps the PID of the process that created the socket
// even after it exits and another process (of any account) gets the PID,
// with the handle inherited or duplicated into a survivor; a process that
// started after the connection existed cannot have created it (S1
// REVIEW-code-slice4 P1-1). The table is read again with the process open
// and must show the same rows. A missing creation time is refused, and
// every failure is an error: the caller treats it as unverified, never as
// a fallback identity.
func (l ownerSIDLookup) verify(local, remote *net.TCPAddr, serverPID uint32, want TCPConnOwner) (PeerIdentity, error) {
	if want.PID == 0 || want.CreateTime == 0 {
		return PeerIdentity{}, ErrOwnerChanged
	}
	check := func() error {
		rows, err := l.rows()
		if err != nil {
			return err
		}
		if err := serverRowOwnedBy(rows, local, remote, serverPID); err != nil {
			return err
		}
		row, err := clientRow(rows, local, remote)
		if err != nil {
			return err
		}
		if row.PID != want.PID || row.CreateTime != want.CreateTime {
			return ErrOwnerChanged
		}
		return nil
	}
	if err := check(); err != nil {
		return PeerIdentity{}, err
	}
	process, err := l.open(want.PID)
	if err != nil {
		return PeerIdentity{}, err
	}
	defer process.Close()
	started, err := process.CreationTime()
	if err != nil {
		return PeerIdentity{}, fmt.Errorf("peercred: read the client process creation time: %w", err)
	}
	if started == 0 {
		return PeerIdentity{}, errors.New("peercred: the client process has no creation time")
	}
	if started > want.CreateTime {
		return PeerIdentity{}, fmt.Errorf("peercred: process %d started after the loopback connection was created (its PID was reused)", want.PID)
	}
	identity, err := process.Identity()
	if err != nil {
		return PeerIdentity{}, err
	}
	if identity.SID == "" {
		return PeerIdentity{}, errors.New("peercred: the client token has no user SID")
	}
	if err := check(); err != nil {
		if errors.Is(err, ErrOwnerChanged) {
			return PeerIdentity{}, errors.New("peercred: the loopback connection changed owner while it was read")
		}
		return PeerIdentity{}, err
	}
	return identity, nil
}
