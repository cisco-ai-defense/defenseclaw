//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package peercred

import (
	"errors"
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modIPHelper             = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTCPTable = modIPHelper.NewProc("GetExtendedTcpTable")
)

const (
	tcpTableOwnerModuleConnections = 7 // TCP_TABLE_OWNER_MODULE_CONNECTIONS
	afInet                         = 2
	afInet6                        = 23
)

// readTCPOwnerTable returns the raw owner-module connection table of
// family (rows carry the connection creation timestamp).
func readTCPOwnerTable(family uint32) ([]byte, error) {
	if err := procGetExtendedTCPTable.Find(); err != nil {
		return nil, fmt.Errorf("peercred: GetExtendedTcpTable: %w", err)
	}
	size := uint32(16 << 10)
	for attempt := 0; attempt < 8; attempt++ {
		buf := make([]byte, size)
		ret, _, _ := procGetExtendedTCPTable.Call(
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&size)),
			0, // unsorted
			uintptr(family),
			tcpTableOwnerModuleConnections,
			0,
		)
		switch windows.Errno(ret) {
		case 0:
			return buf[:size], nil
		case windows.ERROR_INSUFFICIENT_BUFFER:
			// The table grew between the size query and the read.
			size += 4 << 10
			continue
		default:
			return nil, fmt.Errorf("peercred: GetExtendedTcpTable: %w", windows.Errno(ret))
		}
	}
	return nil, errors.New("peercred: the TCP table kept growing")
}

// tcpOwnerRows reads the IPv4 and IPv6 connection tables.
func tcpOwnerRows() ([]tcpOwnerRow, error) {
	var rows []tcpOwnerRow
	for _, family := range []uint32{afInet, afInet6} {
		buf, err := readTCPOwnerTable(family)
		if err != nil {
			return nil, err
		}
		parse := parseTCP4OwnerTable
		if family == afInet6 {
			parse = parseTCP6OwnerTable
		}
		got, err := parse(buf)
		if err != nil {
			return nil, err
		}
		rows = append(rows, got...)
	}
	return rows, nil
}

// The owner-module table is readable by any account. Opening another
// account process and its token is not: only the guardian peer broker
// (LocalSystem, internal/managed/peerbroker) calls verifyLoopbackTCPPeer;
// the managed gateway reads only the client row (loopbackTCPClientOwner)
// and asks the broker (S1 Q7 lead ruling: no SeDebugPrivilege for the
// gateway, no in-process fallback).
func loopbackTCPClientOwner(local, remote *net.TCPAddr) (TCPConnOwner, error) {
	return ownerSIDLookup{rows: tcpOwnerRows}.clientOwner(local, remote)
}

func verifyLoopbackTCPPeer(local, remote *net.TCPAddr, serverPID uint32, want TCPConnOwner) (PeerIdentity, error) {
	return ownerSIDLookup{rows: tcpOwnerRows, open: openPeerProcess}.verify(local, remote, serverPID, want)
}

// windowsPeerProcess is an opened client process.
type windowsPeerProcess struct {
	handle windows.Handle
}

func openPeerProcess(pid uint32) (peerProcess, error) {
	if pid == windows.GetCurrentProcessId() {
		// The broker never answers for itself.
		return nil, errors.New("peercred: the loopback client is the asking process")
	}
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return nil, fmt.Errorf("peercred: open the client process: %w", err)
	}
	return windowsPeerProcess{handle: process}, nil
}

func (p windowsPeerProcess) CreationTime() (uint64, error) {
	var created, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(p.handle, &created, &exited, &kernel, &user); err != nil {
		return 0, err
	}
	return uint64(created.HighDateTime)<<32 | uint64(created.LowDateTime), nil
}

func (p windowsPeerProcess) Identity() (PeerIdentity, error) {
	var token windows.Token
	if err := windows.OpenProcessToken(p.handle, windows.TOKEN_QUERY, &token); err != nil {
		return PeerIdentity{}, fmt.Errorf("peercred: open the client process token: %w", err)
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return PeerIdentity{}, fmt.Errorf("peercred: read the client token user: %w", err)
	}
	if user == nil || user.User.Sid == nil || !user.User.Sid.IsValid() {
		return PeerIdentity{}, errors.New("peercred: the client token has no valid user SID")
	}
	var session uint32
	var n uint32
	if err := windows.GetTokenInformation(token, windows.TokenSessionId, (*byte)(unsafe.Pointer(&session)), uint32(unsafe.Sizeof(session)), &n); err != nil {
		return PeerIdentity{}, fmt.Errorf("peercred: read the client token session: %w", err)
	}
	return PeerIdentity{SID: user.User.Sid.String(), SessionID: session}, nil
}

func (p windowsPeerProcess) Close() {
	_ = windows.CloseHandle(p.handle)
}
