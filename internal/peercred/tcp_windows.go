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

// loopbackTCPOwnerSID maps the client end of the connection to the user SID
// of its owning process (ownerSIDLookup: creation-time PID reuse check and
// a second table read with the process open).
//
// Access: the managed Windows gateway runs as LocalSystem with a
// write-restricted service SID (sc sidtype restricted, privileges
// SeChangeNotifyPrivilege only; DefenseClawEnterprise.psm1
// Get-DefenseClawGatewayServiceAccount). A write-restricted token is
// checked against its restricting SIDs for write access only, and
// OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION), GetProcessTimes and
// OpenProcessToken(TOKEN_QUERY) are read access that the default DACL of a
// user process and its token grants SYSTEM, so this in-process lookup works
// for every user without SeDebugPrivilege or a broker. A gateway still on
// the legacy NT SERVICE account gets ERROR_ACCESS_DENIED for other users,
// which is unverified (fails closed). One live probe on the managed
// Windows host confirms it before release (CERT-110, S1 slice 4).
func loopbackTCPOwnerSID(local, remote *net.TCPAddr) (string, error) {
	return ownerSIDLookup{rows: tcpOwnerRows, open: openPeerProcess}.lookup(local, remote)
}

// windowsPeerProcess is an opened client process; self is this process
// (its pseudo handle is never closed).
type windowsPeerProcess struct {
	handle windows.Handle
	self   bool
}

func openPeerProcess(pid uint32) (peerProcess, error) {
	if pid == windows.GetCurrentProcessId() {
		return windowsPeerProcess{handle: windows.CurrentProcess(), self: true}, nil
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

func (p windowsPeerProcess) UserSID() (string, error) {
	if p.self {
		return processUserSIDOfToken(windows.GetCurrentProcessToken())
	}
	var token windows.Token
	if err := windows.OpenProcessToken(p.handle, windows.TOKEN_QUERY, &token); err != nil {
		return "", fmt.Errorf("peercred: open the client process token: %w", err)
	}
	defer token.Close()
	return processUserSIDOfToken(token)
}

func (p windowsPeerProcess) Close() {
	if !p.self {
		_ = windows.CloseHandle(p.handle)
	}
}

func processUserSIDOfToken(token windows.Token) (string, error) {
	user, err := token.GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("peercred: read the client token user: %w", err)
	}
	if user == nil || user.User.Sid == nil || !user.User.Sid.IsValid() {
		return "", errors.New("peercred: the client token has no valid user SID")
	}
	return user.User.Sid.String(), nil
}
