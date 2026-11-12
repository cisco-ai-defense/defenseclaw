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
	tcpTableOwnerPIDConnections = 4 // TCP_TABLE_OWNER_PID_CONNECTIONS
	afInet                      = 2
	afInet6                     = 23
)

// readTCPOwnerTable returns the raw owner-PID connection table of family.
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
			tcpTableOwnerPIDConnections,
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

// loopbackTCPOwnerSID maps the client end of the connection to its owning
// PID, reads that process user SID, then reads the table again and requires
// the same PID on the same ESTABLISHED row. The process handle stays open
// over the second read, so the PID cannot be reused in between. Every
// failure is an error: the caller treats it as unverified, never as a
// fallback identity.
//
// Access: OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION) and
// OpenProcessToken(TOKEN_QUERY) on another account process need that
// process DACL to admit the caller. A user process admits its own user,
// SYSTEM and Administrators, not a virtual service account, so the managed
// gateway (NT SERVICE account) gets ERROR_ACCESS_DENIED here for other
// users; S1 DESIGN 20 (question Q7) recommends a LocalSystem broker.
func loopbackTCPOwnerSID(local, remote *net.TCPAddr) (string, error) {
	rows, err := tcpOwnerRows()
	if err != nil {
		return "", err
	}
	pid, err := clientRowPID(rows, local, remote)
	if err != nil {
		return "", err
	}
	if pid == windows.GetCurrentProcessId() {
		sid, err := processUserSIDOfToken(windows.GetCurrentProcessToken())
		if err != nil {
			return "", err
		}
		return sid, nil
	}
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", fmt.Errorf("peercred: open the client process: %w", err)
	}
	defer windows.CloseHandle(process)
	var token windows.Token
	if err := windows.OpenProcessToken(process, windows.TOKEN_QUERY, &token); err != nil {
		return "", fmt.Errorf("peercred: open the client process token: %w", err)
	}
	sid, err := processUserSIDOfToken(token)
	_ = token.Close()
	if err != nil {
		return "", err
	}
	again, err := tcpOwnerRows()
	if err != nil {
		return "", err
	}
	if pid2, err := clientRowPID(again, local, remote); err != nil || pid2 != pid {
		return "", errors.New("peercred: the loopback connection changed owner while it was read")
	}
	return sid, nil
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
