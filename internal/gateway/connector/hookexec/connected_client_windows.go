// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookexec

import (
	"errors"
	"net"

	"golang.org/x/sys/windows"
)

// ConnectedLoopbackClientSID is the account owning the client end of an
// accepted TCP connection. The server must check the exact four-tuple before
// answering a credential proof, otherwise a second account can relay the
// challenge to the real gateway and impersonate its listener.
func ConnectedLoopbackClientSID(local, remote *net.TCPAddr) (string, error) {
	if local == nil || remote == nil || !local.IP.IsLoopback() || !remote.IP.IsLoopback() {
		return "", errors.New("connected caller is not on loopback TCP")
	}
	server, err := managedIPv4EndpointFromAddr(local)
	if err != nil {
		return "", err
	}
	client, err := managedIPv4EndpointFromAddr(remote)
	if err != nil {
		return "", err
	}
	// Swap the endpoints to select the client's ESTABLISHED row, not the
	// server's accepted socket or the listener's current PID.
	pid, err := connectedManagedGatewayPIDForEndpoints(server, client)
	if err != nil {
		return "", err
	}
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(process)
	var token windows.Token
	if err := windows.OpenProcessToken(process, windows.TOKEN_QUERY, &token); err != nil {
		return "", err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return "", errors.New("connected caller SID is unavailable")
	}
	return user.User.Sid.String(), nil
}
