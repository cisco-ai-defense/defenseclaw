// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookexec

import (
	"errors"
	"fmt"
	"net"

	"golang.org/x/sys/windows"
)

func verifyLocalPeerTuple(client, server *net.TCPAddr) error {
	clientEndpoint, err := managedIPv4EndpointFromAddr(client)
	if err != nil {
		return err
	}
	serverEndpoint, err := managedIPv4EndpointFromAddr(server)
	if err != nil {
		return err
	}
	pid, err := connectedManagedGatewayPIDForEndpoints(clientEndpoint, serverEndpoint)
	if err != nil {
		return err
	}
	if pid == 0 {
		return errors.New("connected local peer has no owner PID")
	}
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return fmt.Errorf("open connected local peer process: %w", err)
	}
	defer windows.CloseHandle(process)
	var token windows.Token
	if err := windows.OpenProcessToken(process, windows.TOKEN_QUERY, &token); err != nil {
		return fmt.Errorf("read connected local peer account: %w", err)
	}
	defer token.Close()
	peer, err := token.GetTokenUser()
	if err != nil {
		return fmt.Errorf("read connected local peer account SID: %w", err)
	}
	self, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fmt.Errorf("read current account SID: %w", err)
	}
	if !peer.User.Sid.Equals(self.User.Sid) && !peer.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		return errors.New("connected local peer belongs to another account")
	}
	return nil
}
