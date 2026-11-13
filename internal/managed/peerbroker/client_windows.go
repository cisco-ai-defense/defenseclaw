// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package peerbroker

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/managed/cmidbroker"
	"github.com/defenseclaw/defenseclaw/internal/peercred"
	"golang.org/x/sys/windows"
)

// openTimeout bounds waiting for the pipe: an absent broker is refused
// fast instead of holding the request for the whole exchange timeout.
const openTimeout = 500 * time.Millisecond

// Client is the gateway end.
type Client struct {
	names Names
}

// NewClient builds the client for gatewayService (this gateway).
func NewClient(gatewayService string) (*Client, error) {
	names, err := NamesFor(gatewayService)
	if err != nil {
		return nil, err
	}
	return &Client{names: names}, nil
}

// Lookup asks the broker who owns the client end of the connection local
// (the address this gateway accepted it on) and remote. An error that wraps
// ErrUnavailable means no trusted broker answered.
func (c *Client) Lookup(ctx context.Context, local, remote *net.TCPAddr) (peercred.PeerIdentity, error) {
	if c == nil {
		return peercred.PeerIdentity{}, ErrUnavailable
	}
	owner, err := peercred.LoopbackTCPClientOwner(local, remote)
	if err != nil {
		return peercred.PeerIdentity{}, err
	}
	request, err := NewRequest(local, remote, owner)
	if err != nil {
		return peercred.PeerIdentity{}, err
	}
	message, err := EncodeRequest(request)
	if err != nil {
		return peercred.PeerIdentity{}, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, OperationTimeout)
	defer cancel()
	openCtx, openCancel := context.WithTimeout(ctx, openTimeout)
	pipe, err := cmidbroker.OpenClientPipe(openCtx, c.names.Pipe)
	openCancel()
	if err != nil {
		return peercred.PeerIdentity{}, fmt.Errorf("%w: open the broker pipe: %v", ErrUnavailable, err)
	}
	defer windows.CloseHandle(pipe)
	if err := verifyPipeServer(pipe, c.names.Guardian); err != nil {
		return peercred.PeerIdentity{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if _, err := cmidbroker.WritePipeMessage(ctx, pipe, message); err != nil {
		return peercred.PeerIdentity{}, fmt.Errorf("%w: write: %v", ErrUnavailable, err)
	}
	buffer := make([]byte, MaxMessageBytes+1)
	count, err := cmidbroker.ReadPipeMessage(ctx, pipe, buffer)
	if err != nil || count == 0 || count > MaxMessageBytes {
		return peercred.PeerIdentity{}, fmt.Errorf("%w: read: %v", ErrUnavailable, err)
	}
	return DecodeResponse(buffer[:count])
}

// verifyPipeServer proves the pipe server is the guardian: its process
// runs as LocalSystem (an ordinary account can create a pipe with this
// name while the guardian is down, but not a LocalSystem process) and,
// when SCM answers, it is the PID of the guardian service.
func verifyPipeServer(pipe windows.Handle, guardianService string) error {
	var pid uint32
	if err := windows.GetNamedPipeServerProcessId(pipe, &pid); err != nil || pid == 0 {
		return errors.New("the broker pipe server PID is unavailable")
	}
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return fmt.Errorf("open the broker pipe server: %w", err)
	}
	defer windows.CloseHandle(process)
	var token windows.Token
	if err := windows.OpenProcessToken(process, windows.TOKEN_QUERY, &token); err != nil {
		return fmt.Errorf("open the broker pipe server token: %w", err)
	}
	user, err := token.GetTokenUser()
	token.Close()
	if err != nil || user == nil || user.User.Sid == nil || !user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		return errors.New("the broker pipe server is not LocalSystem")
	}
	guardianPID, err := cmidbroker.ServiceProcessID(guardianService)
	switch {
	case errors.Is(err, cmidbroker.ErrUnavailable):
		return errors.New("the guardian service is not running")
	case err != nil:
		// A hardened service descriptor can deny the status query; the
		// LocalSystem token check above is the boundary.
		return nil
	case guardianPID != pid:
		return errors.New("the broker pipe server is not the guardian service")
	}
	return nil
}
