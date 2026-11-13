// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package peerbroker

import (
	"context"
	"errors"
	"net"
	"strings"
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
	names     Names
	published string
}

// NewClient builds the client for gatewayService (this gateway) that reads
// the published pipe name under dataDir (the machine data dir the guardian
// shares).
func NewClient(gatewayService, dataDir string) (*Client, error) {
	names, err := NamesFor(gatewayService)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(dataDir) == "" {
		return nil, errors.New("peer broker: the data dir is not set")
	}
	return &Client{names: names, published: names.PublishedPath(dataDir)}, nil
}

// Lookup asks the broker who owns the client end of the connection local
// (the address this gateway accepted it on) and remote. An error that wraps
// ErrUnavailable (an *UnavailableError) means no trusted broker answered.
// The published pipe name is read on every lookup (a small file), so a
// guardian restart under a new name is picked up at once.
func (c *Client) Lookup(ctx context.Context, local, remote *net.TCPAddr) (peercred.PeerIdentity, error) {
	if c == nil {
		return peercred.PeerIdentity{}, unavailable(UnavailableNoService)
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
	published, err := readPublishedPipeName(c.published, c.names)
	if err != nil {
		return peercred.PeerIdentity{}, unavailable(UnavailableNotPublished)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, OperationTimeout)
	defer cancel()
	openCtx, openCancel := context.WithTimeout(ctx, openTimeout)
	pipe, err := cmidbroker.OpenClientPipe(openCtx, published.Pipe)
	openCancel()
	if err != nil {
		return peercred.PeerIdentity{}, unavailable(UnavailableNoAnswer)
	}
	defer windows.CloseHandle(pipe)
	if err := verifyPipeServer(pipe, c.names.Guardian, published.PID); err != nil {
		return peercred.PeerIdentity{}, err
	}
	if _, err := cmidbroker.WritePipeMessage(ctx, pipe, message); err != nil {
		return peercred.PeerIdentity{}, unavailable(UnavailableNoAnswer)
	}
	buffer := make([]byte, MaxMessageBytes+1)
	count, err := cmidbroker.ReadPipeMessage(ctx, pipe, buffer)
	if err != nil || count == 0 || count > MaxMessageBytes {
		return peercred.PeerIdentity{}, unavailable(UnavailableNoAnswer)
	}
	return DecodeResponse(buffer[:count])
}

// verifyPipeServer proves the pipe server is the guardian: it is the
// process that published the name, its process runs as LocalSystem (an
// ordinary account can create a pipe with the published name while the
// guardian is down, but not a LocalSystem process) and, when SCM answers,
// it is the PID of the guardian service. A server that fails is
// UnavailableHeld with its PID.
func verifyPipeServer(pipe windows.Handle, guardianService string, publishedPID uint32) error {
	var pid uint32
	if err := windows.GetNamedPipeServerProcessId(pipe, &pid); err != nil || pid == 0 {
		return unavailable(UnavailableNoAnswer)
	}
	held := &UnavailableError{Reason: UnavailableHeld, HolderPID: pid}
	if pid != publishedPID {
		return held
	}
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return held
	}
	defer windows.CloseHandle(process)
	var token windows.Token
	if err := windows.OpenProcessToken(process, windows.TOKEN_QUERY, &token); err != nil {
		return held
	}
	user, err := token.GetTokenUser()
	token.Close()
	if err != nil || user == nil || user.User.Sid == nil || !user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		return held
	}
	guardianPID, err := cmidbroker.ServiceProcessID(guardianService)
	switch {
	case errors.Is(err, cmidbroker.ErrUnavailable):
		// The guardian service is not running: this LocalSystem process
		// is not it.
		return held
	case err != nil:
		// A hardened service descriptor can deny the status query; the
		// LocalSystem token and published PID checks above are the boundary.
		return nil
	case guardianPID != pid:
		return held
	}
	return nil
}
