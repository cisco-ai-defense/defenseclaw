// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cmidbroker

import (
	"context"
	"time"

	"golang.org/x/sys/windows"
)

// The named-pipe primitives below are shared with the guardian peer SID
// broker (internal/managed/peerbroker), which uses the same process model:
// a LocalSystem server on a pipe whose DACL lets only the gateway service
// SID connect, and every client authenticated by its token. They add no
// operation to the CMID broker.

// GatewayPipeSecurity is the protected pipe security descriptor: SYSTEM
// full access, the gateway service SID read and write, nobody else.
type GatewayPipeSecurity struct{ security *pipeSecurity }

// NewGatewayPipeSecurity builds the descriptor for gatewayServiceName.
func NewGatewayPipeSecurity(gatewayServiceName string) (GatewayPipeSecurity, error) {
	security, err := pipeSecurityAttributes(gatewayServiceName)
	return GatewayPipeSecurity{security: security}, err
}

// GatewayPipeSDDL is the descriptor NewGatewayPipeSecurity builds, as SDDL
// (the peer broker tests check it and apply its access list).
func GatewayPipeSDDL(gatewayServiceName string) (string, error) {
	return gatewayPipeSDDL(gatewayServiceName)
}

// PipeSecurityFromSDDL builds a pipe descriptor from SDDL: the peer broker
// tests serve as an ordinary account, which cannot make SYSTEM the owner.
func PipeSecurityFromSDDL(sddl string) (GatewayPipeSecurity, error) {
	security, err := pipeSecurityFromSDDL(sddl)
	return GatewayPipeSecurity{security: security}, err
}

// CreateGatewayServerPipe creates one overlapped message-mode instance of
// pipeName (first: FILE_FLAG_FIRST_PIPE_INSTANCE, so a pipe someone else
// created first is refused) that rejects remote clients.
func CreateGatewayServerPipe(pipeName string, security GatewayPipeSecurity, first bool) (windows.Handle, error) {
	return createServerPipe(pipeName, security.security, first)
}

// ConnectServerPipe waits for a client on pipe until ctx ends.
func ConnectServerPipe(ctx context.Context, pipe windows.Handle) error {
	return connectServerPipe(ctx, pipe)
}

// AuthenticateGatewayPipeClient proves the connected client is the running
// gateway service (its token carries the gateway service SID and its PID
// is the SCM gateway PID when SCM answers) and returns its PID.
func AuthenticateGatewayPipeClient(pipe windows.Handle, gatewayServiceName string) (uint32, error) {
	return authenticatePipeClient(pipe, gatewayServiceName)
}

// OpenClientPipe opens pipeName for one message exchange (identification
// impersonation level only), retrying while it is busy or absent.
func OpenClientPipe(ctx context.Context, pipeName string) (windows.Handle, error) {
	return openClientPipe(ctx, pipeName)
}

// ReadPipeMessage reads one message until ctx ends.
func ReadPipeMessage(ctx context.Context, handle windows.Handle, buffer []byte) (uint32, error) {
	return readOverlapped(ctx, handle, buffer)
}

// WritePipeMessage writes one message until ctx ends.
func WritePipeMessage(ctx context.Context, handle windows.Handle, message []byte) (uint32, error) {
	return writeOverlapped(ctx, handle, message)
}

// FlushPipeBounded drains the server end before a disconnect, bounded.
func FlushPipeBounded(handle windows.Handle, timeout time.Duration) {
	flushPipeBounded(handle, timeout)
}

// ServiceProcessID is the PID SCM reports for a starting or running
// service. ErrUnavailable: SCM answered and the service has no process;
// any other error: SCM did not answer.
func ServiceProcessID(name string) (uint32, error) {
	facts, err := queryService(name, false)
	if err != nil {
		return 0, err
	}
	if (facts.state != windows.SERVICE_RUNNING && facts.state != windows.SERVICE_START_PENDING) || facts.pid == 0 {
		return 0, ErrUnavailable
	}
	return facts.pid, nil
}
