// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package refusalpipe

import (
	"context"
	"errors"
	"fmt"
	"time"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"golang.org/x/sys/windows"
)

// clientPipeAccess is all a reporting client asks for: write the one
// message and read the server process ID. FILE_APPEND_DATA would be
// FILE_CREATE_PIPE_INSTANCE on a pipe, so GENERIC_WRITE is never used.
const clientPipeAccess = windows.FILE_WRITE_DATA | windows.FILE_READ_ATTRIBUTES | windows.SYNCHRONIZE

const clientRetryInterval = 25 * time.Millisecond

// Test seams: the pipe the client opens and the process that must serve it.
var (
	clientPipeName   = PipeName
	gatewayServerPID = func() (uint32, error) { return serviceProcessID(managed.StandaloneWindowsGatewaySvc) }
)

// Send delivers one refusal report to the gateway service, best effort and
// bounded by ctx. It writes nothing unless the pipe server is the running
// gateway service process, and it lets the server identify, but never
// impersonate, the calling account (SECURITY_IDENTIFICATION).
func Send(ctx context.Context, report Report) error {
	message, err := Encode(report)
	if err != nil {
		return err
	}
	name, err := windows.UTF16PtrFromString(clientPipeName)
	if err != nil {
		return err
	}
	var handle windows.Handle
	for {
		handle, err = windows.CreateFile(
			name,
			clientPipeAccess,
			0,
			nil,
			windows.OPEN_EXISTING,
			windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION,
			0,
		)
		if err == nil {
			break
		}
		if !errors.Is(err, windows.ERROR_PIPE_BUSY) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(clientRetryInterval):
		}
	}
	defer windows.CloseHandle(handle)
	var serverPID uint32
	if err := windows.GetNamedPipeServerProcessId(handle, &serverPID); err != nil {
		return err
	}
	expected, err := gatewayServerPID()
	if err != nil {
		return err
	}
	if serverPID == 0 || serverPID != expected {
		return fmt.Errorf("refusal pipe server pid %d is not the gateway service (pid %d)", serverPID, expected)
	}
	// The server buffers a whole message (MaxMessageBytes), so the write
	// completes without waiting for the server to read it.
	var written uint32
	if err := windows.WriteFile(handle, message, &written, nil); err != nil {
		return err
	}
	if int(written) != len(message) {
		return errors.New("refusal report was not written whole")
	}
	return nil
}

// serviceProcessID returns the process ID of a running service.
func serviceProcessID(serviceName string) (uint32, error) {
	manager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return 0, err
	}
	defer windows.CloseServiceHandle(manager)
	name, err := windows.UTF16PtrFromString(serviceName)
	if err != nil {
		return 0, err
	}
	service, err := windows.OpenService(manager, name, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return 0, err
	}
	defer windows.CloseServiceHandle(service)
	var status windows.SERVICE_STATUS_PROCESS
	var needed uint32
	if err := windows.QueryServiceStatusEx(
		service,
		windows.SC_STATUS_PROCESS_INFO,
		(*byte)(unsafe.Pointer(&status)),
		uint32(unsafe.Sizeof(status)),
		&needed,
	); err != nil {
		return 0, err
	}
	if status.CurrentState != windows.SERVICE_RUNNING || status.ProcessId == 0 {
		return 0, fmt.Errorf("service %s is not running", serviceName)
	}
	return status.ProcessId, nil
}
