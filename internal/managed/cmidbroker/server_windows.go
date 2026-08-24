// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cmidbroker

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"golang.org/x/sys/windows"
)

const brokerShutdownTimeout = 20 * time.Second

func (server *Server) Serve(ctx context.Context) error {
	return server.ServeWithReady(ctx, nil)
}

func (server *Server) ServeWithReady(ctx context.Context, ready chan<- struct{}) error {
	if server == nil {
		return errors.New("cmid broker server is unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	security, err := pipeSecurityAttributes(server.config.GatewayServiceName)
	if err != nil {
		return err
	}
	semaphore := make(chan struct{}, server.config.MaximumClients)
	var active sync.WaitGroup
	firstInstance := true
	readySignaled := false

	for {
		select {
		case <-ctx.Done():
			return waitForActiveClients(&active)
		case semaphore <- struct{}{}:
		}

		pipe, err := createServerPipe(server.config.PipeName, security, firstInstance)
		if err != nil {
			<-semaphore
			return fmt.Errorf("create protected CMID broker pipe: %w", err)
		}
		firstInstance = false
		if !readySignaled {
			readySignaled = true
			if ready != nil {
				close(ready)
			}
		}
		if err := connectServerPipe(ctx, pipe); err != nil {
			_ = windows.CloseHandle(pipe)
			<-semaphore
			if ctx.Err() != nil {
				return waitForActiveClients(&active)
			}
			continue
		}
		clientPID, err := authenticatePipeClient(pipe, server.config.GatewayServiceName)
		if err != nil {
			_ = windows.DisconnectNamedPipe(pipe)
			_ = windows.CloseHandle(pipe)
			<-semaphore
			if server.log != nil {
				server.log(Event{Stage: "client-auth", ClientPID: clientPID})
			}
			continue
		}

		active.Add(1)
		go func(handle windows.Handle, pid uint32) {
			defer active.Done()
			defer func() { <-semaphore }()
			defer windows.CloseHandle(handle)
			defer windows.DisconnectNamedPipe(handle)
			// Ensure any pending server->client bytes are drained
			// before disconnect. DisconnectNamedPipe discards
			// unread data, and the client only reads the response
			// after its own write completes. Bound the flush by
			// OperationTimeout so a hung reader cannot hold the
			// active-client slot indefinitely.
			defer flushPipeBounded(handle, server.config.OperationTimeout)
			server.handleConnection(ctx, handle, pid)
		}(pipe, clientPID)
	}
}

func (server *Server) handleConnection(ctx context.Context, pipe windows.Handle, clientPID uint32) {
	message := make([]byte, MaxMessageBytes)
	count, err := readOverlapped(ctx, pipe, message)
	if err != nil || count == 0 || count > MaxMessageBytes {
		if server.log != nil {
			server.log(Event{Stage: "read", ClientPID: clientPID})
		}
		return
	}
	response, err := server.processMessageForClient(ctx, message[:count], clientPID)
	if err != nil {
		return
	}
	if _, err := writeOverlapped(ctx, pipe, response); err != nil && server.log != nil {
		server.log(Event{Stage: "write", ClientPID: clientPID})
	}
}

// flushPipeBounded runs windows.FlushFileBuffers on handle without
// blocking the caller past timeout. FlushFileBuffers on a pipe server
// handle waits until the client has read every buffered byte; a client
// that stops reading would otherwise pin the active-client semaphore.
// Runs in its own goroutine. On timeout the flush is CANCELLED via
// CancelIoEx and the caller waits for the goroutine to observe that
// cancellation before returning, so the pipe handle is guaranteed to
// still be valid at every point the goroutine references it. This
// prevents a race where a slow flush would keep touching the handle
// after the caller (via subsequent deferred CloseHandle) had already
// released it.
func flushPipeBounded(handle windows.Handle, timeout time.Duration) {
	if timeout <= 0 {
		timeout = defaultOperationTimeout
	}
	done := make(chan struct{})
	go func() {
		_ = windows.FlushFileBuffers(handle)
		close(done)
	}()
	select {
	case <-done:
		return
	case <-time.After(timeout):
	}
	// Cancel the outstanding I/O on this handle so the goroutine's
	// FlushFileBuffers returns promptly. CancelIoEx targets any
	// pending operation on the handle; on a pipe server that already
	// wrote its response, the flush is what we're waiting on.
	_ = windows.CancelIoEx(handle, nil)
	// Wait for the goroutine to finish before returning so the caller
	// may safely proceed to DisconnectNamedPipe / CloseHandle. The
	// goroutine cannot block forever: CancelIoEx unblocks the pending
	// flush; if the handle is somehow already closed, FlushFileBuffers
	// returns immediately with an error we deliberately ignore.
	<-done
}

func createServerPipe(
	pipeName string,
	security *pipeSecurity,
	first bool,
) (windows.Handle, error) {
	pointer, err := windows.UTF16PtrFromString(pipeName)
	if err != nil {
		return 0, err
	}
	flags := uint32(windows.PIPE_ACCESS_DUPLEX | windows.FILE_FLAG_OVERLAPPED)
	if first {
		flags |= windows.FILE_FLAG_FIRST_PIPE_INSTANCE
	}
	handle, err := windows.CreateNamedPipe(
		pointer,
		flags,
		windows.PIPE_TYPE_MESSAGE|windows.PIPE_READMODE_MESSAGE|windows.PIPE_WAIT|windows.PIPE_REJECT_REMOTE_CLIENTS,
		windows.PIPE_UNLIMITED_INSTANCES,
		MaxMessageBytes,
		MaxMessageBytes,
		uint32(defaultOperationTimeout/time.Millisecond),
		&security.attributes,
	)
	runtime.KeepAlive(security.descriptor)
	return handle, err
}

func connectServerPipe(ctx context.Context, pipe windows.Handle) error {
	_, err := runOverlapped(ctx, pipe, func(_ *uint32, overlapped *windows.Overlapped) error {
		err := windows.ConnectNamedPipe(pipe, overlapped)
		if errors.Is(err, windows.ERROR_PIPE_CONNECTED) {
			return nil
		}
		return err
	})
	return err
}

type pipeSecurity struct {
	descriptor *windows.SECURITY_DESCRIPTOR
	attributes windows.SecurityAttributes
}

func pipeSecurityAttributes(gatewayServiceName string) (*pipeSecurity, error) {
	sid, err := managed.WindowsServiceAccountSID(`NT SERVICE\` + gatewayServiceName)
	if err != nil || sid == nil {
		return nil, errors.New("resolve CMID broker gateway service SID")
	}
	descriptor, err := windows.SecurityDescriptorFromString(
		"O:SYD:P(A;;GA;;;SY)(A;;GRGW;;;" + sid.String() + ")",
	)
	if err != nil {
		return nil, errors.New("build CMID broker pipe security descriptor")
	}
	return &pipeSecurity{
		descriptor: descriptor,
		attributes: windows.SecurityAttributes{
			Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
			SecurityDescriptor: descriptor,
		},
	}, nil
}

func waitForActiveClients(active *sync.WaitGroup) error {
	done := make(chan struct{})
	go func() {
		active.Wait()
		close(done)
	}()
	timer := time.NewTimer(brokerShutdownTimeout)
	defer timer.Stop()
	select {
	case <-done:
		return nil
	case <-timer.C:
		return errors.New("CMID broker shutdown timed out")
	}
}
