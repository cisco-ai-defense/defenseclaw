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

// CancelSynchronousIo is exposed by kernel32.dll but is not currently
// exported by golang.org/x/sys/windows. Bind it via the system-only
// lazy loader so a same-directory kernel32.dll plant can't hijack the
// resolution (KnownDLLs already covers most cases; this is defense in
// depth on par with the loader we use in service_identity_windows.go).
var (
	modKernel32             = windows.NewLazySystemDLL("kernel32.dll")
	procCancelSynchronousIo = modKernel32.NewProc("CancelSynchronousIo")
)

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
//
// FlushFileBuffers is synchronous — CancelIoEx (which targets *pending*
// overlapped I/O on a handle) cannot interrupt it. The correct primitive
// is CancelSynchronousIo, which targets a specific *thread* whose
// currently-executing synchronous kernel call should be aborted with
// ERROR_OPERATION_ABORTED.
//
// To use CancelSynchronousIo we (a) pin the flush goroutine to a
// dedicated OS thread via runtime.LockOSThread, (b) duplicate the
// pseudo-handle from GetCurrentThread() into a real handle we hand to
// the parent, (c) on timeout the parent calls CancelSynchronousIo on
// that thread handle, and (d) the parent then waits on done — which is
// guaranteed to close promptly because the kernel unwinds the aborted
// FlushFileBuffers. The goroutine deliberately does NOT UnlockOSThread:
// on timeout the Go runtime destroys the still-being-cancelled OS
// thread rather than releasing a possibly-not-yet-unwound thread back
// into the shared pool. Same pattern as
// runWindowsEnterpriseImpersonatedCallback in internal/enterprisehooks.
func flushPipeBounded(handle windows.Handle, timeout time.Duration) {
	if timeout <= 0 {
		timeout = defaultOperationTimeout
	}
	// threadCh carries the duplicated real thread handle from the
	// flush goroutine to the parent. Buffered so the goroutine can send
	// and proceed without waiting.
	threadCh := make(chan windows.Handle, 1)
	done := make(chan struct{})
	go func() {
		runtime.LockOSThread()
		// Duplicate the pseudo-handle from GetCurrentThread() into a
		// real handle. GetCurrentThread's return value only refers to
		// the calling thread; DuplicateHandle produces a shareable
		// real handle we can pass to CancelSynchronousIo from a
		// different goroutine.
		var realThread windows.Handle
		proc := windows.CurrentProcess()
		if err := windows.DuplicateHandle(
			proc, windows.CurrentThread(),
			proc, &realThread,
			0, false, windows.DUPLICATE_SAME_ACCESS,
		); err != nil {
			// Signal that no cancel is possible so the parent can
			// still time out cleanly. The flush will run to completion
			// or return once the handle is closed by the parent.
			threadCh <- 0
		} else {
			threadCh <- realThread
		}
		_ = windows.FlushFileBuffers(handle)
		close(done)
		// Intentionally NOT UnlockOSThread — see doc comment above.
	}()

	threadHandle := <-threadCh
	defer func() {
		if threadHandle != 0 {
			_ = windows.CloseHandle(threadHandle)
		}
	}()

	select {
	case <-done:
		return
	case <-time.After(timeout):
	}
	// Timed out. Cancel the synchronous FlushFileBuffers on the flush
	// goroutine's thread; it unwinds with ERROR_OPERATION_ABORTED and
	// close(done) runs, so the subsequent <-done returns bounded even
	// when the client never drained the pipe.
	if threadHandle != 0 {
		_, _, _ = procCancelSynchronousIo.Call(uintptr(threadHandle))
	}
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
