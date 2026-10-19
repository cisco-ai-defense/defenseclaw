// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package bridgeowner

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// OverlappedPrivatePipe owns construction, including every partial failure.
// Take transfers only a fully connected pair once. Keep a nonnil value after
// any Close failure. No context timeout frees pending OVERLAPPED storage.
type OverlappedPrivatePipe struct {
	mu                                             sync.Mutex
	serial                                         chan struct{}
	server, client, event                          windows.Handle
	operation                                      *windows.Overlapped
	pin                                            runtime.Pinner
	pending, ready, transferred, closed, uncertain bool
	// Fixed in production; per-owner hooks allow pure failure/lifetime tests.
	cancel      func(windows.Handle, *windows.Overlapped) error
	result      func(windows.Handle, *windows.Overlapped, *uint32, bool) error
	closeNative func(windows.Handle) error
}

func NewOverlappedPrivatePipe(ctx context.Context, direction Direction) (pipe *OverlappedPrivatePipe, resultErr error) {
	if ctx == nil || ctx.Err() != nil || direction != ToPeer && direction != FromPeer {
		return nil, ErrClosed
	}
	deadline, bounded := ctx.Deadline()
	if !bounded || time.Until(deadline) <= 0 || time.Until(deadline) > 30*time.Second {
		return nil, ErrClosed
	}
	pipe = &OverlappedPrivatePipe{serial: make(chan struct{}, 1), cancel: windows.CancelIoEx, result: windows.GetOverlappedResult, closeNative: windows.CloseHandle}
	// The nonnil result, not an error defer, owns every created native object.
	owner, err := windows.GetCurrentThreadEffectiveToken().GetTokenUser()
	if err != nil || owner == nil || owner.User.Sid == nil {
		return pipe, ErrClosed
	}
	grants := fmt.Sprintf("(A;;GA;;;%s)", owner.User.Sid)
	if !owner.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		grants += "(A;;GA;;;SY)"
	}
	descriptor, err := windows.SecurityDescriptorFromString(fmt.Sprintf("O:%sD:P%s", owner.User.Sid, grants))
	if err != nil {
		return pipe, ErrClosed
	}
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return pipe, ErrClosed
	}
	name, err := windows.UTF16PtrFromString(`\\.\pipe\LOCAL\defenseclaw-axis-` + hex.EncodeToString(nonce[:]))
	if err != nil {
		return pipe, ErrClosed
	}
	access, clientAccess := uint32(windows.PIPE_ACCESS_INBOUND), uint32(windows.GENERIC_WRITE)
	if direction == ToPeer {
		access, clientAccess = windows.PIPE_ACCESS_OUTBOUND, windows.GENERIC_READ
	}
	security := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: descriptor}
	pipe.server, err = windows.CreateNamedPipe(name, access|windows.FILE_FLAG_OVERLAPPED|windows.FILE_FLAG_FIRST_PIPE_INSTANCE,
		windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT|windows.PIPE_REJECT_REMOTE_CLIENTS, 1, 64<<10, 64<<10, 1000, &security)
	runtime.KeepAlive(descriptor)
	if pipe.server == windows.InvalidHandle {
		pipe.server = 0
	}
	if err != nil || pipe.server == 0 {
		return pipe, ErrClosed
	}
	pipe.client, err = windows.CreateFile(name, clientAccess, 0, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED, 0)
	if pipe.client == windows.InvalidHandle {
		pipe.client = 0
	}
	if err != nil || pipe.client == 0 {
		return pipe, ErrClosed
	}
	var clientPID, serverPID uint32
	if windows.GetNamedPipeClientProcessId(pipe.server, &clientPID) != nil || windows.GetNamedPipeServerProcessId(pipe.client, &serverPID) != nil ||
		clientPID != windows.GetCurrentProcessId() || serverPID != windows.GetCurrentProcessId() {
		return pipe, ErrClosed
	}
	pipe.event, err = windows.CreateEvent(nil, 1, 0, nil)
	if err != nil || pipe.event == 0 {
		return pipe, ErrClosed
	}
	pipe.operation = &windows.Overlapped{HEvent: pipe.event}
	pipe.pin.Pin(pipe.operation)
	err = windows.ConnectNamedPipe(pipe.server, pipe.operation)
	if errors.Is(err, windows.ERROR_IO_PENDING) {
		pipe.pending = true
		// Unexpected for the verified already-connected client. Refuse and
		// leave cancellation/terminal drain to this retained resource owner.
		return pipe, ErrClosed
	}
	pipe.pin.Unpin()
	pipe.operation = nil
	if err != nil && !errors.Is(err, windows.ERROR_PIPE_CONNECTED) {
		return pipe, ErrClosed
	}
	if !pipe.closeOne(&pipe.event) {
		return pipe, ErrCleanup
	}
	pipe.ready = true
	return pipe, nil
}

// Take exposes neither a partial endpoint nor a pending operation. Parent and
// Child stay noninheritable; the launcher makes explicit inheritable copies.
// The child is OVERLAPPED and requires the matching raw Windows Rust I/O loop.
func (pipe *OverlappedPrivatePipe) Take() (PrivatePipe, error) {
	if pipe == nil {
		return PrivatePipe{}, ErrClosed
	}
	pipe.mu.Lock()
	defer pipe.mu.Unlock()
	if !pipe.ready || pipe.closed || pipe.pending || pipe.uncertain || pipe.transferred || pipe.server == 0 || pipe.client == 0 {
		return PrivatePipe{}, ErrClosed
	}
	result := PrivatePipe{os.NewFile(uintptr(pipe.server), "private-axis-overlapped-parent"), os.NewFile(uintptr(pipe.client), "private-axis-overlapped-child")}
	pipe.server, pipe.client = 0, 0
	pipe.transferred = true
	return result, nil
}

func (pipe *OverlappedPrivatePipe) closeOne(handle *windows.Handle) bool {
	if *handle == 0 {
		return true
	}
	owned := *handle
	*handle = 0 // exactly one native close attempt, including an uncertain error
	if pipe.closeNative == nil || pipe.closeNative(owned) != nil {
		pipe.uncertain = true
		return false
	}
	return true
}

func (pipe *OverlappedPrivatePipe) Close(ctx context.Context) error {
	if pipe == nil || ctx == nil || pipe.serial == nil {
		return ErrClosed
	}
	select {
	case pipe.serial <- struct{}{}:
		defer func() { <-pipe.serial }()
	case <-ctx.Done():
		return ctx.Err()
	}
	pipe.mu.Lock()
	defer pipe.mu.Unlock()
	pipe.closed = true
	if pipe.pending {
		// Never close the event or release the pinned OVERLAPPED until the
		// exact server operation is observed terminal. No wait=true is used.
		if pipe.cancel == nil || pipe.result == nil {
			return ErrCleanup
		}
		err := pipe.cancel(pipe.server, pipe.operation)
		if err != nil && !errors.Is(err, windows.ERROR_NOT_FOUND) {
			return ErrCleanup
		}
		for {
			var transferred uint32
			err = pipe.result(pipe.server, pipe.operation, &transferred, false)
			if err == nil || errors.Is(err, windows.ERROR_OPERATION_ABORTED) || errors.Is(err, windows.ERROR_BROKEN_PIPE) || errors.Is(err, windows.ERROR_PIPE_NOT_CONNECTED) {
				pipe.pending = false
				pipe.pin.Unpin()
				pipe.operation = nil
				break
			}
			if !errors.Is(err, windows.ERROR_IO_INCOMPLETE) {
				return ErrCleanup
			}
			pipe.mu.Unlock()
			timer := time.NewTimer(time.Millisecond)
			select {
			case <-timer.C:
			case <-ctx.Done():
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				pipe.mu.Lock()
				return ctx.Err()
			}
			pipe.mu.Lock()
		}
	}
	pipe.closeOne(&pipe.client)
	pipe.closeOne(&pipe.server)
	pipe.closeOne(&pipe.event)
	if pipe.uncertain {
		return ErrCleanup
	}
	return nil
}
