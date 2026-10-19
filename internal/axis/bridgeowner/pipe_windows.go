// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package bridgeowner

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

var comparePipeObjects = windows.NewLazySystemDLL("kernelbase.dll").NewProc("CompareObjectHandles")

func distinctPipeObjects(_ []*os.File, ids []uintptr) error {
	if comparePipeObjects.Find() != nil {
		return ErrClosed
	}
	for i, id := range ids {
		for _, previous := range ids[:i] {
			same, _, compareErr := comparePipeObjects.Call(id, previous)
			if same != 0 || !errors.Is(compareErr, windows.ERROR_NOT_SAME_OBJECT) {
				return ErrClosed
			}
		}
	}
	return nil
}

func newPrivatePipe(direction Direction) (_ PrivatePipe, retErr error) {
	owner, err := windows.GetCurrentThreadEffectiveToken().GetTokenUser()
	if err != nil {
		return PrivatePipe{}, err
	}
	if owner == nil || owner.User.Sid == nil {
		return PrivatePipe{}, ErrClosed
	}
	grants := fmt.Sprintf("(A;;GA;;;%s)", owner.User.Sid)
	if !owner.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		grants += "(A;;GA;;;SY)"
	}
	sd, err := windows.SecurityDescriptorFromString(fmt.Sprintf("O:%sD:P%s", owner.User.Sid, grants))
	if err != nil {
		return PrivatePipe{}, err
	}
	var nonce [24]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return PrivatePipe{}, err
	}
	name, err := windows.UTF16PtrFromString(`\\.\pipe\LOCAL\defenseclaw-axis-` + hex.EncodeToString(nonce[:]))
	if err != nil {
		return PrivatePipe{}, err
	}
	access, clientAccess := uint32(windows.PIPE_ACCESS_INBOUND), uint32(windows.GENERIC_WRITE)
	if direction == ToPeer {
		access, clientAccess = windows.PIPE_ACCESS_OUTBOUND, windows.GENERIC_READ
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	server, err := windows.CreateNamedPipe(name, access|windows.FILE_FLAG_OVERLAPPED|windows.FILE_FLAG_FIRST_PIPE_INSTANCE,
		windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT|windows.PIPE_REJECT_REMOTE_CLIENTS, 1, 64<<10, 64<<10, 1000, &sa)
	runtime.KeepAlive(sd)
	if err != nil {
		return PrivatePipe{}, err
	}
	defer func() {
		if retErr != nil {
			_ = windows.CloseHandle(server)
		}
	}()
	client, err := windows.CreateFile(name, clientAccess, 0, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return PrivatePipe{}, err
	}
	defer func() {
		if retErr != nil {
			_ = windows.CloseHandle(client)
		}
	}()
	// The only client is an end opened by this exact process, before a peer
	// exists. A connection race is refused, never served as a public endpoint.
	var clientPID, serverPID uint32
	if windows.GetNamedPipeClientProcessId(server, &clientPID) != nil || windows.GetNamedPipeServerProcessId(client, &serverPID) != nil ||
		clientPID != windows.GetCurrentProcessId() || serverPID != windows.GetCurrentProcessId() {
		return PrivatePipe{}, ErrClosed
	}
	event, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return PrivatePipe{}, err
	}
	defer windows.CloseHandle(event)
	overlapped := windows.Overlapped{HEvent: event}
	err = windows.ConnectNamedPipe(server, &overlapped)
	if err != nil && !errors.Is(err, windows.ERROR_PIPE_CONNECTED) {
		if errors.Is(err, windows.ERROR_IO_PENDING) {
			// An already-connected verified client should never take this path.
			// Finish cancellation before releasing the OVERLAPPED storage.
			_ = windows.CancelIoEx(server, &overlapped)
			var transferred uint32
			_ = windows.GetOverlappedResult(server, &overlapped, &transferred, true)
		}
		return PrivatePipe{}, ErrClosed
	}
	// NewFile detects FILE_FLAG_OVERLAPPED and enrolls only the parent end in
	// Go's poller. The child end stays synchronous for the Rust stdio runtime.
	return PrivatePipe{os.NewFile(uintptr(server), "private-axis-parent"), os.NewFile(uintptr(client), "private-axis-child")}, nil
}
