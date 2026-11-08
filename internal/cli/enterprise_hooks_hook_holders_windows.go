//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/binary"
	"errors"
	"fmt"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// GAP-0755. The Windows calls under the guardian's bounded handle close
// (enterprise_hooks_hook_holders_policy_windows.go holds the rules). Nothing
// here decides anything: it lists, inspects and, when told to, closes.

// windowsSystemExtendedHandleInformation is the NtQuerySystemInformation
// class that lists every handle with its owner and object type.
const windowsSystemExtendedHandleInformation = 64

// windowsFileProcessIdsUsingFileInformation is the NtQueryInformationFile
// class that lists the processes that have a file open or mapped (the
// information Restart Manager uses).
const windowsFileProcessIdsUsingFileInformation = 47

// windowsFileAccessInformation is the NtQueryInformationFile class that
// returns the access a handle was granted.
const windowsFileAccessInformation = 8

// windowsProcessProtectionInformation is the NtQueryInformationProcess class
// that returns the PS_PROTECTION byte (0 for an unprotected process).
const windowsProcessProtectionInformation = 61

// windowsHolderMaxTableBytes bounds the handle table the guardian reads: a
// table larger than this is refused instead of allocated.
const windowsHolderMaxTableBytes = 192 << 20

// windowsHandleEntryEx is SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX.
type windowsHandleEntryEx struct {
	Object                uintptr
	UniqueProcessID       uintptr
	HandleValue           uintptr
	GrantedAccess         uint32
	CreatorBackTraceIndex uint16
	ObjectTypeIndex       uint16
	HandleAttributes      uint32
	Reserved              uint32
}

// windowsQuerySystemHandles lists every handle of every process. The slice
// points into the buffer the call filled; it is not copied.
func windowsQuerySystemHandles() ([]windowsHandleEntryEx, error) {
	size := uint32(4 << 20)
	for attempt := 0; attempt < 12; attempt++ {
		buffer := make([]uint64, (size+7)/8)
		var needed uint32
		err := windows.NtQuerySystemInformation(windowsSystemExtendedHandleInformation, unsafe.Pointer(&buffer[0]), size, &needed)
		if err == nil {
			header := 2 * unsafe.Sizeof(uintptr(0))
			count := *(*uintptr)(unsafe.Pointer(&buffer[0]))
			if uintptr(size) < header || count > (uintptr(size)-header)/unsafe.Sizeof(windowsHandleEntryEx{}) {
				return nil, fmt.Errorf("the handle table answer is malformed (%d entries in %d bytes)", count, size)
			}
			return unsafe.Slice((*windowsHandleEntryEx)(unsafe.Add(unsafe.Pointer(&buffer[0]), header)), count), nil
		}
		if !errors.Is(err, windows.STATUS_INFO_LENGTH_MISMATCH) {
			return nil, err
		}
		grown := uint64(max(needed, size)) + uint64(size)/2 + 1<<16
		if grown > windowsHolderMaxTableBytes {
			return nil, fmt.Errorf("the handle table is larger than %d MiB", windowsHolderMaxTableBytes>>20)
		}
		size = uint32(grown)
	}
	return nil, errors.New("the handle table kept growing while it was read")
}

// windowsFileIdentity names the file object a handle refers to: the 64-bit
// volume serial number and the 128-bit file id (FileIdInfo, because the
// 64-bit index of GetFileInformationByHandle can collide on ReFS). A volume
// that does not answer FileIdInfo gets the older volume and index, which are
// compared the same way for both sides of every comparison.
func windowsFileIdentity(handle windows.Handle) (windowsHookHolderIdentity, error) {
	var info struct {
		VolumeSerialNumber uint64
		FileID             [16]byte
	}
	if err := windows.GetFileInformationByHandleEx(handle, windows.FileIdInfo, (*byte)(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err == nil {
		return windowsHookHolderIdentity{volume: info.VolumeSerialNumber, id: info.FileID}, nil
	}
	var legacy windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &legacy); err != nil {
		return windowsHookHolderIdentity{}, err
	}
	identity := windowsHookHolderIdentity{volume: uint64(legacy.VolumeSerialNumber)}
	binary.LittleEndian.PutUint32(identity.id[0:4], legacy.FileIndexLow)
	binary.LittleEndian.PutUint32(identity.id[4:8], legacy.FileIndexHigh)
	identity.id[15] = 1 // the id came from the 64-bit index
	return identity, nil
}

// windowsProcessIDsUsingFile lists the processes that have the file open or
// mapped. The answer narrows the handle scan to those processes; ok is false
// when the volume or the system does not answer, and the scan then looks at
// every process within its limits.
func windowsProcessIDsUsingFile(handle windows.Handle) (pids []uint32, ok bool) {
	for size := 4096; size <= 1<<20; size *= 4 {
		buffer := make([]uint64, size/8)
		var status windows.IO_STATUS_BLOCK
		err := windows.NtQueryInformationFile(handle, &status, (*byte)(unsafe.Pointer(&buffer[0])), uint32(size), windowsFileProcessIdsUsingFileInformation)
		if err == nil {
			count := uint64(*(*uint32)(unsafe.Pointer(&buffer[0])))
			list := buffer[1:] // ULONG_PTR ProcessIdList[], after a ULONG padded to 8 bytes
			if count > uint64(len(list)) {
				return nil, false
			}
			for _, pid := range list[:count] {
				pids = append(pids, uint32(pid))
			}
			return pids, true
		}
		if !errors.Is(err, windows.STATUS_INFO_LENGTH_MISMATCH) && !errors.Is(err, windows.STATUS_BUFFER_OVERFLOW) {
			return nil, false
		}
	}
	return nil, false
}

// windowsNativeHolderSystem is the real handle table and the real processes.
type windowsNativeHolderSystem struct{}

// Snapshot lists the system handles and names the hook's file object. An
// attribute-only open takes no part in sharing, so it works while a holder
// shares nothing; its own handle is in the table, which shows the file
// object type's index (resolved here, once, instead of by name).
func (windowsNativeHolderSystem) Snapshot(path string) (windowsHolderSnapshot, error) {
	name, err := winpath.UTF16Ptr(path)
	if err != nil {
		return windowsHolderSnapshot{}, err
	}
	probe, err := windows.CreateFile(name, windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return windowsHolderSnapshot{}, fmt.Errorf("open %s to identify it: %w", filepath.Base(path), err)
	}
	snapshot := windowsHolderSnapshot{FileType: -1, Release: func() { _ = windows.CloseHandle(probe) }}
	if snapshot.Identity, err = windowsFileIdentity(probe); err != nil {
		snapshot.Release()
		return windowsHolderSnapshot{}, err
	}
	snapshot.PIDs, snapshot.PIDsKnown = windowsProcessIDsUsingFile(probe)
	if snapshot.Entries, err = windowsQuerySystemHandles(); err != nil {
		snapshot.Release()
		return windowsHolderSnapshot{}, fmt.Errorf("list the open handles: %w", err)
	}
	self := uintptr(windows.GetCurrentProcessId())
	for _, entry := range snapshot.Entries {
		if entry.UniqueProcessID == self && entry.HandleValue == uintptr(probe) {
			snapshot.FileType = int(entry.ObjectTypeIndex)
			break
		}
	}
	return snapshot, nil
}

// OpenProcess opens a process to duplicate handles out of it and reads what
// the close rules need to know about it. A process the guardian cannot open
// for DUP_HANDLE (a protected one) is an error, and so is one that ended
// (ERROR_INVALID_PARAMETER, which the scan reads as "gone", not "protected").
func (windowsNativeHolderSystem) OpenProcess(pid uint32) (windowsHolderProc, error) {
	process, err := windows.OpenProcess(windows.PROCESS_DUP_HANDLE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		// ERROR_INVALID_PARAMETER: no such process (it ended after the
		// snapshot). ERROR_ACCESS_DENIED: a process the guardian may not open.
		return nil, err
	}
	if event, _ := windows.WaitForSingleObject(process, 0); event == windows.WAIT_OBJECT_0 {
		// The process ended and something still holds its object: gone.
		_ = windows.CloseHandle(process)
		return nil, fmt.Errorf("the process had ended: %w", windows.ERROR_INVALID_PARAMETER)
	}
	proc := &windowsNativeHolderProc{process: process, facts: windowsHolderProcess{PID: pid}}
	proc.readFacts()
	return proc, nil
}

type windowsNativeHolderProc struct {
	process windows.Handle
	facts   windowsHolderProcess
}

func (p *windowsNativeHolderProc) fail(what string, err error) {
	if p.facts.FactsErr == nil {
		p.facts.FactsErr = fmt.Errorf("%s: %w", what, err)
	}
}

func (p *windowsNativeHolderProc) readFacts() {
	// The creation time tells a process from a later one that got its id.
	var created, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(p.process, &created, &exited, &kernel, &user); err != nil {
		p.fail("creation time", err)
	} else {
		p.facts.Started = uint64(created.HighDateTime)<<32 | uint64(created.LowDateTime)
	}
	var image [4096]uint16
	imageSize := uint32(len(image))
	if err := windows.QueryFullProcessImageName(p.process, 0, &image[0], &imageSize); err == nil {
		p.facts.Image = windows.UTF16ToString(image[:imageSize])
	}
	var protection byte
	var returned uint32
	if err := windows.NtQueryInformationProcess(p.process, windowsProcessProtectionInformation, unsafe.Pointer(&protection), 1, &returned); err != nil {
		p.fail("protection level", err)
	} else {
		p.facts.Protected = protection != 0
	}
	var machine, native uint16
	if err := windows.IsWow64Process2(p.process, &machine, &native); err == nil {
		p.facts.Wow64 = machine != 0
	} else {
		var wow bool
		if err := windows.IsWow64Process(p.process, &wow); err == nil {
			p.facts.Wow64 = wow
		}
	}
	var token windows.Token
	if err := windows.OpenProcessToken(p.process, windows.TOKEN_QUERY, &token); err != nil {
		p.fail("token", err)
		return
	}
	defer token.Close()
	if owner, err := token.GetTokenUser(); err != nil {
		p.fail("token user", err)
	} else {
		p.facts.SID = owner.User.Sid.String()
	}
	var session uint32
	if err := windows.GetTokenInformation(token, windows.TokenSessionId, (*byte)(unsafe.Pointer(&session)), 4, &returned); err != nil {
		p.fail("session", err)
	} else {
		p.facts.Session = session
	}
}

func (p *windowsNativeHolderProc) Facts() windowsHolderProcess { return p.facts }

// duplicate copies handle out of the process with the same access.
func (p *windowsNativeHolderProc) duplicate(handle uintptr, options uint32) (windows.Handle, error) {
	var duplicate windows.Handle
	err := windows.DuplicateHandle(p.process, windows.Handle(handle), windows.CurrentProcess(), &duplicate, 0, false, windows.DUPLICATE_SAME_ACCESS|options)
	return duplicate, err
}

// Identify duplicates one handle into the guardian and names its file
// object. It asks nothing of the handle before its type is known to be a
// disk file: GetFileType first, then the file id. No name is queried (a
// name query blocks on a synchronous pipe).
func (p *windowsNativeHolderProc) Identify(handle uintptr) (windowsHookHolderIdentity, bool, error) {
	duplicate, err := p.duplicate(handle, 0)
	if err != nil {
		return windowsHookHolderIdentity{}, false, err
	}
	defer windows.CloseHandle(duplicate)
	if kind, err := windows.GetFileType(duplicate); err != nil || kind != windows.FILE_TYPE_DISK {
		return windowsHookHolderIdentity{}, false, err
	}
	identity, err := windowsFileIdentity(duplicate)
	return identity, err == nil, err
}

// errWindowsHolderChanged is returned when the handle no longer names the hook.
var errWindowsHolderChanged = errors.New("the handle no longer names the hook")

// errWindowsHolderWrongObject is returned when the close was made and the
// handle it closed was not the hook's: its owner replaced it between the
// guardian's check and the close.
var errWindowsHolderWrongObject = errors.New("the handle closed was not the hook's: it changed between the check and the close")

// errWindowsHolderCloseFailed is returned when the last call of a close failed.
// DuplicateHandle with DUPLICATE_CLOSE_SOURCE closes the source handle
// whatever it returns, so the handle may be gone.
var errWindowsHolderCloseFailed = errors.New("the last call of the close failed, and the handle may have been closed anyway")

// CloseIf closes one handle in its owner, after a fresh duplicate shows that
// it is still a data or execute handle on the hook's file object, and checks
// the duplicate the close itself returns. DuplicateHandle with
// DUPLICATE_CLOSE_SOURCE cannot be conditional, so the window between the
// fresh check and the close is two calls wide; the check after it tells a
// close that hit something else.
//
// The caller runs all of it on a worker with a timeout (closeWindowsHolderHandle):
// the owner can close the handle value and get it back as a synchronous pipe
// with a read pending, and GetFileType on a duplicate of that blocks. commit
// is false once the caller gave up, and the close is then not made; when it
// is true the caller knows the close has begun and waits a little longer for
// the answer.
func (p *windowsNativeHolderProc) CloseIf(handle uintptr, want windowsHookHolderIdentity, commit func() bool) error {
	fresh, err := p.duplicate(handle, 0)
	if err != nil {
		return fmt.Errorf("%w (%v)", errWindowsHolderChanged, err)
	}
	valid := false
	if kind, err := windows.GetFileType(fresh); err == nil && kind == windows.FILE_TYPE_DISK {
		if got, err := windowsFileIdentity(fresh); err == nil && got == want {
			valid = true
			var status windows.IO_STATUS_BLOCK
			var access uint32
			if err := windows.NtQueryInformationFile(fresh, &status, (*byte)(unsafe.Pointer(&access)), 4, windowsFileAccessInformation); err == nil && access&windowsHolderDataAccess == 0 {
				valid = false
			}
		}
	}
	_ = windows.CloseHandle(fresh)
	if !valid {
		return errWindowsHolderChanged
	}
	if !commit() {
		return errWindowsHolderTimedOut
	}
	closing, err := p.duplicate(handle, windows.DUPLICATE_CLOSE_SOURCE)
	if err != nil {
		// The source is closed regardless of an error status.
		return fmt.Errorf("%w (%v)", errWindowsHolderCloseFailed, err)
	}
	defer windows.CloseHandle(closing)
	if got, err := windowsFileIdentity(closing); err != nil || got != want {
		return errWindowsHolderWrongObject
	}
	return nil
}

func (p *windowsNativeHolderProc) Release() { _ = windows.CloseHandle(p.process) }

// windowsHookBinaryDeleteBlocked reports whether a handle on the hook shares
// no deletion, so that no swap of the name can succeed and every start of the
// image is refused: an open for DELETE that allows every sharing mode is
// refused with a sharing violation. It is a fact about the whole file; the
// handle table does not say which handle it is. Tests replace it.
var windowsHookBinaryDeleteBlocked = func(path string) bool {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false
	}
	handle, err := windows.CreateFile(name, windows.DELETE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
		return true
	}
	if err == nil {
		_ = windows.CloseHandle(handle)
	}
	return false
}
