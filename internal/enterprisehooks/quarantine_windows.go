//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"errors"
	"fmt"
	"strings"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

const (
	windowsQuarantineDirectoryBufferSize = 64 * 1024
	windowsQuarantineMaxDepth            = 32
	windowsQuarantineMaxEntries          = 4096
	windowsQuarantineMaxPasses           = 32
	windowsFullDirectoryInfoNameOffset   = 68
)

var windowsQuarantineTargetTokenCheck = windowsEnterpriseEffectiveTokenCheck

type windowsQuarantineBudget struct {
	entries int
}

type windowsFileAttributeTagInfo struct {
	FileAttributes uint32
	ReparseTag     uint32
}

type windowsFileBasicInfo struct {
	CreationTime   int64
	LastAccessTime int64
	LastWriteTime  int64
	ChangeTime     int64
	FileAttributes uint32
	_              uint32
}

// purgeWindowsTargetOwnedQuarantine recycles the single quarantine slot while
// executing as the exact, non-elevated target token. It opens the root without
// following it, validates its owner on that handle, and traverses descendants
// only with handle-relative NtCreateFile calls using FILE_OPEN_REPARSE_POINT.
// Thus a junction within the quarantine can only cause the junction itself to
// be deleted; its target is never opened or enumerated.
func purgeWindowsTargetOwnedQuarantine(path string, target *windows.SID) error {
	if target == nil {
		return fmt.Errorf("enterprise hooks: quarantine target SID is unavailable")
	}
	if err := windowsQuarantineTargetTokenCheck(target); err != nil {
		return fmt.Errorf("enterprise hooks: quarantine deletion requires exact target-token impersonation: %w", err)
	}

	handle, err := openWindowsQuarantineRoot(path)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
		return nil
	}
	if err != nil {
		return err
	}

	owner, ownerErr := windowsHandleOwner(handle)
	if ownerErr != nil {
		windows.CloseHandle(handle)
		return ownerErr
	}
	if owner == nil || !owner.Equals(target) {
		windows.CloseHandle(handle)
		return fmt.Errorf("quarantine is not owned by target SID %s", target)
	}

	budget := &windowsQuarantineBudget{}
	purgeErr := purgeWindowsQuarantineHandle(handle, 0, budget)
	closeErr := windows.CloseHandle(handle)
	if purgeErr != nil {
		return purgeErr
	}
	if closeErr != nil {
		return fmt.Errorf("enterprise hooks: close deleted quarantine root: %w", closeErr)
	}
	return nil
}

func openWindowsQuarantineRoot(path string) (windows.Handle, error) {
	extended, err := winpath.Extended(path)
	if err != nil {
		return 0, err
	}
	ptr, err := windows.UTF16PtrFromString(extended)
	if err != nil {
		return 0, err
	}
	handle, err := windows.CreateFile(
		ptr,
		windows.DELETE|windows.FILE_LIST_DIRECTORY|windows.FILE_READ_ATTRIBUTES|
			windows.FILE_WRITE_ATTRIBUTES|windows.READ_CONTROL|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return 0, fmt.Errorf("enterprise hooks: open bounded quarantine without following %s: %w", path, err)
	}
	return handle, nil
}

func windowsHandleOwner(handle windows.Handle) (*windows.SID, error) {
	sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return nil, err
	}
	if sd == nil {
		return nil, fmt.Errorf("enterprise hooks: quarantine handle has no security descriptor")
	}
	owner, _, err := sd.Owner()
	return owner, err
}

func purgeWindowsQuarantineHandle(
	handle windows.Handle,
	depth int,
	budget *windowsQuarantineBudget,
) error {
	if depth > windowsQuarantineMaxDepth {
		return fmt.Errorf("enterprise hooks: bounded quarantine exceeds maximum depth %d", windowsQuarantineMaxDepth)
	}
	attributes, err := windowsQuarantineHandleAttributes(handle)
	if err != nil {
		return err
	}
	if attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
		attributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return markWindowsQuarantineHandleForDeletion(handle, attributes)
	}

	for pass := 0; pass < windowsQuarantineMaxPasses; pass++ {
		names, err := windowsQuarantineDirectoryNames(handle)
		if err != nil {
			return err
		}
		if len(names) == 0 {
			err = markWindowsQuarantineHandleForDeletion(handle, attributes)
			if errors.Is(err, windows.ERROR_DIR_NOT_EMPTY) {
				continue
			}
			return err
		}

		for _, name := range names {
			budget.entries++
			if budget.entries > windowsQuarantineMaxEntries {
				return fmt.Errorf(
					"enterprise hooks: bounded quarantine exceeds maximum entry count %d",
					windowsQuarantineMaxEntries,
				)
			}
			child, err := openWindowsQuarantineChild(handle, name)
			if windowsQuarantineChildDisappeared(err) {
				continue
			}
			if err != nil {
				return fmt.Errorf("enterprise hooks: open quarantine child %q without following: %w", name, err)
			}
			childErr := purgeWindowsQuarantineHandle(child, depth+1, budget)
			closeErr := windows.CloseHandle(child)
			if childErr != nil {
				return fmt.Errorf("enterprise hooks: purge quarantine child %q: %w", name, childErr)
			}
			if closeErr != nil {
				return fmt.Errorf("enterprise hooks: close deleted quarantine child %q: %w", name, closeErr)
			}
		}
	}
	return fmt.Errorf(
		"enterprise hooks: bounded quarantine remained active after %d no-follow purge passes",
		windowsQuarantineMaxPasses,
	)
}

func windowsQuarantineHandleAttributes(handle windows.Handle) (uint32, error) {
	var info windowsFileAttributeTagInfo
	if err := windows.GetFileInformationByHandleEx(
		handle,
		windows.FileAttributeTagInfo,
		(*byte)(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
	); err != nil {
		return 0, fmt.Errorf("enterprise hooks: inspect quarantine handle attributes: %w", err)
	}
	return info.FileAttributes, nil
}

func windowsQuarantineDirectoryNames(handle windows.Handle) ([]string, error) {
	// Directory information buffers must be naturally aligned. A []byte only
	// promises byte alignment, so retain an aligned uint64 backing allocation
	// and parse its byte view.
	aligned := make([]uint64, windowsQuarantineDirectoryBufferSize/8)
	buffer := unsafe.Slice((*byte)(unsafe.Pointer(&aligned[0])), windowsQuarantineDirectoryBufferSize)
	names := make([]string, 0, 16)
	// The 64 KiB buffer can hold ~4096 short entries but far fewer when
	// names are long. Restart on the first call, then continue with
	// FileFullDirectoryInfo until ERROR_NO_MORE_FILES so a valid but
	// long-named quarantine slot cannot leave stragglers unread.
	infoClass := uint32(windows.FileFullDirectoryRestartInfo)
	for {
		err := windows.GetFileInformationByHandleEx(
			handle,
			infoClass,
			&buffer[0],
			uint32(len(buffer)),
		)
		if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
			return names, nil
		}
		if err != nil {
			return nil, fmt.Errorf("enterprise hooks: enumerate bounded quarantine without following: %w", err)
		}
		for offset := 0; ; {
			if offset < 0 || offset+windowsFullDirectoryInfoNameOffset > len(buffer) {
				return nil, fmt.Errorf("enterprise hooks: invalid bounded quarantine directory record")
			}
			next := *(*uint32)(unsafe.Pointer(&buffer[offset]))
			nameBytes := *(*uint32)(unsafe.Pointer(&buffer[offset+60]))
			if nameBytes%2 != 0 || uint64(offset)+windowsFullDirectoryInfoNameOffset+uint64(nameBytes) > uint64(len(buffer)) {
				return nil, fmt.Errorf("enterprise hooks: invalid bounded quarantine directory name length")
			}
			nameUnits := unsafe.Slice(
				(*uint16)(unsafe.Pointer(&buffer[offset+windowsFullDirectoryInfoNameOffset])),
				int(nameBytes/2),
			)
			name := windows.UTF16ToString(nameUnits)
			if name != "." && name != ".." {
				if name == "" || strings.ContainsAny(name, "\\/\x00") {
					return nil, fmt.Errorf("enterprise hooks: invalid bounded quarantine child name")
				}
				names = append(names, name)
			}
			if next == 0 {
				break
			}
			if next < windowsFullDirectoryInfoNameOffset || uint64(offset)+uint64(next) >= uint64(len(buffer)) {
				return nil, fmt.Errorf("enterprise hooks: invalid bounded quarantine directory continuation")
			}
			offset += int(next)
		}
		infoClass = uint32(windows.FileFullDirectoryInfo)
	}
}

func openWindowsQuarantineChild(parent windows.Handle, name string) (windows.Handle, error) {
	objectName, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return 0, err
	}
	attributes := windows.OBJECT_ATTRIBUTES{
		Length:        uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})),
		RootDirectory: parent,
		ObjectName:    objectName,
		Attributes:    windows.OBJ_CASE_INSENSITIVE,
	}
	var handle windows.Handle
	var status windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(
		&handle,
		windows.DELETE|windows.FILE_LIST_DIRECTORY|windows.FILE_READ_ATTRIBUTES|
			windows.FILE_WRITE_ATTRIBUTES|windows.SYNCHRONIZE,
		&attributes,
		&status,
		nil,
		0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		windows.FILE_OPEN,
		windows.FILE_OPEN_REPARSE_POINT|windows.FILE_SYNCHRONOUS_IO_NONALERT,
		0,
		0,
	)
	if err != nil {
		return 0, err
	}
	return handle, nil
}

func windowsQuarantineChildDisappeared(err error) bool {
	// errors.Is keeps this rule correct if any future caller wraps the raw
	// NTSTATUS: an unwrapped == would silently turn "child already gone"
	// into "hard failure" and fail the teardown for a benign race.
	return errors.Is(err, windows.STATUS_OBJECT_NAME_NOT_FOUND) ||
		errors.Is(err, windows.STATUS_OBJECT_PATH_NOT_FOUND) ||
		errors.Is(err, windows.STATUS_DELETE_PENDING)
}

func markWindowsQuarantineHandleForDeletion(handle windows.Handle, attributes uint32) error {
	flags := uint32(windows.FILE_DISPOSITION_DELETE | windows.FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE)
	// Preserve the FileDispositionInfoEx failure so a subsequent legacy
	// FileDispositionInfo failure can join both causes in the returned
	// error. Otherwise the extended failure — which is what modern
	// Windows uses to expose file-in-use / delete-on-close diagnostics —
	// is silently discarded and teardown loses that signal.
	exErr := windows.SetFileInformationByHandle(
		handle,
		windows.FileDispositionInfoEx,
		(*byte)(unsafe.Pointer(&flags)),
		uint32(unsafe.Sizeof(flags)),
	)
	if exErr == nil {
		return nil
	}

	if attributes&windows.FILE_ATTRIBUTE_READONLY != 0 {
		var basic windowsFileBasicInfo
		if err := windows.GetFileInformationByHandleEx(
			handle,
			windows.FileBasicInfo,
			(*byte)(unsafe.Pointer(&basic)),
			uint32(unsafe.Sizeof(basic)),
		); err != nil {
			return fmt.Errorf("enterprise hooks: inspect read-only quarantine object: %w", err)
		}
		basic.FileAttributes &^= windows.FILE_ATTRIBUTE_READONLY
		if basic.FileAttributes == 0 {
			basic.FileAttributes = windows.FILE_ATTRIBUTE_NORMAL
		}
		if err := windows.SetFileInformationByHandle(
			handle,
			windows.FileBasicInfo,
			(*byte)(unsafe.Pointer(&basic)),
			uint32(unsafe.Sizeof(basic)),
		); err != nil {
			return fmt.Errorf("enterprise hooks: clear read-only quarantine object by handle: %w", err)
		}
	}

	deleteFile := byte(1)
	if err := windows.SetFileInformationByHandle(
		handle,
		windows.FileDispositionInfo,
		&deleteFile,
		1,
	); err != nil {
		return fmt.Errorf(
			"enterprise hooks: mark quarantine object for deletion by handle: %w (FileDispositionInfoEx also failed: %v)",
			err, exErr,
		)
	}
	return nil
}
