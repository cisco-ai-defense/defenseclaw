// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

func openAtomicTransformBoundDirectoryPlatform(path string) (*os.File, error) {
	ptr, err := winpath.UTF16Ptr(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(
		ptr,
		windows.GENERIC_READ|windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, err
	}
	if err := validateAtomicTransformWindowsHandleType(handle, true); err != nil {
		_ = windows.CloseHandle(handle)
		return nil, err
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, fmt.Errorf("wrap bound compare-and-swap directory handle")
	}
	return file, nil
}

func validateAtomicTransformWindowsHandleType(handle windows.Handle, wantDirectory bool) error {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("bound compare-and-swap handle is a reparse point")
	}
	isDirectory := info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	if isDirectory != wantDirectory {
		return fmt.Errorf("bound compare-and-swap handle has unexpected file type")
	}
	return nil
}

func validateAtomicTransformBoundDirectoryPlatform(file *os.File, requirePrivate bool) error {
	var flags uint32
	err := windows.GetFileInformationByHandleEx(
		windows.Handle(file.Fd()), windows.FileCaseSensitiveInfo,
		(*byte)(unsafe.Pointer(&flags)), uint32(unsafe.Sizeof(flags)),
	)
	if err != nil && !errors.Is(err, windows.ERROR_INVALID_PARAMETER) &&
		!errors.Is(err, windows.ERROR_NOT_SUPPORTED) {
		return fmt.Errorf("query bound compare-and-swap directory case semantics: %w", err)
	}
	if flags&windows.FILE_CS_FLAG_CASE_SENSITIVE_DIR != 0 {
		return fmt.Errorf("case-sensitive Windows directory is unsupported for compare-and-swap recovery")
	}
	if !requirePrivate {
		return nil
	}
	return validateAtomicTransformWindowsPrivateHandle(windows.Handle(file.Fd()))
}

func validateAtomicTransformBoundFilePrivatePlatform(file *os.File) error {
	return validateAtomicTransformWindowsPrivateHandle(windows.Handle(file.Fd()))
}

func validateAtomicTransformBoundDirectoryDurabilityPlatform(file *os.File) error {
	// FILE_REMOTE_PROTOCOL_INFO succeeds only for a remote filesystem handle.
	// Reject it even when the server reports an NTFS backing filesystem: the
	// local MOVEFILE_WRITE_THROUGH ordering contract does not extend to SMB.
	// FILE_REMOTE_PROTOCOL_INFO is 180 bytes through its protocol-specific
	// union on current supported Windows SDKs.
	remoteInfo := make([]byte, 180)
	remoteErr := windows.GetFileInformationByHandleEx(
		windows.Handle(file.Fd()), windows.FileRemoteProtocolInfo,
		&remoteInfo[0], uint32(len(remoteInfo)),
	)
	if remoteErr == nil {
		return fmt.Errorf("remote Windows filesystems are unsupported for compare-and-swap durability")
	}
	if !errors.Is(remoteErr, windows.ERROR_INVALID_PARAMETER) &&
		!errors.Is(remoteErr, windows.ERROR_NOT_SUPPORTED) &&
		!errors.Is(remoteErr, windows.ERROR_INVALID_FUNCTION) {
		return fmt.Errorf("determine whether compare-and-swap directory is remote: %w", remoteErr)
	}
	var flags uint32
	var serial uint32
	var maxComponent uint32
	filesystem := make([]uint16, 32)
	err := windows.GetVolumeInformationByHandle(
		windows.Handle(file.Fd()), nil, 0, &serial, &maxComponent, &flags,
		&filesystem[0], uint32(len(filesystem)),
	)
	if err != nil {
		return fmt.Errorf("query compare-and-swap volume durability capabilities: %w", err)
	}
	filesystemName := windows.UTF16ToString(filesystem)
	if !strings.EqualFold(filesystemName, "NTFS") {
		return fmt.Errorf("unsupported Windows compare-and-swap filesystem %q; local NTFS is required", filesystemName)
	}
	required := uint32(windows.FILE_PERSISTENT_ACLS | windows.FILE_SUPPORTS_OPEN_BY_FILE_ID)
	if flags&required != required || flags&windows.FILE_READ_ONLY_VOLUME != 0 {
		return fmt.Errorf("Windows compare-and-swap volume lacks persistent ACL/file-ID/write durability capabilities")
	}
	return nil
}

func validateAtomicTransformWindowsPrivateHandle(handle windows.Handle) error {
	descriptor, err := windows.GetSecurityInfo(
		handle, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return err
	}
	control, _, err := descriptor.Control()
	if err != nil {
		return err
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf("bound private compare-and-swap object has an inheritable DACL")
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		return err
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return fmt.Errorf("bound private state directory has no DACL")
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return fmt.Errorf("resolve current user for bound state directory: %w", err)
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return err
	}
	if owner == nil || !owner.Equals(user.User.Sid) {
		return fmt.Errorf("bound compare-and-swap state directory is not owned by current user")
	}
	var ownerMask, systemMask windows.ACCESS_MASK
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(index), &ace); err != nil {
			return err
		}
		if ace == nil || (ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE &&
			ace.Header.AceType != windows.ACCESS_DENIED_ACE_TYPE) {
			return fmt.Errorf("bound compare-and-swap state directory has unsupported ACL entries")
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		inheritOnly := ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0
		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE && ace.Mask != 0 &&
			(sid.Equals(user.User.Sid) || sid.Equals(system) || sid.IsWellKnown(windows.WinCreatorOwnerRightsSid)) {
			return fmt.Errorf("bound compare-and-swap state directory denies a trusted principal")
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Mask == 0 {
			continue
		}
		switch {
		case sid.Equals(user.User.Sid) || sid.IsWellKnown(windows.WinCreatorOwnerRightsSid):
			if !inheritOnly {
				ownerMask |= ace.Mask
			}
		case sid.Equals(system):
			if !inheritOnly {
				systemMask |= ace.Mask
			}
		default:
			return fmt.Errorf("bound compare-and-swap state directory grants access to another principal")
		}
	}
	const fileAllAccess windows.ACCESS_MASK = 0x001F01FF
	full := fileAllAccess
	if ownerMask&windows.GENERIC_ALL != 0 {
		ownerMask |= full
	}
	if systemMask&windows.GENERIC_ALL != 0 {
		systemMask |= full
	}
	if ownerMask&full != full || systemMask&full != full {
		return fmt.Errorf("bound private compare-and-swap object does not grant owner and SYSTEM full effective access")
	}
	return nil
}

func atomicTransformBoundObjectAttributes(
	parent *os.File, name string, descriptor *windows.SECURITY_DESCRIPTOR,
) (*windows.OBJECT_ATTRIBUTES, error) {
	if filepathBase := filepath.Base(name); filepathBase != name || name == "." || name == ".." {
		return nil, fmt.Errorf("invalid relative compare-and-swap artifact name %q", name)
	}
	unicode, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return nil, err
	}
	return &windows.OBJECT_ATTRIBUTES{
		Length:             uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})),
		RootDirectory:      windows.Handle(parent.Fd()),
		ObjectName:         unicode,
		Attributes:         windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE,
		SecurityDescriptor: descriptor,
	}, nil
}

func atomicTransformPrivateSecurityDescriptor() (*windows.SECURITY_DESCRIPTOR, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return nil, fmt.Errorf("resolve current Windows user for private CAS artifact: %w", err)
	}
	return windows.SecurityDescriptorFromString(fmt.Sprintf(
		"O:%sD:P(A;;FA;;;SY)(A;;FA;;;%s)", user.User.Sid, user.User.Sid,
	))
}

func createAtomicTransformBoundFilePlatform(parent *os.File, name string, _ os.FileMode) (*os.File, error) {
	descriptor, err := atomicTransformPrivateSecurityDescriptor()
	if err != nil {
		return nil, err
	}
	attributes, err := atomicTransformBoundObjectAttributes(parent, name, descriptor)
	if err != nil {
		return nil, err
	}
	var handle windows.Handle
	var status windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(
		&handle,
		windows.GENERIC_READ|windows.GENERIC_WRITE|windows.DELETE|windows.READ_CONTROL|windows.SYNCHRONIZE,
		attributes,
		&status,
		nil,
		windows.FILE_ATTRIBUTE_NORMAL,
		windows.FILE_SHARE_READ,
		windows.FILE_CREATE,
		windows.FILE_NON_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT|windows.FILE_WRITE_THROUGH|windows.FILE_SYNCHRONOUS_IO_NONALERT,
		0,
		0,
	)
	if err != nil {
		if errors.Is(err, windows.STATUS_OBJECT_NAME_COLLISION) {
			return nil, os.ErrExist
		}
		return nil, err
	}
	if err := validateAtomicTransformWindowsHandleType(handle, false); err != nil {
		_ = windows.CloseHandle(handle)
		return nil, err
	}
	return os.NewFile(uintptr(handle), name), nil
}

func openAtomicTransformBoundFilePlatform(parent *os.File, name string, rename bool) (*os.File, error) {
	attributes, err := atomicTransformBoundObjectAttributes(parent, name, nil)
	if err != nil {
		return nil, err
	}
	access := uint32(windows.GENERIC_READ | windows.READ_CONTROL | windows.SYNCHRONIZE)
	share := uint32(windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE)
	if rename {
		access |= windows.GENERIC_WRITE | windows.DELETE
		share = windows.FILE_SHARE_READ
	}
	var handle windows.Handle
	var status windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(
		&handle, access, attributes, &status, nil, 0, share, windows.FILE_OPEN,
		windows.FILE_NON_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT|windows.FILE_SYNCHRONOUS_IO_NONALERT|
			func() uint32 {
				if rename {
					return windows.FILE_WRITE_THROUGH
				}
				return 0
			}(),
		0, 0,
	)
	if errors.Is(err, windows.STATUS_OBJECT_NAME_NOT_FOUND) || errors.Is(err, windows.STATUS_OBJECT_PATH_NOT_FOUND) {
		return nil, os.ErrNotExist
	}
	if err != nil {
		return nil, err
	}
	if err := validateAtomicTransformWindowsHandleType(handle, false); err != nil {
		_ = windows.CloseHandle(handle)
		return nil, err
	}
	return os.NewFile(uintptr(handle), name), nil
}

func renameAtomicTransformBoundFilePlatform(
	parent, source *os.File, targetName string, replace bool,
) error {
	name, err := windows.UTF16FromString(targetName)
	if err != nil {
		return err
	}
	name = name[:len(name)-1]
	var layout atomicTransformFileRenameInfo
	bufferSize := int(unsafe.Offsetof(layout.FileName)) + len(name)*2
	buffer := make([]byte, bufferSize)
	info := (*atomicTransformFileRenameInfo)(unsafe.Pointer(&buffer[0]))
	if replace {
		info.ReplaceIfExists = 1
	}
	info.RootDirectory = windows.Handle(parent.Fd())
	info.FileNameLength = uint32(len(name) * 2)
	copy(unsafe.Slice(&info.FileName[0], len(name)), name)
	var status windows.IO_STATUS_BLOCK
	if err := windows.NtSetInformationFile(
		windows.Handle(source.Fd()), &status, &buffer[0], uint32(len(buffer)), windows.FileRenameInformation,
	); err != nil {
		if errors.Is(err, windows.STATUS_OBJECT_NAME_COLLISION) || errors.Is(err, windows.STATUS_OBJECT_NAME_EXISTS) {
			return errAtomicTransformConflict
		}
		return err
	}
	// FILE_WRITE_THROUGH causes NTFS to flush metadata changes, including a
	// rename, that result from requests on this exact handle. FlushFileBuffers
	// then explicitly flushes its remaining buffered file metadata before the
	// next phase receipt is published. RootDirectory keeps the mutation bound to
	// the already-validated directory object even if its lexical path is moved.
	return windows.FlushFileBuffers(windows.Handle(source.Fd()))
}

func syncAtomicTransformBoundDirectoryPlatform(*os.File) error {
	// Windows does not document FlushFileBuffers for directory handles. Bound
	// file handles are opened FILE_WRITE_THROUGH and flushed after each rename;
	// phase receipts provide the independently durable recovery ordering.
	return nil
}

func deleteAtomicTransformBoundFilePlatform(_ *os.File, file *os.File, _ string) error {
	// A disposition-marked handle may only be closed. Rs/Rt remains durable
	// across this gap; the subsequent no-replace marker rename is opened
	// FILE_WRITE_THROUGH and flushed, which is the deletion ordering boundary.
	return deleteAtomicTransformHandle(windows.Handle(file.Fd()))
}

func createAtomicTransformBoundDeleteOnCloseFilePlatform(
	parent *os.File, name string, _ os.FileMode,
) (*os.File, error) {
	descriptor, err := atomicTransformPrivateSecurityDescriptor()
	if err != nil {
		return nil, err
	}
	attributes, err := atomicTransformBoundObjectAttributes(parent, name, descriptor)
	if err != nil {
		return nil, err
	}
	var handle windows.Handle
	var status windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(
		&handle,
		windows.GENERIC_READ|windows.GENERIC_WRITE|windows.DELETE|windows.READ_CONTROL|windows.SYNCHRONIZE,
		attributes, &status, nil, windows.FILE_ATTRIBUTE_NORMAL, windows.FILE_SHARE_READ,
		windows.FILE_CREATE,
		windows.FILE_NON_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT|windows.FILE_WRITE_THROUGH|
			windows.FILE_SYNCHRONOUS_IO_NONALERT|windows.FILE_DELETE_ON_CLOSE,
		0, 0,
	)
	if err != nil {
		if errors.Is(err, windows.STATUS_OBJECT_NAME_COLLISION) {
			return nil, os.ErrExist
		}
		return nil, err
	}
	return os.NewFile(uintptr(handle), name), nil
}

func linkAtomicTransformBoundFilePlatform(
	parent, source *os.File, targetName string, afterLink func() error,
) error {
	name, err := windows.UTF16FromString(targetName)
	if err != nil {
		return err
	}
	name = name[:len(name)-1]
	var layout atomicTransformFileRenameInfo
	bufferSize := int(unsafe.Offsetof(layout.FileName)) + len(name)*2
	buffer := make([]byte, bufferSize)
	info := (*atomicTransformFileRenameInfo)(unsafe.Pointer(&buffer[0]))
	info.RootDirectory = windows.Handle(parent.Fd())
	info.FileNameLength = uint32(len(name) * 2)
	copy(unsafe.Slice(&info.FileName[0], len(name)), name)
	var status windows.IO_STATUS_BLOCK
	const fileLinkInformation = 11
	if err := windows.NtSetInformationFile(
		windows.Handle(source.Fd()), &status, &buffer[0], uint32(len(buffer)), fileLinkInformation,
	); err != nil {
		if errors.Is(err, windows.STATUS_OBJECT_NAME_COLLISION) || errors.Is(err, windows.STATUS_OBJECT_NAME_EXISTS) {
			return errAtomicTransformConflict
		}
		return err
	}
	if afterLink != nil {
		if err := afterLink(); err != nil {
			return err
		}
	}
	return windows.FlushFileBuffers(windows.Handle(source.Fd()))
}

func atomicTransformBoundLinkCountPlatform(file *os.File) (uint32, error) {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &info); err != nil {
		return 0, err
	}
	return info.NumberOfLinks, nil
}

func withAtomicTransformBoundProtocolLock(
	dir *atomicTransformBoundDirectory, name string, fn func() error,
) error {
	if err := validateAtomicTransformBoundLeaf(name); err != nil {
		return err
	}
	if err := dir.validatePrivate(); err != nil {
		return err
	}
	descriptor, err := atomicTransformPrivateSecurityDescriptor()
	if err != nil {
		return err
	}
	attributes, err := atomicTransformBoundObjectAttributes(dir.file, name, descriptor)
	if err != nil {
		return err
	}
	var handle windows.Handle
	var status windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(
		&handle,
		windows.GENERIC_READ|windows.GENERIC_WRITE|windows.READ_CONTROL|windows.SYNCHRONIZE,
		attributes, &status, nil, windows.FILE_ATTRIBUTE_NORMAL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		windows.FILE_OPEN_IF,
		windows.FILE_NON_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT|
			windows.FILE_SYNCHRONOUS_IO_NONALERT|windows.FILE_WRITE_THROUGH,
		0, 0,
	)
	if err != nil {
		return fmt.Errorf("open bound V2 protocol lock: %w", err)
	}
	file := os.NewFile(uintptr(handle), name)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return fmt.Errorf("wrap bound V2 protocol lock")
	}
	defer file.Close()
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	if err := validateAtomicTransformWindowsHandleType(handle, false); err != nil {
		return err
	}
	if err := validateAtomicTransformBoundFilePrivatePlatform(file); err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if info.Size() != 0 {
		return fmt.Errorf("bound V2 protocol lock contains unexpected data")
	}
	openedIdentity, err := atomicTransformOpenFileIdentity(file)
	if err != nil {
		return err
	}
	overlapped := new(windows.Overlapped)
	if err := windows.LockFileEx(handle, windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, overlapped); err != nil {
		return fmt.Errorf("acquire bound V2 protocol lock: %w", err)
	}
	defer func() { _ = windows.UnlockFileEx(handle, 0, 1, 0, overlapped) }()
	if err := dir.validatePrivate(); err != nil {
		return err
	}
	named, err := openAtomicTransformBoundFilePlatform(dir.file, name, false)
	if err != nil {
		return err
	}
	namedIdentity, identityErr := atomicTransformOpenFileIdentity(named)
	namedPrivateErr := validateAtomicTransformBoundFilePrivatePlatform(named)
	namedCloseErr := named.Close()
	if identityErr != nil || namedPrivateErr != nil || namedCloseErr != nil {
		return errors.Join(identityErr, namedPrivateErr, namedCloseErr)
	}
	if namedIdentity != openedIdentity {
		return fmt.Errorf("bound V2 protocol lock path does not name the held lock inode")
	}
	return fn()
}
