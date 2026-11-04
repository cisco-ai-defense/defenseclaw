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

package managed

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// The enterprise Setup trust rule covers the objects one lifecycle run stages
// and executes: the outer Setup's staging directory and payload, the
// installer script and module the staged CLI runs, and Windows PowerShell.
//
//   - The named file or directory keeps every verdict fatal: its owner must be
//     Administrators, LocalSystem, TrustedInstaller (or the caller's pinned
//     writer), and no untrusted principal may hold a write-like right. An
//     administrator-equivalent owner or writer is accepted and logged, as
//     everywhere else in the managed trust walk.
//   - Structure is fatal everywhere: a symbolic link, a reparse point, the
//     wrong object type, more than one hard link on the file, or a volume that
//     is not fixed local NTFS.
//   - Every ancestor is advisory. Setup runs from wherever the deployment
//     system put it and stages under ProgramData, whose permissions belong to
//     the operating system, the imaging process and other installers. An
//     ancestor's owner or ACL verdict is logged once with
//     TrustAdvisoryMarker and MarkerAccept and the walk continues; the
//     narrow replace-only mask still applies, so the log only names grants
//     that could replace a child. TrustStrictAncestorsEnv makes the ancestor
//     verdicts fatal again.
//
// Holding the named objects open while they are used (PinSetupPath) is what
// makes the advisory ancestors safe: nobody can rename, replace or rewrite a
// pinned object, whatever its parents allow.

const (
	setupFileSDDL      = "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)"
	setupDirectorySDDL = "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	// setupRemoveDepth bounds a removal walk; staging trees are a few levels.
	setupRemoveDepth = 64
)

// ValidateSetupPath applies the enterprise Setup trust rule to path.
func ValidateSetupPath(path, label string, kind SetupPathKind) error {
	return ValidateSetupPathWithWriter(path, label, kind, nil)
}

// ValidateSetupPathWithWriter is ValidateSetupPath that also trusts
// allowedWriter as the named object's owner or writer. The outer Setup passes
// the elevated administrator's own user SID for the --config and --manifest
// files it was handed, which that administrator legitimately owns.
func ValidateSetupPathWithWriter(path, label string, kind SetupPathKind, allowedWriter *windows.SID) error {
	clean, label, err := setupCleanPath(path, label)
	if err != nil {
		return err
	}
	directory := kind == SetupPathDirectory
	if err := validateTrustedWindowsPathElementWithWriter(clean, directory, label, allowedWriter, windowsTrustLeaf); err != nil {
		return err
	}
	if kind == SetupPathFile {
		if err := rejectSetupHardLinks(clean, label); err != nil {
			return err
		}
	}
	return validateSetupAncestors(clean, label, allowedWriter)
}

// ValidateSetupPathStructure applies only the structural half of the Setup
// trust rule, to the named object and every ancestor: no symbolic link, no
// reparse point, the expected type, one hard link on a file, fixed local NTFS.
// Owners and ACLs are not read. Used for the PowerShell working directory and
// before a cleanup walk.
func ValidateSetupPathStructure(path, label string, kind SetupPathKind) error {
	clean, label, err := setupCleanPath(path, label)
	if err != nil {
		return err
	}
	directory := kind == SetupPathDirectory
	structure := windowsTrustScope{structureOnly: true}
	if err := validateTrustedWindowsPathElementWithWriter(clean, directory, label, nil, structure); err != nil {
		return err
	}
	if kind == SetupPathFile {
		if err := rejectSetupHardLinks(clean, label); err != nil {
			return err
		}
	}
	for dir := filepath.Dir(clean); ; dir = filepath.Dir(dir) {
		if err := validateTrustedWindowsPathElementWithWriter(dir, true, label, nil, structure); err != nil {
			return err
		}
		if dir == filepath.Dir(dir) {
			return nil
		}
	}
}

func setupCleanPath(path, label string) (string, string, error) {
	if label == "" {
		label = "enterprise Setup path"
	}
	if strings.TrimSpace(path) == "" {
		return "", label, fmt.Errorf("%s path is empty", label)
	}
	clean, err := filepath.Abs(path)
	if err != nil {
		return "", label, fmt.Errorf("resolve %s path: %w", label, err)
	}
	if _, err := winpath.ValidateFixedNTFSMountedPath(clean); err != nil {
		return "", label, fmt.Errorf("%s is not on a trusted mount-manager NTFS drive: %w", label, err)
	}
	return filepath.Clean(clean), label, nil
}

// validateSetupAncestors walks every parent of clean up to the volume root.
// Structure is fatal; an owner or ACL verdict is accepted and logged unless
// the strict pin is set.
func validateSetupAncestors(clean, label string, allowedWriter *windows.SID) error {
	structure := windowsTrustScope{structureOnly: true}
	for dir := filepath.Dir(clean); ; dir = filepath.Dir(dir) {
		if err := validateTrustedWindowsPathElementWithWriter(dir, true, label, nil, structure); err != nil {
			return err
		}
		if verdict := validateTrustedWindowsPathElementWithWriter(
			dir, true, label, allowedWriter, windowsTrustNamedDir,
		); verdict != nil {
			if trustStrictAncestors() {
				return verdict
			}
			reportSetupAncestorAccept(dir, label, verdict)
		}
		if dir == filepath.Dir(dir) {
			return nil
		}
	}
}

func reportSetupAncestorAccept(dir, label string, verdict error) {
	reportTrustAdvisory(dir, label, verdict.Error())
	fields := map[string]string{
		"path":   dir,
		"object": label,
		"reason": "ancestor permissions are not provably trusted; the named object is pinned while in use: " + verdict.Error(),
	}
	if !advisoryLogDedupe.shouldEmit(dir, MarkerAccept, FormatResilienceEvent(MarkerAccept, fields)) {
		return
	}
	EmitResilienceEvent(MarkerAccept, fields)
}

func rejectSetupHardLinks(path, label string) error {
	handle, err := openSetupNoFollow(path, windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE)
	if err != nil {
		return fmt.Errorf("%s: open %s for link inspection: %w", path, label, err)
	}
	defer func() { _ = windows.CloseHandle(handle) }()
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return fmt.Errorf("%s: inspect %s: %w", path, label, err)
	}
	if info.NumberOfLinks != 1 {
		return fmt.Errorf("%s: %s has %d hard links, expected exactly 1", path, label, info.NumberOfLinks)
	}
	return nil
}

// openSetupNoFollow opens path itself (never a reparse target) with backup
// semantics so directories open too. Sharing and lock violations are retried
// within the package's bounded budget.
func openSetupNoFollow(path string, access, share uint32) (windows.Handle, error) {
	pointer, err := winpath.UTF16Ptr(path)
	if err != nil {
		return windows.InvalidHandle, err
	}
	return retryTransientOpen(func() (windows.Handle, error) {
		return windows.CreateFile(
			pointer,
			access,
			share,
			nil,
			windows.OPEN_EXISTING,
			windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
			0,
		)
	})
}

// SetupFileID identifies one file system object: its volume serial number and
// file index. Two paths with the same ID name the same object.
type SetupFileID struct {
	Volume uint32
	High   uint32
	Low    uint32
}

func setupFileIDFromInfo(info *windows.ByHandleFileInformation) SetupFileID {
	return SetupFileID{Volume: info.VolumeSerialNumber, High: info.FileIndexHigh, Low: info.FileIndexLow}
}

// SetupFileIDOf returns the ID of path itself, without following a reparse
// point.
func SetupFileIDOf(path string) (SetupFileID, error) {
	handle, err := openSetupNoFollow(path, windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE)
	if err != nil {
		return SetupFileID{}, err
	}
	defer func() { _ = windows.CloseHandle(handle) }()
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return SetupFileID{}, err
	}
	return setupFileIDFromInfo(&info), nil
}

// SetupFileIDOfFile returns the ID of an open file.
func SetupFileIDOfFile(file *os.File) (SetupFileID, error) {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &info); err != nil {
		return SetupFileID{}, err
	}
	return setupFileIDFromInfo(&info), nil
}

// SetupPin holds one staged object open so it cannot be renamed, deleted or
// rewritten while a lifecycle run uses it. A file is shared for reading only,
// so the image loader and PowerShell can still read it; a directory is shared
// for reading and writing but never for deletion, so its contents can change
// but it cannot be renamed or replaced.
type SetupPin struct {
	handle windows.Handle
	path   string
	kind   SetupPathKind
	id     SetupFileID
}

// PinSetupPath opens path itself, refuses a reparse point, the wrong type or
// a file with more than one hard link, and keeps the handle until Close.
func PinSetupPath(path string, kind SetupPathKind) (*SetupPin, error) {
	clean, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve pinned path %s: %w", path, err)
	}
	// The read-data right is what makes the share mode bind: an open that
	// asks only for attributes takes no part in sharing checks.
	access := uint32(windows.FILE_READ_DATA | windows.FILE_READ_ATTRIBUTES | windows.READ_CONTROL | windows.SYNCHRONIZE)
	share := uint32(windows.FILE_SHARE_READ)
	if kind == SetupPathDirectory {
		share |= windows.FILE_SHARE_WRITE
	}
	handle, err := openSetupNoFollow(clean, access, share)
	if err != nil {
		return nil, fmt.Errorf("pin %s: %w", clean, err)
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		_ = windows.CloseHandle(handle)
		return nil, fmt.Errorf("pin %s: inspect: %w", clean, err)
	}
	if err := setupStructureFromInfo(clean, &info, kind); err != nil {
		_ = windows.CloseHandle(handle)
		return nil, err
	}
	return &SetupPin{handle: handle, path: clean, kind: kind, id: setupFileIDFromInfo(&info)}, nil
}

func setupStructureFromInfo(path string, info *windows.ByHandleFileInformation, kind SetupPathKind) error {
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("%s: reparse points are not allowed for staged objects", path)
	}
	isDir := info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	if kind == SetupPathDirectory && !isDir {
		return fmt.Errorf("%s: expected a directory", path)
	}
	if kind != SetupPathDirectory {
		if isDir {
			return fmt.Errorf("%s: expected a regular file", path)
		}
		if kind == SetupPathFile && info.NumberOfLinks != 1 {
			return fmt.Errorf("%s: file has %d hard links, expected exactly 1", path, info.NumberOfLinks)
		}
	}
	return nil
}

// Path is the pinned object's absolute path.
func (pin *SetupPin) Path() string { return pin.path }

// ID is the pinned object's file ID.
func (pin *SetupPin) ID() SetupFileID { return pin.id }

// Read reads the pinned file from its current position.
func (pin *SetupPin) Read(buffer []byte) (int, error) {
	if pin == nil || pin.handle == windows.InvalidHandle {
		return 0, os.ErrClosed
	}
	if len(buffer) == 0 {
		return 0, nil
	}
	var read uint32
	if err := windows.ReadFile(pin.handle, buffer, &read, nil); err != nil {
		if errors.Is(err, windows.ERROR_HANDLE_EOF) || errors.Is(err, windows.ERROR_BROKEN_PIPE) {
			return 0, io.EOF
		}
		return int(read), err
	}
	if read == 0 {
		return 0, io.EOF
	}
	return int(read), nil
}

// Rewind moves the pinned file back to its first byte.
func (pin *SetupPin) Rewind() error {
	if pin == nil || pin.handle == windows.InvalidHandle {
		return os.ErrClosed
	}
	_, err := windows.Seek(pin.handle, 0, 0)
	return err
}

// Matches reports whether path, opened without following a reparse point,
// is still the pinned object.
func (pin *SetupPin) Matches(path string) (bool, error) {
	id, err := SetupFileIDOf(path)
	if err != nil {
		return false, err
	}
	return id == pin.id, nil
}

// Close releases the pin. It is safe to call more than once.
func (pin *SetupPin) Close() error {
	if pin == nil || pin.handle == windows.InvalidHandle {
		return nil
	}
	err := windows.CloseHandle(pin.handle)
	pin.handle = windows.InvalidHandle
	return err
}

// CreateSetupDirectory creates path as a new directory owned by
// Administrators with a protected SYSTEM-and-Administrators DACL, so its owner
// never depends on which administrator account ran Setup.
func CreateSetupDirectory(path string) error {
	pointer, err := winpath.UTF16Ptr(path)
	if err != nil {
		return err
	}
	attributes, err := setupSecurityAttributes(setupDirectorySDDL)
	if err != nil {
		return err
	}
	err = windows.CreateDirectory(pointer, attributes)
	if !errors.Is(err, windows.ERROR_INVALID_OWNER) {
		return err
	}
	// The token cannot assign Administrators as owner directly: create with
	// the default owner, then set it, as the canonical repair does.
	attributes, err = setupSecurityAttributes(strings.TrimPrefix(setupDirectorySDDL, "O:BA"))
	if err != nil {
		return err
	}
	if err := windows.CreateDirectory(pointer, attributes); err != nil {
		return err
	}
	return setSetupAdministratorsOwner(path)
}

// CreateSetupFile creates path as a new file owned by Administrators with a
// protected SYSTEM-and-Administrators DACL, open for reading and writing. It
// fails if anything already exists at path.
func CreateSetupFile(path string) (*os.File, error) {
	pointer, err := winpath.UTF16Ptr(path)
	if err != nil {
		return nil, err
	}
	create := func(sddl string) (windows.Handle, error) {
		attributes, err := setupSecurityAttributes(sddl)
		if err != nil {
			return windows.InvalidHandle, err
		}
		// WRITE_OWNER and READ_CONTROL let the ERROR_INVALID_OWNER fallback
		// re-own the new file on this handle; GENERIC_WRITE grants neither.
		return windows.CreateFile(
			pointer,
			windows.GENERIC_READ|windows.GENERIC_WRITE|windows.WRITE_OWNER|windows.READ_CONTROL,
			windows.FILE_SHARE_READ,
			attributes,
			windows.CREATE_NEW,
			windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
			0,
		)
	}
	handle, err := create(setupFileSDDL)
	if errors.Is(err, windows.ERROR_INVALID_OWNER) {
		handle, err = create(strings.TrimPrefix(setupFileSDDL, "O:BA"))
		if err == nil {
			if ownerErr := setSetupAdministratorsOwnerByHandle(handle); ownerErr != nil {
				_ = windows.CloseHandle(handle)
				return nil, errors.Join(fmt.Errorf("set Administrators owner on %s: %w", path, ownerErr), removeSetupPathBestEffort(path))
			}
		}
	}
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(handle), path), nil
}

func setupSecurityAttributes(sddl string) (*windows.SecurityAttributes, error) {
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, fmt.Errorf("build staging descriptor: %w", err)
	}
	return &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}, nil
}

func setSetupAdministratorsOwner(path string) error {
	handle, err := openSetupNoFollow(path, windows.WRITE_OWNER|windows.READ_CONTROL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE)
	if err != nil {
		return err
	}
	defer func() { _ = windows.CloseHandle(handle) }()
	return setSetupAdministratorsOwnerByHandle(handle)
}

func setSetupAdministratorsOwnerByHandle(handle windows.Handle) error {
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	return windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION,
		administrators, nil, nil, nil)
}

func removeSetupPathBestEffort(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// RemoveSetupTree removes path and everything below it without following any
// reparse point: a symbolic link or junction inside the tree is removed
// itself, never its target. A reparse point at path itself is refused. Each
// directory is held open without delete sharing while its entries are
// removed, so it cannot be renamed or swapped mid-walk. Sharing violations
// are retried within a bounded budget. A missing path is not an error.
func RemoveSetupTree(path string) error {
	clean, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", path, err)
	}
	handle, info, err := openSetupForDelete(clean)
	if setupNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open %s for removal: %w", clean, err)
	}
	defer func() { _ = windows.CloseHandle(handle) }()
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("%s: refusing to remove a reparse point root", clean)
	}
	return removeSetupObject(handle, clean, &info, 0)
}

// RemoveSetupTreeIfSame is RemoveSetupTree that first proves path is still
// the object with id, so a cleanup never removes a directory that replaced
// the one it staged.
func RemoveSetupTreeIfSame(path string, id SetupFileID) error {
	clean, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", path, err)
	}
	handle, info, err := openSetupForDelete(clean)
	if setupNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open %s for removal: %w", clean, err)
	}
	defer func() { _ = windows.CloseHandle(handle) }()
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("%s: refusing to remove a reparse point root", clean)
	}
	if setupFileIDFromInfo(&info) != id {
		return fmt.Errorf("%s: refusing to remove an object that replaced the staged one", clean)
	}
	return removeSetupObject(handle, clean, &info, 0)
}

func setupNotFound(err error) bool {
	return errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND)
}

func openSetupForDelete(path string) (windows.Handle, windows.ByHandleFileInformation, error) {
	var info windows.ByHandleFileInformation
	access := uint32(windows.DELETE | windows.FILE_LIST_DIRECTORY | windows.FILE_READ_ATTRIBUTES |
		windows.FILE_WRITE_ATTRIBUTES | windows.SYNCHRONIZE)
	handle, err := openSetupNoFollow(path, access, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE)
	if err != nil {
		return windows.InvalidHandle, info, err
	}
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		_ = windows.CloseHandle(handle)
		return windows.InvalidHandle, info, err
	}
	return handle, info, nil
}

func removeSetupObject(handle windows.Handle, path string, info *windows.ByHandleFileInformation, depth int) error {
	if depth > setupRemoveDepth {
		return fmt.Errorf("%s: staging tree is deeper than %d levels", path, setupRemoveDepth)
	}
	isDir := info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	isReparse := info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0
	if isDir && !isReparse {
		// List through the handle already held for delete: a second open
		// such as os.ReadDir does not share delete access and fails with a
		// sharing violation, and the handle is the directory just verified.
		names, err := listSetupDirectoryByHandle(handle)
		if err != nil {
			return fmt.Errorf("list %s: %w", path, err)
		}
		var failures []error
		for _, name := range names {
			if err := removeSetupChild(filepath.Join(path, name), depth+1); err != nil {
				failures = append(failures, err)
			}
		}
		if len(failures) != 0 {
			return errors.Join(failures...)
		}
	}
	if err := setSetupDeleteDisposition(handle, info.FileAttributes); err != nil {
		return fmt.Errorf("remove %s: %w", path, err)
	}
	return nil
}

// listSetupDirectoryByHandle returns the entry names of the directory open
// as handle (which needs FILE_LIST_DIRECTORY), without "." and "..". It reads
// FILE_FULL_DIR_INFO records: NextEntryOffset at 0, FileNameLength at 60 and
// the UTF-16 name at 68.
func listSetupDirectoryByHandle(handle windows.Handle) ([]string, error) {
	const (
		fileFullDirectoryInfo        = 14
		fileFullDirectoryRestartInfo = 15
		nameLengthOffset             = 60
		nameOffset                   = 68
	)
	// The records hold 8-byte fields, so back the buffer with uint64s.
	words := make([]uint64, 8<<10)
	buffer := unsafe.Slice((*byte)(unsafe.Pointer(&words[0])), len(words)*8)
	class := uint32(fileFullDirectoryRestartInfo)
	var names []string
	for {
		err := windows.GetFileInformationByHandleEx(handle, class, &buffer[0], uint32(len(buffer)))
		if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
			return names, nil
		}
		if err != nil {
			return nil, err
		}
		class = fileFullDirectoryInfo
		for offset := 0; ; {
			if offset < 0 || offset+nameOffset > len(buffer) {
				return nil, errors.New("directory listing record overruns its buffer")
			}
			record := buffer[offset:]
			next := int(binary.LittleEndian.Uint32(record[0:4]))
			nameLength := int(binary.LittleEndian.Uint32(record[nameLengthOffset : nameLengthOffset+4]))
			if nameLength%2 != 0 || nameOffset+nameLength > len(record) {
				return nil, errors.New("directory listing record has an invalid name length")
			}
			name := make([]uint16, nameLength/2)
			for index := range name {
				name[index] = binary.LittleEndian.Uint16(record[nameOffset+2*index:])
			}
			if entry := string(utf16.Decode(name)); entry != "." && entry != ".." {
				names = append(names, entry)
			}
			if next == 0 {
				break
			}
			offset += next
		}
	}
}

func removeSetupChild(path string, depth int) error {
	handle, info, err := openSetupForDelete(path)
	if setupNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open %s for removal: %w", path, err)
	}
	defer func() { _ = windows.CloseHandle(handle) }()
	return removeSetupObject(handle, path, &info, depth)
}

type setupDispositionInfoEx struct {
	Flags uint32
}

type setupDispositionInfo struct {
	DeleteFile byte
}

type setupBasicInfo struct {
	CreationTime   int64
	LastAccessTime int64
	LastWriteTime  int64
	ChangeTime     int64
	FileAttributes uint32
	_              uint32
}

// setSetupDeleteDisposition marks the open object for deletion. POSIX
// semantics take the name out of the directory at once even if another
// process still has the object open, so the parent can be removed right
// after; older systems fall back to the classic disposition.
func setSetupDeleteDisposition(handle windows.Handle, attributes uint32) error {
	delay := canonicalOpenBackoff
	var lastErr error
	for attempt := 0; attempt < canonicalOpenAttempts; attempt++ {
		ex := setupDispositionInfoEx{Flags: windows.FILE_DISPOSITION_DELETE |
			windows.FILE_DISPOSITION_POSIX_SEMANTICS |
			windows.FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE}
		err := windows.SetFileInformationByHandle(handle, windows.FileDispositionInfoEx,
			(*byte)(unsafe.Pointer(&ex)), uint32(unsafe.Sizeof(ex)))
		if err != nil && (errors.Is(err, windows.ERROR_INVALID_PARAMETER) ||
			errors.Is(err, windows.ERROR_NOT_SUPPORTED) || errors.Is(err, windows.ERROR_INVALID_FUNCTION)) {
			if attributes&windows.FILE_ATTRIBUTE_READONLY != 0 {
				cleared := attributes &^ windows.FILE_ATTRIBUTE_READONLY
				if cleared == 0 {
					cleared = windows.FILE_ATTRIBUTE_NORMAL
				}
				basic := setupBasicInfo{FileAttributes: cleared}
				_ = windows.SetFileInformationByHandle(handle, windows.FileBasicInfo,
					(*byte)(unsafe.Pointer(&basic)), uint32(unsafe.Sizeof(basic)))
			}
			classic := setupDispositionInfo{DeleteFile: 1}
			err = windows.SetFileInformationByHandle(handle, windows.FileDispositionInfo,
				(*byte)(unsafe.Pointer(&classic)), uint32(unsafe.Sizeof(classic)))
		}
		if err == nil {
			return nil
		}
		lastErr = err
		if !IsTransientWindowsError(err) && !errors.Is(err, windows.ERROR_DIR_NOT_EMPTY) {
			return err
		}
		time.Sleep(delay)
		delay *= 2
	}
	return lastErr
}

// ScheduleSetupTreeRemovalAtReboot asks Windows to delete path and everything
// below it at the next restart, children first. Reparse points are scheduled
// themselves and never descended into. It is the last resort after
// RemoveSetupTree failed, for example because an endpoint product still holds
// a staged file open.
func ScheduleSetupTreeRemovalAtReboot(path string) error {
	clean, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", path, err)
	}
	var ordered []string
	if err := collectSetupTreePostOrder(clean, 0, &ordered); err != nil {
		return err
	}
	var failures []error
	for _, entry := range ordered {
		pointer, err := winpath.UTF16Ptr(entry)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		if err := windows.MoveFileEx(pointer, nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT); err != nil {
			failures = append(failures, fmt.Errorf("schedule %s for removal at restart: %w", entry, err))
		}
	}
	return errors.Join(failures...)
}

func collectSetupTreePostOrder(path string, depth int, ordered *[]string) error {
	if depth > setupRemoveDepth {
		return fmt.Errorf("%s: staging tree is deeper than %d levels", path, setupRemoveDepth)
	}
	pointer, err := winpath.UTF16Ptr(path)
	if err != nil {
		return err
	}
	attributes, err := windows.GetFileAttributes(pointer)
	if setupNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect %s: %w", path, err)
	}
	if attributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 && attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT == 0 {
		entries, err := os.ReadDir(path)
		if err != nil {
			return fmt.Errorf("list %s: %w", path, err)
		}
		for _, entry := range entries {
			if err := collectSetupTreePostOrder(filepath.Join(path, entry.Name()), depth+1, ordered); err != nil {
				return err
			}
		}
	}
	*ordered = append(*ordered, path)
	return nil
}

// SetupStagingRoots returns the parents a lifecycle run may stage under:
// ProgramData itself and, when it already exists as a plain directory,
// ProgramData\Cisco. The second is never created here; it is the fallback
// when Controlled Folder Access or an endpoint product refuses a new
// directory directly under ProgramData.
func SetupStagingRoots(programData string) []string {
	roots := []string{filepath.Clean(programData)}
	if fallback, ok := SetupStagingFallbackRoot(programData); ok {
		roots = append(roots, fallback)
	}
	return roots
}

// SetupStagingFallbackRoot returns ProgramData\Cisco when it exists as a
// plain directory (no reparse point).
func SetupStagingFallbackRoot(programData string) (string, bool) {
	fallback := filepath.Join(filepath.Clean(programData), "Cisco")
	info, err := os.Lstat(fallback)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", false
	}
	pointer, err := winpath.UTF16Ptr(fallback)
	if err != nil {
		return "", false
	}
	attributes, err := windows.GetFileAttributes(pointer)
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return "", false
	}
	return fallback, true
}

// IsSetupStagingChild reports whether path is a direct child of one of roots
// whose name carries one of prefixes and a 128-bit capability. Cleanup and
// the leftover sweep never touch anything else.
func IsSetupStagingChild(path string, roots, prefixes []string) bool {
	clean := filepath.Clean(path)
	parent := filepath.Dir(clean)
	for _, root := range roots {
		if strings.EqualFold(parent, filepath.Clean(root)) {
			return IsSetupLeftoverName(filepath.Base(clean), prefixes)
		}
	}
	return false
}

// SweepSetupLeftovers removes leftover staging directories directly under
// each root: only names IsSetupLeftoverName accepts, only real directories,
// only those older than SetupLeftoverMaxAge. A reparse point is refused and
// logged; every removal is logged with MarkerRecover. Nothing here fails the
// caller: a leftover that cannot be removed is logged and left for the next
// run.
func SweepSetupLeftovers(roots, prefixes []string, now time.Time) {
	for _, root := range roots {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !IsSetupLeftoverName(entry.Name(), prefixes) {
				continue
			}
			sweepSetupLeftover(filepath.Join(root, entry.Name()), now)
		}
	}
}

func sweepSetupLeftover(path string, now time.Time) {
	handle, err := openSetupNoFollow(path, windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE)
	if err != nil {
		return
	}
	var info windows.ByHandleFileInformation
	infoErr := windows.GetFileInformationByHandle(handle, &info)
	_ = windows.CloseHandle(handle)
	if infoErr != nil {
		return
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		emitSetupOnce(path, MarkerSkip, map[string]string{
			"path":   path,
			"reason": "leftover staging name is a reparse point; not removed",
		})
		return
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return
	}
	created := time.Unix(0, info.CreationTime.Nanoseconds())
	modified := time.Unix(0, info.LastWriteTime.Nanoseconds())
	if !SetupLeftoverExpired(created, modified, now) {
		return
	}
	if err := RemoveSetupTreeIfSame(path, setupFileIDFromInfo(&info)); err != nil {
		emitSetupOnce(path, MarkerRecover, map[string]string{
			"path":   path,
			"reason": "leftover staging directory could not be removed; retrying on the next run: " + err.Error(),
		})
		return
	}
	emitSetupOnce(path, MarkerRecover, map[string]string{
		"path":   path,
		"reason": fmt.Sprintf("removed leftover staging directory older than %s", SetupLeftoverMaxAge),
	})
}

func emitSetupOnce(path, marker string, fields map[string]string) {
	if !advisoryLogDedupe.shouldEmit(path, marker, FormatResilienceEvent(marker, fields)) {
		return
	}
	EmitResilienceEvent(marker, fields)
}
