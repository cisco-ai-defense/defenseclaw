// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

type atomicTransformFileRenameInfo struct {
	ReplaceIfExists uint32
	RootDirectory   windows.Handle
	FileNameLength  uint32
	FileName        [1]uint16
}

// conditionalCommitAtomicTransformExisting binds the comparison and detach to
// one Windows file object. The durable intent is published first. A handle
// sharing only reads then excludes both in-place writes and path replacement
// until that exact object has been renamed to its recovery tombstone.
func conditionalCommitAtomicTransformExisting(
	path string,
	stateDir string,
	snapshot atomicFileSnapshot,
	stagedPath string,
	expectedStagedState atomicTransformArtifactState,
	remove bool,
) error {
	intent, intentPath, err := prepareAtomicTransformIntent(path, stateDir, snapshot, stagedPath, expectedStagedState, remove)
	if err != nil {
		if stagedPath != "" {
			_ = os.Remove(stagedPath)
		}
		return err
	}
	intentState, err := persistAtomicTransformIntent(intentPath, intent)
	if err != nil {
		if stagedPath != "" {
			_ = os.Remove(stagedPath)
		}
		return err
	}
	tombstone, staged := atomicTransformIntentArtifacts(intent)
	phaseState := atomicTransformPhaseState{
		IntentPath: intentPath,
		TargetPath: intent.TargetPath,
		Tombstone:  tombstone,
		Staged:     staged,
	}
	if err := runAtomicTransformPhaseHook(path, atomicTransformPhaseIntentPersisted, phaseState); err != nil {
		return err
	}

	file, info, err := openLockedAtomicTransformWindowsFile(intent.TargetPath)
	if err != nil {
		if atomicTransformWindowsConflict(err) {
			return recoverAfterAtomicTransformError(path, stateDir, errAtomicTransformConflict)
		}
		return recoverAfterAtomicTransformError(path, stateDir, err)
	}
	closed := false
	closeFile := func() error {
		if closed {
			return nil
		}
		closed = true
		return file.Close()
	}
	defer closeFile()

	identity, identityErr := atomicTransformOpenFileIdentity(file)
	if identityErr != nil {
		_ = closeFile()
		return recoverAfterAtomicTransformError(path, stateDir, identityErr)
	}
	if !os.SameFile(snapshot.info, info) || identity != snapshot.identity {
		_ = closeFile()
		return recoverAfterAtomicTransformError(path, stateDir, errAtomicTransformConflict)
	}
	if info.Mode() != snapshot.info.Mode() {
		_ = closeFile()
		return recoverAfterAtomicTransformError(path, stateDir, errAtomicTransformConflict)
	}
	data, err := readAtomicTransformBytes(file, intent.TargetPath, atomicTransformMaxConfigBytes)
	if err != nil {
		_ = closeFile()
		return recoverAfterAtomicTransformError(path, stateDir, err)
	}
	if !bytes.Equal(snapshot.data, data) {
		_ = closeFile()
		return recoverAfterAtomicTransformError(path, stateDir, errAtomicTransformConflict)
	}
	protectionDigest, err := atomicTransformProtectionDigest(file)
	if err != nil {
		_ = closeFile()
		return recoverAfterAtomicTransformError(path, stateDir, err)
	}
	if protectionDigest != snapshot.protectionDigest ||
		protectionDigest != intent.OldProtectionSHA256 || info.Mode() != os.FileMode(intent.OldMode) {
		_ = closeFile()
		return recoverAfterAtomicTransformError(path, stateDir, errAtomicTransformConflict)
	}
	pathInfo, err := os.Lstat(intent.TargetPath)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, pathInfo) {
		_ = closeFile()
		return recoverAfterAtomicTransformError(path, stateDir, errAtomicTransformConflict)
	}
	resolved, err := resolveAtomicWritePath(path)
	if err == nil {
		resolved, err = canonicalAtomicTransformTargetPath(resolved)
	}
	if err != nil || !atomicTransformPathsEqual(resolved, intent.TargetPath) {
		_ = closeFile()
		return recoverAfterAtomicTransformError(path, stateDir, errAtomicTransformConflict)
	}

	if err := renameAtomicTransformHandle(windows.Handle(file.Fd()), tombstone); err != nil {
		_ = closeFile()
		if atomicTransformWindowsConflict(err) {
			return recoverAfterAtomicTransformError(path, stateDir, errAtomicTransformConflict)
		}
		return recoverAfterAtomicTransformError(path, stateDir, fmt.Errorf("move compared config to tombstone: %w", err))
	}
	if err := syncAtomicTransformParent(filepath.Dir(intent.TargetPath)); err != nil {
		_ = closeFile()
		return recoverAfterAtomicTransformError(path, stateDir, err)
	}
	resolved, resolveErr := resolveAtomicWritePath(path)
	if resolveErr == nil {
		resolved, resolveErr = canonicalAtomicTransformTargetPath(resolved)
	}
	if resolveErr != nil || !atomicTransformPathsEqual(resolved, intent.TargetPath) {
		_ = closeFile()
		return recoverAfterAtomicTransformError(path, stateDir, errAtomicTransformConflict)
	}
	if err := runAtomicTransformPhaseHook(path, atomicTransformPhaseDetached, phaseState); err != nil {
		return err
	}

	if !remove {
		stagedState, inspectErr := inspectAtomicTransformArtifact(staged)
		if inspectErr != nil || !atomicTransformStateMatchesNew(stagedState, intent) {
			_ = closeFile()
			if inspectErr == nil {
				inspectErr = fmt.Errorf("staged config changed before publication")
			}
			return recoverAfterAtomicTransformError(path, stateDir, inspectErr)
		}
		if err := publishAtomicTransformArtifact(staged, intent.TargetPath, stagedState); err != nil {
			_ = closeFile()
			if errors.Is(err, errAtomicTransformConflict) {
				return recoverAfterAtomicTransformError(path, stateDir, errAtomicTransformConflict)
			}
			return recoverAfterAtomicTransformError(path, stateDir, fmt.Errorf("publish staged config: %w", err))
		}
		if err := syncAtomicTransformParent(filepath.Dir(intent.TargetPath)); err != nil {
			_ = closeFile()
			return recoverAfterAtomicTransformError(path, stateDir, err)
		}
	}
	if err := runAtomicTransformPhaseHook(path, atomicTransformPhasePublished, phaseState); err != nil {
		return err
	}
	oldStillMatches, err := atomicTransformWindowsOpenFileMatchesOld(file, intent)
	if err != nil {
		_ = closeFile()
		return recoverAfterAtomicTransformError(path, stateDir, err)
	}
	if !oldStillMatches {
		_ = closeFile()
		return recoverAfterAtomicTransformError(path, stateDir, errAtomicTransformConflict)
	}
	if err := deleteAtomicTransformHandle(windows.Handle(file.Fd())); err != nil {
		return fmt.Errorf("retain recovery intent after exact tombstone delete failed: %w", err)
	}
	if err := closeFile(); err != nil {
		return fmt.Errorf("close deleted compare-and-swap tombstone: %w", err)
	}
	return finishAtomicTransformIntent(intent, intentPath, intentState)
}

func atomicTransformWindowsOpenFileMatchesOld(file *os.File, intent atomicTransformIntent) (bool, error) {
	if _, err := file.Seek(0, 0); err != nil {
		return false, err
	}
	info, err := file.Stat()
	if err != nil {
		return false, err
	}
	data, err := readAtomicTransformBytes(file, intent.TargetPath, atomicTransformMaxConfigBytes)
	if err != nil {
		return false, err
	}
	protectionDigest, err := atomicTransformProtectionDigest(file)
	if err != nil {
		return false, err
	}
	return atomicTransformDigest(data) == intent.OldSHA256 &&
		int64(len(data)) == intent.OldSize &&
		info.Mode() == os.FileMode(intent.OldMode) &&
		protectionDigest == intent.OldProtectionSHA256, nil
}

func openLockedAtomicTransformWindowsFile(path string) (*os.File, os.FileInfo, error) {
	pathPtr, err := winpath.UTF16Ptr(path)
	if err != nil {
		return nil, nil, err
	}
	handle, err := windows.CreateFile(
		pathPtr,
		windows.GENERIC_READ|windows.DELETE,
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, nil, err
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, nil, fmt.Errorf("wrap compare-and-swap file handle: %s", path)
	}
	var handleInfo windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &handleInfo); err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	if handleInfo.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		_ = file.Close()
		return nil, nil, fmt.Errorf("compare-and-swap path is a reparse point or directory: %s", path)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, nil, fmt.Errorf("compare-and-swap path is not a regular file: %s", path)
	}
	return file, info, nil
}

func openAtomicTransformRegularFile(path string) (*os.File, os.FileInfo, error) {
	pathPtr, err := winpath.UTF16Ptr(path)
	if err != nil {
		return nil, nil, err
	}
	handle, err := windows.CreateFile(
		pathPtr,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, nil, err
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, nil, fmt.Errorf("wrap compare-and-swap artifact handle: %s", path)
	}
	var handleInfo windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &handleInfo); err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	if handleInfo.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		_ = file.Close()
		return nil, nil, fmt.Errorf("compare-and-swap artifact is a reparse point or directory: %s", path)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, nil, fmt.Errorf("compare-and-swap artifact is not a regular file: %s", path)
	}
	return file, info, nil
}

func publishAtomicTransformArtifact(source, target string, expected atomicTransformArtifactState) error {
	file, info, err := openLockedAtomicTransformWindowsFile(source)
	if err != nil {
		return err
	}
	if !os.SameFile(expected.info, info) {
		_ = file.Close()
		return fmt.Errorf("staged compare-and-swap artifact changed identity before publication: %s", source)
	}
	data, err := readAtomicTransformBytes(file, source, atomicTransformMaxConfigBytes)
	if err != nil {
		_ = file.Close()
		return err
	}
	protectionDigest, err := atomicTransformProtectionDigest(file)
	if err != nil {
		_ = file.Close()
		return err
	}
	if atomicTransformDigest(data) != expected.digest || int64(len(data)) != expected.size ||
		info.Mode() != expected.info.Mode() ||
		protectionDigest != expected.protectionDigest {
		_ = file.Close()
		return fmt.Errorf("staged compare-and-swap artifact changed before publication: %s", source)
	}
	if err := file.Close(); err != nil {
		return err
	}
	// The stage name is a private random DefenseClaw artifact. MoveFileEx with
	// MOVEFILE_WRITE_THROUGH is the documented durable publication boundary;
	// no replace preserves a concurrently created live target.
	if err := installAtomicTransformFile(source, target); err != nil {
		return err
	}
	published, err := inspectAtomicTransformArtifact(target)
	if err != nil {
		return err
	}
	if !published.exists || !os.SameFile(published.info, expected.info) ||
		published.digest != expected.digest || published.size != expected.size ||
		published.info.Mode() != expected.info.Mode() ||
		published.protectionDigest != expected.protectionDigest {
		return fmt.Errorf("durably published config changed identity or metadata: %s", target)
	}
	return nil
}

func restoreAtomicTransformArtifact(source, target string, expected atomicTransformArtifactState) error {
	file, info, err := openLockedAtomicTransformWindowsFile(source)
	if err != nil {
		return err
	}
	if !os.SameFile(expected.info, info) {
		_ = file.Close()
		return fmt.Errorf("recovery tombstone changed identity before restore: %s", source)
	}
	data, err := readAtomicTransformBytes(file, source, atomicTransformMaxConfigBytes)
	if err != nil {
		_ = file.Close()
		return err
	}
	protectionDigest, err := atomicTransformProtectionDigest(file)
	if err != nil {
		_ = file.Close()
		return err
	}
	if atomicTransformDigest(data) != expected.digest || int64(len(data)) != expected.size ||
		info.Mode() != expected.info.Mode() ||
		protectionDigest != expected.protectionDigest {
		_ = file.Close()
		return fmt.Errorf("recovery tombstone changed before restore: %s", source)
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := installAtomicTransformFile(source, target); err != nil {
		return err
	}
	restored, err := inspectAtomicTransformArtifact(target)
	if err != nil {
		return err
	}
	if !restored.exists || !os.SameFile(restored.info, expected.info) ||
		restored.digest != expected.digest || restored.size != expected.size ||
		restored.info.Mode() != expected.info.Mode() ||
		restored.protectionDigest != expected.protectionDigest {
		return fmt.Errorf("durably restored config changed identity or metadata: %s", target)
	}
	return nil
}

func atomicTransformProtectionDigest(file *os.File) (string, error) {
	descriptor, err := windows.GetSecurityInfo(
		windows.Handle(file.Fd()),
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return "", err
	}
	// Hash the canonical SDDL representation. Hashing the raw self-relative
	// descriptor also includes alignment bytes that Windows does not promise to
	// initialize deterministically, which made unchanged hard links appear to
	// have different protection metadata during recovery.
	sddl := descriptor.String()
	if sddl == "" {
		return "", fmt.Errorf("convert Windows security descriptor to SDDL")
	}
	return atomicTransformDigest([]byte(sddl)), nil
}

func syncAtomicTransformPlatformParent(string) error {
	// Namespace durability on Windows is supplied by the documented
	// MOVEFILE_WRITE_THROUGH publication/receipt transitions. Windows does not
	// document FlushFileBuffers for directory handles.
	return nil
}

func deleteAtomicTransformArtifact(path string, expected atomicTransformArtifactState) error {
	file, info, err := openLockedAtomicTransformWindowsFile(path)
	if err != nil {
		return err
	}
	closed := false
	defer func() {
		if !closed {
			_ = file.Close()
		}
	}()
	if !os.SameFile(expected.info, info) {
		return fmt.Errorf("artifact changed identity before exact deletion")
	}
	data, err := readAtomicTransformBytes(file, path, atomicTransformMaxConfigBytes)
	if err != nil {
		return err
	}
	protectionDigest, err := atomicTransformProtectionDigest(file)
	if err != nil {
		return err
	}
	if atomicTransformDigest(data) != expected.digest || int64(len(data)) != expected.size ||
		info.Mode() != expected.info.Mode() ||
		protectionDigest != expected.protectionDigest {
		return fmt.Errorf("artifact changed before exact deletion")
	}
	if err := deleteAtomicTransformHandle(windows.Handle(file.Fd())); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	closed = true
	return nil
}

func renameAtomicTransformHandle(handle windows.Handle, target string) error {
	dirPtr, err := winpath.UTF16Ptr(filepath.Dir(target))
	if err != nil {
		return err
	}
	dirHandle, err := windows.CreateFile(
		dirPtr,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(dirHandle)
	name, err := windows.UTF16FromString(filepath.Base(target))
	if err != nil {
		return err
	}
	name = name[:len(name)-1]
	var layout atomicTransformFileRenameInfo
	bufferSize := int(unsafe.Offsetof(layout.FileName)) + len(name)*2
	buffer := make([]byte, bufferSize)
	info := (*atomicTransformFileRenameInfo)(unsafe.Pointer(&buffer[0]))
	info.RootDirectory = dirHandle
	info.FileNameLength = uint32(len(name) * 2)
	copy(unsafe.Slice(&info.FileName[0], len(name)), name)
	var status windows.IO_STATUS_BLOCK
	return windows.NtSetInformationFile(
		handle,
		&status,
		&buffer[0],
		uint32(len(buffer)),
		windows.FileRenameInformation,
	)
}

func deleteAtomicTransformHandle(handle windows.Handle) error {
	flags := uint32(
		windows.FILE_DISPOSITION_DELETE |
			windows.FILE_DISPOSITION_POSIX_SEMANTICS |
			windows.FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE,
	)
	err := windows.SetFileInformationByHandle(
		handle,
		windows.FileDispositionInfoEx,
		(*byte)(unsafe.Pointer(&flags)),
		uint32(unsafe.Sizeof(flags)),
	)
	if err == nil || (!errors.Is(err, windows.ERROR_INVALID_PARAMETER) &&
		!errors.Is(err, windows.ERROR_NOT_SUPPORTED)) {
		return err
	}
	deleteFile := uint32(1)
	return windows.SetFileInformationByHandle(
		handle,
		windows.FileDispositionInfo,
		(*byte)(unsafe.Pointer(&deleteFile)),
		uint32(unsafe.Sizeof(deleteFile)),
	)
}

func atomicTransformWindowsConflict(err error) bool {
	return errors.Is(err, windows.ERROR_FILE_NOT_FOUND) ||
		errors.Is(err, windows.ERROR_PATH_NOT_FOUND) ||
		errors.Is(err, windows.ERROR_ALREADY_EXISTS) ||
		errors.Is(err, windows.ERROR_FILE_EXISTS) ||
		errors.Is(err, windows.ERROR_SHARING_VIOLATION) ||
		errors.Is(err, windows.ERROR_LOCK_VIOLATION) ||
		errors.Is(err, windows.STATUS_OBJECT_NAME_EXISTS) ||
		errors.Is(err, windows.STATUS_OBJECT_NAME_COLLISION) ||
		errors.Is(err, windows.STATUS_SHARING_VIOLATION)
}
