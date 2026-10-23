// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

// windowsCursorManagedFileLockTimeout bounds how long a swap waits for
// another process to close a Cursor artifact it has open for writing.
const windowsCursorManagedFileLockTimeout = 2 * time.Second

// windowsCursorManagedSwap is one compare-and-swap write of a Cursor
// enterprise artifact.
type windowsCursorManagedSwap struct {
	path  string
	data  []byte
	limit int
	// metadata, when set, is the security descriptor and attributes the
	// file ends with.
	metadata *windowsCursorManagedFileMetadata
	// keepReplacedMetadata keeps the replaced file's metadata. Otherwise, and
	// for a new file, the file gets DefenseClaw's protection, as
	// windowsManagedPolicyWriter writes it.
	keepReplacedMetadata bool
}

type windowsCursorManagedSwapResult struct {
	// swapped reports that data was published at path.
	swapped bool
	// replaced is the file the swap replaced, absent when there was none.
	replaced         windowsManagedFileSnapshot
	replacedMetadata windowsCursorManagedFileMetadata
}

// windowsCursorManagedFileSwap is swapWindowsCursorManagedFile; tests replace
// it to fail or interleave a write.
var windowsCursorManagedFileSwap = swapWindowsCursorManagedFile

// swapWindowsCursorManagedFile publishes data at path and returns the exact
// file it replaced. The administrator and Cursor do not take the DefenseClaw
// lock, so a read before a write cannot see a save made in between. Instead
// the swap opens the current file with a handle that shares only reads, so no
// other process can write, rename or delete it, reads it through that handle,
// renames it aside through the same handle and moves the new file in under
// its name. A file another process creates in the instant the name is free is
// newer: the swap keeps it, drops the older file it holds, and reports a race.
func swapWindowsCursorManagedFile(request windowsCursorManagedSwap) (windowsCursorManagedSwapResult, error) {
	path := request.path
	result := windowsCursorManagedSwapResult{replaced: windowsManagedFileSnapshot{path: path}}
	if err := rejectWindowsReparseChain(path); err != nil {
		return result, err
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return result, fmt.Errorf("enterprise hooks: refusing non-regular managed policy file: %s", path)
		}
		if err := windowsManagedPolicyFileTrustCheck(path); err != nil {
			return result, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return result, err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".defenseclaw-policy-*.tmp")
	if err != nil {
		return result, err
	}
	tempPath := temp.Name()
	defer func() { _ = os.Remove(tempPath) }()
	_, err = temp.Write(request.data)
	if err == nil {
		err = temp.Sync()
	}
	if closeErr := temp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return result, err
	}
	userReadable := !strings.EqualFold(filepath.Base(path), windowsCursorManagedReceiptFile)
	if err := setWindowsManagedPolicyProtection(tempPath, false, userReadable); err != nil {
		return result, err
	}

	current, err := lockWindowsCursorManagedFile(path)
	if err != nil {
		return result, err
	}
	if current == nil {
		if err := moveWindowsCursorManagedFile(tempPath, path); err != nil {
			if windowsCursorManagedNameTaken(err) {
				return result, windowsCursorManagedGuardRebuildRaced(path)
			}
			return result, fmt.Errorf("enterprise hooks: publish managed policy %s: %w", path, err)
		}
	} else {
		defer current.Close()
		data, metadata, err := readWindowsCursorManagedLockedFile(current, request.limit)
		if err != nil {
			return result, err
		}
		result.replaced.existed, result.replaced.data, result.replacedMetadata = true, data, metadata
		if err := renameWindowsCursorManagedLockedFile(current, tempPath+".replaced"); err != nil {
			return result, fmt.Errorf("enterprise hooks: move aside managed policy %s: %w", path, err)
		}
		if err := moveWindowsCursorManagedFile(tempPath, path); err != nil {
			if windowsCursorManagedNameTaken(err) {
				// Another writer saved a new file under the free name: it is
				// newer than the file this swap holds.
				_ = deleteWindowsCursorManagedLockedFile(current)
				return result, windowsCursorManagedGuardRebuildRaced(path)
			}
			if restoreErr := renameWindowsCursorManagedLockedFile(current, path); restoreErr != nil {
				return result, fmt.Errorf("enterprise hooks: publish managed policy %s: %w (the replaced file is kept at %s.replaced: %v)",
					path, err, tempPath, restoreErr)
			}
			return result, fmt.Errorf("enterprise hooks: publish managed policy %s: %w", path, err)
		}
		if err := deleteWindowsCursorManagedLockedFile(current); err != nil {
			fmt.Fprintf(os.Stderr, "[enterprise-hooks] remove the replaced copy %s.replaced: %v\n", tempPath, err)
		}
	}
	result.swapped = true
	switch {
	case request.metadata != nil:
		err = restoreWindowsCursorManagedFileMetadata(path, *request.metadata)
	case request.keepReplacedMetadata && result.replaced.existed:
		err = restoreWindowsCursorManagedFileMetadata(path, result.replacedMetadata)
	default:
		err = setWindowsManagedPolicyProtection(path, false, userReadable)
		if err == nil {
			err = windowsManagedPolicyFileTrustCheck(path)
		}
	}
	return result, err
}

// removeWindowsCursorManagedFileIfUnchanged deletes path only while it holds
// data: it reads and deletes the file through one handle that no other
// process can write through. A different file is kept and reported as a race.
func removeWindowsCursorManagedFileIfUnchanged(path string, data []byte, limit int) error {
	current, err := lockWindowsCursorManagedFile(path)
	if err != nil || current == nil {
		return err
	}
	defer current.Close()
	onDisk, _, err := readWindowsCursorManagedLockedFile(current, limit)
	if err != nil {
		return err
	}
	if !bytes.Equal(onDisk, data) {
		return windowsCursorManagedGuardRebuildRaced(path)
	}
	if err := deleteWindowsCursorManagedLockedFile(current); err != nil {
		return fmt.Errorf("enterprise hooks: remove %s: %w", path, err)
	}
	return nil
}

// lockWindowsCursorManagedFile opens path for reading, reading its security
// descriptor and deleting, and shares only reads: while the handle is open no
// other process can write, rename, replace or delete the file, and Cursor can
// still read it. It waits a short while for a writer that has the file open.
// It returns nil for a file that does not exist.
func lockWindowsCursorManagedFile(path string) (*os.File, error) {
	name, err := winpath.UTF16Ptr(path)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(windowsCursorManagedFileLockTimeout)
	for {
		handle, err := windows.CreateFile(
			name,
			windows.GENERIC_READ|windows.DELETE|windows.READ_CONTROL,
			windows.FILE_SHARE_READ,
			nil,
			windows.OPEN_EXISTING,
			windows.FILE_FLAG_OPEN_REPARSE_POINT,
			0,
		)
		if err == nil {
			return os.NewFile(uintptr(handle), path), nil
		}
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			return nil, nil
		}
		if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) || !time.Now().Before(deadline) {
			return nil, fmt.Errorf("enterprise hooks: open managed policy %s: %w", path, err)
		}
		time.Sleep(time.Millisecond)
	}
}

func readWindowsCursorManagedLockedFile(
	file *os.File,
	limit int,
) ([]byte, windowsCursorManagedFileMetadata, error) {
	handle := windows.Handle(file.Fd())
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return nil, windowsCursorManagedFileMetadata{}, err
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DEVICE) != 0 {
		return nil, windowsCursorManagedFileMetadata{}, fmt.Errorf(
			"enterprise hooks: refusing unsafe Cursor file attributes for %s", file.Name())
	}
	descriptor, err := windows.GetSecurityInfo(
		handle,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil || descriptor == nil || descriptor.String() == "" {
		if err == nil {
			err = errors.New("empty security descriptor")
		}
		return nil, windowsCursorManagedFileMetadata{}, fmt.Errorf(
			"enterprise hooks: snapshot Cursor security descriptor for %s: %w", file.Name(), err)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, windowsCursorManagedFileMetadata{}, err
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil {
		return nil, windowsCursorManagedFileMetadata{}, err
	}
	if len(data) > limit {
		return nil, windowsCursorManagedFileMetadata{}, fmt.Errorf(
			"enterprise hooks: refusing unsafe managed policy artifact: %s", file.Name())
	}
	return data, windowsCursorManagedFileMetadata{
		securityDescriptor: descriptor.String(),
		attributes:         info.FileAttributes,
	}, nil
}

// renameWindowsCursorManagedLockedFile renames the file behind file to
// target, which must not exist.
func renameWindowsCursorManagedLockedFile(file *os.File, target string) error {
	name, err := windows.UTF16FromString(target)
	if err != nil {
		return err
	}
	type fileRenameInfo struct {
		ReplaceIfExists uint32
		RootDirectory   windows.Handle
		FileNameLength  uint32
		FileName        [1]uint16
	}
	size := unsafe.Offsetof(fileRenameInfo{}.FileName) + uintptr(len(name))*2
	buffer := make([]uint64, (size+7)/8)
	info := (*fileRenameInfo)(unsafe.Pointer(&buffer[0]))
	info.FileNameLength = uint32((len(name) - 1) * 2)
	copy(unsafe.Slice(&info.FileName[0], len(name)), name)
	return windows.SetFileInformationByHandle(
		windows.Handle(file.Fd()), windows.FileRenameInfo, (*byte)(unsafe.Pointer(&buffer[0])), uint32(size))
}

// deleteWindowsCursorManagedLockedFile deletes the file behind file when the
// handle closes.
func deleteWindowsCursorManagedLockedFile(file *os.File) error {
	deleteFile := byte(1) // FILE_DISPOSITION_INFO.DeleteFile
	return windows.SetFileInformationByHandle(windows.Handle(file.Fd()), windows.FileDispositionInfo, &deleteFile, 1)
}

// moveWindowsCursorManagedFile moves source to destination, which must not
// exist.
func moveWindowsCursorManagedFile(source, destination string) error {
	from, err := winpath.UTF16Ptr(source)
	if err != nil {
		return err
	}
	to, err := winpath.UTF16Ptr(destination)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(from, to, windows.MOVEFILE_WRITE_THROUGH)
}

func windowsCursorManagedNameTaken(err error) bool {
	return errors.Is(err, windows.ERROR_ALREADY_EXISTS) || errors.Is(err, windows.ERROR_FILE_EXISTS)
}
