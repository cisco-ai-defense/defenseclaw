// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package safefile

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

// ErrSwapRaced reports that a compare-and-swap found a different file than
// the one it expected: another writer changed it. The newer file is kept.
var ErrSwapRaced = errors.New("safefile: the file changed concurrently")

// swapLockTimeout bounds how long a compare-and-swap waits for another
// process to close a file it has open for writing, and for a reader that
// does not share deletion to close the file the swap replaces.
const swapLockTimeout = 2 * time.Second

const (
	// FILE_RENAME_INFO.Flags for FileRenameInfoEx.
	fileRenameReplaceIfExists         = 0x1
	fileRenamePOSIXSemantics          = 0x2
	fileRenameIgnoreReadOnlyAttribute = 0x40
)

// swapBeforeReplace runs after the comparison, just before the replacement;
// tests replace it to change the file in between.
var swapBeforeReplace = func(string) {}

// swapRenameReplace is renameReplace; tests replace it to stand for a volume
// without POSIX renames.
var swapRenameReplace = renameReplace

// SwapExpectation is the file a compare-and-swap may replace: absent, or
// present with exactly Data.
type SwapExpectation struct {
	Exists bool
	Data   []byte
}

// SwapResult reports what a compare-and-swap changed.
type SwapResult struct {
	// Swapped reports that the new file was published (or, for
	// RemoveFileIfUnchanged, that the file was removed).
	Swapped bool
	// Replaced reports that an existing file was replaced.
	Replaced bool
}

// CompareAndSwapFile moves source to destination only while destination
// holds expected. Writers that do not take the caller's lock, an
// administrator's editor or the agent itself, can save between a read and a
// write, so the comparison and the replacement happen while the swap holds
// the current file open:
//
//   - The comparison reads through a handle that shares only reads, so no
//     other process can write, rename, replace or delete the file meanwhile.
//   - Before that handle closes, a second handle on the same file takes over.
//     It still refuses writers, so the compared bytes cannot change, and it
//     shares deletion so that the swap can replace the file.
//   - The swap then renames source over destination in one step (POSIX
//     semantics). destination names the old file or the new one at every
//     instant: an agent that loads its policy during the swap never finds it
//     missing. Just before the rename it opens destination again and checks
//     that it still names the held file, so a POSIX-semantics replacement,
//     deletion or rename by another process after the comparison is refused
//     as a race; only one that lands in the instant between that check and
//     the rename is not.
//
// Readers keep reading throughout. Cursor (Node) and Codex (Rust) share
// deletion and are never refused. Windows refuses a reader that does not
// share deletion for the instant of the rename, as it does for any atomic
// replacement (ReplaceFileW included), and never during the comparison. A
// reader that has the file open without sharing deletion makes the swap wait
// for it, with the old file in place.
//
// Any other file than expected returns ErrSwapRaced with destination
// untouched and source left for the caller to remove. inspect, when set, runs
// on the locked current file before the comparison, so a caller can read its
// metadata or refuse it.
func CompareAndSwapFile(
	source, destination string,
	expected SwapExpectation,
	limit int,
	inspect func(*os.File) error,
) (SwapResult, error) {
	current, err := lockFileForSwap(destination, windows.GENERIC_READ|windows.READ_CONTROL)
	if err != nil {
		return SwapResult{}, err
	}
	if current == nil {
		if expected.Exists {
			return SwapResult{}, swapRaced(destination)
		}
		if err := moveFileNoReplace(source, destination); err != nil {
			if swapNameTaken(err) {
				return SwapResult{}, swapRaced(destination)
			}
			return SwapResult{}, fmt.Errorf("safefile: publish %s: %w", destination, err)
		}
		return SwapResult{Swapped: true}, nil
	}
	held, err := holdMatchedFileForReplace(current, destination, expected, limit, inspect)
	if closeErr := current.Close(); err == nil && closeErr != nil {
		_ = held.Close()
		err = closeErr
	}
	if err != nil {
		return SwapResult{}, err
	}
	defer held.Close()
	swapBeforeReplace(destination)
	if err := replaceHeldFile(source, destination, held); err != nil {
		if errors.Is(err, ErrSwapRaced) {
			return SwapResult{}, err
		}
		return SwapResult{}, fmt.Errorf("safefile: publish %s: %w", destination, err)
	}
	return SwapResult{Swapped: true, Replaced: true}, nil
}

// RemoveFileIfUnchanged deletes path only while it holds expected: it reads
// and deletes the file through one handle no other process can write
// through. A different or missing file returns ErrSwapRaced; a different file
// is kept. inspect is as for CompareAndSwapFile.
func RemoveFileIfUnchanged(path string, expected []byte, limit int, inspect func(*os.File) error) (SwapResult, error) {
	current, err := lockFileForSwap(path, windows.GENERIC_READ|windows.DELETE|windows.READ_CONTROL)
	if err != nil {
		return SwapResult{}, err
	}
	if current == nil {
		return SwapResult{}, swapRaced(path)
	}
	defer current.Close()
	if err := matchLockedFile(current, SwapExpectation{Exists: true, Data: expected}, limit, inspect); err != nil {
		return SwapResult{}, err
	}
	if err := deleteLockedFile(current); err != nil {
		return SwapResult{}, fmt.Errorf("safefile: remove %s: %w", path, err)
	}
	return SwapResult{Swapped: true, Replaced: true}, nil
}

func swapRaced(path string) error {
	return fmt.Errorf("%w: %s", ErrSwapRaced, path)
}

// matchLockedFile reports ErrSwapRaced unless the locked file holds expected.
func matchLockedFile(file *os.File, expected SwapExpectation, limit int, inspect func(*os.File) error) error {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &info); err != nil {
		return err
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DEVICE) != 0 {
		return fmt.Errorf("safefile: refusing a file that is not regular: %s", file.Name())
	}
	if inspect != nil {
		if err := inspect(file); err != nil {
			return err
		}
	}
	if !expected.Exists {
		return swapRaced(file.Name())
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil {
		return err
	}
	if len(data) > limit || !bytes.Equal(data, expected.Data) {
		return swapRaced(file.Name())
	}
	return nil
}

// holdMatchedFileForReplace compares the locked file with expected and, on a
// match, opens a second handle on it that still refuses writers but shares
// deletion, for the replacement. The locked handle stays open until the
// caller closes it, so the file cannot change between the two.
func holdMatchedFileForReplace(
	current *os.File,
	path string,
	expected SwapExpectation,
	limit int,
	inspect func(*os.File) error,
) (*os.File, error) {
	if err := matchLockedFile(current, expected, limit, inspect); err != nil {
		return nil, err
	}
	name, err := winpath.UTF16Ptr(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(
		name,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("safefile: open %s: %w", path, err)
	}
	held := os.NewFile(uintptr(handle), path)
	if same, err := sameFile(current, held); err != nil || !same {
		_ = held.Close()
		if err != nil {
			return nil, err
		}
		return nil, swapRaced(path)
	}
	return held, nil
}

// replaceHeldFile renames source over destination while destination still
// names held. Each attempt first opens destination for deletion, which
// succeeds only while every other handle on it shares deletion, and keeps
// that handle until the rename is done: Windows can briefly drop the name of
// a file whose POSIX replacement fails on a handle that does not share
// deletion, so the swap never tries the rename while such a handle is open.
// It waits a short while for a reader that has destination open without
// sharing deletion.
func replaceHeldFile(source, destination string, held *os.File) error {
	deadline := time.Now().Add(swapLockTimeout)
	for {
		target, err := openFileForReplace(destination)
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			return swapRaced(destination)
		}
		if err == nil {
			var same bool
			if same, err = sameFile(held, target); err == nil && !same {
				err = swapRaced(destination)
			}
			if err == nil {
				err = swapRenameReplace(source, destination, windows.FileRenameInfoEx,
					fileRenameReplaceIfExists|fileRenamePOSIXSemantics|fileRenameIgnoreReadOnlyAttribute)
			}
			_ = target.Close()
			if err == nil {
				return nil
			}
		}
		switch {
		case errors.Is(err, windows.ERROR_INVALID_PARAMETER) ||
			errors.Is(err, windows.ERROR_NOT_SUPPORTED) ||
			errors.Is(err, windows.ERROR_INVALID_FUNCTION):
			// A volume without POSIX renames replaces only a file nobody
			// has open: release the hold and replace in one step.
			return replaceReleasedFile(source, destination, held, deadline)
		case !swapBusy(err) || !time.Now().Before(deadline):
			return err
		}
		time.Sleep(time.Millisecond)
	}
}

// replaceReleasedFile is replaceHeldFile for a volume without POSIX renames.
func replaceReleasedFile(source, destination string, held *os.File, deadline time.Time) error {
	identity, err := fileIdentity(held)
	if err != nil {
		return err
	}
	if err := held.Close(); err != nil {
		return err
	}
	for {
		current, err := openFileAttributes(destination)
		if err != nil {
			if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
				return swapRaced(destination)
			}
			return err
		}
		currentIdentity, err := fileIdentity(current)
		_ = current.Close()
		if err != nil {
			return err
		}
		if currentIdentity != identity {
			return swapRaced(destination)
		}
		err = swapRenameReplace(source, destination, windows.FileRenameInfo, fileRenameReplaceIfExists)
		if err == nil || !swapBusy(err) || !time.Now().Before(deadline) {
			return err
		}
		time.Sleep(time.Millisecond)
	}
}

func swapBusy(err error) bool {
	return errors.Is(err, windows.ERROR_SHARING_VIOLATION) ||
		errors.Is(err, windows.ERROR_ACCESS_DENIED) ||
		errors.Is(err, windows.ERROR_LOCK_VIOLATION)
}

type swapFileIdentity struct {
	volume, high, low uint32
}

func fileIdentity(file *os.File) (swapFileIdentity, error) {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &info); err != nil {
		return swapFileIdentity{}, err
	}
	return swapFileIdentity{volume: info.VolumeSerialNumber, high: info.FileIndexHigh, low: info.FileIndexLow}, nil
}

func sameFile(a, b *os.File) (bool, error) {
	first, err := fileIdentity(a)
	if err != nil {
		return false, err
	}
	second, err := fileIdentity(b)
	if err != nil {
		return false, err
	}
	return first == second, nil
}

// openFileForReplace opens path for deletion, sharing reads and deletion:
// it fails while another handle on path does not share deletion, and while
// it is open no such handle can be opened.
func openFileForReplace(path string) (*os.File, error) {
	name, err := winpath.UTF16Ptr(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(
		name,
		windows.DELETE|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(handle), path), nil
}

// openFileAttributes opens path for reading its attributes only, which
// neither blocks nor is blocked by any other handle.
func openFileAttributes(path string) (*os.File, error) {
	name, err := winpath.UTF16Ptr(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(
		name,
		windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(handle), path), nil
}

// lockFileForSwap opens path with access, sharing only reads: while the
// handle is open no other process can write, rename, replace or delete the
// file. It waits a short while for a writer that has the file open, and
// returns nil for a missing file.
func lockFileForSwap(path string, access uint32) (*os.File, error) {
	name, err := winpath.UTF16Ptr(path)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(swapLockTimeout)
	for {
		handle, err := windows.CreateFile(
			name,
			access,
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
			return nil, fmt.Errorf("safefile: open %s: %w", path, err)
		}
		time.Sleep(time.Millisecond)
	}
}

// renameReplace renames source to destination through a handle on source,
// with a FileRenameInfo or FileRenameInfoEx request carrying flags.
func renameReplace(source, destination string, class uint32, flags uint32) error {
	from, err := winpath.UTF16Ptr(source)
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(
		from,
		windows.DELETE|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	name, err := windows.UTF16FromString(destination)
	if err != nil {
		return err
	}
	type fileRenameInfo struct {
		Flags          uint32
		RootDirectory  windows.Handle
		FileNameLength uint32
		FileName       [1]uint16
	}
	size := unsafe.Offsetof(fileRenameInfo{}.FileName) + uintptr(len(name))*2
	buffer := make([]uint64, (size+7)/8)
	info := (*fileRenameInfo)(unsafe.Pointer(&buffer[0]))
	info.Flags = flags
	info.FileNameLength = uint32((len(name) - 1) * 2)
	copy(unsafe.Slice(&info.FileName[0], len(name)), name)
	return windows.SetFileInformationByHandle(handle, class, (*byte)(unsafe.Pointer(&buffer[0])), uint32(size))
}

// deleteLockedFile deletes the file behind file when the handle closes. A
// read-only file is deleted too, as DeleteFile would refuse: the caller
// already proved the file holds exactly the bytes it may remove.
func deleteLockedFile(file *os.File) error {
	handle := windows.Handle(file.Fd())
	flags := uint32(windows.FILE_DISPOSITION_DELETE | windows.FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE)
	if err := windows.SetFileInformationByHandle(
		handle, windows.FileDispositionInfoEx, (*byte)(unsafe.Pointer(&flags)), uint32(unsafe.Sizeof(flags)),
	); err == nil {
		return nil
	}
	// Volumes without FileDispositionInfoEx: the classic request, which
	// refuses a read-only file.
	deleteFile := byte(1) // FILE_DISPOSITION_INFO.DeleteFile
	return windows.SetFileInformationByHandle(handle, windows.FileDispositionInfo, &deleteFile, 1)
}

// moveFileNoReplace moves source to destination, which must not exist.
func moveFileNoReplace(source, destination string) error {
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

func swapNameTaken(err error) bool {
	return errors.Is(err, windows.ERROR_ALREADY_EXISTS) || errors.Is(err, windows.ERROR_FILE_EXISTS)
}
