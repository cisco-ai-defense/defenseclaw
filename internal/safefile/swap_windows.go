// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package safefile

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

// ErrSwapRaced reports that a compare-and-swap found a different file than
// the one it expected: another writer changed it. The newer file is kept.
var ErrSwapRaced = errors.New("safefile: the file changed concurrently")

// ErrSwapUnsupported reports that a volume without POSIX-semantics renames
// cannot replace the file while the compared file is held. Releasing the
// hold could overwrite a concurrent save, so the file is left in place.
var ErrSwapUnsupported = errors.New("safefile: this volume has no POSIX-semantics rename, so a shared file cannot be replaced without losing a concurrent save; nothing was changed")

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

// swapMoveFileReplace is the one-step replacement on volumes that reject
// FileRenameInfoEx. Tests replace it to check the fallback while the compared
// file remains held.
var swapMoveFileReplace = moveFileReplace

var swapMoveFileWarning sync.Once

func warnSwapMoveFileFallback() {
	swapMoveFileWarning.Do(func() {
		log.Printf("defenseclaw: WARNING: this volume does not support POSIX file replacement; trying MoveFileEx while the compared file remains held")
	})
}

// SwapExpectation is the file a compare-and-swap may replace: absent, or
// present with exactly Data and, when Metadata is set, exactly that owner,
// group, access list and attributes.
type SwapExpectation struct {
	Exists   bool
	Data     []byte
	Metadata *FileMetadata
}

// SwapResult reports what a compare-and-swap changed.
type SwapResult struct {
	// Swapped reports that the new file was published (or, for
	// RemoveFileIfUnchanged, that the file was removed).
	Swapped bool
	// Replaced reports that an existing file was replaced.
	Replaced bool
	// ReplacedMetadata is the metadata the replaced file had when it was
	// replaced, read through the swap's handle just before the rename; nil
	// when it could not be read. Share modes do not stop an owner, access
	// list or attribute change, so it can differ from what the comparison
	// saw. It is not read after the rename: the replaced file is then out of
	// its folder, and its inherited entries read back as explicit ones.
	ReplacedMetadata *FileMetadata
}

// PublicationClass selects the Windows rename mode from the file's writers.
// A file with external writers cannot reserve its name in a transaction:
// ordinary editors have no way to retry a transactional conflict.
type PublicationClass uint8

const (
	PublishDefenseClawOwned PublicationClass = iota + 1
	PublishSharedWithExternalWriters
)

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
//   - For DefenseClaw-owned non-image files, the swap submits the
//     POSIX-semantics rename in a file transaction, so an outside pathname
//     open sees the old or new file. Files with external writers use the
//     guarded one-step rename, as do volumes without transactions; a
//     concurrent opener may need to retry there. Just before publication it
//     opens destination again and checks that it still names the held file,
//     so a POSIX-semantics replacement,
//     deletion or rename by another process after the comparison is refused
//     as a race; only one that lands in the instant between that check and
//     the rename is not.
//
// Open readers keep reading throughout. A fresh open of an owned non-image
// file sees the old or new name during a transaction. A fresh open of a
// shared file can receive a transient name or sharing error during the
// ordinary replacement and follows the documented bounded-retry contract.
// A reader that has the file open without sharing deletion makes the swap
// wait for it, with the old file in place.
//
// expected.Metadata, when set, is compared too. Share modes do not stop an
// owner, access list or attribute change, so SwapResult.ReplacedMetadata
// reports what the replaced file had at the rename, for a caller to keep a
// change that landed after the comparison (PublishSharedFile does).
//
// Any other file than expected returns ErrSwapRaced with destination
// untouched and source left for the caller to remove. inspect, when set, runs
// on the locked current file before the comparison, so a caller can read its
// metadata or refuse it. class is required and describes whether another
// program can save this destination.
func CompareAndSwapFile(
	source, destination string,
	expected SwapExpectation,
	limit int,
	inspect func(*os.File) error,
	class PublicationClass,
) (SwapResult, error) {
	if class != PublishDefenseClawOwned && class != PublishSharedWithExternalWriters {
		return SwapResult{}, errors.New("safefile: publication class is required")
	}
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
	result := SwapResult{Swapped: true, Replaced: true}
	readReplaced := func() {
		result.ReplacedMetadata = nil
		if metadata, err := ReadFileMetadata(held); err == nil {
			result.ReplacedMetadata = &metadata
		}
	}
	if err := replaceHeldFile(source, destination, held, readReplaced, class); err != nil {
		if errors.Is(err, ErrSwapRaced) {
			return SwapResult{}, err
		}
		return SwapResult{}, fmt.Errorf("safefile: publish %s: %w", destination, err)
	}
	return result, nil
}

// RemoveFileIfUnchanged deletes path only while it holds expected: it reads
// and deletes the file through one handle no other process can write
// through. A different or missing file returns ErrSwapRaced; a different file
// is kept. inspect is as for CompareAndSwapFile.
func RemoveFileIfUnchanged(path string, expected SwapExpectation, limit int, inspect func(*os.File) error) (SwapResult, error) {
	current, err := lockFileForSwap(path, windows.GENERIC_READ|windows.DELETE|windows.READ_CONTROL)
	if err != nil {
		return SwapResult{}, err
	}
	if current == nil {
		return SwapResult{}, swapRaced(path)
	}
	defer current.Close()
	expected.Exists = true
	if err := matchLockedFile(current, expected, limit, inspect); err != nil {
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
	if expected.Metadata != nil {
		metadata, err := ReadFileMetadata(file)
		if err != nil {
			return err
		}
		if metadata != *expected.Metadata {
			return swapRaced(file.Name())
		}
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
// names held. The owned-file transacted path checks identity with a
// read-attributes handle, then publishes the staged file in one transaction.
// Its rollback leaves the old name intact if a reader refuses deletion.
// Shared files and volumes without transactions use a DELETE-access
// destination handle to exclude such readers while the guarded one-step
// rename runs.
//
// beforeRename runs just before each publication attempt, while held still
// names the file at destination.
func replaceHeldFile(source, destination string, held *os.File, beforeRename func(), class PublicationClass) error {
	deadline := time.Now().Add(swapLockTimeout)
	useTransaction := class == PublishDefenseClawOwned && !swapRequiresPlainRename(source)
	for {
		target, err := openFileForReplace(destination, useTransaction)
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			return swapRaced(destination)
		}
		if err == nil {
			var same bool
			if same, err = sameFile(held, target); err == nil && !same {
				err = swapRaced(destination)
			}
			if err == nil {
				var flags uint32
				flags, err = swapPOSIXRenameFlags(target)
				if err == nil {
					beforeRename()
					if useTransaction {
						var unavailable bool
						unavailable, err = swapRenameInTransaction(source, destination, flags)
						if unavailable || posixRenameUnsupported(err) || errors.Is(err, windows.ERROR_INVALID_FUNCTION) {
							// Recheck identity under the plain path's DELETE-access
							// guard before attempting the non-transactional rename.
							// A name conflict retains the transaction route: the plain
							// rename can leave a first-open name gap for a reader.
							useTransaction = false
							warnSwapTransactionFallback()
							_ = target.Close()
							continue
						}
					} else {
						err = swapRenameReplace(source, destination, windows.FileRenameInfoEx, flags)
					}
					if posixRenameUnsupported(err) || errors.Is(err, windows.ERROR_INVALID_FUNCTION) {
						// Keep both holds while trying the other one-step API. If
						// the volume cannot replace an open destination, refuse the
						// swap instead of releasing the comparison and losing a save.
						warnSwapMoveFileFallback()
						err = swapMoveFileReplace(source, destination)
						if swapBusy(err) {
							err = fmt.Errorf("%w (%s: %v)", ErrSwapUnsupported, destination, err)
						}
					}
				}
			}
			_ = target.Close()
			if err == nil {
				return nil
			}
		}
		switch {
		case !swapBusy(err) || !time.Now().Before(deadline):
			return err
		}
		time.Sleep(time.Millisecond)
	}
}

func swapPOSIXRenameFlags(target *os.File) (uint32, error) {
	flags := uint32(fileRenameReplaceIfExists | fileRenamePOSIXSemantics)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(target.Fd()), &info); err != nil {
		return 0, err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_READONLY != 0 {
		// Windows requires this flag to replace a read-only destination.
		flags |= fileRenameIgnoreReadOnlyAttribute
	}
	return flags, nil
}

func swapBusy(err error) bool {
	return errors.Is(err, windows.ERROR_SHARING_VIOLATION) ||
		errors.Is(err, windows.ERROR_ACCESS_DENIED) ||
		errors.Is(err, windows.ERROR_LOCK_VIOLATION) ||
		errors.Is(err, windows.ERROR_TRANSACTIONAL_CONFLICT)
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

// openFileForReplace checks the destination name. The plain path requests
// DELETE access, excluding readers that do not share deletion. The transacted
// path uses read attributes because Windows can refuse a transacted rename
// over a destination held with DELETE access outside that transaction.
func openFileForReplace(path string, transacted bool) (*os.File, error) {
	name, err := winpath.UTF16Ptr(path)
	if err != nil {
		return nil, err
	}
	access := uint32(windows.DELETE | windows.FILE_READ_ATTRIBUTES)
	if transacted {
		access = windows.FILE_READ_ATTRIBUTES
	}
	handle, err := windows.CreateFile(
		name,
		access,
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
	return renameHandle(handle, 0, destination, class, flags)
}

// ReplaceFileInDirectory publishes a staged file through its held handle.
// The caller has bound source to parent and keeps that directory and its
// ancestors held against rename. SetFileInformationByHandle requires a null
// RootDirectory with this absolute destination path. Unsupported volumes use
// the classic replacement request.
func ReplaceFileInDirectory(parent, source *os.File, targetName string) error {
	if targetName == "" || targetName == "." || targetName == ".." ||
		strings.ContainsAny(targetName, `\/:`) {
		return fmt.Errorf("safefile: invalid destination leaf")
	}
	if parent == nil || !filepath.IsAbs(parent.Name()) {
		return fmt.Errorf("safefile: destination directory has no absolute path")
	}
	destination := filepath.Join(parent.Name(), targetName)
	err := renameHandle(windows.Handle(source.Fd()), 0, destination,
		windows.FileRenameInfoEx, fileRenameReplaceIfExists|fileRenamePOSIXSemantics|fileRenameIgnoreReadOnlyAttribute)
	if err == nil || !posixRenameUnsupported(err) {
		return err
	}
	warnClassicRenameFallback()
	return renameHandle(windows.Handle(source.Fd()), 0, destination,
		windows.FileRenameInfo, fileRenameReplaceIfExists)
}

func renameHandle(handle, parent windows.Handle, destination string, class uint32, flags uint32) error {
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
	info.RootDirectory = parent
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
	return moveFileForSwap(source, destination, windows.MOVEFILE_WRITE_THROUGH)
}

func moveFileReplace(source, destination string) error {
	return moveFileForSwap(source, destination, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

func moveFileForSwap(source, destination string, flags uint32) error {
	from, err := winpath.UTF16Ptr(source)
	if err != nil {
		return err
	}
	to, err := winpath.UTF16Ptr(destination)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(from, to, flags)
}

func swapNameTaken(err error) bool {
	return errors.Is(err, windows.ERROR_ALREADY_EXISTS) || errors.Is(err, windows.ERROR_FILE_EXISTS)
}
