// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package safefile

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

var (
	swapKTM                 = windows.NewLazySystemDLL("ktmw32.dll")
	swapCreateTransaction   = swapKTM.NewProc("CreateTransaction")
	swapCommitTransaction   = swapKTM.NewProc("CommitTransaction")
	swapRollbackTransaction = swapKTM.NewProc("RollbackTransaction")
	swapCreateTransacted    = windows.NewLazySystemDLL("kernel32.dll").NewProc("CreateFileTransactedW")
	swapTransactedRename    = renameTransacted
	swapTransactionWarning  sync.Once
)

const swapTransactionTimeoutMS = 30_000

func warnSwapTransactionFallback() {
	swapTransactionWarning.Do(func() {
		log.Print("defenseclaw: WARNING: transactional file replacement is unavailable; compare-and-swap uses ordinary Windows replacement, so concurrent pathname opens may need retry")
	})
}

// swapRequiresPlainRename keeps Windows program images out of a file
// transaction. Data may also start with MZ, so inspect the PE signature and
// image header before choosing the plain path. If the stage cannot be read,
// retain the original plain rename behavior. Windows can refuse an outside
// process launch while an image is transacted.
func swapRequiresPlainRename(path string) bool {
	file, err := os.Open(path)
	if err != nil {
		return true
	}
	defer file.Close()
	var dos [0x40]byte
	if _, err := file.ReadAt(dos[:], 0); err != nil {
		return !errors.Is(err, io.EOF)
	}
	if dos[0] != 'M' || dos[1] != 'Z' {
		return false
	}
	// e_lfanew names the PE signature after the DOS header. ReadAt avoids
	// allocating from an offset supplied by the staged file.
	offset := int64(binary.LittleEndian.Uint32(dos[0x3c:]))
	if offset < int64(len(dos)) {
		return false
	}
	var image [26]byte // PE signature, COFF header, optional-header magic.
	if _, err := file.ReadAt(image[:], offset); err != nil {
		return !errors.Is(err, io.EOF)
	}
	if image[0] != 'P' || image[1] != 'E' || image[2] != 0 || image[3] != 0 {
		return false
	}
	if binary.LittleEndian.Uint16(image[20:22]) < 2 || binary.LittleEndian.Uint16(image[22:24])&0x2 == 0 {
		return false
	}
	magic := binary.LittleEndian.Uint16(image[24:26])
	return magic == 0x10b || magic == 0x20b
}

// renameTransacted opens the staged file as part of tx, then renames through
// that handle. The handle is closed before the transaction commits.
func renameTransacted(source, destination string, flags uint32, tx windows.Handle) error {
	from, err := winpath.UTF16Ptr(source)
	if err != nil {
		return err
	}
	handle, _, callErr := swapCreateTransacted.Call(
		uintptr(unsafe.Pointer(from)),
		uintptr(windows.DELETE|windows.SYNCHRONIZE),
		uintptr(windows.FILE_SHARE_READ|windows.FILE_SHARE_DELETE),
		0,
		uintptr(windows.OPEN_EXISTING),
		uintptr(windows.FILE_FLAG_OPEN_REPARSE_POINT),
		0,
		uintptr(tx),
		0,
		0,
	)
	runtime.KeepAlive(from)
	if handle == 0 || windows.Handle(handle) == windows.InvalidHandle {
		return swapCallError(callErr)
	}
	defer windows.CloseHandle(windows.Handle(handle))
	return renameHandle(windows.Handle(handle), 0, destination, windows.FileRenameInfoEx, flags)
}

// swapRenameInTransaction publishes one staged non-image file. The source
// handle joins the transaction; the compared-file handles remain outside it.
// unavailable is true when the platform or staged file cannot participate in
// the transaction; the caller can then use its guarded one-step replacement.
func swapRenameInTransaction(source, destination string, flags uint32) (unavailable bool, err error) {
	for _, proc := range []*windows.LazyProc{
		swapCreateTransaction, swapCommitTransaction, swapRollbackTransaction,
		swapCreateTransacted,
	} {
		if err := proc.Find(); err != nil {
			return true, nil
		}
	}
	tx, _, callErr := swapCreateTransaction.Call(0, 0, 0, 0, 0, swapTransactionTimeoutMS, 0)
	if tx == 0 || windows.Handle(tx) == windows.InvalidHandle {
		if swapTransactionUnavailable(callErr) {
			return true, nil
		}
		return false, swapCallError(callErr)
	}
	handle := windows.Handle(tx)
	defer windows.CloseHandle(handle)
	renameErr := swapTransactedRename(source, destination, flags, handle)
	if renameErr != nil {
		if ok, _, rollbackErr := swapRollbackTransaction.Call(tx); ok == 0 {
			return false, fmt.Errorf("safefile: rollback file transaction after %v: %w", renameErr, swapCallError(rollbackErr))
		}
		if swapTransactionUnavailable(renameErr) {
			return true, nil
		}
		return false, renameErr
	}
	if ok, _, callErr := swapCommitTransaction.Call(tx); ok == 0 {
		if rollbackOK, _, rollbackErr := swapRollbackTransaction.Call(tx); rollbackOK == 0 {
			return false, fmt.Errorf("safefile: commit file transaction: %v; rollback: %w", swapCallError(callErr), swapCallError(rollbackErr))
		}
		return false, fmt.Errorf("safefile: commit file transaction: %w", swapCallError(callErr))
	}
	return false, nil
}

func swapTransactionUnavailable(err error) bool {
	return errors.Is(err, windows.ERROR_NOT_SUPPORTED) ||
		errors.Is(err, windows.ERROR_INVALID_FUNCTION) ||
		errors.Is(err, windows.ERROR_TRANSACTIONS_UNSUPPORTED_REMOTE) ||
		errors.Is(err, windows.ERROR_EFS_NOT_ALLOWED_IN_TRANSACTION)
}

func swapCallError(err error) error {
	if err == nil || err == syscall.Errno(0) {
		return syscall.EINVAL
	}
	return err
}
