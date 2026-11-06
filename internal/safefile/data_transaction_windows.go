// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package safefile

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

var (
	dataKTM                   = windows.NewLazySystemDLL("ktmw32.dll")
	dataCreateTransaction     = dataKTM.NewProc("CreateTransaction")
	dataCommitTransaction     = dataKTM.NewProc("CommitTransaction")
	dataRollbackTransaction   = dataKTM.NewProc("RollbackTransaction")
	dataNTDLL                 = windows.NewLazySystemDLL("ntdll.dll")
	dataGetCurrentTransaction = dataNTDLL.NewProc("RtlGetCurrentTransaction")
	dataSetCurrentTransaction = dataNTDLL.NewProc("RtlSetCurrentTransaction")
)

const dataTransactionRetryBudget = 3 * time.Second

// InDataFileTransaction publishes a staged data file while Windows keeps the
// old name available to concurrent openers. A program image always takes the
// existing plain path. An unavailable transaction also leaves the existing
// publication behavior in place. A busy file is retried within a fixed budget.
// The operation must open its mutation handles while the transaction is bound
// and must be safe to repeat after a rolled-back attempt.
func InDataFileTransaction(stage, destination string, operation func() error) error {
	return inDataFileTransaction(!dataFileMayBeProgramImage(stage) && !dataFileMayBeProgramImage(destination), operation)
}

// InDataBytesTransaction is for a writer that creates its stage inside the
// operation and already has its complete data body in memory.
func InDataBytesTransaction(data []byte, destination string, operation func() error) error {
	return inDataFileTransaction(!dataLooksLikeProgramImage(data) && !dataFileMayBeProgramImage(destination), operation)
}

func inDataFileTransaction(dataFile bool, operation func() error) error {
	if !dataFile || !dataTransactionsAvailable() {
		return operation()
	}
	deadline := time.Now().Add(dataTransactionRetryBudget)
	for {
		used, err := runDataFileTransaction(operation)
		if err == nil {
			return nil
		}
		if !used || dataTransactionUnsupported(err) {
			return operation()
		}
		if !dataTransactionBusy(err) {
			return err
		}
		if !time.Now().Before(deadline) {
			return err
		}
		time.Sleep(time.Millisecond)
	}
}

func dataFileMayBeProgramImage(path string) bool {
	var file *os.File
	err := RetryTransientRead(func() error {
		var openErr error
		file, openErr = os.Open(path)
		return openErr
	})
	if err != nil {
		return true
	}
	defer file.Close()
	var signature [2]byte
	n, err := io.ReadFull(file, signature[:])
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	return n == len(signature) && dataLooksLikeProgramImage(signature[:])
}

func dataLooksLikeProgramImage(data []byte) bool {
	return len(data) >= 2 && data[0] == 'M' && data[1] == 'Z'
}

func dataTransactionsAvailable() bool {
	return dataCreateTransaction.Find() == nil &&
		dataCommitTransaction.Find() == nil &&
		dataRollbackTransaction.Find() == nil &&
		dataGetCurrentTransaction.Find() == nil &&
		dataSetCurrentTransaction.Find() == nil
}

func dataTransactionBusy(err error) bool {
	return errors.Is(err, windows.ERROR_SHARING_VIOLATION) ||
		errors.Is(err, windows.ERROR_LOCK_VIOLATION) ||
		errors.Is(err, windows.ERROR_ACCESS_DENIED) ||
		errors.Is(err, windows.ERROR_TRANSACTIONAL_CONFLICT)
}

func dataTransactionUnsupported(err error) bool {
	return errors.Is(err, windows.ERROR_NOT_SUPPORTED) ||
		errors.Is(err, windows.ERROR_INVALID_FUNCTION) ||
		errors.Is(err, windows.ERROR_INVALID_PARAMETER) ||
		errors.Is(err, windows.ERROR_TRANSACTIONS_UNSUPPORTED_REMOTE) ||
		errors.Is(err, windows.ERROR_TRANSACTION_NOT_ACTIVE) ||
		errors.Is(err, windows.ERROR_TRANSACTIONAL_OPEN_NOT_ALLOWED)
}

// runDataFileTransaction reports used=false only when no transaction was
// started. A failed operation is rolled back before the caller retries it.
func runDataFileTransaction(operation func() error) (used bool, err error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if current, _, _ := dataGetCurrentTransaction.Call(); current != 0 {
		return true, operation()
	}
	handle, _, callErr := dataCreateTransaction.Call(0, 0, 0, 0, 0, 30_000, 0)
	if handle == 0 || windows.Handle(handle) == windows.InvalidHandle {
		return false, dataTransactionCallError(callErr)
	}
	transaction := windows.Handle(handle)
	defer windows.CloseHandle(transaction)
	committed := false
	defer func() {
		if !committed {
			_, _, _ = dataRollbackTransaction.Call(handle)
		}
	}()
	if ok, _, setErr := dataSetCurrentTransaction.Call(handle); ok == 0 {
		return false, dataTransactionCallError(setErr)
	}
	func() {
		defer dataSetCurrentTransaction.Call(0)
		err = operation()
	}()
	if err != nil {
		return true, err
	}
	if ok, _, commitErr := dataCommitTransaction.Call(handle); ok == 0 {
		// A failed commit can leave its final state uncertain to this process.
		// Do not rerun a publication against that state.
		return true, fmt.Errorf("commit data file transaction: %v", dataTransactionCallError(commitErr))
	}
	committed = true
	return true, nil
}

func dataTransactionCallError(err error) error {
	if err == nil || err == syscall.Errno(0) {
		return syscall.EINVAL
	}
	return err
}
