// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"os"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

// openHookConfigForRead opens an agent config for a read-only presence check.
// os.Open omits FILE_SHARE_DELETE, so a concurrent check would make the
// connector's atomic replacement of the same file fail with ACCESS_DENIED.
// Sharing delete lets the replacement proceed; the reader keeps the bytes of
// the file it opened. Like os.Open, this follows links and opens directories
// so readHookConfigFile can report a non-regular path precisely.
func openHookConfigForRead(path string) (*os.File, error) {
	if err := managed.RequireWindowsGatewayPathOutsideUserProfiles(path); err != nil {
		return nil, err
	}
	return openSharedForRead(path)
}

// openManagedTargetForRead opens a managed target for reading. An agent saves
// its own config by replacing the file, and a vendor tool or an indexer can
// hold it briefly, so a plain os.Open fails with a sharing violation in the
// middle of a Setup or Teardown that inspects the file. The open shares read,
// write and delete and waits a bounded time for a lock another process holds,
// like every other connector state read. It opens directories and other
// non-file paths the way os.Open does, so readManagedTarget still refuses
// them by their mode. A Windows named pipe is opened by a name in the
// \\.\pipe\ namespace; a managed target is a file path, so this open is not
// expected to wait for a writer.
func openManagedTargetForRead(path string) (*os.File, error) {
	for attempt := 1; ; attempt++ {
		file, err := openSharedForRead(path)
		if err == nil || !connectorStateFileBusy(err) || attempt >= connectorStateReadAttempts {
			return file, err
		}
		connectorStateReadSleep(connectorStateReadRetryDelay)
	}
}

// openSharedForRead opens path read-only with read, write and delete sharing.
func openSharedForRead(path string) (*os.File, error) {
	name, err := winpath.UTF16Ptr(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(
		name,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(handle), path), nil
}
