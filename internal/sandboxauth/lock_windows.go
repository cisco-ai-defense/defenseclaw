// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package sandboxauth

import (
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

const lockSupported = true

// lockExclusive locks a persistent, private sentinel. The parent and leaf
// handles exclude delete sharing, so the lock cannot be replaced while held.
// As on Unix, the sentinel must never be unlinked: a waiting writer and a new
// writer could otherwise lock different objects.
func lockExclusive(path string) (func(), error) {
	// The effective Windows identity can be a thread token. Keep that token
	// stable through parent validation and the native leaf creation.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	name := filepath.Base(path)
	if name == "." || name == ".." || strings.ContainsAny(name, `\/:`) {
		return nil, fmt.Errorf("sandboxauth: invalid binding lock name")
	}
	dir := filepath.Dir(path)
	if err := safefile.ValidatePrivateDirectory(dir); err != nil {
		return nil, fmt.Errorf("sandboxauth: binding lock directory is not private: %w", err)
	}
	extended, err := winpath.Extended(dir)
	if err != nil {
		return nil, fmt.Errorf("sandboxauth: binding lock directory path: %w", err)
	}
	parentName, err := windows.UTF16PtrFromString(extended)
	if err != nil {
		return nil, fmt.Errorf("sandboxauth: binding lock directory name: %w", err)
	}
	parent, err := windows.CreateFile(parentName,
		windows.FILE_LIST_DIRECTORY|windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, fmt.Errorf("sandboxauth: open binding lock directory: %w", err)
	}
	defer func() {
		if parent != 0 {
			_ = windows.CloseHandle(parent)
		}
	}()
	var parentInfo windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(parent, &parentInfo); err != nil {
		return nil, fmt.Errorf("sandboxauth: inspect binding lock directory: %w", err)
	}
	if parentInfo.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 ||
		parentInfo.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return nil, fmt.Errorf("sandboxauth: binding lock parent is not an ordinary directory")
	}
	if err := safefile.ValidatePrivateHandle(parent); err != nil {
		return nil, fmt.Errorf("sandboxauth: binding lock parent is not private: %w", err)
	}

	user, err := bindingLockEffectiveUser()
	if err != nil {
		return nil, fmt.Errorf("sandboxauth: binding lock owner: %w", err)
	}
	// The initial create has a protected, owner-only DACL. An inherited broad
	// DACL would expose a writable lock file even if it were fixed afterward.
	sd, err := windows.SecurityDescriptorFromString(fmt.Sprintf(
		"O:%sD:P(A;;FA;;;SY)(A;;FA;;;%s)", user, user))
	if err != nil {
		return nil, fmt.Errorf("sandboxauth: binding lock descriptor: %w", err)
	}
	unicode, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return nil, fmt.Errorf("sandboxauth: binding lock name: %w", err)
	}
	attrs := &windows.OBJECT_ATTRIBUTES{
		Length:        uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})),
		RootDirectory: parent, ObjectName: unicode,
		Attributes:         windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE,
		SecurityDescriptor: sd,
	}
	var leaf windows.Handle
	var status windows.IO_STATUS_BLOCK
	if err := windows.NtCreateFile(&leaf,
		windows.GENERIC_READ|windows.GENERIC_WRITE|windows.READ_CONTROL|windows.SYNCHRONIZE,
		attrs, &status, nil, windows.FILE_ATTRIBUTE_NORMAL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, windows.FILE_OPEN_IF,
		windows.FILE_NON_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT|windows.FILE_SYNCHRONOUS_IO_NONALERT,
		0, 0); err != nil {
		return nil, fmt.Errorf("sandboxauth: open binding lock: %w", err)
	}
	defer func() {
		if leaf != 0 {
			_ = windows.CloseHandle(leaf)
		}
	}()
	if err := validateBindingLockHandle(leaf); err != nil {
		return nil, err
	}
	var overlapped windows.Overlapped
	if err := windows.LockFileEx(leaf, windows.LOCKFILE_EXCLUSIVE_LOCK,
		0, 1, 0, &overlapped); err != nil {
		return nil, fmt.Errorf("sandboxauth: acquire binding lock: %w", err)
	}
	if err := validateBindingLockHandle(leaf); err != nil {
		_ = windows.UnlockFileEx(leaf, 0, 1, 0, &overlapped)
		return nil, err
	}
	// Transfer both handles to the release closure. The parent prevents a
	// rename during the caller's table read/replace transaction.
	locked, heldParent := leaf, parent
	leaf, parent = 0, 0
	var once sync.Once
	return func() {
		once.Do(func() {
			_ = windows.UnlockFileEx(locked, 0, 1, 0, &overlapped)
			_ = windows.CloseHandle(locked)
			_ = windows.CloseHandle(heldParent)
		})
	}, nil
}

func validateBindingLockHandle(handle windows.Handle) error {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return fmt.Errorf("sandboxauth: inspect binding lock: %w", err)
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
		info.NumberOfLinks != 1 || info.FileSizeHigh != 0 || info.FileSizeLow != 0 {
		return fmt.Errorf("sandboxauth: binding lock is not an ordinary empty single-link file")
	}
	if err := safefile.ValidatePrivateHandle(handle); err != nil {
		return fmt.Errorf("sandboxauth: binding lock is not private: %w", err)
	}
	return nil
}

func bindingLockEffectiveUser() (*windows.SID, error) {
	var token windows.Token
	err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &token)
	if err == nil {
		defer token.Close()
	} else if errors.Is(err, windows.ERROR_NO_TOKEN) {
		token = windows.GetCurrentProcessToken()
	} else {
		return nil, err
	}
	user, err := token.GetTokenUser()
	if err != nil {
		return nil, err
	}
	if user == nil || user.User.Sid == nil {
		return nil, fmt.Errorf("current token has no user SID")
	}
	return user.User.Sid.Copy()
}
