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

package inventory

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func platformProcessSnapshot() ([]processInfo, error) {
	return collectWindowsSnapshot(nativeWindowsSnapshotReader{})
}

type nativeWindowsSnapshotReader struct{}

func (nativeWindowsSnapshotReader) List() ([]windowsProcessEntry, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot: %w", err)
	}
	defer windows.CloseHandle(snapshot)

	entry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	if err := windows.Process32First(snapshot, &entry); err != nil {
		if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
			return []windowsProcessEntry{}, nil
		}
		return nil, fmt.Errorf("Process32First: %w", err)
	}
	var entries []windowsProcessEntry
	for {
		entries = append(entries, windowsProcessEntry{
			PID: int(entry.ProcessID), PPID: int(entry.ParentProcessID),
			Comm: windows.UTF16ToString(entry.ExeFile[:]),
		})
		entry.Size = uint32(unsafe.Sizeof(windows.ProcessEntry32{}))
		if err := windows.Process32Next(snapshot, &entry); err != nil {
			if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
				break
			}
			return nil, fmt.Errorf("Process32Next: %w", err)
		}
	}
	return entries, nil
}

func (nativeWindowsSnapshotReader) Details(pid int) (windowsProcessDetails, error) {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return windowsProcessDetails{}, err
	}
	defer windows.CloseHandle(handle)

	var details windowsProcessDetails
	var creation, exit, kernel, user windows.Filetime
	var errs []error
	if err := windows.GetProcessTimes(handle, &creation, &exit, &kernel, &user); err == nil {
		details.StartedAt = time.Unix(0, creation.Nanoseconds()).UTC()
	} else {
		errs = append(errs, err)
	}
	var token windows.Token
	if err := windows.OpenProcessToken(handle, windows.TOKEN_QUERY, &token); err == nil {
		if tokenUser, err := token.GetTokenUser(); err == nil {
			account, domain, _, lookupErr := tokenUser.User.Sid.LookupAccount("")
			if lookupErr == nil {
				details.User = account
				if domain != "" {
					details.User = strings.Join([]string{domain, account}, `\`)
				}
			} else {
				errs = append(errs, lookupErr)
			}
		} else {
			errs = append(errs, err)
		}
		token.Close()
	} else {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return details, fmt.Errorf("partial process metadata: %w", errors.Join(errs...))
	}
	return details, nil
}
