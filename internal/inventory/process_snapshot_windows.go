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
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// processOwnerUID is needed only where ps truncates user names (Linux).
func processOwnerUID(int) string { return "" }

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
	owners := windowsProcessSessionOwners()
	var entries []windowsProcessEntry
	for {
		entries = append(entries, windowsProcessEntry{
			PID: int(entry.ProcessID), PPID: int(entry.ParentProcessID),
			Comm:           windows.UTF16ToString(entry.ExeFile[:]),
			SessionOwnerID: owners[int(entry.ProcessID)],
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
	// The image path needs no process handle, so it is known even for
	// another account's process, which the gateway service cannot open.
	details := windowsProcessDetails{Image: windowsProcessImagePath(uint32(pid))}
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return details, err
	}
	defer windows.CloseHandle(handle)

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

var (
	modWTSAPI32                     = windows.NewLazySystemDLL("wtsapi32.dll")
	procWTSEnumerateProcessesW      = modWTSAPI32.NewProc("WTSEnumerateProcessesW")
	procWTSQuerySessionInformationW = modWTSAPI32.NewProc("WTSQuerySessionInformationW")
)

// wtsProcessInfo is WTS_PROCESS_INFOW.
type wtsProcessInfo struct {
	SessionID   uint32
	ProcessID   uint32
	ProcessName *uint16
	UserSid     *windows.SID
}

// WTS_INFO_CLASS values.
const (
	wtsUserName   = 5
	wtsDomainName = 7
)

// windowsProcessSessionOwners maps each process to the SID of the account
// it runs as. The gateway service cannot open another account's process,
// so neither its token nor (for a machine-wide install such as VS Code's
// copilot-runtime.exe under Program Files) its image path names the owner
// (GAP-2043). Remote Desktop Services answers an unrestricted caller with
// every process's session and every session's user, and with the token SID
// of the processes the caller may see; session 0 has no user. It refuses
// the managed gateway's restricted service token, which gets the owner from
// the sensor helper instead (SetProcessAccountLookup).
func windowsProcessSessionOwners() map[int]string {
	var info *wtsProcessInfo
	var count uint32
	if r, _, _ := procWTSEnumerateProcessesW.Call(0, 0, 1, uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&count))); r == 0 || info == nil {
		return nil
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(info)))
	sessions := map[uint32]string{}
	owners := make(map[int]string, count)
	for _, row := range unsafe.Slice(info, count) {
		sid := ""
		if row.UserSid != nil && row.UserSid.IsValid() {
			sid = row.UserSid.String()
		} else if row.SessionID != 0 {
			cached, ok := sessions[row.SessionID]
			if !ok {
				cached = windowsSessionUserSID(row.SessionID)
				sessions[row.SessionID] = cached
			}
			sid = cached
		}
		if sid != "" {
			owners[int(row.ProcessID)] = sid
		}
	}
	return owners
}

// windowsSessionUserSID is the SID of the account signed in to session, or "".
func windowsSessionUserSID(session uint32) string {
	user := windowsSessionString(session, wtsUserName)
	if user == "" {
		return ""
	}
	if domain := windowsSessionString(session, wtsDomainName); domain != "" {
		user = domain + `\` + user
	}
	sid, _, _, err := windows.LookupSID("", user)
	if err != nil {
		return ""
	}
	return sid.String()
}

func windowsSessionString(session uint32, class uintptr) string {
	var buf *uint16
	var size uint32
	if r, _, _ := procWTSQuerySessionInformationW.Call(0, uintptr(session), class, uintptr(unsafe.Pointer(&buf)), uintptr(unsafe.Pointer(&size))); r == 0 || buf == nil {
		return ""
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(buf)))
	return windows.UTF16PtrToString(buf)
}

// systemProcessIDInformation is SYSTEM_PROCESS_ID_INFORMATION, the
// NtQuerySystemInformation class that names a process's image without a
// handle to it.
type systemProcessIDInformation struct {
	ProcessID uintptr
	ImageName windows.NTUnicodeString
}

const systemProcessIDInformationClass = 88

// windowsProcessImagePath returns pid's executable as a drive path, or ""
// when Windows does not report one.
func windowsProcessImagePath(pid uint32) string {
	if pid == 0 {
		return ""
	}
	buf := make([]uint16, 4096)
	info := systemProcessIDInformation{ProcessID: uintptr(pid)}
	info.ImageName.MaximumLength = uint16(len(buf) * 2)
	info.ImageName.Buffer = &buf[0]
	if err := windows.NtQuerySystemInformation(systemProcessIDInformationClass, unsafe.Pointer(&info), uint32(unsafe.Sizeof(info)), nil); err != nil {
		return ""
	}
	n := int(info.ImageName.Length / 2)
	if n <= 0 || n > len(buf) {
		return ""
	}
	return windowsDrivePathForDevicePath(windows.UTF16ToString(buf[:n]), windowsDeviceDrives())
}

// windowsDrivePathForDevicePath turns \Device\HarddiskVolume3\Users\a\x.exe into
// C:\Users\a\x.exe with the drives' device names.
func windowsDrivePathForDevicePath(path string, drives map[string]string) string {
	for device, drive := range drives {
		if len(path) > len(device) && path[len(device)] == '\\' && strings.EqualFold(path[:len(device)], device) {
			return drive + path[len(device):]
		}
	}
	return ""
}

var windowsDeviceDriveCache struct {
	sync.Mutex
	at     time.Time
	drives map[string]string
}

// windowsDeviceDrives maps each drive's device name to its letter, refreshed
// at most once a minute.
func windowsDeviceDrives() map[string]string {
	windowsDeviceDriveCache.Lock()
	defer windowsDeviceDriveCache.Unlock()
	if windowsDeviceDriveCache.drives != nil && time.Since(windowsDeviceDriveCache.at) < time.Minute {
		return windowsDeviceDriveCache.drives
	}
	drives := map[string]string{}
	mask, err := windows.GetLogicalDrives()
	if err == nil {
		target := make([]uint16, 512)
		for i := 0; i < 26; i++ {
			if mask&(1<<uint(i)) == 0 {
				continue
			}
			drive := string(rune('A'+i)) + ":"
			name, nameErr := windows.UTF16PtrFromString(drive)
			if nameErr != nil {
				continue
			}
			if n, qErr := windows.QueryDosDevice(name, &target[0], uint32(len(target))); qErr == nil && n > 0 {
				if device := windows.UTF16ToString(target); device != "" {
					drives[device] = drive
				}
			}
		}
	}
	windowsDeviceDriveCache.drives, windowsDeviceDriveCache.at = drives, time.Now()
	return drives
}
