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

package procprobe

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modWTSAPI32                     = windows.NewLazySystemDLL("wtsapi32.dll")
	procWTSQuerySessionInformationW = modWTSAPI32.NewProc("WTSQuerySessionInformationW")
)

// WTS_INFO_CLASS values.
const (
	wtsUserName   = 5
	wtsDomainName = 7
)

// processSessions maps every pid to its session. The kernel's process list
// names the session of each process without a handle to it, so it answers
// for other accounts' processes too, which this service cannot open.
func processSessions() map[uint32]uint32 {
	size := uint32(1 << 20)
	for attempt := 0; attempt < 4; attempt++ {
		buffer := make([]byte, size)
		var needed uint32
		err := windows.NtQuerySystemInformation(windows.SystemProcessInformation,
			unsafe.Pointer(&buffer[0]), size, &needed)
		if err == windows.STATUS_INFO_LENGTH_MISMATCH {
			size = max(needed, size) + 256<<10
			continue
		}
		if err != nil {
			return nil
		}
		return parseProcessSessions(buffer)
	}
	return nil
}

// parseProcessSessions walks a SystemProcessInformation buffer. Each entry
// is bounds-checked against the buffer before it is read.
func parseProcessSessions(buffer []byte) map[uint32]uint32 {
	entrySize := int(unsafe.Sizeof(windows.SYSTEM_PROCESS_INFORMATION{}))
	sessions := make(map[uint32]uint32, 256)
	for offset := 0; offset >= 0 && offset+entrySize <= len(buffer); {
		info := (*windows.SYSTEM_PROCESS_INFORMATION)(unsafe.Pointer(&buffer[offset]))
		if info.UniqueProcessID != 0 {
			sessions[uint32(info.UniqueProcessID)] = info.SessionID
		}
		if info.NextEntryOffset == 0 {
			break
		}
		offset += int(info.NextEntryOffset)
	}
	return sessions
}

// SessionUser names the account signed in to a Windows session as
// DOMAIN\name (COMPUTER\name for a local account) with its SID. It returns
// empty strings for session 0, a session nobody is signed in to, and when
// Remote Desktop Services refuses the caller.
func SessionUser(session uint32) (name, sid string) {
	if session == 0 {
		return "", ""
	}
	user := sessionString(session, wtsUserName)
	if user == "" {
		return "", ""
	}
	if domain := sessionString(session, wtsDomainName); domain != "" {
		user = domain + `\` + user
	}
	account, _, _, err := windows.LookupSID("", user)
	if err != nil {
		return "", ""
	}
	return user, account.String()
}

func sessionString(session uint32, class uintptr) string {
	var buffer *uint16
	var size uint32
	if r, _, _ := procWTSQuerySessionInformationW.Call(0, uintptr(session), class,
		uintptr(unsafe.Pointer(&buffer)), uintptr(unsafe.Pointer(&size))); r == 0 || buffer == nil {
		return ""
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(buffer)))
	return windows.UTF16PtrToString(buffer)
}
