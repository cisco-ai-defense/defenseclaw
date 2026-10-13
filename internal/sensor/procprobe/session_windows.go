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
	"time"
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

// processFact is what the kernel's process list says about one process
// without a handle to it.
type processFact struct {
	ppid    uint32
	session uint32
	// created is the kernel's creation time, the start half of the
	// process's ProcKey (GAP-1372).
	created time.Time
}

// processFacts maps every pid to its parent, session and creation time. The
// kernel's process list names them without a handle to the process, so it
// answers for other accounts' processes too, which this service cannot
// open -- and a creation time read without OpenProcess is what keeps a
// recycled pid from passing for the process that held it before.
func processFacts() map[uint32]processFact {
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
		return parseProcessFacts(buffer)
	}
	return nil
}

// parseProcessFacts walks a SystemProcessInformation buffer. Each entry is
// bounds-checked against the buffer before it is read.
func parseProcessFacts(buffer []byte) map[uint32]processFact {
	entrySize := int(unsafe.Sizeof(windows.SYSTEM_PROCESS_INFORMATION{}))
	facts := make(map[uint32]processFact, 256)
	for offset := 0; offset >= 0 && offset+entrySize <= len(buffer); {
		info := (*windows.SYSTEM_PROCESS_INFORMATION)(unsafe.Pointer(&buffer[offset]))
		if info.UniqueProcessID != 0 {
			fact := processFact{ppid: uint32(info.InheritedFromUniqueProcessID), session: info.SessionID}
			if info.CreateTime > 0 {
				filetime := windows.Filetime{
					LowDateTime: uint32(info.CreateTime), HighDateTime: uint32(info.CreateTime >> 32),
				}
				fact.created = time.Unix(0, filetime.Nanoseconds())
			}
			facts[uint32(info.UniqueProcessID)] = fact
		}
		if info.NextEntryOffset == 0 {
			break
		}
		offset += int(info.NextEntryOffset)
	}
	return facts
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
