// Copyright 2026 Cisco Systems, Inc. and its affiliates
// Copyright (c) 2026 Mike Storm. All rights reserved.
//
// Derived from ShadowClaw -- Universal Shadow AI Detector, by Mike Storm,
// Distinguished Engineer, CCIE Security 13847. Reimplemented in Go and
// absorbed into the DefenseClaw gateway; see NOTICE for the modifications.
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
	"errors"
	"fmt"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// maxCmdlineBytes bounds the argv retained per process.
const maxCmdlineBytes = 16 << 10

// snapshot enumerates the process table with Toolhelp32 and enriches each row
// with CPU time, resident memory, and argv.
//
// None of the three enrichments is required for a usable row. A process owned
// by another user or running at a higher integrity level will refuse
// OpenProcess, and that refusal is ordinary rather than exceptional -- it is
// the same asymmetry ps and /proc already have. Such a row is retained with the
// Toolhelp fields it does have and counted, so an unprivileged run can report
// how much of the table it could not fully read.
func snapshot() ([]Process, int, error) {
	handle, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, 0, fmt.Errorf("CreateToolhelp32Snapshot: %w", err)
	}
	defer windows.CloseHandle(handle)

	entry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	if err := windows.Process32First(handle, &entry); err != nil {
		if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
			return []Process{}, 0, nil
		}
		return nil, 0, fmt.Errorf("Process32First: %w", err)
	}

	rows := make([]Process, 0, 256)
	partial := 0
	for {
		row := Process{
			PID:  int(entry.ProcessID),
			PPID: int(entry.ParentProcessID),
			Name: windows.UTF16ToString(entry.ExeFile[:]),
		}
		if row.PID > 0 {
			if !enrich(&row) {
				partial++
			}
			rows = append(rows, row)
		}
		entry.Size = uint32(unsafe.Sizeof(windows.ProcessEntry32{}))
		if err := windows.Process32Next(handle, &entry); err != nil {
			if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
				break
			}
			return rows, partial, fmt.Errorf("Process32Next: %w", err)
		}
	}
	return rows, partial, nil
}

// enrich fills CPU, RSS, user, and argv. It reports false when the process
// handle could not be opened at all, which is the case worth counting.
func enrich(row *Process) bool {
	const access = windows.PROCESS_QUERY_LIMITED_INFORMATION | windows.PROCESS_VM_READ
	process, err := windows.OpenProcess(access, false, uint32(row.PID))
	if err != nil {
		// Retry without VM_READ: CPU and RSS are available at the limited
		// level, and only argv needs the read. Losing argv is worth reporting
		// but is not worth losing the row.
		process, err = windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(row.PID))
		if err != nil {
			return false
		}
		defer windows.CloseHandle(process)
		readTimes(process, row)
		readMemory(process, row)
		row.User = readUser(process)
		return false
	}
	defer windows.CloseHandle(process)
	readTimes(process, row)
	readMemory(process, row)
	row.User = readUser(process)
	if cmdline, err := readCommandLine(process); err == nil {
		row.Cmdline = cmdline
	}
	return true
}

func readTimes(process windows.Handle, row *Process) {
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(process, &creation, &exit, &kernel, &user); err != nil {
		return
	}
	// Filetime counts 100-nanosecond intervals.
	ticks := int64(kernel.HighDateTime)<<32 | int64(kernel.LowDateTime)
	ticks += int64(user.HighDateTime)<<32 | int64(user.LowDateTime)
	row.CPUTime = time.Duration(ticks) * 100 * time.Nanosecond
}

// processMemoryCounters mirrors PROCESS_MEMORY_COUNTERS. golang.org/x/sys does
// not bind it, so the struct and the psapi entry point are declared here.
type processMemoryCounters struct {
	CB                         uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
}

var (
	// K32GetProcessMemoryInfo lives in kernel32 on every supported release and
	// forwards to psapi, which avoids a second DLL load.
	modKernel32              = windows.NewLazySystemDLL("kernel32.dll")
	procGetProcessMemoryInfo = modKernel32.NewProc("K32GetProcessMemoryInfo")
)

func readMemory(process windows.Handle, row *Process) {
	var counters processMemoryCounters
	counters.CB = uint32(unsafe.Sizeof(counters))
	ret, _, _ := procGetProcessMemoryInfo.Call(
		uintptr(process), uintptr(unsafe.Pointer(&counters)), uintptr(counters.CB),
	)
	if ret == 0 {
		return
	}
	row.RSSBytes = int64(counters.WorkingSetSize)
}

func readUser(process windows.Handle) string {
	var token windows.Token
	if err := windows.OpenProcessToken(process, windows.TOKEN_QUERY, &token); err != nil {
		return ""
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return ""
	}
	account, _, _, err := user.User.Sid.LookupAccount("")
	if err != nil {
		return ""
	}
	return account
}

// processBasicInformation mirrors PROCESS_BASIC_INFORMATION. Only PebBaseAddress
// is read; the remaining fields exist so the struct size matches what
// NtQueryInformationProcess expects.
type processBasicInformation struct {
	ExitStatus                   uintptr
	PebBaseAddress               uintptr
	AffinityMask                 uintptr
	BasePriority                 uintptr
	UniqueProcessID              uintptr
	InheritedFromUniqueProcessID uintptr
}

// unicodeString mirrors UNICODE_STRING.
type unicodeString struct {
	Length        uint16
	MaximumLength uint16
	_             [4]byte // padding on 64-bit before the 8-byte pointer
	Buffer        uintptr
}

// PEB and RTL_USER_PROCESS_PARAMETERS field offsets for 64-bit Windows. These
// are stable across every supported release; the structures are documented and
// the offsets before the fields read here have not moved.
const (
	pebProcessParametersOffset = 0x20
	paramsCommandLineOffset    = 0x70
)

// readCommandLine reads the target's argv out of its PEB.
//
// There is no supported Win32 call that returns another process's command
// line, and this is the documented route the platform's own tooling takes.
// Each step is bounds-checked because the target controls the memory being
// read: a hostile or merely corrupt process must not be able to make this
// allocate without limit or read outside the length it declares.
func readCommandLine(process windows.Handle) (string, error) {
	var info processBasicInformation
	var returned uint32
	status := windows.NtQueryInformationProcess(
		process, windows.ProcessBasicInformation,
		unsafe.Pointer(&info), uint32(unsafe.Sizeof(info)), &returned,
	)
	if status != nil {
		return "", status
	}
	if info.PebBaseAddress == 0 {
		return "", errors.New("procprobe: process has no readable PEB")
	}

	var parameters uintptr
	if err := readRemote(process, info.PebBaseAddress+pebProcessParametersOffset,
		unsafe.Pointer(&parameters), unsafe.Sizeof(parameters)); err != nil {
		return "", err
	}
	if parameters == 0 {
		return "", errors.New("procprobe: process has no readable parameter block")
	}

	var commandLine unicodeString
	if err := readRemote(process, parameters+paramsCommandLineOffset,
		unsafe.Pointer(&commandLine), unsafe.Sizeof(commandLine)); err != nil {
		return "", err
	}
	length := int(commandLine.Length)
	if length <= 0 || commandLine.Buffer == 0 {
		return "", nil
	}
	if length > maxCmdlineBytes {
		length = maxCmdlineBytes
	}
	if length%2 == 1 {
		length--
	}
	buffer := make([]uint16, length/2)
	if err := readRemote(process, commandLine.Buffer,
		unsafe.Pointer(&buffer[0]), uintptr(length)); err != nil {
		return "", err
	}
	return windows.UTF16ToString(buffer), nil
}

func readRemote(process windows.Handle, address uintptr, into unsafe.Pointer, size uintptr) error {
	var read uintptr
	if err := windows.ReadProcessMemory(
		process, address, (*byte)(into), size, &read,
	); err != nil {
		return err
	}
	if read != size {
		return fmt.Errorf("procprobe: short remote read at %#x (%d of %d bytes)", address, read, size)
	}
	return nil
}
