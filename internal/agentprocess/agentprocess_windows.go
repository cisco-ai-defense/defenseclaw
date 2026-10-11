// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package agentprocess

import (
	"errors"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// stillActive is STILL_ACTIVE, the exit code of a running process.
const stillActive = 259

// currentClock reads the wall clock as a FILETIME, the unit of process
// creation times.
func currentClock() (string, int64, bool) {
	now := windows.NsecToFiletime(time.Now().UnixNano())
	return "", int64(now.HighDateTime)<<32 | int64(now.LowDateTime), true
}

// newLookup takes one process snapshot for the parent links and names, and
// reads each start time from the process itself. A process that is not in
// the snapshot and cannot be opened does not exist.
func newLookup() (func(int) (Process, error), func()) {
	type entry struct {
		parent int
		name   string
	}
	entries := map[int]entry{}
	if snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0); err == nil {
		var row windows.ProcessEntry32
		row.Size = uint32(unsafe.Sizeof(row))
		for err = windows.Process32First(snapshot, &row); err == nil; err = windows.Process32Next(snapshot, &row) {
			entries[int(row.ProcessID)] = entry{parent: int(row.ParentProcessID), name: windows.UTF16ToString(row.ExeFile[:])}
		}
		_ = windows.CloseHandle(snapshot)
	}
	lookup := func(pid int) (Process, error) {
		start, exited, err := processStart(pid)
		if err != nil {
			return Process{}, err
		}
		process := Process{PID: pid, Start: start, Exited: exited}
		if found, ok := entries[pid]; ok {
			process.Parent, process.Name = found.parent, found.name
		}
		return process, nil
	}
	return lookup, func() {}
}

func executablePath(pid int) string {
	if pid <= 0 || pid > int(^uint32(0)) {
		return ""
	}
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(handle)
	buf := make([]uint16, windows.MAX_LONG_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(handle, 0, &buf[0], &size); err != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:size])
}

// commandLine reads the process's command line (ProcessCommandLineInformation,
// which PROCESS_QUERY_LIMITED_INFORMATION may read) and splits it as the C
// runtime does. Windows does not report another process's working directory
// here.
func commandLine(pid int) ([]string, string, error) {
	if pid <= 0 || pid > int(^uint32(0)) {
		return nil, "", errNotFound
	}
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return nil, "", err
	}
	defer windows.CloseHandle(handle)
	buf := make([]byte, 8192)
	for {
		var size uint32
		err = windows.NtQueryInformationProcess(handle, windows.ProcessCommandLineInformation,
			unsafe.Pointer(&buf[0]), uint32(len(buf)), &size)
		if err == nil {
			break
		}
		tooSmall := errors.Is(err, windows.STATUS_INFO_LENGTH_MISMATCH) || errors.Is(err, windows.STATUS_BUFFER_TOO_SMALL) ||
			errors.Is(err, windows.STATUS_BUFFER_OVERFLOW)
		if !tooSmall || size <= uint32(len(buf)) || size > 2*maxCommandLineBytes+64 {
			return nil, "", err
		}
		buf = make([]byte, size)
	}
	line := (*windows.NTUnicodeString)(unsafe.Pointer(&buf[0])).String()
	args, err := windows.DecomposeCommandLine(line)
	if err != nil {
		return nil, "", err
	}
	return args, "", nil
}

func processStart(pid int) (int64, bool, error) {
	if pid <= 0 || pid > int(^uint32(0)) {
		return 0, false, errNotFound
	}
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
		return 0, false, errNotFound
	}
	if err != nil {
		return 0, false, err
	}
	defer windows.CloseHandle(handle)
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(handle, &creation, &exit, &kernel, &user); err != nil {
		return 0, false, err
	}
	var code uint32
	exited := windows.GetExitCodeProcess(handle, &code) == nil && code != stillActive
	return int64(creation.HighDateTime)<<32 | int64(creation.LowDateTime), exited, nil
}
