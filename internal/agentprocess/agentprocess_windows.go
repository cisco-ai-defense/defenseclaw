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
	"unsafe"

	"golang.org/x/sys/windows"
)

// stillActive is STILL_ACTIVE, the exit code of a running process.
const stillActive = 259

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
