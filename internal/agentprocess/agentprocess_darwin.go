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
	"bytes"
	"errors"
	"time"

	"golang.org/x/sys/unix"
)

// darwinZombie is SZOMB in <sys/proc.h>.
const darwinZombie = 5

func newLookup() (func(int) (Process, error), func()) { return lookupSysctl, func() {} }

// currentClock reads the wall clock start times count, in microseconds.
func currentClock() (string, int64, bool) { return "", time.Now().UnixMicro(), true }

// lookupSysctl reads kern.proc.pid.<pid>. A process that does not exist
// returns no record, which x/sys reports as EIO.
func lookupSysctl(pid int) (Process, error) {
	info, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if errors.Is(err, unix.EIO) || errors.Is(err, unix.ESRCH) {
		return Process{}, errNotFound
	}
	if err != nil {
		return Process{}, err
	}
	if int(info.Proc.P_pid) != pid {
		return Process{}, errNotFound
	}
	start := info.Proc.P_starttime
	return Process{
		PID:    pid,
		Parent: int(info.Eproc.Ppid),
		Name:   unix.ByteSliceToString(info.Proc.P_comm[:]),
		Start:  int64(start.Sec)*1_000_000 + int64(start.Usec),
		Exited: info.Proc.P_stat == darwinZombie,
	}, nil
}

// executablePath reads the executable path kern.procargs2 records after its
// 4-byte argument count.
func executablePath(pid int) string {
	data, err := unix.SysctlRaw("kern.procargs2", pid)
	if err != nil || len(data) <= 4 {
		return ""
	}
	path := data[4:]
	if end := bytes.IndexByte(path, 0); end >= 0 {
		path = path[:end]
	}
	return string(path)
}
