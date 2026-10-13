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
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

var (
	bootOnce sync.Once
	bootID   string
)

func currentBootID() string {
	bootOnce.Do(func() {
		if data, err := os.ReadFile("/proc/sys/kernel/random/boot_id"); err == nil {
			bootID = strings.TrimSpace(string(data))
		}
	})
	return bootID
}

func newLookup() (func(int) (Process, error), func()) { return lookupProc, func() {} }

// linuxClockTicks is USER_HZ, the unit of the start time in /proc/<pid>/stat.
const linuxClockTicks = 100

// currentClock reads the boot-based clock that /proc/<pid>/stat start times
// count, in the same ticks.
func currentClock() (string, int64, bool) {
	boot := currentBootID()
	var now unix.Timespec
	if boot == "" || unix.ClockGettime(unix.CLOCK_BOOTTIME, &now) != nil {
		return "", 0, false
	}
	return boot, now.Nano() / (1_000_000_000 / linuxClockTicks), true
}

// lookupProc reads /proc/<pid>/stat. The name comes from the executable
// link, not the command name: the kernel names a process started from a
// script after the script ("cursor-hook.sh"), while its executable is the
// shell that runs it.
func lookupProc(pid int) (Process, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ESRCH) {
		return Process{}, errNotFound
	}
	if err != nil {
		return Process{}, err
	}
	process, err := parseStat(pid, data)
	if err != nil {
		return Process{}, err
	}
	if exe := executablePath(pid); exe != "" {
		process.Name = filepath.Base(exe)
	}
	process.Boot = currentBootID()
	return process, nil
}

// parseStat parses /proc/<pid>/stat: "pid (comm) state ppid ... starttime"
// with starttime the 22nd field. comm may hold spaces and parentheses, so
// the fields after it start at the last ')'.
func executablePath(pid int) string {
	exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return ""
	}
	return strings.TrimSuffix(exe, " (deleted)")
}

// commandLine reads /proc/<pid>/cmdline, NUL-separated arguments, and the
// process's working directory.
func commandLine(pid int) ([]string, string, error) {
	file, err := os.Open(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return nil, "", err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxCommandLineBytes+1))
	if err != nil {
		return nil, "", err
	}
	if len(data) > maxCommandLineBytes {
		return nil, "", fmt.Errorf("the command line of process %d exceeds %d bytes", pid, maxCommandLineBytes)
	}
	if len(data) == 0 {
		return nil, "", fmt.Errorf("process %d has no command line", pid)
	}
	dir, _ := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
	return strings.Split(strings.TrimSuffix(string(data), "\x00"), "\x00"), dir, nil
}

func parseStat(pid int, data []byte) (Process, error) {
	open := bytes.IndexByte(data, '(')
	closing := bytes.LastIndexByte(data, ')')
	if open < 0 || closing < open || closing+2 > len(data) {
		return Process{}, fmt.Errorf("malformed /proc/%d/stat", pid)
	}
	fields := strings.Fields(string(data[closing+2:]))
	if len(fields) < 20 {
		return Process{}, fmt.Errorf("malformed /proc/%d/stat", pid)
	}
	parent, err := strconv.Atoi(fields[1])
	if err != nil {
		return Process{}, fmt.Errorf("malformed /proc/%d/stat: %w", pid, err)
	}
	start, err := strconv.ParseInt(fields[19], 10, 64)
	if err != nil {
		return Process{}, fmt.Errorf("malformed /proc/%d/stat: %w", pid, err)
	}
	return Process{
		PID:    pid,
		Parent: parent,
		Name:   string(data[open+1 : closing]),
		Start:  start,
		Exited: fields[0] == "Z" || fields[0] == "X",
	}, nil
}
