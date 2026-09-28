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
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
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
	if exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid)); err == nil {
		process.Name = filepath.Base(strings.TrimSuffix(exe, " (deleted)"))
	}
	process.Boot = currentBootID()
	return process, nil
}

// parseStat parses /proc/<pid>/stat: "pid (comm) state ppid ... starttime"
// with starttime the 22nd field. comm may hold spaces and parentheses, so
// the fields after it start at the last ')'.
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
