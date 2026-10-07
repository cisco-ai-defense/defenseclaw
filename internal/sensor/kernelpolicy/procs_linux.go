//go:build linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package kernelpolicy

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/sensor/tactics"
)

const (
	cmdlineLimit = 8192
	cmdlineArgs  = 32
	statusLimit  = 4096
)

// ScanProcs reads procRoot (/proc). A process of an enrolled uid is read in
// full; any other process is read as far as its name, and kept only when the
// name is a known agent (it is reported as not enrolled). Processes that
// vanish mid-scan are skipped.
func ScanProcs(procRoot string, enrolled func(uid int) bool) ([]Proc, error) {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, err
	}
	hostNS, hostErr := os.Readlink(filepath.Join(procRoot, "self", "ns", "pid"))
	var out []Proc
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		dir := filepath.Join(procRoot, entry.Name())
		uid, euid, ok := readUIDs(filepath.Join(dir, "status"))
		if !ok {
			continue
		}
		p := Proc{PID: pid, UID: uid, EUID: euid}
		if hostErr == nil && hostNS != "" {
			if ns, err := os.Readlink(filepath.Join(dir, "ns", "pid")); err == nil {
				p.Host = ns == hostNS
			}
		}
		stat, ok := readStat(filepath.Join(dir, "stat"))
		if !ok {
			continue
		}
		p.PPID, p.StartTicks, p.Comm = stat.ppid, stat.start, stat.comm
		if !enrolled(uid) {
			if tactics.IsAgentProcess(p.Comm) {
				out = append(out, p)
			}
			continue
		}
		if exe, err := os.Readlink(filepath.Join(dir, "exe")); err == nil {
			p.Exe = strings.TrimSuffix(exe, " (deleted)")
		}
		if cwd, err := os.Readlink(filepath.Join(dir, "cwd")); err == nil {
			p.Cwd = cwd
		}
		p.Cmdline = readCmdline(filepath.Join(dir, "cmdline"))
		// /proc files are read separately. A PID can exit and be reused while
		// we read exe and argv; never combine an old identity with a new one.
		again, statOK := readStat(filepath.Join(dir, "stat"))
		againUID, againEUID, uidOK := readUIDs(filepath.Join(dir, "status"))
		if !statOK || !uidOK || again.start != p.StartTicks || againUID != uid || againEUID != euid {
			continue
		}
		out = append(out, p)
	}
	return out, nil
}

func readSmall(path string, limit int64) ([]byte, bool) {
	file, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit))
	if err != nil {
		return nil, false
	}
	return data, true
}

func readUIDs(path string) (uid, euid int, ok bool) {
	data, read := readSmall(path, statusLimit)
	if !read {
		return 0, 0, false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "Uid:") {
			continue
		}
		fields := strings.Fields(strings.TrimPrefix(line, "Uid:"))
		if len(fields) < 2 {
			return 0, 0, false
		}
		real, err1 := strconv.Atoi(fields[0])
		effective, err2 := strconv.Atoi(fields[1])
		return real, effective, err1 == nil && err2 == nil
	}
	return 0, 0, false
}

type procStat struct {
	comm  string
	ppid  int
	start uint64
}

// readStat parses /proc/<pid>/stat. comm is parenthesized and may contain
// spaces and parentheses, so the fields are counted after the last ')'.
func readStat(path string) (procStat, bool) {
	data, ok := readSmall(path, statusLimit)
	if !ok {
		return procStat{}, false
	}
	open, closeIdx := bytes.IndexByte(data, '('), bytes.LastIndexByte(data, ')')
	if open < 0 || closeIdx < open {
		return procStat{}, false
	}
	fields := strings.Fields(string(data[closeIdx+1:]))
	// state ppid pgrp session tty_nr tpgid flags minflt cminflt majflt
	// cmajflt utime stime cutime cstime priority nice num_threads
	// itrealvalue starttime
	if len(fields) < 20 {
		return procStat{}, false
	}
	ppid, err1 := strconv.Atoi(fields[1])
	start, err2 := strconv.ParseUint(fields[19], 10, 64)
	if err1 != nil || err2 != nil {
		return procStat{}, false
	}
	return procStat{comm: string(data[open+1 : closeIdx]), ppid: ppid, start: start}, true
}

func readCmdline(path string) []string {
	data, ok := readSmall(path, cmdlineLimit)
	if !ok || len(data) == 0 {
		return nil
	}
	parts := bytes.Split(bytes.TrimRight(data, "\x00"), []byte{0})
	if len(parts) > cmdlineArgs {
		parts = parts[:cmdlineArgs]
	}
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		out = append(out, string(part))
	}
	return out
}
