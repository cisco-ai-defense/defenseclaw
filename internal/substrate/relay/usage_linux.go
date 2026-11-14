// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package relay

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// clockTicks is USER_HZ, the unit of /proc/<pid>/stat CPU times (100 on
// every Linux the actor images run).
const clockTicks = 100

// processGroupUsage sums the CPU time and the I/O bytes (rchar + wchar) of
// the live processes of process group pgid, from /proc. A process whose
// io file cannot be read adds its CPU time only.
func processGroupUsage(pgid int) (Usage, bool) {
	return procGroupUsage("/proc", pgid)
}

func procGroupUsage(proc string, pgid int) (Usage, bool) {
	ents, err := os.ReadDir(proc)
	if err != nil {
		return Usage{}, false
	}
	var u Usage
	found := false
	for _, e := range ents {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		dir := filepath.Join(proc, e.Name())
		stat, err := os.ReadFile(filepath.Join(dir, "stat"))
		if err != nil {
			continue
		}
		group, cpu, ok := parseProcStat(stat)
		if !ok || group != pgid {
			continue
		}
		found = true
		u.CPU += cpu
		u.IO += readProcIO(filepath.Join(dir, "io"))
	}
	return u, found
}

// parseProcStat reads the process group and utime + stime of a stat line;
// the command name in parentheses may hold spaces and parentheses.
func parseProcStat(b []byte) (int, time.Duration, bool) {
	i := bytes.LastIndexByte(b, ')')
	if i < 0 || i+2 > len(b) {
		return 0, 0, false
	}
	f := strings.Fields(string(b[i+1:]))
	// f[0] state, f[1] ppid, f[2] pgrp, ..., f[11] utime, f[12] stime.
	if len(f) < 13 {
		return 0, 0, false
	}
	group, err1 := strconv.Atoi(f[2])
	ut, err2 := strconv.ParseUint(f[11], 10, 64)
	st, err3 := strconv.ParseUint(f[12], 10, 64)
	if err1 != nil || err2 != nil || err3 != nil {
		return 0, 0, false
	}
	return group, time.Duration(ut+st) * time.Second / clockTicks, true
}

func readProcIO(path string) uint64 {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	var n uint64
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if !ok || (k != "rchar" && k != "wchar") {
			continue
		}
		if x, err := strconv.ParseUint(strings.TrimSpace(v), 10, 64); err == nil {
			n += x
		}
	}
	return n
}
