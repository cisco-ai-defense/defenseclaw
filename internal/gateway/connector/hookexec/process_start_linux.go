// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hookexec

import (
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// linuxClockTicks is USER_HZ, the unit of /proc/<pid>/stat's starttime: 100
// on every Linux architecture DefenseClaw ships for.
const linuxClockTicks = 100

// processStartTime reads the start of this process from /proc/self/stat, in
// clock ticks since boot, and turns it into an age against CLOCK_BOOTTIME
// (the clock the kernel counts it on), so a wall-clock step does not move it.
// processStartTimeKnown reports a system that names the process start.
const processStartTimeKnown = true

func processStartTime(now time.Time) (time.Time, bool) {
	return procStatStartTime("/proc/self/stat", now)
}

// processStartTimeOf is when process pid started, read as processStartTime
// reads this one; false when /proc does not say.
func processStartTimeOf(pid int, now time.Time) (time.Time, bool) {
	return procStatStartTime("/proc/"+strconv.Itoa(pid)+"/stat", now)
}

func procStatStartTime(path string, now time.Time) (time.Time, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return time.Time{}, false
	}
	ticks, ok := parseProcStatStartTicks(string(data))
	if !ok {
		return time.Time{}, false
	}
	var boot unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &boot); err != nil {
		return time.Time{}, false
	}
	sinceBoot := time.Duration(boot.Nano())
	startedSinceBoot := time.Duration(ticks) * time.Second / linuxClockTicks
	return now.Add(-(sinceBoot - startedSinceBoot)), true
}

// parseProcStatStartTicks returns field 22 (starttime) of a /proc/<pid>/stat
// line. The command name (field 2) is in parentheses and may hold spaces, so
// the fields are counted from the last ')'.
func parseProcStatStartTicks(stat string) (uint64, bool) {
	end := strings.LastIndexByte(stat, ')')
	if end < 0 {
		return 0, false
	}
	fields := strings.Fields(stat[end+1:])
	// fields[0] is field 3 (state), so field 22 is fields[19].
	if len(fields) < 20 {
		return 0, false
	}
	ticks, err := strconv.ParseUint(fields[19], 10, 64)
	return ticks, err == nil
}
