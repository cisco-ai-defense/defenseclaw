// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package procidentity

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// clockTicks is USER_HZ, the unit of /proc/<pid>/stat starttime: 100 on
// every Linux the release supports.
const clockTicks = 100

func startTime(pid int) (time.Time, bool) {
	stat, err := os.ReadFile("/proc/stat")
	if err != nil {
		return time.Time{}, false
	}
	var boot int64 = -1
	for _, line := range strings.Split(string(stat), "\n") {
		if rest, ok := strings.CutPrefix(line, "btime "); ok {
			boot, err = strconv.ParseInt(strings.TrimSpace(rest), 10, 64)
			if err != nil {
				return time.Time{}, false
			}
			break
		}
	}
	if boot < 0 {
		return time.Time{}, false
	}
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return time.Time{}, false
	}
	end := strings.LastIndexByte(string(data), ')')
	if end < 0 {
		return time.Time{}, false
	}
	fields := strings.Fields(string(data)[end+1:])
	if len(fields) < 20 {
		return time.Time{}, false
	}
	ticks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	return time.Unix(boot, 0).Add(time.Duration(ticks) * time.Second / clockTicks), true
}
