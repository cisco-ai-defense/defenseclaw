// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package testenv

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// readThreadTimes reads the scheduler statistics of every thread of this
// process (/proc/self/task/<tid>/schedstat: nanoseconds on the CPU,
// nanoseconds ready and waiting, time slices). It is nil when the kernel
// keeps none.
func readThreadTimes() map[int]threadTimes {
	entries, err := os.ReadDir("/proc/self/task")
	if err != nil {
		return nil
	}
	threads := make(map[int]threadTimes, len(entries))
	for _, entry := range entries {
		tid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		data, err := os.ReadFile("/proc/self/task/" + entry.Name() + "/schedstat")
		if err != nil {
			if os.IsNotExist(err) {
				continue // the thread ended
			}
			return nil
		}
		fields := strings.Fields(string(data))
		if len(fields) < 2 {
			return nil
		}
		run, errRun := strconv.ParseInt(fields[0], 10, 64)
		wait, errWait := strconv.ParseInt(fields[1], 10, 64)
		if errRun != nil || errWait != nil {
			return nil
		}
		threads[tid] = threadTimes{run: time.Duration(run), wait: time.Duration(wait)}
	}
	return threads
}
