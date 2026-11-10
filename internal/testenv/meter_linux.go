// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package testenv

import (
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// readSchedstat reads /proc/self/task/<task>/schedstat: nanoseconds on the CPU,
// nanoseconds ready and waiting, time slices. It is false when the kernel
// keeps none for the thread. gone is true for a thread that has ended.
func readSchedstat(task string) (times threadTimes, gone, ok bool) {
	data, err := os.ReadFile("/proc/self/task/" + task + "/schedstat")
	if err != nil {
		return threadTimes{}, os.IsNotExist(err), false
	}
	fields := strings.Fields(string(data))
	if len(fields) < 2 {
		return threadTimes{}, false, false
	}
	run, errRun := strconv.ParseInt(fields[0], 10, 64)
	wait, errWait := strconv.ParseInt(fields[1], 10, 64)
	if errRun != nil || errWait != nil || run < 0 || wait < 0 {
		return threadTimes{}, false, false
	}
	return threadTimes{run: time.Duration(run), wait: time.Duration(wait)}, false, true
}

// threadWaited is the time the calling thread has been ready to run and had no
// CPU since it began. It reports false when the kernel keeps none. The caller
// holds its thread (runtime.LockOSThread), so two readings are of one thread.
func threadWaited() (time.Duration, bool) {
	times, _, ok := readSchedstat(strconv.Itoa(syscall.Gettid()))
	return times.wait, ok
}

// readThreadTimes reads the scheduler statistics of every thread of this
// process. It is nil when the kernel keeps none.
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
		times, gone, ok := readSchedstat(entry.Name())
		if gone {
			continue // the thread ended
		}
		if !ok {
			return nil
		}
		threads[tid] = times
	}
	return threads
}
